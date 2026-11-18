package api

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/oh-my-cpa/oh-my-cpa/internal/cpa/management"
	"github.com/oh-my-cpa/oh-my-cpa/internal/repository"
	"github.com/oh-my-cpa/oh-my-cpa/internal/security"
	"github.com/oh-my-cpa/oh-my-cpa/internal/statecoord"
)

type ClientAPIKeyItemDTO struct {
	Index int `json:"index"`
	// Key is the key's display mask (`security.MaskSecret`), and the key itself only
	// when the caller asked for it with `include_keys=true`: the key page joins this
	// list against the configuration document it edits, and it needs the value to do
	// that, while every other reader renders the mask. The field always carries the
	// same shape for the same key either way, so a reader that masks what it is given
	// reads both forms identically.
	Key string `json:"key"`
	// Fingerprint is the legacy keys-page identity, computed under the
	// "client-key" purpose. It is retained so existing clients keep working.
	Fingerprint string `json:"fingerprint"`
	// UsageFingerprint is the identity this key has in the usage records
	// (`usage_events.api_group_key`), computed under the "usage-api-key"
	// purpose. Only this value can be joined to a request record, so it is what
	// an alias is stored against and what the "view requests" action filters by.
	// Empty when the cipher is unavailable; an empty value must never be used as
	// an alias identity.
	UsageFingerprint string `json:"usage_fingerprint,omitempty"`
	Length           int    `json:"length"`
	// Alias is the operator-assigned name, empty when the key is unnamed.
	Alias string `json:"alias,omitempty"`
	// AliasVersion is the version a rename must cite; zero means no alias exists.
	AliasVersion int64 `json:"alias_version"`
	// AllowedModels and DeniedModels are the key's model patterns in CPA's
	// `access.api-key-model-access`. Both empty means the key is unrestricted. CPA owns the
	// matching rules; a gateway without the feature simply never reports any.
	AllowedModels []string `json:"allowed_models,omitempty"`
	DeniedModels  []string `json:"denied_models,omitempty"`
}

var (
	errClientKeyDuplicate   = errors.New("api key already exists")
	errClientKeyOutOfBounds = errors.New("key index out of bounds")
	errClientKeyStaleIndex  = errors.New("the key at this position changed; reload and try again")
)

func (h *Handler) projectClientAPIKeyItems(keys []string, access map[string]management.ClientKeyModelAccess, aliases map[string]repository.ClientKeyAlias, includeKeys bool) []ClientAPIKeyItemDTO {
	items := make([]ClientAPIKeyItemDTO, 0, len(keys))
	for i, key := range keys {
		trimmed := strings.TrimSpace(key)
		fingerprint := security.FingerprintOrRedacted(h.cipher, "client-key", trimmed)
		// The mask is idempotent, so a reader that masks whatever it is given
		// renders this field identically in both forms.
		displayKey := trimmed
		if !includeKeys {
			displayKey = security.MaskSecret(trimmed)
		}
		item := ClientAPIKeyItemDTO{
			Index:       i,
			Key:         displayKey,
			Fingerprint: fingerprint,
			Length:      len(trimmed),
		}
		if entry, ok := access[key]; ok {
			item.AllowedModels = slices.Clone(entry.Allowed)
			item.DeniedModels = slices.Clone(entry.Denied)
		}
		// The usage identity is derived with the purpose the ingestion path uses,
		// which is what makes a name attach to the requests this key served. It is
		// left empty when the fingerprint fails rather than filled with the shared
		// redacted marker, because an alias keyed on that value would leak one
		// key's name onto another's records.
		if usageFingerprint, fpErr := h.repo.UsageClientKeyFingerprint(trimmed); fpErr == nil {
			item.UsageFingerprint = usageFingerprint
			if entry, ok := aliases[usageFingerprint]; ok {
				item.Alias = entry.Alias
				item.AliasVersion = entry.Version
			}
		}
		items = append(items, item)
	}
	return items
}

// ClientAPIKeyListResponseDTO lists configured client API keys (masked unless explicitly revealed).
type ClientAPIKeyListResponseDTO struct {
	Keys    []ClientAPIKeyItemDTO `json:"keys"`
	Total   int                   `json:"total"`
	Version uint64                `json:"version,omitempty"`
}

// ClientAPIKeyMutationResponseDTO returns the masked key and fingerprints after creating or updating a key.
type ClientAPIKeyMutationResponseDTO struct {
	Status           string `json:"status"`
	Index            int    `json:"index"`
	Key              string `json:"key"`
	Fingerprint      string `json:"fingerprint"`
	UsageFingerprint string `json:"usage_fingerprint,omitempty"`
	Version          uint64 `json:"version,omitempty"`
}

// ClientAPIKeyDeleteResponseDTO confirms deletion of a client API key by index.
type ClientAPIKeyDeleteResponseDTO struct {
	Status  string `json:"status"`
	Deleted int    `json:"deleted"`
	Version uint64 `json:"version,omitempty"`
}

// @Summary List client API keys
// @Description Return caller API key masks, fingerprints, and aliases (or raw keys when include_keys=true with fail-closed audit).
// @Tags ClientKeys
// @Produce json
// @Security CookieAuth
// @Param include_keys query boolean false "Include raw key strings (audited fail-closed; refused in demo)"
// @Success 200 {object} ClientAPIKeyListResponseDTO
// @Failure 401 {object} ErrorResponseDTO
// @Failure 500 {object} ErrorResponseDTO
// @Failure 502 {object} ErrorResponseDTO
// @Router /v1/management/api-keys [get]
func (h *Handler) listClientAPIKeys(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	client, ok := h.managementClientOrError(writer, request)
	if !ok {
		return
	}
	// The raw caller keys leave the process only for the page whose contract
	// includes editing them, which is the same opt-in the provider list uses. A
	// response that merely reports the keys - the dashboard's picker, a future
	// panel - needs the mask and must not be able to read a credential out of a
	// response body.
	includeKeys := h.revealKeysAllowed(request)

	var (
		keys    []string
		access  map[string]management.ClientKeyModelAccess
		version uint64
		err     error
	)
	if h.stateCoord != nil {
		type clientKeySnapshot struct {
			keys   []string
			access map[string]management.ClientKeyModelAccess
		}
		env, coordErr := statecoord.ProjectTyped(request.Context(), h.stateCoord, func(state projectedConfigState, _ uint64) (clientKeySnapshot, error) {
			return clientKeySnapshot{slices.Clone(state.ClientKeys), cloneClientKeyModelAccess(state.ClientKeyModelAccess)}, nil
		})
		if coordErr == nil {
			keys = env.Data.keys
			access = env.Data.access
			version = env.Version
		} else {
			err = coordErr
		}
	} else {
		keys, access, err = client.ClientKeyAccess(request.Context())
	}
	if err != nil {
		writeCPAFacadeError(writer, err)
		return
	}

	aliases, aliasErr := h.repo.ListClientKeyAliases(request.Context(), defaultInstanceID())
	if aliasErr != nil {
		// The alias overlay is metadata. Failing the whole key list over it would
		// hide the keys themselves, so the list is served unnamed instead.
		aliases = map[string]repository.ClientKeyAlias{}
	}

	items := h.projectClientAPIKeyItems(keys, access, aliases, includeKeys)

	if includeKeys {
		// The reveal is the audit boundary: a masked response carries no credential,
		// so it is not a credential read and must not fill the log on every poll.
		if auditErr := h.recordAudit(request, "api_key.reveal", "client_api_key", "list", "success", map[string]any{
			"key_count": len(items),
		}); auditErr != nil {
			writeAuditFailure(writer, "audit log failure; client key reveal aborted")
			return
		}
	}

	setStateVersionHeader(writer, version)
	writeJSON(writer, http.StatusOK, ClientAPIKeyListResponseDTO{
		Keys:    items,
		Total:   len(items),
		Version: version,
	})
}

type createClientKeyRequest struct {
	Key                 string `json:"key"`
	ExpectedFingerprint string `json:"expected_fingerprint,omitempty"`
}

// @Summary Create a client API key
// @Description Append a new caller API key to CPA and return its masked representation and fingerprints.
// @Tags ClientKeys
// @Accept json
// @Produce json
// @Security CookieAuth
// @Param body body createClientKeyRequest true "New client API key"
// @Success 200 {object} ClientAPIKeyMutationResponseDTO
// @Failure 400 {object} ErrorResponseDTO
// @Failure 401 {object} ErrorResponseDTO
// @Failure 409 {object} ErrorResponseDTO
// @Failure 500 {object} ErrorResponseDTO
// @Failure 502 {object} ErrorResponseDTO
// @Failure 503 {object} ErrorResponseDTO
// @Router /v1/management/api-keys [post]
func (h *Handler) createClientAPIKey(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	var req createClientKeyRequest
	if err := decodeManagementJSON(writer, request, 8*1024, &req); err != nil {
		return
	}
	newKey := strings.TrimSpace(req.Key)
	if newKey == "" {
		writeError(writer, http.StatusBadRequest, "api key cannot be empty")
		return
	}
	if len(newKey) > 8192 {
		writeError(writer, http.StatusBadRequest, "api key exceeds maximum length")
		return
	}

	client, ok := h.managementClientOrError(writer, request)
	if !ok {
		return
	}

	fingerprint := security.FingerprintOrRedacted(h.cipher, "client-key", newKey)
	usageFingerprint, _ := h.repo.UsageClientKeyFingerprint(newKey)

	if h.stateCoord != nil {
		env, loadErr := statecoord.ProjectTyped(request.Context(), h.stateCoord, func(state projectedConfigState, _ uint64) (int, error) {
			return len(state.ClientKeys), nil
		})
		if loadErr != nil {
			writeCPAFacadeError(writer, loadErr)
			return
		}
		targetLabel := fmt.Sprintf("index:%d", env.Data)
		if auditErr := h.recordAudit(request, "api_key.create", "client_api_key", targetLabel, "attempt", nil); auditErr != nil {
			writeError(writer, http.StatusInternalServerError, "audit failure; key creation aborted")
			return
		}

		createdIndex := 0
		version, mutErr := h.mutateCoordinatorWithAudit(request, stateDomainClientKeys, "api_key.create", "client_api_key", targetLabel, nil, func(state *projectedConfigState) error {
			for _, existing := range state.ClientKeys {
				if strings.TrimSpace(existing) == newKey {
					return errClientKeyDuplicate
				}
			}
			createdIndex = len(state.ClientKeys)
			state.ClientKeys = append(state.ClientKeys, newKey)
			return nil
		})
		if mutErr != nil {
			_ = h.recordAudit(request, "api_key.create", "client_api_key", targetLabel, "failure", map[string]any{"error": mutErr.Error()})
			if errors.Is(mutErr, errClientKeyDuplicate) {
				writeJSON(writer, http.StatusConflict, map[string]string{"error": mutErr.Error(), "code": "resource_conflict"})
				return
			}
			writeProviderWriteError(writer, mutErr)
			return
		}
		h.invalidateClientKeyCatalog()
		setStateVersionHeader(writer, version)
		writeJSON(writer, http.StatusOK, ClientAPIKeyMutationResponseDTO{
			Status:           "ok",
			Index:            createdIndex,
			Key:              security.MaskSecret(newKey),
			Fingerprint:      fingerprint,
			UsageFingerprint: usageFingerprint,
			Version:          version,
		})
		return
	}

	currentKeys, err := client.ClientAPIKeys(request.Context())
	if err != nil {
		writeCPAFacadeError(writer, err)
		return
	}

	if auditErr := h.recordAudit(request, "api_key.create", "client_api_key", fmt.Sprintf("index:%d", len(currentKeys)), "attempt", nil); auditErr != nil {
		writeError(writer, http.StatusInternalServerError, "audit failure; key creation aborted")
		return
	}

	createdIndex, err := h.operationsService().CreateKey(request.Context(), newKey, "")
	if err != nil {
		_ = h.recordAudit(request, "api_key.create", "client_api_key", fmt.Sprintf("index:%d", len(currentKeys)), "failure", map[string]any{"error": err.Error()})
		if err.Error() == "resource_conflict" {
			writeJSON(writer, http.StatusConflict, map[string]string{"error": "api key already exists", "code": "resource_conflict"})
			return
		}
		writeCPAFacadeError(writer, err)
		return
	}

	_ = h.recordAudit(request, "api_key.create", "client_api_key", fmt.Sprintf("index:%d", len(currentKeys)), "success", nil)

	writeJSON(writer, http.StatusOK, ClientAPIKeyMutationResponseDTO{
		Status:           "ok",
		Index:            createdIndex,
		Key:              security.MaskSecret(newKey),
		Fingerprint:      fingerprint,
		UsageFingerprint: usageFingerprint,
	})
}

// @Summary Update a client API key
// @Description Replace an existing caller API key at the given positional index with optional fingerprint guard.
// @Tags ClientKeys
// @Accept json
// @Produce json
// @Security CookieAuth
// @Param index path integer true "Positional key index"
// @Param body body createClientKeyRequest true "Replacement client API key"
// @Success 200 {object} ClientAPIKeyMutationResponseDTO
// @Failure 400 {object} ErrorResponseDTO
// @Failure 401 {object} ErrorResponseDTO
// @Failure 404 {object} ErrorResponseDTO
// @Failure 409 {object} ErrorResponseDTO
// @Failure 500 {object} ErrorResponseDTO
// @Failure 502 {object} ErrorResponseDTO
// @Failure 503 {object} ErrorResponseDTO
// @Router /v1/management/api-keys/{index} [put]
func (h *Handler) updateClientAPIKey(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	rawIndex := chi.URLParam(request, "index")
	index, err := strconv.Atoi(rawIndex)
	if err != nil || index < 0 {
		writeError(writer, http.StatusBadRequest, "invalid key index")
		return
	}

	var req createClientKeyRequest
	if err := decodeManagementJSON(writer, request, 8*1024, &req); err != nil {
		return
	}
	updatedKey := strings.TrimSpace(req.Key)
	if updatedKey == "" {
		writeError(writer, http.StatusBadRequest, "api key cannot be empty")
		return
	}
	if len(updatedKey) > 8192 {
		writeError(writer, http.StatusBadRequest, "api key exceeds maximum length")
		return
	}

	client, ok := h.managementClientOrError(writer, request)
	if !ok {
		return
	}

	fingerprint := security.FingerprintOrRedacted(h.cipher, "client-key", updatedKey)
	usageFingerprint, _ := h.repo.UsageClientKeyFingerprint(updatedKey)
	expectedFingerprint := strings.TrimSpace(req.ExpectedFingerprint)
	targetLabel := fmt.Sprintf("index:%d", index)

	if h.stateCoord != nil {
		observed, loadErr := statecoord.ProjectTyped(request.Context(), h.stateCoord, func(state projectedConfigState, _ uint64) (string, error) {
			if index >= len(state.ClientKeys) {
				return "", errClientKeyOutOfBounds
			}
			actual := strings.TrimSpace(state.ClientKeys[index])
			if expectedFingerprint != "" && security.FingerprintOrRedacted(h.cipher, "client-key", actual) != expectedFingerprint {
				return "", errClientKeyStaleIndex
			}
			return state.ClientKeys[index], nil
		})
		if loadErr != nil {
			if errors.Is(loadErr, errClientKeyOutOfBounds) {
				writeError(writer, http.StatusNotFound, "key index out of bounds")
				return
			}
			if errors.Is(loadErr, errClientKeyStaleIndex) {
				writeJSON(writer, http.StatusConflict, map[string]string{"error": loadErr.Error(), "code": "resource_conflict"})
				return
			}
			writeCPAFacadeError(writer, loadErr)
			return
		}
		expectedKey := observed.Data

		if auditErr := h.recordAudit(request, "api_key.update", "client_api_key", targetLabel, "attempt", nil); auditErr != nil {
			writeError(writer, http.StatusInternalServerError, "audit failure; key update aborted")
			return
		}

		version, mutErr := h.mutateCoordinatorWithAudit(request, stateDomainClientKeys, "api_key.update", "client_api_key", targetLabel, nil, func(state *projectedConfigState) error {
			if index >= len(state.ClientKeys) {
				return errClientKeyOutOfBounds
			}
			if state.ClientKeys[index] != expectedKey {
				return errClientKeyStaleIndex
			}
			if expectedFingerprint != "" && security.FingerprintOrRedacted(h.cipher, "client-key", strings.TrimSpace(state.ClientKeys[index])) != expectedFingerprint {
				return errClientKeyStaleIndex
			}
			for pos, existing := range state.ClientKeys {
				if pos != index && strings.TrimSpace(existing) == updatedKey {
					return errClientKeyDuplicate
				}
			}
			moveClientKeyModelAccess(state, state.ClientKeys[index], updatedKey)
			state.ClientKeys[index] = updatedKey
			return nil
		})
		if mutErr != nil {
			_ = h.recordAudit(request, "api_key.update", "client_api_key", targetLabel, "failure", map[string]any{"error": mutErr.Error()})
			if errors.Is(mutErr, errClientKeyOutOfBounds) {
				writeError(writer, http.StatusNotFound, "key index out of bounds")
				return
			}
			if errors.Is(mutErr, errClientKeyDuplicate) || errors.Is(mutErr, errClientKeyStaleIndex) {
				writeJSON(writer, http.StatusConflict, map[string]string{"error": mutErr.Error(), "code": "resource_conflict"})
				return
			}
			writeProviderWriteError(writer, mutErr)
			return
		}
		h.invalidateClientKeyCatalog()
		setStateVersionHeader(writer, version)
		writeJSON(writer, http.StatusOK, ClientAPIKeyMutationResponseDTO{
			Status:           "ok",
			Index:            index,
			Key:              security.MaskSecret(updatedKey),
			Fingerprint:      fingerprint,
			UsageFingerprint: usageFingerprint,
			Version:          version,
		})
		return
	}

	if err := h.providerWrites.acquire(request.Context()); err != nil {
		writeProviderWriteError(writer, err)
		return
	}
	defer h.providerWrites.release()

	currentKeys, currentAccess, err := client.ClientKeyAccess(request.Context())
	if err != nil {
		writeCPAFacadeError(writer, err)
		return
	}
	if index >= len(currentKeys) {
		writeError(writer, http.StatusNotFound, "key index out of bounds")
		return
	}
	if expectedFingerprint != "" && security.FingerprintOrRedacted(h.cipher, "client-key", strings.TrimSpace(currentKeys[index])) != expectedFingerprint {
		writeJSON(writer, http.StatusConflict, map[string]string{"error": errClientKeyStaleIndex.Error(), "code": "resource_conflict"})
		return
	}
	for pos, existing := range currentKeys {
		if pos != index && strings.TrimSpace(existing) == updatedKey {
			writeJSON(writer, http.StatusConflict, map[string]string{"error": "api key already exists", "code": "resource_conflict"})
			return
		}
	}
	if auditErr := h.recordAudit(request, "api_key.update", "client_api_key", targetLabel, "attempt", nil); auditErr != nil {
		writeError(writer, http.StatusInternalServerError, "audit failure; key update aborted")
		return
	}
	nextKeys := slices.Clone(currentKeys)
	nextKeys[index] = updatedKey
	carried := moveModelAccessEntry(currentAccess, currentKeys[index], updatedKey)
	if err := client.UpdateClientKeyAccess(request.Context(), nextKeys, currentAccess, carried); err != nil {
		_ = h.recordAudit(request, "api_key.update", "client_api_key", targetLabel, "failure", map[string]any{"error": err.Error()})
		writeCPAFacadeError(writer, err)
		return
	}
	h.invalidateClientKeyCatalog()
	_ = h.recordAudit(request, "api_key.update", "client_api_key", targetLabel, "success", nil)
	writeJSON(writer, http.StatusOK, ClientAPIKeyMutationResponseDTO{
		Status:           "ok",
		Index:            index,
		Key:              security.MaskSecret(updatedKey),
		Fingerprint:      fingerprint,
		UsageFingerprint: usageFingerprint,
	})
}

// @Summary Delete a client API key
// @Description Remove a caller API key at the given positional index with optional fingerprint verification.
// @Tags ClientKeys
// @Produce json
// @Security CookieAuth
// @Param index path integer true "Positional key index"
// @Param expected_fingerprint query string false "Expected key fingerprint for stale-index protection"
// @Success 200 {object} ClientAPIKeyDeleteResponseDTO
// @Failure 400 {object} ErrorResponseDTO
// @Failure 401 {object} ErrorResponseDTO
// @Failure 404 {object} ErrorResponseDTO
// @Failure 409 {object} ErrorResponseDTO
// @Failure 500 {object} ErrorResponseDTO
// @Failure 502 {object} ErrorResponseDTO
// @Failure 503 {object} ErrorResponseDTO
// @Router /v1/management/api-keys/{index} [delete]
func (h *Handler) deleteClientAPIKey(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	rawIndex := chi.URLParam(request, "index")
	index, err := strconv.Atoi(rawIndex)
	if err != nil || index < 0 {
		writeError(writer, http.StatusBadRequest, "invalid key index")
		return
	}

	client, ok := h.managementClientOrError(writer, request)
	if !ok {
		return
	}
	expectedFingerprint := strings.TrimSpace(request.URL.Query().Get("expected_fingerprint"))

	if h.stateCoord != nil {
		observed, loadErr := statecoord.ProjectTyped(request.Context(), h.stateCoord, func(state projectedConfigState, _ uint64) (string, error) {
			if index >= len(state.ClientKeys) {
				return "", errClientKeyOutOfBounds
			}
			actual := strings.TrimSpace(state.ClientKeys[index])
			if expectedFingerprint != "" && security.FingerprintOrRedacted(h.cipher, "client-key", actual) != expectedFingerprint {
				return "", errClientKeyStaleIndex
			}
			return state.ClientKeys[index], nil
		})
		if loadErr != nil {
			if errors.Is(loadErr, errClientKeyOutOfBounds) {
				writeError(writer, http.StatusNotFound, "key index out of bounds")
				return
			}
			if errors.Is(loadErr, errClientKeyStaleIndex) {
				writeJSON(writer, http.StatusConflict, map[string]string{"error": loadErr.Error(), "code": "resource_conflict"})
				return
			}
			writeCPAFacadeError(writer, loadErr)
			return
		}
		expectedKey := observed.Data

		targetLabel := fmt.Sprintf("index:%d", index)
		if auditErr := h.recordAudit(request, "api_key.delete", "client_api_key", targetLabel, "attempt", nil); auditErr != nil {
			writeError(writer, http.StatusInternalServerError, "audit failure; key deletion aborted")
			return
		}

		version, mutErr := h.mutateCoordinatorWithAudit(request, stateDomainClientKeys, "api_key.delete", "client_api_key", targetLabel, nil, func(state *projectedConfigState) error {
			if index >= len(state.ClientKeys) {
				return errClientKeyOutOfBounds
			}
			if state.ClientKeys[index] != expectedKey {
				return errClientKeyStaleIndex
			}
			if expectedFingerprint != "" && security.FingerprintOrRedacted(h.cipher, "client-key", strings.TrimSpace(state.ClientKeys[index])) != expectedFingerprint {
				return errClientKeyStaleIndex
			}
			moveClientKeyModelAccess(state, state.ClientKeys[index], "")
			state.ClientKeys = append(state.ClientKeys[:index:index], state.ClientKeys[index+1:]...)
			return nil
		})
		if mutErr != nil {
			_ = h.recordAudit(request, "api_key.delete", "client_api_key", targetLabel, "failure", map[string]any{"error": mutErr.Error()})
			if errors.Is(mutErr, errClientKeyOutOfBounds) {
				writeError(writer, http.StatusNotFound, "key index out of bounds")
				return
			}
			if errors.Is(mutErr, errClientKeyStaleIndex) {
				writeJSON(writer, http.StatusConflict, map[string]string{"error": mutErr.Error(), "code": "resource_conflict"})
				return
			}
			writeProviderWriteError(writer, mutErr)
			return
		}
		h.invalidateClientKeyCatalog()
		setStateVersionHeader(writer, version)
		writeJSON(writer, http.StatusOK, ClientAPIKeyDeleteResponseDTO{
			Status:  "ok",
			Deleted: index,
			Version: version,
		})
		return
	}

	currentKeys, err := client.ClientAPIKeys(request.Context())
	if err != nil {
		writeCPAFacadeError(writer, err)
		return
	}

	if index >= len(currentKeys) {
		writeError(writer, http.StatusNotFound, "key index out of bounds")
		return
	}
	if expectedFingerprint != "" && security.FingerprintOrRedacted(h.cipher, "client-key", strings.TrimSpace(currentKeys[index])) != expectedFingerprint {
		writeJSON(writer, http.StatusConflict, map[string]string{"error": errClientKeyStaleIndex.Error(), "code": "resource_conflict"})
		return
	}

	fingerprint, err := h.repo.UsageClientKeyFingerprint(strings.TrimSpace(currentKeys[index]))
	if err != nil {
		writeInternalError(writer, err)
		return
	}

	if auditErr := h.recordAudit(request, "api_key.delete", "client_api_key", fmt.Sprintf("index:%d", index), "attempt", nil); auditErr != nil {
		writeError(writer, http.StatusInternalServerError, "audit failure; key deletion aborted")
		return
	}

	if err := h.operationsService().DeleteKey(request.Context(), index, fingerprint, ""); err != nil {
		_ = h.recordAudit(request, "api_key.delete", "client_api_key", fmt.Sprintf("index:%d", index), "failure", map[string]any{"error": err.Error()})
		writeCPAFacadeError(writer, err)
		return
	}

	_ = h.recordAudit(request, "api_key.delete", "client_api_key", fmt.Sprintf("index:%d", index), "success", nil)

	writeJSON(writer, http.StatusOK, ClientAPIKeyDeleteResponseDTO{
		Status:  "ok",
		Deleted: index,
	})
}

// moveClientKeyModelAccess carries a key's restriction to its replacement, or drops it when
// the key is deleted (to == ""), and marks the mapping for writing. A key without an entry
// leaves the mapping and the flag alone, so editing an unrestricted key never touches
// `access.api-key-model-access`.
func moveClientKeyModelAccess(state *projectedConfigState, from, to string) {
	if moveModelAccessEntry(state.ClientKeyModelAccess, from, to) {
		state.ClientKeyAccessDirty = true
	}
}

// moveModelAccessEntry renames or removes one entry in place and reports whether the mapping
// changed.
func moveModelAccessEntry(access map[string]management.ClientKeyModelAccess, from, to string) bool {
	entry, ok := access[from]
	if !ok || from == to {
		return false
	}
	delete(access, from)
	if to != "" {
		access[to] = entry
	}
	return true
}

const (
	maxModelAccessPatterns      = 200
	maxModelAccessPatternLength = 256
)

var errModelAccessInvalid = errors.New("invalid model access patterns")

// normalizeModelPatterns trims, drops blanks and removes duplicates while keeping the order
// the operator wrote. CPA does its own case folding when it matches, so case is preserved.
func normalizeModelPatterns(patterns []string) ([]string, error) {
	out := make([]string, 0, len(patterns))
	seen := make(map[string]struct{}, len(patterns))
	for _, raw := range patterns {
		pattern := strings.TrimSpace(raw)
		if pattern == "" {
			continue
		}
		if len(pattern) > maxModelAccessPatternLength || strings.ContainsFunc(pattern, unicode.IsControl) {
			return nil, errModelAccessInvalid
		}
		if _, dup := seen[pattern]; dup {
			continue
		}
		seen[pattern] = struct{}{}
		out = append(out, pattern)
	}
	if len(out) > maxModelAccessPatterns {
		return nil, errModelAccessInvalid
	}
	return out, nil
}

type updateClientKeyModelAccessRequest struct {
	ExpectedFingerprint string   `json:"expected_fingerprint,omitempty"`
	AllowedModels       []string `json:"allowed_models"`
	DeniedModels        []string `json:"denied_models"`
}

// @Summary Set a client API key's model access
// @Description Replace the allowed/denied model patterns of the caller API key at the given positional index. Both lists empty removes the restriction. Needs a CPA that supports access.api-key-model-access; CPA owns pattern matching.
// @Tags ClientKeys
// @Accept json
// @Produce json
// @Security CookieAuth
// @Param index path integer true "Positional key index"
// @Param body body updateClientKeyModelAccessRequest true "Model patterns"
// @Success 200 {object} ClientAPIKeyModelAccessResponseDTO
// @Failure 400 {object} ErrorResponseDTO
// @Failure 401 {object} ErrorResponseDTO
// @Failure 404 {object} ErrorResponseDTO
// @Failure 409 {object} ErrorResponseDTO
// @Failure 500 {object} ErrorResponseDTO
// @Failure 502 {object} ErrorResponseDTO
// @Failure 503 {object} ErrorResponseDTO
// @Router /v1/management/api-keys/{index}/model-access [put]
func (h *Handler) updateClientAPIKeyModelAccess(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	index, err := strconv.Atoi(chi.URLParam(request, "index"))
	if err != nil || index < 0 {
		writeError(writer, http.StatusBadRequest, "invalid key index")
		return
	}
	var req updateClientKeyModelAccessRequest
	if err := decodeManagementJSON(writer, request, 64*1024, &req); err != nil {
		return
	}
	allowed, allowedErr := normalizeModelPatterns(req.AllowedModels)
	denied, deniedErr := normalizeModelPatterns(req.DeniedModels)
	if allowedErr != nil || deniedErr != nil {
		writeError(writer, http.StatusBadRequest, fmt.Sprintf("model patterns must be at most %d entries of %d characters without control characters", maxModelAccessPatterns, maxModelAccessPatternLength))
		return
	}
	next := management.ClientKeyModelAccess{Allowed: allowed, Denied: denied}
	expectedFingerprint := strings.TrimSpace(req.ExpectedFingerprint)
	targetLabel := fmt.Sprintf("index:%d", index)

	client, ok := h.managementClientOrError(writer, request)
	if !ok {
		return
	}
	details := map[string]any{"allowed_count": len(allowed), "denied_count": len(denied)}
	respond := func(version uint64) {
		setStateVersionHeader(writer, version)
		writeJSON(writer, http.StatusOK, ClientAPIKeyModelAccessResponseDTO{
			Status:        "ok",
			Index:         index,
			AllowedModels: allowed,
			DeniedModels:  denied,
			Version:       version,
		})
	}
	fail := func(err error) {
		_ = h.recordAudit(request, "api_key.model_access", "client_api_key", targetLabel, "failure", map[string]any{"error": err.Error()})
		switch {
		case errors.Is(err, errClientKeyOutOfBounds):
			writeError(writer, http.StatusNotFound, "key index out of bounds")
		case errors.Is(err, errClientKeyStaleIndex):
			writeJSON(writer, http.StatusConflict, map[string]string{"error": err.Error(), "code": "resource_conflict"})
		default:
			writeProviderWriteError(writer, err)
		}
	}
	if auditErr := h.recordAudit(request, "api_key.model_access", "client_api_key", targetLabel, "attempt", details); auditErr != nil {
		writeError(writer, http.StatusInternalServerError, "audit failure; model access update aborted")
		return
	}

	if h.stateCoord != nil {
		version, mutErr := h.mutateCoordinatorWithAudit(request, stateDomainClientKeys, "api_key.model_access", "client_api_key", targetLabel, details, func(state *projectedConfigState) error {
			if index >= len(state.ClientKeys) {
				return errClientKeyOutOfBounds
			}
			key := state.ClientKeys[index]
			if expectedFingerprint != "" && security.FingerprintOrRedacted(h.cipher, "client-key", strings.TrimSpace(key)) != expectedFingerprint {
				return errClientKeyStaleIndex
			}
			if state.ClientKeyModelAccess == nil {
				state.ClientKeyModelAccess = map[string]management.ClientKeyModelAccess{}
			}
			if next.IsZero() {
				delete(state.ClientKeyModelAccess, key)
			} else {
				state.ClientKeyModelAccess[key] = next
			}
			state.ClientKeyAccessDirty = true
			return nil
		})
		if mutErr != nil {
			fail(mutErr)
			return
		}
		respond(version)
		return
	}

	if err := h.providerWrites.acquire(request.Context()); err != nil {
		fail(err)
		return
	}
	defer h.providerWrites.release()
	keys, access, err := client.ClientKeyAccess(request.Context())
	if err != nil {
		fail(err)
		return
	}
	if index >= len(keys) {
		fail(errClientKeyOutOfBounds)
		return
	}
	key := keys[index]
	if expectedFingerprint != "" && security.FingerprintOrRedacted(h.cipher, "client-key", strings.TrimSpace(key)) != expectedFingerprint {
		fail(errClientKeyStaleIndex)
		return
	}
	if next.IsZero() {
		delete(access, key)
	} else {
		access[key] = next
	}
	if err := client.UpdateClientKeyAccess(request.Context(), keys, access, true); err != nil {
		fail(err)
		return
	}
	_ = h.recordAudit(request, "api_key.model_access", "client_api_key", targetLabel, "success", details)
	respond(0)
}

// ClientAPIKeyModelAccessResponseDTO echoes the normalized patterns that were stored.
type ClientAPIKeyModelAccessResponseDTO struct {
	Status        string   `json:"status"`
	Index         int      `json:"index"`
	AllowedModels []string `json:"allowed_models"`
	DeniedModels  []string `json:"denied_models"`
	Version       uint64   `json:"version,omitempty"`
}
