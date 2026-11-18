package api

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

const modelAccessBase = "/omc/api/v1/management/api-keys"

func listedKeyAccess(t *testing.T, fixture providerTestFixture, index int) ClientAPIKeyItemDTO {
	t.Helper()
	resp, payload := getJSON(t, fixture.client, fixture.baseURL+modelAccessBase+"?include_keys=true")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d body %s", resp.StatusCode, payload)
	}
	var list struct {
		Keys []ClientAPIKeyItemDTO `json:"keys"`
	}
	if err := json.Unmarshal(payload, &list); err != nil || index >= len(list.Keys) {
		t.Fatalf("unexpected list: %s", payload)
	}
	return list.Keys[index]
}

func storedAccess(t *testing.T, fixture providerTestFixture) map[string]any {
	t.Helper()
	fixture.state.mu.Lock()
	defer fixture.state.mu.Unlock()
	out := map[string]any{}
	for key, value := range fixture.state.modelAccess {
		out[key] = value
	}
	return out
}

// A key's patterns are written to CPA's `access.api-key-model-access` under the key's own text,
// reported back by the key list, normalized on the way in, and removed when both lists empty.
func TestClientKeyModelAccessRoundTrip(t *testing.T) {
	fixture := newProviderTestFixture(t)
	item := listedKeyAccess(t, fixture, 0)

	body := `{"expected_fingerprint":"` + item.Fingerprint + `","allowed_models":[" claude-* ","gpt-5-codex","claude-*",""],"denied_models":["gpt-5.6-*"]}`
	resp, payload := doJSON(t, fixture.client, http.MethodPut, fixture.baseURL+modelAccessBase+"/0/model-access", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set access status = %d body %s", resp.StatusCode, payload)
	}
	if strings.Contains(string(payload), "sk-original-key-1") {
		t.Fatalf("the response must not carry the key: %s", payload)
	}
	want := map[string]any{"sk-original-key-1": map[string]any{
		"allowed-models": []any{"claude-*", "gpt-5-codex"},
		"denied-models":  []any{"gpt-5.6-*"},
	}}
	if got := storedAccess(t, fixture); !reflect.DeepEqual(got, want) {
		t.Fatalf("CPA restriction = %#v, want %#v", got, want)
	}

	listed := listedKeyAccess(t, fixture, 0)
	if !reflect.DeepEqual(listed.AllowedModels, []string{"claude-*", "gpt-5-codex"}) || !reflect.DeepEqual(listed.DeniedModels, []string{"gpt-5.6-*"}) {
		t.Fatalf("listed access = %v / %v", listed.AllowedModels, listed.DeniedModels)
	}
	if other := listedKeyAccess(t, fixture, 1); len(other.AllowedModels)+len(other.DeniedModels) != 0 {
		t.Fatalf("a key without an entry must read as unrestricted: %#v", other)
	}

	resp, payload = doJSON(t, fixture.client, http.MethodPut, fixture.baseURL+modelAccessBase+"/0/model-access", `{"expected_fingerprint":"`+item.Fingerprint+`","allowed_models":[],"denied_models":[]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clear access status = %d body %s", resp.StatusCode, payload)
	}
	if got := storedAccess(t, fixture); len(got) != 0 {
		t.Fatalf("clearing both lists must remove the section, CPA holds %#v", got)
	}
}

func TestClientKeyModelAccessRefusals(t *testing.T) {
	fixture := newProviderTestFixture(t)
	item := listedKeyAccess(t, fixture, 0)
	put := func(index, body string) int {
		resp, _ := doJSON(t, fixture.client, http.MethodPut, fixture.baseURL+modelAccessBase+"/"+index+"/model-access", body)
		return resp.StatusCode
	}
	if status := put("0", `{"expected_fingerprint":"`+item.Fingerprint+`x","allowed_models":["a"],"denied_models":[]}`); status != http.StatusConflict {
		t.Fatalf("stale fingerprint status = %d, want 409", status)
	}
	if status := put("9", `{"allowed_models":["a"],"denied_models":[]}`); status != http.StatusNotFound {
		t.Fatalf("out-of-range index status = %d, want 404", status)
	}
	if status := put("0", `{"allowed_models":["bad\nline"],"denied_models":[]}`); status != http.StatusBadRequest {
		t.Fatalf("control character status = %d, want 400", status)
	}
	if status := put("0", `{"allowed_models":["`+strings.Repeat("a", 300)+`"],"denied_models":[]}`); status != http.StatusBadRequest {
		t.Fatalf("overlong pattern status = %d, want 400", status)
	}
	if got := storedAccess(t, fixture); len(got) != 0 {
		t.Fatalf("a refused write reached CPA: %#v", got)
	}
}

// Replacing a key's secret carries its restriction to the new text, and deleting the key removes
// the entry, so the mapping never holds a restriction for a secret CPA no longer knows.
func TestClientKeyModelAccessFollowsTheKey(t *testing.T) {
	fixture := newProviderTestFixture(t)
	item := listedKeyAccess(t, fixture, 0)
	resp, payload := doJSON(t, fixture.client, http.MethodPut, fixture.baseURL+modelAccessBase+"/0/model-access", `{"expected_fingerprint":"`+item.Fingerprint+`","allowed_models":["claude-*"],"denied_models":[]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set access status = %d body %s", resp.StatusCode, payload)
	}

	resp, payload = doJSON(t, fixture.client, http.MethodPut, fixture.baseURL+modelAccessBase+"/0", `{"key":"sk-renamed-key-1","expected_fingerprint":"`+item.Fingerprint+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rename status = %d body %s", resp.StatusCode, payload)
	}
	got := storedAccess(t, fixture)
	if _, old := got["sk-original-key-1"]; old || got["sk-renamed-key-1"] == nil {
		t.Fatalf("the restriction did not move to the new key: %#v", got)
	}

	// Editing an unrestricted key must not touch the section at all.
	fixture.state.mu.Lock()
	fixture.state.modelAccess = map[string]any{"sk-renamed-key-1": got["sk-renamed-key-1"]}
	fixture.state.mu.Unlock()

	resp, payload = doJSON(t, fixture.client, http.MethodDelete, fixture.baseURL+modelAccessBase+"/0", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d body %s", resp.StatusCode, payload)
	}
	if got := storedAccess(t, fixture); len(got) != 0 {
		t.Fatalf("deleting the key left its restriction behind: %#v", got)
	}
}

// Through the write-behind coordinator the key list and the restriction ride one flush, and a
// key replaced inside the same batch keeps its restriction.
func TestStateCoordinatorClientKeyModelAccessWriteBehind(t *testing.T) {
	fixture := newProviderTestFixture(t)
	if err := fixture.handler.EnableStateCoordinator(context.Background(), StateCoordinatorOptions{
		DebounceWindow: 40 * time.Millisecond,
		MaxBatchWait:   500 * time.Millisecond,
	}); err != nil {
		t.Fatalf("EnableStateCoordinator failed: %v", err)
	}
	t.Cleanup(func() { fixture.handler.CloseStateCoordinator(context.Background()) })

	item := listedKeyAccess(t, fixture, 1)
	resp, payload := doJSON(t, fixture.client, http.MethodPut, fixture.baseURL+modelAccessBase+"/1/model-access", `{"expected_fingerprint":"`+item.Fingerprint+`","allowed_models":[],"denied_models":["gpt-5.6-*"]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set access status = %d body %s", resp.StatusCode, payload)
	}
	resp, payload = doJSON(t, fixture.client, http.MethodPut, fixture.baseURL+modelAccessBase+"/1", `{"key":"sk-wb-renamed","expected_fingerprint":"`+item.Fingerprint+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rename status = %d body %s", resp.StatusCode, payload)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		fixture.state.mu.Lock()
		keys := append([]string(nil), fixture.state.clientKeys...)
		access := fixture.state.modelAccess
		fixture.state.mu.Unlock()
		if len(keys) == 2 && keys[1] == "sk-wb-renamed" && access["sk-wb-renamed"] != nil {
			if _, old := access["sk-original-key-2"]; old {
				t.Fatalf("the old key's entry survived the rename: %#v", access)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("write-behind never settled: keys %v access %#v", keys, access)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
