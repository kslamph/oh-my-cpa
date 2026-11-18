package management

import (
	"context"
	"errors"
	"strings"
)

// QuotaObservationWindow is one quota window as reported to CPA's routing: CPA alone decides
// which windows are exhausted and when the credential recovers.
type QuotaObservationWindow struct {
	Name string `json:"name"`
	// RemainingFraction is 0..1, or nil when the remaining amount is unknown.
	RemainingFraction *float64 `json:"remaining_fraction"`
	// ResetAt is an absolute RFC3339 UTC time, or nil when unknown.
	ResetAt *string `json:"reset_at"`
}

// ReportQuotaObservation hands a credential's freshly read quota windows to CPA's routing
// (`POST /routing/quota/observation`), so a refresh made here can set or clear that credential's
// out-of-quota block. It needs a CPA that carries the endpoint; an older one answers 404, which
// callers treat as "nothing to report to".
func (c *Client) ReportQuotaObservation(ctx context.Context, authIndex string, windows []QuotaObservationWindow) error {
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" {
		return errors.New("auth_index is required")
	}
	if windows == nil {
		windows = []QuotaObservationWindow{}
	}
	return c.doJSONBody(ctx, "POST", "/routing/quota/observation", map[string]any{
		"auth_index": authIndex,
		"windows":    windows,
	}, nil)
}
