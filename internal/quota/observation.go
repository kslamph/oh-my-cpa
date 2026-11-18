package quota

import (
	"context"
	"math"
	"time"

	"github.com/oh-my-cpa/oh-my-cpa/internal/cpa/management"
)

// observationReporter is implemented by a CPA client whose gateway can take a quota observation.
// It is a separate interface so a client without the endpoint still satisfies CPAClient.
type observationReporter interface {
	ReportQuotaObservation(ctx context.Context, authIndex string, windows []management.QuotaObservationWindow) error
}

const observationTimeout = 5 * time.Second

// observationWindowIDs are the windows that gate ordinary inference requests, per provider whose
// quota this console reads itself. Code-review, model-scoped and feature limits do not decide
// whether the credential can serve a request, so reporting them would block a usable credential.
// Codex: the main rate limit (5h / weekly / monthly). Claude: the all-model 5h and 7d windows;
// the usage builder files seven_day_oauth_apps and seven_day_cowork under the standard scope too,
// so the id, not the scope alone, selects.
var observationWindowIDs = map[string]map[string]bool{
	"codex":  {"five_hour": true, "weekly": true, "monthly": true},
	"claude": {"five_hour": true, "seven_day": true},
}

// ObservationWindows maps a credential's parsed windows to the ones CPA's routing should see.
// An unknown provider reports nothing.
func ObservationWindows(provider string, windows []QuotaWindow) []management.QuotaObservationWindow {
	ids := observationWindowIDs[provider]
	out := make([]management.QuotaObservationWindow, 0, len(windows))
	for _, window := range windows {
		if !ids[window.ID] || window.Scope != "standard" || window.Model != "" {
			continue
		}
		observed := management.QuotaObservationWindow{Name: window.ID}
		if window.RemainingPercent != nil && !math.IsNaN(*window.RemainingPercent) && !math.IsInf(*window.RemainingPercent, 0) {
			fraction := math.Min(1, math.Max(0, *window.RemainingPercent/100))
			observed.RemainingFraction = &fraction
		}
		if window.ResetAtMS != nil && *window.ResetAtMS > 0 {
			resetAt := time.UnixMilli(*window.ResetAtMS).UTC().Format(time.RFC3339)
			observed.ResetAt = &resetAt
		}
		out = append(out, observed)
	}
	return out
}

// reportObservation tells CPA's routing what a successful read found, best effort: the reading
// and what the console shows never depend on it, and an older CPA without the endpoint, a timeout
// or a refusal changes nothing here. CPA logs every observation it applies.
func (s *Service) reportObservation(ctx context.Context, provider, authIndex string, windows []QuotaWindow) {
	reporter, ok := s.client.(observationReporter)
	if !ok || authIndex == "" {
		return
	}
	observed := ObservationWindows(provider, windows)
	if len(observed) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, observationTimeout)
	defer cancel()
	_ = reporter.ReportQuotaObservation(ctx, authIndex, observed)
}
