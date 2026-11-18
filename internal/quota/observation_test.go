package quota

import (
	"context"
	"errors"
	"testing"

	"github.com/oh-my-cpa/oh-my-cpa/internal/cpa/management"
)

func ptr[T any](v T) *T { return &v }

type recordingReporter struct {
	mockCPAClient
	authIndex string
	windows   []management.QuotaObservationWindow
	calls     int
	err       error
}

func (r *recordingReporter) ReportQuotaObservation(_ context.Context, authIndex string, windows []management.QuotaObservationWindow) error {
	r.calls++
	r.authIndex = authIndex
	r.windows = windows
	return r.err
}

// Only the windows that decide whether a credential can serve a request are reported; a limit on
// code review, one model or a side product would block a usable credential.
func TestObservationWindowsSelectGatingWindowsOnly(t *testing.T) {
	reset := int64(1_800_000_000_000)
	codex := ObservationWindows("codex", []QuotaWindow{
		{ID: "five_hour", Scope: "standard", RemainingPercent: ptr(0.0), ResetAtMS: &reset},
		{ID: "weekly", Scope: "standard", RemainingPercent: ptr(42.0)},
		{ID: "code_review_5h", Scope: "code_review", RemainingPercent: ptr(0.0), ResetAtMS: &reset},
		{ID: "gpt_5_spark_5h", Scope: "model", Model: "gpt-5-spark", RemainingPercent: ptr(0.0)},
	})
	if len(codex) != 2 || codex[0].Name != "five_hour" || codex[1].Name != "weekly" {
		t.Fatalf("codex windows = %#v, want five_hour and weekly only", codex)
	}
	if codex[0].RemainingFraction == nil || *codex[0].RemainingFraction != 0 {
		t.Fatalf("an exhausted window must report remaining 0: %#v", codex[0])
	}
	if codex[0].ResetAt == nil || *codex[0].ResetAt != "2027-01-15T08:00:00Z" {
		t.Fatalf("reset = %v, want RFC3339 UTC", codex[0].ResetAt)
	}
	if codex[1].ResetAt != nil {
		t.Fatalf("an unknown reset must stay null, got %v", *codex[1].ResetAt)
	}
	if got := *codex[1].RemainingFraction; got != 0.42 {
		t.Fatalf("remaining fraction = %v, want 0.42", got)
	}

	claude := ObservationWindows("claude", []QuotaWindow{
		{ID: "five_hour", Scope: "standard", RemainingPercent: ptr(10.0)},
		{ID: "seven_day", Scope: "standard", RemainingPercent: ptr(0.0), ResetAtMS: &reset},
		{ID: "seven_day_opus", Scope: "model", Model: "claude-3-opus", RemainingPercent: ptr(0.0)},
		{ID: "seven_day_oauth_apps", Scope: "standard", RemainingPercent: ptr(0.0)},
		{ID: "seven_day_cowork", Scope: "standard", RemainingPercent: ptr(0.0)},
	})
	if len(claude) != 2 || claude[0].Name != "five_hour" || claude[1].Name != "seven_day" {
		t.Fatalf("claude windows = %#v, want the all-model five_hour and seven_day only", claude)
	}

	if got := ObservationWindows("kimi", []QuotaWindow{{ID: "five_hour", Scope: "standard"}}); len(got) != 0 {
		t.Fatalf("a provider CPA reads for itself reports nothing: %#v", got)
	}
}

func TestReportObservationIsBestEffort(t *testing.T) {
	windows := []QuotaWindow{{ID: "five_hour", Scope: "standard", RemainingPercent: ptr(0.0)}}

	reporter := &recordingReporter{}
	NewService(reporter).reportObservation(context.Background(), "codex", "auth-1", windows)
	if reporter.calls != 1 || reporter.authIndex != "auth-1" || len(reporter.windows) != 1 {
		t.Fatalf("report = %d calls, auth %q, windows %#v", reporter.calls, reporter.authIndex, reporter.windows)
	}

	// A refusal (older CPA: 404) changes nothing the caller can see.
	failing := &recordingReporter{err: errors.New("404")}
	NewService(failing).reportObservation(context.Background(), "claude", "auth-2", []QuotaWindow{{ID: "seven_day", Scope: "standard"}})
	if failing.calls != 1 {
		t.Fatalf("a failing reporter was called %d times", failing.calls)
	}

	// Nothing gating, nothing to say; a client without the endpoint is left alone.
	quiet := &recordingReporter{}
	NewService(quiet).reportObservation(context.Background(), "codex", "auth-3", []QuotaWindow{{ID: "code_review_5h", Scope: "code_review"}})
	NewService(&mockCPAClient{}).reportObservation(context.Background(), "codex", "auth-4", windows)
	if quiet.calls != 0 {
		t.Fatalf("no gating window must not report, got %d calls", quiet.calls)
	}
}
