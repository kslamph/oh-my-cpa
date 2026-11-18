package management

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestReportQuotaObservationPostsWindowsToTheV8Route(t *testing.T) {
	gateway := &configGateway{stored: "config-version: 8\n"}
	client := newConfigClient(t, gateway)
	fraction := 0.0
	resetAt := "2027-01-15T08:00:00Z"
	err := client.ReportQuotaObservation(context.Background(), " auth-1 ", []QuotaObservationWindow{
		{Name: "five_hour", RemainingFraction: &fraction, ResetAt: &resetAt},
		{Name: "weekly"},
	})
	if err != nil {
		t.Fatal(err)
	}
	const key = "POST /v8/management/routing/quota/observation"
	body, ok := gateway.bodies[key]
	if !ok {
		t.Fatalf("no observation sent: %v", gateway.sent())
	}
	var sent struct {
		AuthIndex string `json:"auth_index"`
		Windows   []struct {
			Name              string   `json:"name"`
			RemainingFraction *float64 `json:"remaining_fraction"`
			ResetAt           *string  `json:"reset_at"`
		} `json:"windows"`
	}
	if err := json.Unmarshal([]byte(body), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.AuthIndex != "auth-1" || len(sent.Windows) != 2 || sent.Windows[0].RemainingFraction == nil || *sent.Windows[0].RemainingFraction != 0 {
		t.Fatalf("observation = %s", body)
	}
	// Unknown amounts stay explicit nulls: CPA reads null as "unknown", not as zero.
	if !strings.Contains(body, `{"name":"weekly","remaining_fraction":null,"reset_at":null}`) {
		t.Fatalf("an unknown window must serialize as nulls: %s", body)
	}
	if err := client.ReportQuotaObservation(context.Background(), " ", nil); err == nil {
		t.Fatal("an empty auth_index must be refused before any request")
	}
}

func TestUpdateClientKeyAccessWritesKeysThenReplacesOrRemovesTheMapping(t *testing.T) {
	gateway := &configGateway{stored: "config-version: 8\n"}
	client := newConfigClient(t, gateway)
	access := map[string]ClientKeyModelAccess{
		"k1": {Allowed: []string{"claude-*"}},
		"k2": {},
	}
	if err := client.UpdateClientKeyAccess(context.Background(), []string{"k1", "k2"}, access, true); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET /v0/management/config.yaml",
		"PATCH /v8/management/config",
		"PUT /v8/management/config/access/api-key-model-access",
	}
	if got := gateway.sent(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("requests = %v, want %v", got, want)
	}
	if body := gateway.bodies["PUT /v8/management/config/access/api-key-model-access"]; body != `{"k1":{"allowed-models":["claude-*"]}}` {
		t.Fatalf("mapping = %s, an entry that restricts nothing must not be written", body)
	}

	empty := &configGateway{stored: "config-version: 8\n"}
	if err := newConfigClient(t, empty).UpdateClientKeyAccess(context.Background(), []string{"k1"}, map[string]ClientKeyModelAccess{}, true); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(empty.sent(), "|"); !strings.Contains(got, "DELETE /v8/management/config/access/api-key-model-access") {
		t.Fatalf("an empty mapping must remove the section: %s", got)
	}

	untouched := &configGateway{stored: "config-version: 8\n"}
	if err := newConfigClient(t, untouched).UpdateClientKeyAccess(context.Background(), []string{"k1"}, access, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(untouched.sent(), "|"); strings.Contains(got, "api-key-model-access") {
		t.Fatalf("an unrestricted edit must leave the section alone: %s", got)
	}
}
