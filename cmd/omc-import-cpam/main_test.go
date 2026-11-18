package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRestoreKeyPutsTheClientKeyBackAndKeepsEverythingElse(t *testing.T) {
	table := keyTable([]string{" sk-live-1 ", "sk-live-2"})
	raw := `{"request_id":"r1","api_key":"[redacted]","latency_ms":6227,"tokens":{"input_tokens":12345678901234567},"note":"a<b>&c"}`

	got, matched, err := restoreKey(raw, sha256Hex("sk-live-1"), table, "sk-live-2")
	if err != nil || !matched {
		t.Fatalf("matched = %v, err = %v", matched, err)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(got), &record); err != nil {
		t.Fatal(err)
	}
	if record["api_key"] != "sk-live-1" {
		t.Fatalf("api_key = %v, want the matched key, trimmed", record["api_key"])
	}
	// A large counter must not pass through a float64, and text is not HTML-escaped.
	if !strings.Contains(got, `"input_tokens":12345678901234567`) || !strings.Contains(got, `a<b>&c`) {
		t.Fatalf("record was altered: %s", got)
	}

	got, matched, err = restoreKey(raw, sha256Hex("sk-deleted"), table, "sk-live-2")
	if err != nil || matched {
		t.Fatalf("an unknown hash must fall back: matched = %v, err = %v", matched, err)
	}
	if !strings.Contains(got, `"api_key":"sk-live-2"`) {
		t.Fatalf("fallback key not applied: %s", got)
	}

	if _, _, err := restoreKey(`not json`, "", table, "k"); err == nil {
		t.Fatal("a malformed record must be refused, not skipped")
	}
}

// A record CPAM cut down to a token total (or kept no record for) is rebuilt from its columns, and
// a real record is never replaced by a rebuild.
func TestRestoreRecordRebuildsOnlyWhatCPAMLostTheRecordFor(t *testing.T) {
	table := keyTable([]string{"sk-live-1"})
	columns := legacyColumns{
		RequestID: "r-old", Provider: "claude", Model: "claude-sonnet-5-5", Endpoint: "POST /v1/messages",
		AuthType: "oauth", AuthIndex: "a1", Source: "me@example.test", TimestampMS: 1760649785000,
		Input: 10, Output: 20, Total: 30, LatencyMS: 900, Failed: 0,
	}
	columns.Stream.Valid, columns.Stream.Int64 = true, 1

	got, matched, rebuilt, err := restoreRecord(`{"total_tokens":30}`, sha256Hex("sk-live-1"), columns, table, "sk-live-1")
	if err != nil || !matched || !rebuilt {
		t.Fatalf("matched=%v rebuilt=%v err=%v", matched, rebuilt, err)
	}
	for _, want := range []string{`"request_id":"r-old"`, `"timestamp":"2025-10-16T`, `"api_key":"sk-live-1"`, `"input_tokens":10`, `"stream":true`, `"model":"claude-sonnet-5-5"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("rebuilt record lacks %s: %s", want, got)
		}
	}

	got, _, rebuilt, err = restoreRecord(`{"request_id":"r-real","api_key":"[redacted]","latency_ms":1}`, "unknown", columns, table, "sk-live-1")
	if err != nil || rebuilt || !strings.Contains(got, `"request_id":"r-real"`) {
		t.Fatalf("a real record must be kept: rebuilt=%v err=%v %s", rebuilt, err, got)
	}

	if _, _, rebuilt, _ = restoreRecord(``, "", columns, table, "sk-live-1"); !rebuilt {
		t.Fatal("a row with no raw record must be rebuilt")
	}
}
