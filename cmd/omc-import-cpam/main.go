// Command omc-import-cpam replays a CPA-Manager-Plus usage history into Oh My CPA.
//
// CPAM keeps the CPA usage record it received for every request (`usage_events.raw_json`) with the
// client key redacted and only its SHA-256 beside it. This tool restores the key from that hash
// and appends the records to OMC's usage inbox, so OMC's own pipeline decodes them exactly as it
// does a live record: same event keys (replays are idempotent), same keyed client identity, same
// pricing at read time.
//
// It takes the database lock, so OMC must be stopped. Records whose key hash matches no current
// client key are attributed to the key named by -fallback-alias (its CPAM alias).
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/oh-my-cpa/oh-my-cpa/internal/backup"
	"github.com/oh-my-cpa/oh-my-cpa/internal/config"
	"github.com/oh-my-cpa/oh-my-cpa/internal/cpa/management"
	appcrypto "github.com/oh-my-cpa/oh-my-cpa/internal/crypto"
	"github.com/oh-my-cpa/oh-my-cpa/internal/repository"
	_ "modernc.org/sqlite"
)

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}

// keyTable maps a CPAM api_key_hash to the client key text that has it.
func keyTable(keys []string) map[string]string {
	table := make(map[string]string, len(keys))
	for _, key := range keys {
		table[sha256Hex(key)] = strings.TrimSpace(key)
	}
	return table
}

// restoreKey returns the record with its client key put back, and whether the key was matched.
// An unmatched hash takes the fallback key; the reported counts say how many did.
func restoreKey(raw string, hash string, table map[string]string, fallbackKey string) (string, bool, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var record map[string]any
	if err := decoder.Decode(&record); err != nil {
		return "", false, err
	}
	return restoreKeyIn(record, hash, table, fallbackKey)
}

func restoreKeyIn(record map[string]any, hash string, table map[string]string, fallbackKey string) (string, bool, error) {
	key, matched := table[hash]
	if !matched {
		key = fallbackKey
	}
	record["api_key"] = key
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(record); err != nil {
		return "", false, err
	}
	return strings.TrimSpace(out.String()), matched, nil
}

// restoreRecord uses the stored raw record when it is a real usage record (it names its request),
// and otherwise rebuilds one from the columns.
func restoreRecord(raw, hash string, c legacyColumns, table map[string]string, fallbackKey string) (string, bool, bool, error) {
	if strings.TrimSpace(raw) != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.UseNumber()
		var record map[string]any
		if err := decoder.Decode(&record); err != nil {
			return "", false, false, err
		}
		if id, _ := record["request_id"].(string); strings.TrimSpace(id) != "" {
			out, matched, err := restoreKeyIn(record, hash, table, fallbackKey)
			return out, matched, false, err
		}
	}
	out, matched, err := restoreKeyIn(rebuildFromColumns(c), hash, table, fallbackKey)
	return out, matched, true, err
}

// legacyColumns are the CPAM columns a record is rebuilt from when its stored raw record is
// missing or was cut down to a token total. Early CPAM rows have only these.
type legacyColumns struct {
	RequestID, Provider, ExecutorType, Model, Endpoint, AuthType, AuthIndex, Source string
	ReasoningEffort, ServiceTier, RequestServiceTier, ResponseServiceTier           sql.NullString
	ResponseModel, ClientIP, XForwardedFor, UserAgent, FailBody                     sql.NullString
	TimestampMS, Input, Output, Reasoning, Cached, CacheRead, CacheCreation, Total  int64
	LatencyMS, FailStatus                                                           int64
	TTFTMS, Stream, Generate                                                        sql.NullInt64
	Failed                                                                          int64
}

// rebuildFromColumns builds a CPA usage record from the columns. It carries what CPAM kept as a
// column; anything it did not keep (response headers, token breakdown) is simply absent, which
// OMC reads as "older CPA build".
func rebuildFromColumns(c legacyColumns) map[string]any {
	record := map[string]any{
		"request_id":    c.RequestID,
		"timestamp":     time.UnixMilli(c.TimestampMS).UTC().Format(time.RFC3339Nano),
		"provider":      c.Provider,
		"executor_type": c.ExecutorType,
		"model":         c.Model,
		"endpoint":      c.Endpoint,
		"auth_type":     c.AuthType,
		"auth_index":    c.AuthIndex,
		"source":        c.Source,
		"latency_ms":    c.LatencyMS,
		"failed":        c.Failed != 0,
		"tokens": map[string]any{
			"input_tokens": c.Input, "output_tokens": c.Output, "reasoning_tokens": c.Reasoning,
			"cached_tokens": c.Cached, "cache_read_tokens": c.CacheRead, "cache_creation_tokens": c.CacheCreation,
			"total_tokens": c.Total,
		},
		"fail": map[string]any{"status_code": c.FailStatus, "body": c.FailBody.String},
	}
	for key, value := range map[string]sql.NullString{
		"reasoning_effort": c.ReasoningEffort, "service_tier": c.ServiceTier,
		"effective_service_tier": c.RequestServiceTier, "response_service_tier": c.ResponseServiceTier,
		"response_model": c.ResponseModel, "client_ip": c.ClientIP, "x_forwarded_for": c.XForwardedFor, "user_agent": c.UserAgent,
	} {
		if value.Valid && value.String != "" {
			record[key] = value.String
		}
	}
	if c.TTFTMS.Valid {
		record["ttft_ms"] = c.TTFTMS.Int64
	}
	if c.Stream.Valid {
		record["stream"] = c.Stream.Int64 != 0
	}
	if c.Generate.Valid {
		record["generate"] = c.Generate.Int64 != 0
	}
	return record
}

func run(ctx context.Context) error {
	cpamPath := flag.String("cpam", "", "path to CPAM's usage.sqlite (opened read-only)")
	fallbackAlias := flag.String("fallback-alias", "", "CPAM alias of the key that takes records whose key no longer exists")
	batch := flag.Int("batch", 500, "records per inbox transaction")
	dryRun := flag.Bool("dry-run", false, "count and classify only; write nothing")
	flag.Parse()
	if *cpamPath == "" || *fallbackAlias == "" {
		return errors.New("-cpam and -fallback-alias are required")
	}

	if _, err := config.LoadDotEnv(config.DotEnvPath()); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	client, err := management.NewClient(cfg.CPA.BaseURL, cfg.CPA.ManagementKey, 15*time.Second, false)
	if err != nil {
		return err
	}
	keys, err := client.ClientAPIKeys(ctx)
	if err != nil {
		return fmt.Errorf("read CPA client keys: %w", err)
	}
	table := keyTable(keys)

	cpam, err := sql.Open("sqlite", "file:"+*cpamPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer cpam.Close()

	var fallbackHash string
	if err := cpam.QueryRowContext(ctx, `SELECT api_key_hash FROM api_key_aliases WHERE alias = ?`, *fallbackAlias).Scan(&fallbackHash); err != nil {
		return fmt.Errorf("find CPAM alias %q: %w", *fallbackAlias, err)
	}
	fallbackKey, ok := table[fallbackHash]
	if !ok {
		return fmt.Errorf("the key aliased %q is not among CPA's current client keys", *fallbackAlias)
	}

	lock, err := backup.LockDatabase(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("%w (stop omcpa first)", err)
	}
	defer lock.Close()
	wrapping, err := appcrypto.New(cfg.MasterKey)
	if err != nil {
		return err
	}
	cipher, err := backup.ResolveCipher(cfg.DatabasePath, wrapping)
	if err != nil {
		return err
	}
	db, err := repository.Open(ctx, cfg.DatabasePath, repository.WithCipher(cipher))
	if err != nil {
		return err
	}
	defer db.Close()
	repo := repository.New(db)

	// Replay only what OMC has not seen live: everything before its first event.
	var firstLiveMS sql.NullInt64
	if err := repo.SQL().QueryRowContext(ctx, `SELECT MIN(timestamp_ms) FROM usage_events`).Scan(&firstLiveMS); err != nil {
		return err
	}
	cutoff := int64(1<<62 - 1)
	if firstLiveMS.Valid {
		cutoff = firstLiveMS.Int64
	}

	rows, err := cpam.QueryContext(ctx, `
		SELECT COALESCE(raw_json, ''), COALESCE(api_key_hash, ''),
		       request_id, timestamp_ms, COALESCE(provider,''), COALESCE(executor_type,''), COALESCE(model,''),
		       COALESCE(endpoint,''), COALESCE(auth_type,''), COALESCE(auth_index,''), COALESCE(source,''),
		       reasoning_effort, service_tier, request_service_tier, response_service_tier, response_model,
		       client_ip, x_forwarded_for, user_agent, fail_body,
		       COALESCE(input_tokens,0), COALESCE(output_tokens,0), COALESCE(reasoning_tokens,0), COALESCE(cached_tokens,0),
		       COALESCE(cache_read_tokens,0), COALESCE(cache_creation_tokens,0), COALESCE(total_tokens,0),
		       COALESCE(latency_ms,0), COALESCE(fail_status_code,0), COALESCE(failed,0), ttft_ms, stream, generate
		FROM usage_events
		WHERE timestamp_ms < ?
		ORDER BY timestamp_ms, id`, cutoff)
	if err != nil {
		return err
	}
	defer rows.Close()

	var total, matched, fallback, written, rebuilt int
	pending := make([]string, 0, *batch)
	flush := func() error {
		if len(pending) == 0 || *dryRun {
			pending = pending[:0]
			return nil
		}
		n, err := repo.AppendUsageInbox(ctx, "default", "import", pending, time.Now())
		written += n
		pending = pending[:0]
		return err
	}
	for rows.Next() {
		var raw, hash string
		var c legacyColumns
		if err := rows.Scan(&raw, &hash,
			&c.RequestID, &c.TimestampMS, &c.Provider, &c.ExecutorType, &c.Model,
			&c.Endpoint, &c.AuthType, &c.AuthIndex, &c.Source,
			&c.ReasoningEffort, &c.ServiceTier, &c.RequestServiceTier, &c.ResponseServiceTier, &c.ResponseModel,
			&c.ClientIP, &c.XForwardedFor, &c.UserAgent, &c.FailBody,
			&c.Input, &c.Output, &c.Reasoning, &c.Cached, &c.CacheRead, &c.CacheCreation, &c.Total,
			&c.LatencyMS, &c.FailStatus, &c.Failed, &c.TTFTMS, &c.Stream, &c.Generate); err != nil {
			return err
		}
		restored, wasMatched, wasRebuilt, err := restoreRecord(raw, hash, c, table, fallbackKey)
		if err != nil {
			return fmt.Errorf("record %d: %w", total+1, err)
		}
		if wasRebuilt {
			rebuilt++
		}
		total++
		if wasMatched {
			matched++
		} else {
			fallback++
		}
		pending = append(pending, restored)
		if len(pending) >= *batch {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := flush(); err != nil {
		return err
	}
	fmt.Printf("cutoff_ms=%d records=%d rebuilt_from_columns=%d matched_key=%d fallback_key=%d inbox_rows_written=%d dry_run=%t\n", cutoff, total, rebuilt, matched, fallback, written, *dryRun)
	return nil
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "omc-import-cpam:", err)
		os.Exit(1)
	}
}
