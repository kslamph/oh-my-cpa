# Fork patches (kslamph/oh-my-cpa)

What this fork carries on top of upstream `WizisCool/oh-my-cpa`, and how to keep it
alive across upstream syncs. Upstream never touches this file, so it never conflicts.

Remotes: `origin` = `kslamph/oh-my-cpa` (this fork), `upstream` = `WizisCool/oh-my-cpa`.
Deploy branch: **`feat/api-key-model-access`**. Base: upstream `main` at v0.4.7 (`4ba8793d`).

This fork replaced our CPA-Manager-Plus (CPAM) fork on LXC 115. The patches below are the
CPAM patches (see `~/goproj/CPA-Manager-Plus/FORK-PATCHES.md`) that OMC did not already have.
They pair with our CPA fork (`~/goproj/CLIProxyAPI`, branch `custom`).

| CPAM patch | In OMC |
|---|---|
| P1 per-API-key model access editor | **Ported** (O1) |
| P2 generic plugin-quota refresh | Native in OMC (`internal/quota/plugin.go`); nothing to port |
| P3 report quota refreshes to CPA routing | **Ported** (O2) |
| P4 plugin reset cards in the Accounts UI | **Display ported** (O3); the Reset action is not ported (see O3) |

## O1 - per-API-key model access (`local-only`)
- CPA side: needs our CPA patch P1 (`access.api-key-model-access`). Without it CPA refuses or
  ignores the section.
- Backend: `internal/cpa/management/client_providers.go` (`ClientKeyAccess`,
  `UpdateClientKeyAccess`), `internal/api/management_client_keys.go`
  (`PUT /v1/management/api-keys/{index}/model-access`, the list DTO's `allowed_models` /
  `denied_models`), `internal/api/state_coordinator.go` (the restriction rides the
  `client_keys` write-behind domain), `internal/operations/keys.go` (delete drops the entry),
  `internal/api/demo_policy.go`.
- Semantics: a replaced key carries its restriction to the new text; a deleted key drops it;
  an unrestricted key's edit never touches `access.api-key-model-access`. The mapping is
  written as a whole value (its keys are secrets, not path segments); both lists empty
  removes the section. CPA owns pattern matching.
- Known: the key list is written (PATCH) before the mapping (PUT/DELETE) in one change set, so
  for a few milliseconds a freshly renamed or created restricted key is unrestricted, and if the
  second request fails CPA reports a partial apply (the UI shows the error and the row can be
  saved again).
- Web: `web/src/pages/ApiKeysPage.tsx` (two textareas, one pattern per line),
  `components/keys/ApiKeysList.tsx` (Model access column), `api/client.ts`, i18n `keys.access_*`.
- Tests: `internal/api/management_client_keys_access_test.go`,
  `internal/cpa/management/client_quota_observation_test.go`,
  `web/tests/api-keys-model-access.component.test.tsx`.
- Conflict hotspots: `management_client_keys.go`, `state_coordinator.go` (`projectedConfigState`
  clone/rebase), `ApiKeysPage.tsx`.
- Drop when: upstream OMC ships a per-key model ACL editor.

## O2 - report codex/claude quota reads to CPA routing (`local-only`)
- After a successful codex or claude read, `RefreshCredentialQuotaWith` posts the gating windows
  to CPA `POST /v8/management/routing/quota/observation` (best effort, 5 s timeout, errors
  ignored; an older CPA answers 404). Plugin credentials already report inside CPA's own quota
  fetch (`POST /plugins/:id/quota`), so they are skipped.
- Files: `internal/quota/observation.go` (+test), `internal/cpa/management/client_quota_observation.go`.
- Window selection mirrors CPAM P3: codex `five_hour`/`weekly`/`monthly`, claude `five_hour`/`seven_day`,
  standard scope, no model. Code-review, model-scoped and side-product limits are never reported.
  Re-check on sync: window ids in `codex.go` / `claude.go`.
- Requires our CPA patch P4. Drop when: CPA observes codex/claude quota itself.

## O3 - plugin reset cards (`local-only`, display only)
- `parsePluginQuotaPlan` reads `reset_cards_five_hour`, `reset_cards_week` and
  `reset_card:<five_hour|week>:<id>` (value = expiry epoch ms) from a plugin's summary into
  `plan.reset_cards`, and keeps them out of the 8-slot metric list.
- Web: `QuotaResetCards.tsx` draws one card per kind with the plugin's count and each card's expiry.
- **Not ported:** the CPAM "Reset quota" action (spends a card through CPA
  `POST /plugins/:id/quota/reset`). It was never exercised live in CPAM either; decide before adding.
- Tests: golden `internal/quota/testdata/golden/plugin/reset-cards.*`, `web/tests/credential-quota.component.test.tsx`.

## O4 - CPAM history import tool (`local-only`, one-off)
- `cmd/omc-import-cpam`: replays CPA-Manager-Plus's `usage_events` into OMC's usage inbox so OMC's
  own pipeline decodes them (same event keys, so a replay is idempotent; same keyed client
  identity; pricing at read time). It restores each record's client key from CPAM's `api_key_hash`
  (CPAM stores the key redacted), attributes hashes with no current key to `-fallback-alias`,
  rebuilds records CPAM cut down to a token total (or never kept) from CPAM's columns, and replays
  only what precedes OMC's first live event. It takes the database lock, so OMC must be stopped.
- Run on 2026-11-18: 89,365 records (1,322 rebuilt, 87,364 matched, 2,001 to `pws-pi`), 36 s;
  per-key request, failure and token totals equal CPAM's on a rehearsal copy first.
- Drop when: CPAM history is no longer wanted.

## O5 - operator re-price of recorded requests (`local-only`, one-off tool)
- `Repository.RepriceUsage` + `cmd/omc-reprice`: re-prices already-priced requests of named models at
  the current price book, replaces cost/price version/tier, and adds the difference to the 15m,
  daily and local-daily facts in the same transaction. The schema trigger `usage_cost_no_reprice`
  is dropped inside each batch transaction and re-created from its stored SQL before commit.
  Upstream deliberately never re-prices (only unpriced requests); do not expose this in the UI.
- Run on 2026-11-18 for the deepseek models; the deployed OMC binary does not contain it (tool only).
- Drop when: upstream gains a re-price action.

## Dependency note
`github.com/googleapis/enterprise-certificate-proxy` is bumped v0.3.21 -> v0.3.22: upstream
retagged v0.3.21 (3 days after release) so the module no longer matches `go.sum`. Verified
against sum.golang.org. Drop when upstream OMC's own go.sum moves past v0.3.21.

## Upstream sync procedure
1. `git fetch upstream --tags`; `git checkout feat/api-key-model-access`; `git merge upstream/main`.
2. Resolve conflicts per the hotspot notes; do not take "theirs" wholesale on O1 files.
3. `pnpm openapi:generate` if DTOs changed; `pnpm test:fast`, `pnpm test:components`, `go vet ./...`.
4. Re-check CPA compatibility: `access.api-key-model-access` round trip, the observation endpoint.

## Release build (static, pure Go; the web bundle is embedded)
```bash
pnpm install --frozen-lockfile
pnpm build   # builds the web bundle and syncs it into internal/web/dist (scripts/sync-web-dist.mjs)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X github.com/oh-my-cpa/oh-my-cpa/internal/config.BuildVersion=v0.4.7-custom.1 \
  -X github.com/oh-my-cpa/oh-my-cpa/internal/config.BuildCommit=$(git rev-parse --short=12 HEAD) \
  -X github.com/oh-my-cpa/oh-my-cpa/internal/config.BuiltAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o bin/oh-my-cpa ./cmd/oh-my-cpa
```

## Deploy
Production is Proxmox LXC 115 (`ssh -J cloudai root@10.10.60.12`); runbook and host record are in
`~/devops/docs` (`runbooks/cpa-deploy.md`, `providers/cpa-lxc.md`). OMC and CPAM must never run
together: both consume CPA's usage queue and would race on it.
