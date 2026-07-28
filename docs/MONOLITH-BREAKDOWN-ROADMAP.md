# Monolith Breakdown Roadmap

> Goal: make the larger Go and Python applications in this repository easier to
> maintain by splitting monolithic files into focused modules. **Behavior must
> not change** — every step is a mechanical move verified by the existing test
> suite. Work in small commits; commit and push after each phase.

## Scope (measured 2026-07-28)

| File | Lines | Verdict |
|---|---|---|
| `dashboard/main.go` | 2822 | **Primary target** — routes, store, aggregation, classification, filters, page builders all in one file |
| `http-honeypot/main.go` | 442 | Secondary — split only if a natural seam exists |
| `multipot/main.go`, `portbridge/main.go`, `dnp3-honeypot/main.go`, `tftp-relay/main.go` | 89–195 | Fine as-is |
| `sandbox/windows/orchestrate/run_sample.py` | 312 | Light touch |
| `sandbox/export-result.py` | 310 | Light touch |
| `ml-worker/worker.py` | 261 | Light touch |
| `analysis/analyze.py` | 260 | Light touch |
| `analysis/ghidra/ghidra_analyze.py` | 223 | Fine as-is |
| Other Python (`conpot/persona_patch.py`, `sandbox/guest-*.py`, …) | <210 | Fine as-is |

Note: `dashboard/page.go` was already split into nine per-page template files
during the UI redesign (commit `a98f03f`) — this roadmap covers the remaining
Go logic in `main.go`.

## Phase 1 — `dashboard/main.go` split (primary)

Current structure and target layout (all stay in `package main`; no symbol
renames, no signature changes, no behavior changes):

| New file | Contents moved (current line ranges) |
|---|---|
| `main.go` | `main()`, route registration, template setup (~2466–2822) |
| `store.go` | `store`, `snapshot`, `storedEvent`, `bucket`, `sensorRow`, `runtimeStatus` types; `rebuild()`, `get()`, `getEvents()`, `notifyLoop()` (~36–322, 1577–1749) |
| `classify.go` | `event`, `viaEntry`, `classify()`, `buildViaMap()`, `viaLookup()`, persona/time/IP/port/header enrichment helpers (~988–1576) |
| `campaigns.go` | `correlateCampaigns()`, `campaignCIDR()`, `dedupeKey()`, `balancedRecent()`, `isOverviewNoise()`, `sortedSet()` (~654–841) |
| `links.go` | URL/row helpers: `eventsURL()`, `investigationURL()`, `linkRows()`, `credentialRows()`, `validCredentialPair()`, `normalizeProtocol()`, `isOperationalAlert()`, `asnRows()`, `fingerprintRows()`, `compactText()` (~842–987) |
| `filters.go` | `filter` type, `parseFilter()`, `match()`, `describe()`, `filtered()`, `containsFold()` (~1750–1932) |
| `pages_data.go` | `eventsPage`/`attackerPage`/`ipRow`/`ipsPage` types, `eventsData()`, `attackerData()`, `ipsData()`, `buildIPsData()`, `boolInt()` (~1933–2215) |
| `payloads_data.go` | `capturedFile`, `payloadSourceStat`, `payloadsPage`, `payloadsData()`, payload cache loops, `scanPayloads()`, `servePayload()`, `humanBytes()` (~2216–2465) |
| `util.go` | `getenv()`, `topN()`, `logFiles()`, `readTail()`, `ago()`, `feedState()`, `firstNonEmpty()`, `shortHash()`, `str()`, `num()`, `numFloat()` (scattered small helpers) |

Rules:

1. One new file per commit (or one cohesive group per commit) — easier review
   and revert.
2. Move code verbatim; only package-level doc comments may be added.
3. After every move: `cd dashboard && go build ./... && go test -count=1 ./...`
   must stay green (vendored, offline).
4. Watch for import lists shrinking in `main.go` — let `goimports`-style
   cleanup happen per file, nothing else.
5. `mapPoint`, `kv`, `payloadRow`, `campaignRow` types travel with their
   primary consumer file.

Verification per commit: build + test green, `git diff --check` clean.

## Phase 2 — Python light touch (optional, only where a seam exists)

The Python scripts are 260–312 lines — borderline. Do **not** force splits.
For each of `run_sample.py`, `export-result.py`, `worker.py`, `analyze.py`:

1. Read the file; if it mixes ≥2 distinct concerns (e.g. CLI/arg parsing +
   orchestration + reporting), extract the secondary concern into a sibling
   module in the same directory.
2. Keep CLI entry points and output formats byte-compatible.
3. If no clean seam: leave the file alone and record "kept as-is" here.
4. Python has no test suite in this repo — validate with
   `python3 -m py_compile <file>` and, where a Dockerfile exists, rely on the
   existing compose build.

## Phase 3 — `http-honeypot/main.go` (optional)

442 lines: split persona/page rendering from server wiring only if the split
is obvious (it already has `pages.go` and `proxyproto.go` siblings — likely
fine as-is; record the decision).

## Progress log

| Date | Step | Result | Commit |
|---|---|---|---|
| 2026-07-28 | Roadmap created | — | (this commit) |
