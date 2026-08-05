# Monolith Breakdown Roadmap

> **Archived 2026-07-31.** Finished, not superseded. All four phases are
> recorded complete in the progress log below, and the outcome was verified in
> the tree before archiving: `dashboard/main.go` is 446 lines (was 2822) and
> every file the Phase 1 table promised exists at about the size it predicted —
> `store.go`, `classify.go`, `campaigns.go`, `links.go`, `filters.go`,
> `pages_data.go`, `payloads_data.go`, `util.go`, plus `aggregate.go` from
> Phase 4. Nothing in the repository linked to this file, so no inbound links
> needed repair.
>
> Kept for the record of what was deliberately *not* split and why —
> `classify.go` and `report_pdf.go` are single concerns, and the four Python
> scripts had no seam. That reasoning is the part still worth reading; do not
> re-litigate those files without it. Verified under
> [#72](https://github.com/Xore/apiary/issues/72).

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
| `analysis/ghidra/ghidra_analyze.py` | 223 | Fine as-is (file later deleted entirely under [#107](https://github.com/Xore/apiary/issues/107) — unrelated to this roadmap's split-vs-keep question) |
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

## Phase 2 — Python light touch (optional, only where a seam exists) — DONE 2026-07-28

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

Outcome (reviewed 2026-07-28): **all four kept as-is — no clean seam.**

- `sandbox/windows/orchestrate/run_sample.py`: every helper is a step of one
  detonation pipeline (revert → copy → telemetry → execute → collect →
  revert); the "VM control primitives" all share module-level env-derived
  constants, so extraction would move config, not a concern.
- `sandbox/export-result.py`: single concern — build a bounded JSON summary
  from guest artifacts. Readers (`text`/`lines`/`pe_forensics`/`pcap_summary`)
  and the payload assembly in `main()` are the same concern.
- `ml-worker/worker.py`: single concern — the poll/score/write service loop;
  the ES helpers exist only to serve that loop.
- `analysis/analyze.py`: parsing, `Stats` aggregation, and table printing are
  tightly coupled (`main()` reads `st.*` attributes directly); no seam that
  survives without an artificial API.

No code changed, so no Dockerfile impact (ml-worker/analysis ship whole
directories anyway).

## Phase 3 — `http-honeypot/main.go` (optional) — DONE 2026-07-28

442 lines: split persona/page rendering from server wiring only if the split
is obvious (it already has `pages.go` and `proxyproto.go` siblings — likely
fine as-is; record the decision).

Outcome: **kept as-is.** Page/persona content already lives in `pages.go` and
the PROXY listener in `proxyproto.go`; what remains in `main.go` is one
concern — request intake, classification, response routing, and wiring — and
`persona_test.go` passes against it.

## Phase 4 — second-pass refinement of the Phase 1 results — DONE 2026-07-28

The Phase 1 split left two larger files worth one more pass:

- `dashboard/store.go` (676 lines): the 328-line `rebuild()` aggregation core
  moved verbatim into `dashboard/aggregate.go`. `store.go` (344 lines) now
  holds the store/snapshot types, accessors, and `notifyLoop()`;
  `aggregate.go` (341 lines) holds the log-scanning/aggregation cycle.
- `dashboard/classify.go` (522 lines, `classify()` ≈ 325 lines): **kept
  as-is** — it is a single cohesive classification function; splitting it
  would require logic changes, violating the no-behavior-change rule.
- `dashboard/report_pdf.go` (628 lines): **kept as-is** — single concern
  (PDF rendering).

Everything below 350 lines per file is considered done; no further splits
planned. The remaining follow-up from the redesign guide (extra tests, visual
acceptance matrix) is tracked in `docs/DASHBOARD-UI-REDESIGN-GUIDE.md` §4.

## Progress log

| Date | Step | Result | Commit |
|---|---|---|---|
| 2026-07-28 | Roadmap created | — | (this commit) |
| 2026-07-28 | Extract `store.go` + `classify.go` from `dashboard/main.go` | build/test/vet/gofmt green | `e830b53` |
| 2026-07-28 | Extract `campaigns.go` + `links.go` + `filters.go` | build/test/vet/gofmt green | `3f0d3ed` |
| 2026-07-28 | Extract `pages_data.go` + `payloads_data.go` + `util.go`; `main.go` down to 380 lines (only `main()`) | build/test/vet/gofmt green | `80cd6bb` |
| 2026-07-28 | Phase 2 review: `sandbox/windows/orchestrate/run_sample.py` | kept as-is — no clean seam (all helpers are steps of one detonation pipeline) | (this commit) |
| 2026-07-28 | Phase 2 review: `sandbox/export-result.py` | kept as-is — no clean seam (single concern: bounded JSON summary) | (this commit) |
| 2026-07-28 | Phase 2 review: `ml-worker/worker.py` | kept as-is — no clean seam (single concern: poll/score/write loop) | (this commit) |
| 2026-07-28 | Phase 2 review: `analysis/analyze.py` | kept as-is — no clean seam (aggregation and reporting tightly coupled) | (this commit) |
| 2026-07-28 | Phase 3 review: `http-honeypot/main.go` | kept as-is — persona/page content already in `pages.go`; remaining is one concern | (this commit) |
| 2026-07-28 | Phase 4: extract `rebuild()` from `store.go` into `aggregate.go` (store 676→344 lines); `classify.go`/`report_pdf.go` reviewed, kept as-is | build/vet/test green | (this commit) |
