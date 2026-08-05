# GitHub Analysis Integration — Implementation Roadmap

> **Status**: Design document — nothing here is built yet
> **Last updated**: 2026-07-30
> **Upstream pipeline**: [`Xore/honeypot`](https://github.com/Xore/honeypot) — `.github/workflows/analyze.yml`
> **Precedent**: [`analysis/ghidra/DASHBOARD_INTEGRATION_PLAN.md`](../analysis/ghidra/DASHBOARD_INTEGRATION_PLAN.md)
> **Tracked in**: [#73](https://github.com/Xore/honeypot-stack/issues/73) (YARA corpus sync) and [#74](https://github.com/Xore/honeypot-stack/issues/74) (publisher and dashboard button)

---

## 1. What this is

[`Xore/honeypot`](https://github.com/Xore/honeypot) is a separate public repository
that stores captured malware samples and runs an eight-scanner GitHub Actions
pipeline over every sample pushed to `samples/`. It produces per-sample JSON
reports, PDF reports, IOC CSVs, and auto-generated YARA rules.

This roadmap connects that pipeline to `dashboard/` so an analyst can send one
selected capture upstream **by pressing a button**, and read the returned
verdicts inside the dashboard next to the existing static analysis and KVM
sandbox results.

### Non-goal: automation

**Publication is never automatic.** No cron, no watcher on the capture
directories, no "publish everything new" sweep. `analysis/collect.sh` — which
currently cron-copies every new Cowrie/Dionaea capture into a clone of
`Xore/honeypot` and pushes it — is explicitly **not** the delivery mechanism for
this feature and is retired by Phase 0.

The reason is a trust boundary, not taste:

- Pushing a capture to `Xore/honeypot` **publishes it to a public repository**
  and to up to eight third-party scanner APIs (VirusTotal, MalwareBazaar,
  Hybrid-Analysis, Malshare, JoeSandbox, MetaDefender, CAPE, Any.run).
- Captures are attacker-supplied bytes. They can contain third-party data,
  credentials harvested elsewhere, or content that identifies the sensor.
- `WORK-LEDGER.md` → "How to work an issue", rule 7 already binds this
  repository: *"External reporting features stay in dry-run until separately
  approved."*

So the design is: **one deliberate, authenticated, per-sample, auditable
action**, with a dry-run default.

---

## 2. Is `analysis/` up to date with `Xore/honeypot`?

**No.** Verified against `Xore/honeypot@main` (pushed 2026-07-29) on 2026-07-30.

| Claim in `docs/analysis/README.md` | Upstream reality |
|---|---|
| "submits to **VirusTotal** and **JoeSandbox**" | Eight scanners: VT, MalwareBazaar, Hybrid-Analysis, Malshare, JoeSandbox, MetaDefender, CAPE, Any.run |
| `analysis/pipeline.py` is a component | **The file does not exist.** Never has, in this tree |
| Results land in `reports/virustotal/*.pdf`, `reports/joesandbox/*.pdf` | Those directories are empty `.gitkeep` stubs. Real output is `reports/scanner/<sha256>.json`, `reports/pdf/`, `reports/yara/` |
| Secrets: `VT_API_KEY`, `JOESANDBOX_API_KEY`, `GH_PAT` | Ten secrets; at least one scanner key required, `GH_PAT` always |
| IOCs: `iocs/hashes.csv` | Also `iocs/families.csv` and `iocs/CHANGELOG.md` |
| (not mentioned) | `yara-rules/` — six hand-written rule files plus `yara-rules/auto/` regenerated from scan telemetry by `generate_yara.py` |
| (not mentioned) | Triggers: push, PR dry-run, weekly Sunday 02:00 UTC full rescan, and `workflow_dispatch` with a `sample_path` input |
| (not mentioned) | Failure contract: single scanner failure never aborts; exit 2 only when every scanner failed on every file |
| (not mentioned) | Only Added/Renamed files are scanned (`--diff-filter=AR`); modified files are deliberately skipped |
| `analysis/SANDBOX_APIS.md` is the capability reference | Superseded by upstream [`docs/SCANNERS.md`](https://github.com/Xore/honeypot/blob/main/docs/SCANNERS.md) |

Two upstream capabilities have **no representation at all** on this side and are
the reason this integration is worth building:

1. **`yara-rules/auto/`** — 18 auto-generated rules exist upstream. The
   dashboard's YARA sidecar reads only `analysis/yara/rules/honeypot.yar`
   (a single 1.9 KB file). The generated corpus never reaches the sensor.
2. **`iocs/families.csv`** — normalised family attribution per SHA-256. The
   dashboard has no family field anywhere.

Phase 0 below fixes the documentation drift; Phases 4 and 6 close the two
capability gaps.

---

## 3. Trust boundary

The dashboard container is unprivileged. It has no Docker socket, no libvirt,
no outbound network, and no credentials. **That does not change here.**

This integration reuses the spool-file pattern already proven twice in this
repository — `sandbox_submit.go` → `/sandbox-requests` → the root-owned
`honeypot-sandbox-web-requests.path` unit → `honeypot-sandbox-worker.service` →
`/sandbox-results` (read-only back into the container).

| Concern | Sandbox (existing) | GitHub analysis (this plan) |
|---|---|---|
| Trigger | `POST /sandbox/submit` writes `{hash}.request` | `POST /github-analysis/submit` writes `{sha256}.request` |
| Spool in | `SANDBOX_REQUEST_DIR` (rw) | `GITHUB_ANALYSIS_REQUEST_DIR` (rw) |
| Validator | `process-web-requests.sh` (root, systemd `.path`) | `process-github-requests.sh` (root, systemd `.path`) |
| Worker | `honeypot-sandbox-worker.service` → libvirt | `honeypot-github-publish.service` → git push + Actions poll |
| Results | `{job}.json` in `SANDBOX_RESULTS_DIR` (ro) | `{sha256}.json` in `GITHUB_ANALYSIS_RESULTS_DIR` (ro) |
| Credentials | none in container | `GH_PAT` lives **only** in the host unit's `EnvironmentFile`, mode 0600, root-owned |

The dashboard never runs `git`, never holds a token, never calls the GitHub API,
and never reads the sample bytes for this feature beyond the `s.payloadPath(hash)`
existence check it already performs. A dashboard RCE yields the ability to
create a zero-byte marker file — nothing else.

---

## 4. Architecture

```
honeypot-stack/
├── analysis/github/                       ← NEW: host-side publisher
│   ├── process-github-requests.sh         ← validates + de-duplicates the spool
│   ├── publish-sample.sh                  ← classify → copy → commit → push
│   ├── collect-results.py                 ← poll Actions run, pull reports back
│   ├── sync-yara.sh                       ← pull yara-rules/auto/ to the scanner
│   ├── honeypot-github-publish.path
│   ├── honeypot-github-publish.service
│   ├── honeypot-github-collect.timer      ← result polling only, not publication
│   ├── honeypot-github-collect.service
│   └── github.env.example
└── dashboard/
    ├── github_analysis.go                 ← NEW: mirrors sandbox.go
    ├── github_analysis_submit.go          ← NEW: mirrors sandbox_submit.go
    ├── page_github_analysis.go            ← NEW: list + detail page data, mirrors page_sandbox.go
    ├── ui/github_analysis.html            ← NEW: the markup, alongside ui/sandbox.html
    └── page_payloads.go                   ← adds the per-row button
```

The `page_*.go` files hold page **data**; the markup is a file under
`dashboard/ui/`. Putting templates back into Go fails the build — see the
render-engine guide.

Data flow:

```
analyst clicks "Send for scanner analysis" (confirm modal)
  → POST /github-analysis/submit          [admin, same-origin, CSRF-checked]
  → {sha256}.request written O_CREATE|O_EXCL
  → systemd .path fires process-github-requests.sh   [root, host]
      · re-validates the hash against the capture store
      · refuses if consent marker absent or dry-run enabled
      · classifies into samples/{ELF,PE,Scripts,Docs,UNKNOWN}/
      · git commit + push to Xore/honeypot
      · records the pushed commit SHA in the pending record
  → Xore/honeypot Actions: analyze.yml (8 scanners → reports/, iocs/, yara-rules/auto/)
  → honeypot-github-collect.timer polls the run
      · on success: fetch reports/scanner/{sha256}.json + families.csv row
      · normalise → {sha256}.json in GITHUB_ANALYSIS_RESULTS_DIR
  → dashboard reads results read-only; payload row shows the verdict badge
```

---

## Phase 0 — Reconcile the documentation and retire the cron path ✅ 2026-07-30

**Why first:** every later phase was described against `docs/analysis/README.md`, and
that file documented a pipeline that does not exist. Nothing here touched
running code.

1. ✅ Rewrote `docs/analysis/README.md` against the eight-scanner reality: correct
   scanner table, correct `reports/` layout, correct secret list, the
   `--diff-filter=AR` scan rule, the four triggers, and the failure contract.
2. ✅ Dropped the `analysis/pipeline.py` row — the file does not exist.
3. ✅ Moved `analysis/SANDBOX_APIS.md` to [`archive/SANDBOX_APIS.md`](archive/SANDBOX_APIS.md)
   with a supersession header; the README now points at upstream
   `docs/SCANNERS.md` as the live capability reference.
4. ✅ Marked `analysis/collect.sh` deprecated in-file, explaining that
   cron-driven bulk publication is replaced by the dashboard button and that the
   script is kept only for a one-time backfill run by hand.

**Exit met:** `docs/analysis/README.md` describes only files that exist and behaviour
that upstream actually implements.

---

## Phase 1 — Host-side publisher 🔶 built 2026-07-31, not installed

`analysis/github/`, root-owned, installed by an `install-github-publisher.sh`
modelled on `sandbox/install-worker.sh`.

**Status:** every file below is written and the dry-run half of the exit
criterion is proven by `analysis/github/tests/test_dry_run.sh` (plus
`test_rejections.sh` for malformed/unresolvable requests) rather than
hand-placed, per `WORK-LEDGER.md` rule 7. Deliberately **not installed on the
production homeserver** and no `GH_PAT` has been created — the second half of
the exit criterion (a real push against a throwaway fork) needs the
operator's separate explicit authorization, same as the IP reporter (#68).
See #74 for the three open questions this phase depended on and how they
were decided.

### `process-github-requests.sh`

Structurally identical to `sandbox/process-web-requests.sh`:

- `flock` guard, `pending/` + `rejected/` directories, mode 0700.
- Hash must match `^[0-9a-f]{64}$` — reject and log otherwise.
- Resolve the sample from the same capture store the dashboard validated
  against. A request whose sample is gone is rejected, not silently dropped.
- **Refuse if `GITHUB_PUBLISH_ENABLED` is not `1`** — dry-run writes a result
  record with `exit_status: "dry_run"` and pushes nothing. This is the default.
- Hand off to `publish-sample.sh`, then `systemctl start --no-block
  honeypot-github-collect.service` to close the path-unit burst race.

### `publish-sample.sh`

1. Classify by `file -b` into `samples/ELF|PE|Scripts|Docs|UNKNOWN/`, matching
   upstream's layout — reuse the dashboard's existing classification codes
   (`sandboxClassification.Platform`/`Category`) rather than re-deriving them.
2. Name the file `{sha256}` with the original extension preserved when the
   capture had one, so upstream's `strings`-based YARA generation has a filename
   hint to work with.
3. Skip if `iocs/hashes.csv` already contains the SHA-256 — upstream only scans
   Added/Renamed files, so a re-push is wasted quota and produces no new run.
4. `git commit -m "sample: <sha256> (<sensor>, <UTC date>)"` then push.
5. Record `{sha256}.pending` containing the pushed commit SHA, request time, and
   sensor of origin.

### `collect-results.py`

- Runs on a **timer**, not on publication — polling GitHub is not the analyst's
  click path and must not block the UI.
- For each `.pending` record: resolve the Actions run for the recorded commit,
  wait for conclusion, then fetch `reports/scanner/{sha256}.json`, the
  `iocs/families.csv` row, and any `yara-rules/auto/` additions from that run.
- Normalise into the result shape below and write it to
  `GITHUB_ANALYSIS_RESULTS_DIR` atomically (`write .tmp` → `rename`).
- Write `status.json` with `queued`/`running`/`done`/`failed` counts and the
  oldest handoff age, exactly the shape `loadSandboxStatus()` already consumes.
- Bound retries and give up with `exit_status: "timeout"` after
  `GITHUB_ANALYSIS_MAX_WAIT` (default 90 min, matching the workflow timeout).

### Result JSON shape

Deliberately mirrors `sandboxResult` field-for-field where the concepts overlap,
so the dashboard's queue, status, alert, and export code needs additive changes
only.

```json
{
  "version": 1,
  "sha256": "…",
  "requested_at": "…", "started_at": "…", "completed_at": "…",
  "exit_status": "ok",
  "commit": "…", "run_id": 123456789,
  "run_url": "https://github.com/Xore/honeypot/actions/runs/123456789",
  "sample_path": "samples/PE/….exe",
  "family": "miori",
  "verdict": { "malicious": 42, "suspicious": 1, "total": 74, "level": "high" },
  "scanners": [
    { "source": "virustotal", "ok": true, "known": true,
      "positives": 42, "total": 74, "permalink": "…" },
    { "source": "hybrid_analysis", "ok": false, "error": "sandbox analysis errored" }
  ],
  "yara_auto_rules": ["fifaconfig_exe.yar"],
  "report_pdf": "reports/pdf/samples/….pdf"
}
```

Scanners that failed are retained with `ok: false` and their error — a partial
result is the normal case upstream, and hiding the failures would misrepresent
coverage.

**Exit:** a hand-placed `.request` file with `GITHUB_PUBLISH_ENABLED=0` produces
a `dry_run` result record and pushes nothing. With it set to `1` against a
throwaway fork, it produces a real `ok` record.

---

## Phase 2 — Dashboard: trigger ⬜

### `github_analysis_submit.go`

`serveGitHubAnalysisSubmit` mirrors `serveSandboxSubmit` exactly:

- `POST /github-analysis/submit`, `requireAdmin`, `sameOriginRequest`.
- `hashName.MatchString(hash)`, then `s.payloadPath(hash)` existence check.
- Refuses with 503 when `GITHUB_ANALYSIS_REQUEST_DIR` is empty — the feature is
  off unless explicitly wired, same as sandbox web submission.
- `O_CREATE|O_EXCL` marker write, so a double click while queued is a no-op.
- Redirect via a `submitReturnURL`-style allowlist extended with
  `/github-analysis/`.

### Consent gate

This is the one place the pattern diverges from sandbox submission, because the
consequence differs: the sandbox detonates locally, this publishes externally.

- The button opens the shared confirm modal (`hp-modals.js`, the destructive
  variant already used for other irreversible actions) stating plainly: *"This
  uploads the sample to the public Xore/honeypot repository and to third-party
  scanner APIs. This cannot be undone."*
- The POST carries a `confirm=publish` field; the handler rejects without it.
- Every submission is written to the audit log with the admin identity, SHA-256,
  and timestamp — reuse the existing audit sink, do not add a second one.

**Exit:** `github_analysis_submit_test.go` covers non-admin 403, cross-origin
403, bad hash 400, unknown payload 404, missing consent 400, disabled 503,
idempotent double submit, and the redirect notice.

---

## Phase 3 — Dashboard: read ⬜

`github_analysis.go` mirrors `sandbox.go`:

- `githubAnalysisResultsDir()` / `githubAnalysisRequestDir()`.
- `loadGitHubAnalysisResults() []githubAnalysisResult` — reads `*.json`.
- `loadGitHubAnalysisStatus()` — `status.json`, same handoff/queue shape.
- `githubAnalysisData(sha256, query string)` — list or detail.
- `GET /github-analysis`, `GET /github-analysis/{sha256}`,
  `GET /api/github-analysis[/{sha256}]`, `GET /export/github-analysis/{sha256}`
  (streams the upstream PDF, falls back to the JSON record).

`page_github_analysis.go` follows the tabbed layout the sandbox and
payload-analysis pages now use:

- **Verdict** — detection ratio, family, risk level, per-scanner table with
  permalinks, failed scanners shown as failed.
- **Provenance** — pushed commit, Actions run link, sample path upstream,
  requesting admin, timestamps.
- **Artifacts** — auto-generated YARA rules from this run, IOC rows added,
  PDF download.

Cross-links, both directions:

- `/payload-analysis/{hash}` gains a card showing the upstream verdict when a
  record exists, next to the existing "Isolated dynamic analysis" card.
- `/payloads` rows gain a verdict badge linking to `/github-analysis/{hash}`.
- The `/search` index (`search.go`) indexes family name and scanner verdict so
  a family name finds the sample.

---

## Phase 4 — Pull the auto-generated YARA corpus back ⬜

Independent of the button, and the highest-value item that does not require
publishing anything.

`sync-yara.sh` fetches `yara-rules/*.yar` and `yara-rules/auto/*.yar` from
upstream into the scanner's rules directory on a timer:

- Validate with `yara --compile` before adopting; a rule that fails compilation
  is dropped, not shipped to the scanner.
- Keep upstream rules in a separate `rules/upstream/` subtree so local rules in
  `analysis/yara/rules/honeypot.yar` are never overwritten.
- Record the upstream commit SHA in a lock file, mirroring the vendored-theme
  approach in `scripts/check-vendored-theme.sh` / `dashboard/frontend/theme.lock`.
- Auto rules carry `auto_generated = true` in their meta; surface them in the
  dashboard's YARA match list with a distinct badge so an auto-rule hit is never
  mistaken for a curated detection.

**Exit:** the YARA sidecar loads upstream rules, a fixture sample matches a
known auto rule, and a deliberately broken rule is rejected at sync time rather
than at scan time.

---

## Phase 5 — Queue health and alerting ✅ 2026-08-02

Extends the existing block in `store.go` (immediately after `ghidraAlerts`) —
same `s.alerts` sink, no new transport, via `githubAnalysisAlerts`
(`github_analysis.go`):

- `github-analysis:handoff` — requests waiting on the host publisher
  (`GITHUB_ANALYSIS_REQUEST_DIR`'s `*.request` markers older than 5 minutes).
- `github-analysis:worker` — a stale `status.json` (collector stopped
  refreshing it).
- `github-analysis:failed` — the queue's failed count is non-zero.
- `github-analysis:verdict:{sha256}` — a returned record at or above
  `GITHUB_ANALYSIS_ALERT_POSITIVES` (default 10 malicious engines).

An unconfigured host (`GITHUB_ANALYSIS_RESULTS_DIR` unset) alerts on none of
these — see #148.

`metrics.go` exposes `honeypot_github_analysis_queue{state=…}` (handoff,
queued, running, failed) alongside the existing `honeypot_sandbox_queue`
gauges, always present (zero when unconfigured) so a scrape never has to
distinguish "never deployed" from "the exporter stopped".

---

## Phase 6 — IOC and family enrichment ✅ 2026-08-02

`githubAnalysisResult.Family` (populated by `family_for()`, backed by
upstream's `iocs/families.csv`) is now surfaced beyond the single-record
detail card:

- `/payloads`: a `Family` badge on `capturedFile` (`payloads_data.go`),
  alongside the existing verdict badge, linking to the `/events?family=…`
  pivot.
- `/payload-analysis/{hash}`: the GitHub-analysis card's family row links to
  the same pivot instead of being a bare, unbounded string.
- `/events?family=…` (`filters.go`): resolves the family label to every
  SHA-256 the pipeline attributed to it
  (`githubAnalysisHashesForFamily`, case/whitespace-normalized so
  differently-cased attribution of the same family doesn't fragment into two
  dead-end filters), then matches events by exact `Shasum` membership in that
  resolved set -- never a substring/pattern test against event fields, so
  the filter cannot broaden beyond hashes the scanner pipeline itself named.

Provenance stays deliberately narrow: this is GitHub-analysis's own scanner
attribution only. Ghidra's separate, explicitly unverified AI-guessed
`FamilyGuess` (`ghidra.go`) is never merged into it and stays on Ghidra's own
page -- see #149.

Family values are bounded for display (`boundedFamily`, `util.go`) and
rendered through the existing `html/template` auto-escaping everywhere else
on these pages already relies on.

---

## Phase 7 — Environment and Compose wiring ⬜

`.env.example`:

```dotenv
# ── GitHub analysis integration ───────────────────────────────────────
GITHUB_ANALYSIS_REQUEST_DIR=/github-analysis-requests
GITHUB_ANALYSIS_RESULTS_DIR=/github-analysis-results
GITHUB_ANALYSIS_ALERT_POSITIVES=10
```

`docker-compose.yml`, dashboard service:

```yaml
    volumes:
      - /var/lib/honeypot-github/requests/pending:/github-analysis-requests
      - /var/lib/honeypot-github/results:/github-analysis-results:ro
```

Host-only, never in the container and never in `.env`:

```dotenv
GITHUB_PUBLISH_ENABLED=0          # 1 arms real publication
GITHUB_REPO=Xore/honeypot
GITHUB_CLONE=/var/lib/honeypot-github/repo
GH_PAT=…                          # /etc/honeypot-github.env, root:root 0600
GITHUB_ANALYSIS_MAX_WAIT=5400
```

---

## Sequencing and dependencies

| Phase | Depends on | Blocked by Gate 0? | Value if run alone |
|---|---|---|---|
| 0 — docs reconciliation ✅ | — | No | Removes actively wrong documentation |
| 4 — YARA corpus sync | 0 | No (read-only, outbound HTTPS) | 18 upstream rules reach the scanner |
| 1 — host publisher | 0 | Yes — needs host access | — |
| 2 — submit button | 1 | Yes | — |
| 3 — result views | 1, 2 | Yes | — |
| 5 — alerting ✅ | 3 | Yes | — |
| 6 — family enrichment ✅ | 3 | Yes | — |
| 7 — env/compose | 1, 2 | Yes | — |

Phases 0 and 4 are the only ones that can proceed before `ROADMAP.md` Gate 0
(restore management access to the homeserver) is green. Everything from Phase 1
onward requires the host, because the publisher is a root-owned systemd unit.

---

## Testing

Following existing `dashboard/` conventions:

| Test file | Covers |
|---|---|
| `github_analysis_test.go` | `loadGitHubAnalysisResults`, `loadGitHubAnalysisStatus`, `githubAnalysisData` against fixture JSON |
| `github_analysis_submit_test.go` | admin-only, same-origin, consent field, hash validation, idempotent spool write, disabled-503, redirect notice |
| `github_analysis_export_test.go` | PDF path, JSON fallback, missing-result 404 |
| `page_structure_test.go` | extend with the two new routes' required landmarks |

Host-side scripts get `bats`-style or plain-shell fixture tests under
`analysis/github/tests/`, asserting that dry-run mode pushes nothing — that
assertion is the safety property of the whole feature and must be a test, not a
convention.

No test may submit a real sample to a real scanner. Fixtures are synthetic and
contain no real indicators, per the `WORK-LEDGER.md` review checklist.

---

## Open questions

Retention denylist, archive convention, and submission quota. All three are
Phase 1 blockers and all three are decisions rather than implementation, so
they are being made in the issue rather than in this document:
[#74](https://github.com/Xore/honeypot-stack/issues/74).
