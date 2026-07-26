# Ghidra Dashboard Integration — Implementation Plan

> **Status**: Planned
> **Last updated**: 2026-07-27
> **Author**: honeypot-stack automated planning
> **Depends on**: [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) (Ghidra headless + Rev·Deck + GhidrAssist)

---

## Overview

[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) covers running Ghidra
headless analysis and produces reports committed to `Xore/Honeypot`. This
document covers the other half: making that analysis a first-class citizen
of the operations `dashboard/` — so an analyst can trigger a Ghidra run on
any captured payload with one click, and see every artifact (functions,
strings, imports, crypto hits, call graph, AI triage) inline, next to the
sandbox dynamic-analysis results the dashboard already shows.

No new trust boundary is introduced. The dashboard container stays
unprivileged and never talks to Docker, the Ghidra REST service, or the
network directly — it follows the **exact same spool-file pattern** already
used for sandbox submission (`sandbox_submit.go`, `sandbox.go`): the
dashboard writes a narrow request marker to a directory; a root-owned host
service outside the container does the actual work and writes results back
to a directory the dashboard only reads.

---

## Precedent: how sandbox integration already does this

| Concern | Sandbox (existing) | Ghidra (this plan) |
|---|---|---|
| Trigger | `POST /sandbox/submit` writes `{hash}.request` to `SANDBOX_REQUEST_DIR` | `POST /ghidra/submit` writes `{sha256}.request` to `GHIDRA_REQUEST_DIR` |
| Worker | Host-side libvirt/KVM worker (`sandbox/honeypot-sandbox-worker.path`) consumes the spool, never run by the dashboard | Host-side Ghidra worker consumes the spool, calls `biniamfd/ghidra-headless-rest` (already defined in `docker-compose.ghidra.yml`), never run by the dashboard |
| Results | Worker writes `{job}.json` to `SANDBOX_RESULTS_DIR`; dashboard only reads | Worker writes `{sha256}_ghidra.json` (+ `.dot`/`.svg` call graph, `.pdf` report) to `GHIDRA_RESULTS_DIR`; dashboard only reads |
| List page | `GET /sandbox` → `sandboxData("", q)` → `{{define "sandbox"}}` | `GET /ghidra` → `ghidraData("", q)` → `{{define "ghidra"}}` |
| Detail page | `GET /sandbox/{job}` | `GET /ghidra/{sha256}` |
| JSON API | `GET /api/sandbox`, `/api/sandbox/{job}` | `GET /api/ghidra`, `/api/ghidra/{sha256}` |
| Export | `GET /export/sandbox/{job}` (bundle download) | `GET /export/ghidra/{sha256}` (PDF from Phase 5 of IMPLEMENTATION_PLAN.md) |
| Queue/health alerting | `loadSandboxStatus()` + the `s.checkAlerts` block in `main.go` (~line 1690) watches for stalled handoff, unhealthy worker, high-risk results | Same block gets three more checks: stalled Ghidra handoff, unhealthy Ghidra worker, "interesting" Ghidra findings (crypto hit, high CAPA score, AI triage flags "malicious") |
| Payloads page action | "Submit to sandbox" button per payload row | "Run Ghidra analysis" button per payload row, next to the existing sandbox button |

Reusing this pattern means no new security review surface: the dashboard's
threat model (unprivileged, spool-file only, no direct access to analysis
infrastructure) doesn't change, it just gets a second spool.

---

## Architecture

```
honeypot-stack/
├── analysis/ghidra/
│   ├── IMPLEMENTATION_PLAN.md         ← Ghidra/Rev·Deck/GhidrAssist analysis pipeline
│   ├── DASHBOARD_INTEGRATION_PLAN.md  ← this file
│   ├── docker-compose.ghidra.yml      ← biniamfd/ghidra-headless-rest (REST API :9090)
│   └── worker/                        ← NEW: host-side spool consumer
│       ├── ghidra-worker.py           ← watches GHIDRA_REQUEST_DIR, calls the REST API,
│       │                                writes GHIDRA_RESULTS_DIR/{sha256}_ghidra.json
│       ├── honeypot-ghidra-worker.path
│       └── honeypot-ghidra-worker.service
└── dashboard/
    ├── ghidra.go            ← NEW: mirrors sandbox.go — loadGhidraResults(),
    │                            loadGhidraStatus(), ghidraData(), serveGhidraAPI(),
    │                            serveGhidraExport()
    ├── ghidra_submit.go     ← NEW: mirrors sandbox_submit.go — serveGhidraSubmit()
    └── page.go              ← adds {{define "ghidra"}} template block
```

---

## Phase 1 — Host-side Ghidra worker (spool consumer) ⬜ Planned

### Goal
A root-owned systemd path unit + oneshot service, structurally identical to
`sandbox/honeypot-sandbox-worker.path` / `honeypot-sandbox-worker.service`,
that:

1. Watches `GHIDRA_REQUEST_DIR` (default `/ghidra-requests`) for new
   `{sha256}.request` files.
2. Resolves the sample from the existing captured-payload store (same
   `s.payloadPath(hash)` lookup the dashboard already uses before it will
   even let a submit happen).
3. POSTs the binary to the `biniamfd/ghidra-headless-rest` container
   (`docker-compose.ghidra.yml`, already defined in the base plan) at
   `POST /analyze`.
4. Polls `/functions`, `/strings`, `/imports`, `/export/ghidra-zip` per
   IMPLEMENTATION_PLAN.md Phase 1, and — if Rev·Deck is configured — runs
   the `program_triage` + `suspicious_behavior` workflows from Phase 2.
5. Writes one normalized `{sha256}_ghidra.json` to `GHIDRA_RESULTS_DIR`
   (default `/ghidra-results`), matching the `sandboxResult` struct's shape
   and conventions (`version`, `requested_at`/`started_at`/`completed_at`,
   `exit_status`) so the dashboard's existing queue/status/alert code needs
   only additive changes, not new patterns.
6. Deletes the consumed `.request` file and writes `status.json` (queued /
   running / done counts) the same way `loadSandboxStatus()` expects.

### Result JSON shape

```json
{
  "version": 1,
  "sha256": "…",
  "requested_at": "…", "started_at": "…", "completed_at": "…",
  "exit_status": "ok",
  "functions": [{"address": "0x401000", "name": "sub_401000", "signature": "…"}],
  "strings": ["…"],
  "imports": ["kernel32.dll!CreateProcessA", "…"],
  "findcrypt": [{"address": "0x402a10", "constant": "AES Te0", "algorithm": "AES"}],
  "call_graph_svg": "402a10.svg",
  "ai_triage": {
    "workflow": "program_triage",
    "family_guess": "…", "risk_level": "…",
    "behaviors": ["…"],
    "model": "qwen3:8b"
  },
  "report_pdf": "{sha256}_ghidra.pdf"
}
```

---

## Phase 2 — Dashboard: trigger + read (`ghidra.go`, `ghidra_submit.go`) ⬜ Planned

### `serveGhidraSubmit` (mirrors `serveSandboxSubmit`)
- `POST /ghidra/submit`, admin-only (`requireAdmin`), same-origin only
  (`sameOriginRequest`).
- Validates `hash` against `hashName`, confirms the payload exists via
  `s.payloadPath(hash)` — the dashboard **never** touches the binary itself
  beyond this existence check.
- Writes `filepath.Join(getenv("GHIDRA_REQUEST_DIR", "/ghidra-requests"), hash+".request")`
  with `O_CREATE|O_EXCL` (idempotent — a second click while queued is a
  no-op, exactly like sandbox submission).
- Redirects to `/payloads?analysis=queued&hash=…` — same notice pattern
  already wired at `main.go:~2732` ("Sandbox analysis requested for …"),
  extended with "Ghidra analysis requested for …".

### `ghidra.go` (mirrors `sandbox.go`)
- `ghidraResultsDir()` / `ghidraRequestDir()` — env-var accessors.
- `loadGhidraResults() []ghidraResult` — reads every `*_ghidra.json`.
- `loadGhidraStatus() ghidraQueueStatus` — reads `status.json`, same
  queued/running/failed/handoff-age shape as `sandboxQueueStatus`.
- `ghidraData(sha256, query string) (ghidraPageData, error)` — list or
  single-result view, same signature shape as `sandboxData`.
- `serveGhidraAPI(w, r)` — `GET /api/ghidra`, `/api/ghidra/{sha256}` → JSON.
- `serveGhidraExport(w, r)` — `GET /export/ghidra/{sha256}` → streams
  `report_pdf` (Phase 5 of IMPLEMENTATION_PLAN.md) or a zip of raw
  artifacts if no PDF exists yet.

### Routes to register in `main.go` (next to the existing sandbox block, ~line 2755)
```go
http.HandleFunc("/ghidra/submit", s.serveGhidraSubmit)
http.HandleFunc("/ghidra", func(w http.ResponseWriter, r *http.Request) {
    data, _ := ghidraData("", r.URL.Query().Get("q"))
    tmpl.ExecuteTemplate(w, "ghidra", data)
})
http.HandleFunc("/ghidra/", func(w http.ResponseWriter, r *http.Request) {
    sha, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/ghidra/"))
    ...
    data, err := ghidraData(sha, "")
    tmpl.ExecuteTemplate(w, "ghidra", data)
})
http.HandleFunc("/api/ghidra", serveGhidraAPI)
http.HandleFunc("/api/ghidra/", serveGhidraAPI)
http.HandleFunc("/export/ghidra/", serveGhidraExport)
```

---

## Phase 3 — UI: payloads page action + result view ⬜ Planned

### Payloads list (`{{define "payloads"}}` in `page.go`)
Add a second per-row button next to the existing sandbox-submit form:
```html
<form method="post" action="/ghidra/submit" class="inline">
  <input type="hidden" name="hash" value="{{.SHA256}}">
  <button type="submit" class="btn-sm">Run Ghidra analysis</button>
</form>
{{if .GhidraResult}}<a href="/ghidra/{{.SHA256}}" class="badge">Ghidra: {{.GhidraResult.RiskLabel}}</a>{{end}}
```

### New `{{define "ghidra"}}` template block (mirrors `{{define "sandbox"}}` at `page.go:622`)
Cards for:
- Function list (paginated, address + name + signature), link-through to
  decompiled pseudocode for flagged/suspicious functions only (avoid
  dumping every function's pseudocode into the page).
- String table with an "interesting" filter (URLs, IPs, registry paths,
  format-string patterns — reuse the honeypot's existing `payload_kind.go`
  heuristics where they overlap).
- Import table, with entries in `SuspiciousImports`-style groupings
  (reuse the naming convention from `sandboxWindows.SuspiciousImports`).
- FindCrypt hits.
- Call graph, rendered as an inline SVG (`call_graph_svg` from the result
  JSON) rather than requiring a DOT viewer.
- AI triage card (Rev·Deck `program_triage`/`suspicious_behavior` output)
  — clearly labeled as AI-generated and evidence-linked back to the
  specific function/string/import that grounded each claim, per
  IMPLEMENTATION_PLAN.md Phase 2's "no hallucination on facts" design.
- "Download full report" button → `/export/ghidra/{sha256}`.

### List page (`{{define "ghidra"}}` list mode, same as `sandbox` list mode)
One row per analyzed sample: hash, family guess (from AI triage if
present), risk level, crypto/import highlights, timestamp, link to detail.

---

## Phase 4 — Queue health + alerting ⬜ Planned

Extend the existing alert-check block in `main.go` (~line 1690, right after
the sandbox checks) with the Ghidra equivalents:

```go
ghidraStatus := loadGhidraStatus()
if ghidraStatus.HandoffOld {
    message := fmt.Sprintf("ghidra handoff stalled: %d dashboard request(s) waiting for the host worker", ghidraStatus.Handoff)
    ...
}
if ghidraStatus.WorkerState == "stale" || ghidraStatus.WorkerState == "error" {
    message := fmt.Sprintf("ghidra worker unhealthy: state=%s queued=%d running=%d", ...)
    ...
}
for _, result := range loadGhidraResults() {
    if len(result.FindCrypt) == 0 && !result.AITriage.Interesting {
        continue
    }
    message := fmt.Sprintf("ghidra flagged sample: sha256=%s crypto_hits=%d ai_risk=%s", result.SHA256, len(result.FindCrypt), result.AITriage.RiskLevel)
    ...
}
```

No new alert transport is introduced — this rides the same `s.alerts`
sink (webhook/notification path) already used for sandbox and Suricata
alerts.

---

## Phase 5 — Environment variables (add to `.env.example`)

```dotenv
# ── Ghidra dashboard integration ──────────────────────────────────────
GHIDRA_REQUEST_DIR=/ghidra-requests
GHIDRA_RESULTS_DIR=/ghidra-results
GHIDRA_API_BASE=http://127.0.0.1:9090
GHIDRA_ALERT_RISK_SCORE=50
```

`GHIDRA_API_BASE` is consumed only by the host-side worker (Phase 1), never
by the dashboard container — consistent with the dashboard never talking to
the Ghidra REST service directly.

---

## Phase 6 — Compose wiring ⬜ Planned

`docker-compose.yml` (main stack) gets the request/results directories
mounted read-only into the dashboard container and read-write into wherever
the Phase 1 worker runs (host or a sibling container with Docker socket
access — mirrors how the sandbox worker is deliberately kept off the
dashboard's container so a dashboard RCE can't reach libvirt):

```yaml
services:
  dashboard:
    environment:
      - GHIDRA_REQUEST_DIR=/ghidra-requests
      - GHIDRA_RESULTS_DIR=/ghidra-results
    volumes:
      - ghidra-requests:/ghidra-requests        # read-write (dashboard only creates marker files)
      - ghidra-results:/ghidra-results:ro        # read-only

volumes:
  ghidra-requests:
  ghidra-results:
```

The Phase 1 worker (host-side systemd unit, not a compose service) owns
read-write access to both volumes and is the only thing that talks to
`analysis/ghidra/docker-compose.ghidra.yml`'s REST container.

---

## Testing

Following the existing test conventions in `dashboard/` (`sandbox_test.go`,
`sandbox_submit_test.go`, `sandbox_export_test.go`):

| Test file | Covers |
|---|---|
| `ghidra_test.go` | `loadGhidraResults`, `loadGhidraStatus`, `ghidraData` against fixture JSON |
| `ghidra_submit_test.go` | `serveGhidraSubmit` — admin-only, same-origin, hash validation, idempotent spool write, redirect notice |
| `ghidra_export_test.go` | `serveGhidraExport` — PDF path, fallback zip path, missing-result 404 |

Also extend `e2e_test.go` with one flow: submit → poll `/api/ghidra/{sha256}`
→ assert eventual `exit_status: "ok"` against a fixture worker (no real
Ghidra container needed for the dashboard-side e2e test — that's covered
separately by whatever validates `docker-compose.ghidra.yml` itself).

---

## Summary of new surface

| Component | New | Reuses |
|---|---|---|
| Host worker | `ghidra-worker.py`, 2 systemd units | Same spool pattern as sandbox worker |
| Dashboard Go | `ghidra.go`, `ghidra_submit.go`, ~6 routes | `requireAdmin`, `sameOriginRequest`, `hashName`, `s.payloadPath`, `s.alerts` |
| Templates | `{{define "ghidra"}}` block, payloads-page button | AdminLTE frontend assets, existing card/table CSS |
| Env vars | `GHIDRA_REQUEST_DIR`, `GHIDRA_RESULTS_DIR`, `GHIDRA_API_BASE`, `GHIDRA_ALERT_RISK_SCORE` | — |
| Trust boundary | None — dashboard still never touches Docker/libvirt/the Ghidra REST API directly | Sandbox's existing spool-file security model |
