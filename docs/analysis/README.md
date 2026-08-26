# Malware Analysis Pipeline

Captured payloads are analysed by a multi-scanner GitHub Actions pipeline that
lives in a **separate repository**, [`Xore/honeypot`](https://github.com/Xore/honeypot).
This folder holds the honeypot-side tooling that feeds it and the local analysis
scripts that run on the sensor host.

> The integration between this repository's dashboard and that pipeline is
> designed in [`docs/github-analysis-integration-roadmap.md`](../github-analysis-integration-roadmap.md)
> and tracked in [#73](https://github.com/Xore/APIARY/issues/73)
> (upstream YARA corpus sync — built, see [`yara/`](../../analysis/yara/)) and
> [#74](https://github.com/Xore/APIARY/issues/74) (the manual publisher).
> Per the roadmap's own status line: **built** — dashboard trigger/read
> (Phases 2-3), the host publisher itself (Phase 1), queue health/alerting
> (Phase 5), and IOC/family enrichment (Phase 6); the host publisher is
> **built but not installed** on a given deployment until an operator runs
> `analysis/github/install-github-publisher.sh` there; environment/Compose
> wiring (Phase 7) has **not started**. Publication is **not** automatic
> even where installed — see "Publication is manual" below.

---

## Architecture

```mermaid
flowchart TB
    subgraph HS["APIARY (this repo) -- dashboard/github_analysis_submit.go"]
        direction TB
        analyst["Admin analyst,<br/>same-origin request"]
        submit["POST /github-analysis/submit<br/>hash + confirm=publish required --<br/>the one submission route in this repo<br/>that needs an explicit consent field,<br/>not just admin + same-origin"]
        reqSpool[("GITHUB_ANALYSIS_REQUEST_DIR<br/>{sha256}.request marker only --<br/>no GH_PAT, no git, no GitHub API<br/>call ever made by the dashboard")]
        audit[("audit log --<br/>every submission, accepted<br/>or refused")]
        resultsDir[("GITHUB_ANALYSIS_RESULTS_DIR<br/>{sha256}.json, read-only")]
        analyst --> submit
        submit --> reqSpool
        submit --> audit
        resultsDir --> submit
    end

    subgraph HostPub["Root-owned host publisher (Phase 1 -- built, install-github-publisher.sh)"]
        direction TB
        process["process-github-requests.sh<br/>drains the spool"]
        denylist["check-denylist.sh"]
        quota["daily quota check"]
        gate{"GITHUB_PUBLISH_ENABLED<br/>(host .env, default 0) --<br/>independent of the dashboard's<br/>own confirm=publish click"}
        dryrun(["dry_run exit_status --<br/>the default posture:<br/>everything up to here runs,<br/>nothing is pushed"])
        collect["collect-results.py<br/>(timer-driven)"]
        process --> denylist --> quota --> gate
        gate -->|"0 (default)"| dryrun
    end

    subgraph XH["Xore/honeypot (public sample archive + pipeline)"]
        direction TB
        samples["samples/{ELF,PE,Scripts,Docs,…}/<br/>push triggers analyze.yml"]
        actions["GitHub Actions run --<br/>8 scanner APIs: VT, MalwareBazaar,<br/>Hybrid-Analysis, Malshare, JoeSandbox,<br/>MetaDefender, CAPE, Any.run"]
        outputs["reports/scanner/&lt;sha256&gt;.json<br/>reports/pdf/, reports/yara/<br/>iocs/hashes.csv, iocs/families.csv<br/>yara-rules/ + yara-rules/auto/ (#73, built)"]
        samples --> actions --> outputs
    end

    reqSpool --> process
    gate -->|"1 -- irreversible,<br/>public, third-party"| samples
    outputs --> collect --> resultsDir
```

---

## Components in this folder

| Path | Purpose |
|---|---|
| `analyze.py` | Offline triage of Cowrie / http-honeypot / multipot / Dionaea JSON logs. Stdlib only |
| `collect.sh` | **Deprecated.** Cron-driven bulk copy of captures into a clone of `Xore/honeypot`. Superseded by the dashboard button; kept for a one-time manual backfill |
| `dedupe-payloads.py` | Collapses duplicate captures by SHA-256 |
| `yara/` | Networkless YARA scanner sidecar, local rules, and the vendored upstream corpus (`yara/sync-yara.sh`) |
| `ghidra/` | Headless Ghidra reverse-engineering pipeline, local-model triage, and the analysis-host installer ([`ghidra/README.md`](ghidra/README.md)) |
| `es-results-importer/` | Ships Ghidra/sandbox/GitHub-analysis/workbench-run results into Elasticsearch, read-only, alongside the raw event stream ([#378](https://github.com/Xore/APIARY/issues/378)) |
| `elasticsearch-setup.sh`, `honeypot-kibana-setup.sh`, `filebeat.yml`, `evebox.yaml` | Log pipeline and search UI provisioning |
| `backup-honeypot.sh`, `verify-backup.sh`, `log-maintenance.sh`, `RECOVERY.md` | Retention and recovery |
| `verify-stack.py` | Post-deploy/recovery health gate over the backend's `/api/v1/source-health` ([#2086](https://github.com/Xore/APIARY/issues/2086)) |

The GitHub Actions workflow itself lives at
[`Xore/honeypot/.github/workflows/analyze.yml`](https://github.com/Xore/honeypot/blob/main/.github/workflows/analyze.yml).
The authoritative scanner capability reference is
[`Xore/honeypot/docs/SCANNERS.md`](https://github.com/Xore/honeypot/blob/main/docs/SCANNERS.md).

---

## Publication is manual

Pushing a capture to `Xore/honeypot` publishes it to a **public repository** and
to up to eight third-party scanner APIs. That is an irreversible external
disclosure, so it is never triggered by a timer or a directory watcher.

The path is a per-sample, admin-only, confirm-gated button in the dashboard
(`POST /github-analysis/submit`, requiring `confirm=publish` in addition to
the admin+same-origin check every other submission route already has),
backed by a root-owned host publisher (`analysis/github/`) — the same
spool-file pattern the KVM sandbox and Ghidra submissions already use. Two
independent gates stand between a confirmed dashboard click and an actual
public push: the dashboard's own confirmation, and the host publisher's own
`GITHUB_PUBLISH_ENABLED` (default `0` — a request resolves as far as
`dry_run` and stops there until an operator explicitly arms it in
`/etc/honeypot-github.env`). `collect.sh` predates this design and should not
be installed on a cron.

---

## Upstream pipeline

### Triggers

| Trigger | Behaviour |
|---|---|
| `push` to `main` touching `samples/**` | Scans only **Added or Renamed** files (`--diff-filter=AR`). Modified files are deliberately skipped — an existing sample was already scanned when it was added |
| `pull_request` | Dry run; results are never committed |
| `schedule` — Sundays 02:00 UTC | Full rescan of `samples/`, refreshing detection scores |
| `workflow_dispatch` | Manual run with an optional `sample_path` input |

### Steps

1. Detect new sample files.
2. YARA pre-scan (`yara-rules/*.yar` + `yara-rules/auto/*.yar`) — offline
   detection before any API quota is spent.
3. Multi-scanner analysis (`analyze_samples.py`): hash lookup, upload if
   unknown, poll for results → `reports/scanner/<sha256>.json`; append
   `iocs/hashes.csv` and `iocs/families.csv`.
4. Auto YARA generation (`generate_yara.py`): reads the scanner reports, runs
   `strings -n 8` over the sample, normalises family names, scores and selects
   detection strings, emits `yara-rules/auto/<family>.yar`, validates with
   `yara --compile`. Invalid rules go to `_invalid/` for review.
5. IOC changelog update (`iocs/CHANGELOG.md`).
6. PDF report generation (`report.py` → `reports/pdf/`).
7. Artifact upload, retained 90 days.
8. Commit `reports/`, `iocs/`, and `yara-rules/auto/` with `[skip ci]`.

### Failure contract

A single scanner API failure never aborts the job, and the JSON report is always
written. The job hard-fails only when no scanner secrets are set at all, the
file list cannot be read, or every scanner errored on every file (exit 2).

### Scanners

| Scanner | Secret | Free tier |
|---|---|---|
| VirusTotal | `VT_API_KEY` | 4 req/min, 500/day — 70+ AV engines |
| MalwareBazaar | `MALWAREBAZAAR_API_KEY` | Yes — `Auth-Key` header required on every request |
| Hybrid-Analysis | `HYBRID_ANALYSIS_KEY` | Yes — `env_id=110` (Win7-64) on free tier |
| Malshare | `MALSHARE_API_KEY` | Yes |
| JoeSandbox | `JOESANDBOX_API_KEY` | Community tier, limited submissions |
| MetaDefender | `METADEFENDER_API_KEY` | Yes — 37+ engines |
| CAPE Sandbox | `CAPE_API_URL` + `CAPE_API_KEY` | Self-hosted |
| Any.run | `ANYRUN_API_KEY` | Paid only |

`GH_PAT` (repo write scope) is always required, for the pipeline's own commits.
At least one scanner secret must be present.

Secrets are configured in `Xore/honeypot` under
**Settings → Secrets and variables → Actions**. None of them belong in this
repository, in `.env`, or in any container.

---

## Local triage

```bash
# Summarise sensor logs without leaving the host
python3 analysis/analyze.py /path/to/logdir --top 15 --json summary.json
```

```bash
# Copy logs out of the Docker volume first
docker run --rm -v honeypot_honeypot-logs:/logs -v "$PWD":/out \
    alpine sh -c 'cp /logs/*.json /out/'
```
