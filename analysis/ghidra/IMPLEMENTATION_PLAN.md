# Ghidra Payload Analysis — Implementation Plan

> **Status**: Design document. Phase 4 (plugin selection) and phase 3
> (GhidrAssist) are unbuilt. Phases 1, 2 and 5 are built — five of the six
> `scripts/` exporters exist (`findcrypt.py` was deleted, superseded by
> `scan_crypto()` in the worker), the `revdeck` service is deployed
> (profile-gated in `docker-compose.ghidra.yml`, interactive-only), and
> `report/generate_report.py` renders an HTML report from every automated
> worker result. Still missing: a verified request/result contract for
> automating Rev·Deck triage, which is what the dashboard's `revdeck`
> workbench adapter is waiting on.  
> **Tracked in**: [#78](https://github.com/Xore/honeypot-stack/issues/78)
> (phases 3–5), [#76](https://github.com/Xore/honeypot-stack/issues/76)
> (dashboard spool and entry points),
> [#85](https://github.com/Xore/honeypot-stack/issues/85) (non-Ghidra static
> tooling)  
> **Last updated**: 2026-08-01  
> **Author**: honeypot-stack automated planning

---

## Overview

This document describes the full implementation plan for adding automated
static reverse-engineering of honeypot payloads using Ghidra's headless mode,
AI-assisted analysis (Rev·Deck / GhidrAssist), and a curated set of
community plugins from the awesome-ghidra list.

All analysis runs in Docker and produces structured output committed to
[Xore/Honeypot](https://github.com/Xore/Honeypot) alongside VirusTotal and
JoeSandbox reports.

> **Dashboard integration**: for triggering these analyses from the
> operations dashboard and viewing every artifact inline (functions,
> strings, imports, crypto hits, call graph, AI triage), see
> [DASHBOARD_INTEGRATION_PLAN.md](DASHBOARD_INTEGRATION_PLAN.md).

---

## Architecture

```
honeypot-stack/
└── analysis/
    └── ghidra/
        ├── IMPLEMENTATION_PLAN.md   ← this file
        ├── docker-compose.ghidra.yml   ← also defines revdeck, profile-gated
        ├── scripts/                 ← Ghidra Python scripts (Jython / Pyhidra)
        │   ├── export_functions.py
        │   ├── export_strings.py
        │   ├── export_imports.py
        │   ├── findcrypt.py         ← deleted, see #136
        │   ├── yara_scan.py         ← run YARA rules inside Ghidra
        │   └── call_graph.py
        ├── revdeck/                 ← biniamf/ai-reverse-engineering integration
        │   └── README.md
        ├── ghidrassist/             ← symgraph/GhidrAssist plugin config
        │   └── README.md
        └── report/
            └── generate_report.py   ← {sha256}_ghidra.json → HTML report
```

This is the *target* layout. Every entry now exists.

Three corrections against the layout this section used to show:

- `headless_analyze.sh` is gone — deleted alongside `ghidra_analyze.py` under
  [#107](https://github.com/Xore/honeypot-stack/issues/107); see
  [Dashboard/Worker Integration](#dashboardworker-integration) below.
- `revdeck/docker-compose.revdeck.yml` was never built as a standalone file.
  The `revdeck` service was instead folded into `docker-compose.ghidra.yml`
  itself, gated behind the `revdeck` profile (commits `9244b87`, `8e828f0`,
  2026-08-01) — hardened (`read_only`, `cap_drop: ALL`, no-new-privileges),
  reachable over the WireGuard `HP_BIND` address through the same Traefik +
  forward-auth SSO path as every other investigation UI. `revdeck/` now holds
  only its `README.md`. That closes the compose gap this document used to
  list; the LLM automation *contract* on top of it — what #78 phase 2/3 and
  the dashboard's `revdeck` workbench adapter
  ([`workbench_domain.go`](../../dashboard/workbench_domain.go)) are actually
  waiting on — is still unbuilt.
- `report/` has no `templates/` subdirectory. [`generate_report.py`](report/generate_report.py)
  follows [#56](https://github.com/Xore/honeypot-stack/issues/56)'s
  `sandbox/windows/orchestrate/generate_report.py`, which doesn't use one
  either — one Python file covering both HTML and inlined CSS isn't enough
  code to be worth splitting.

`scripts/export_imports.py` was added following the shape of its four
siblings — it walks `FunctionManager.getExternalFunctions()` and writes
`{address, name, library}` per import, same as the other exporters write
their own JSON alongside it in the project directory.

---

## Phase 1 — Headless Ghidra (Docker) ✅ Ready to implement

### Goal
Run Ghidra's `analyzeHeadless` in a container against every new sample in
`Xore/Honeypot/samples/`. Export:
- Function list (address, name, signature)
- Decompiled pseudocode for top suspicious functions
- String table
- Import table (dynamic symbols)
- Crypto constant hits (FindCrypt)
- Call graph (DOT format)

### Docker Image
Use [`biniamfd/ghidra-headless-rest:latest`](https://hub.docker.com/r/biniamfd/ghidra-headless-rest)
— the same image that powers Rev·Deck. It exposes a REST API on port 9090.

### REST API Endpoints Used

Verified 2026-07-31 against `biniamfd/ghidra-headless-rest:1.2.1`
(Ghidra 11.3.2, artifact schema 2.1). **The table this section used to carry
was wrong in five of six rows** — it was written from the upstream README, not
from the running service, and it disagreed with the one in
`DASHBOARD_INTEGRATION_PLAN.md`. The service is FastAPI; `GET /openapi.json` is
the authority if this drifts again.

| Endpoint | Purpose | Response envelope |
|---|---|---|
| `GET /v1/health` | Liveness — **not** `/readyz`, which 404s | `{"status":"ok"}` |
| `POST /analyze` | Submit a binary, multipart field `file` | `{"job_id","status"}` |
| `GET /status/{job_id}` | Poll; `queued` → `running` → `done` | object, incl. `analyzer_version` and the service's own `sha256` |
| `GET /results/{job_id}/functions` | Functions, **paged** (`offset`/`limit`, default 100) | `{"total","offset","limit","functions":[…]}` |
| `GET /results/{job_id}/strings` | Strings | `{"count","strings":[{"addr","s",…}]}` |
| `GET /results/{job_id}/imports` | Imports | **bare array** of `{"name","library",…}` |
| `GET /results/{job_id}/function/{addr}/decompile` | Pseudocode for one function | — |
| `GET /v1/jobs/{job_id}/export` | Project archive (was `/export/ghidra-zip`) | — |

Three things worth knowing before writing a client:

* The last three collection endpoints use **three different envelopes** — a
  paged object, a counted object, and a bare array. `GhidraClient` normalises
  them so the stored result has one shape.
* Functions are paged at 100 by default. `/bin/ls` alone returns 412, so a
  client that reads the first page only silently truncates almost everything.
* Field names are not what the result schema uses: functions carry `addr`, and
  strings are objects with the text under `s`. Imports become `library!name`.

### Trigger
GitHub Actions in `Xore/Honeypot` already triggers on sample push.
The existing `analyze.yml` will be extended with a `ghidra` job that runs after
VirusTotal/JoeSandbox jobs complete.

---

## Phase 2 — AI-Assisted Analysis ✅ Built (2026-07-31, #103)

> **Built, but not the way this section describes.** The two workflows below
> run against a local OpenAI-compatible endpoint from the worker itself
> (`worker/ghidra-worker.py`), not through Rev·Deck, and populate `ai_triage`
> on the result. Rev·Deck stays in the compose file behind a profile as an
> analyst-facing chat UI.
>
> Two lines below are wrong and were the reason:
>
> - *"Deploy Rev·Deck as a service"* — its build context is not vendored; the
>   operator has to clone it by hand, so there is no running contract to code
>   against. The endpoint table in this document was already wrong about five
>   of six Ghidra endpoints, which is what taking a plan for a service costs.
> - *"local Ollama or cloud LLM endpoint via `.env`"* — a cloud endpoint is
>   not an option. The prompts carry text lifted out of captured malware.
>   `endpoint_is_local()` refuses any endpoint that is not this host or its
>   network, and there is no override flag.
>
> `attack_surface_triage` and `vulnerability_hypothesis` are not run.
> Operator documentation: [`README.md`](README.md#ai-triage-and-the-local-only-rule).

### Source
[biniamf/ai-reverse-engineering](https://github.com/biniamf/ai-reverse-engineering)

### What It Does
Rev·Deck pairs `biniamfd/ghidra-headless-rest` with an LLM copilot over an
OpenAI-compatible endpoint. Evidence-first: all LLM claims are grounded in
deterministic Ghidra data (functions, strings, imports, call graph). No
hallucination on facts — only bounded hypotheses.

### Integration Plan
- Deploy Rev·Deck as a service on the honeypot analysis host (local, never
  exposed to internet)
- Configure with local Ollama or cloud LLM endpoint via `.env`
- Run autonomous `program_triage` + `suspicious_behavior` workflows per sample
- Export chat transcript + conclusion cards as JSON/Markdown
- Embed AI triage summary in the Ghidra PDF report

### Supported Workflows Used
| Workflow | Output |
|----------|--------|
| `program_triage` | Binary purpose, family guess, risk level |
| `suspicious_behavior` | IOC-grounded behavior list |
| `attack_surface_triage` | Top-K dangerous functions, scored |
| `vulnerability_hypothesis` | CVE-style write-up for interesting payloads |

### Environment Variables
```dotenv
API_BASE=http://127.0.0.1:11434/v1   # Ollama local
API_KEY=not-used
MODEL_NAME=qwen3:8b
GHIDRA_API_BASE=http://127.0.0.1:9090
MAX_UPLOAD_BYTES=104857600
```

---

## Phase 3 — GhidrAssist Plugin ⬜ Planned

### Source
[symgraph/GhidrAssist](https://github.com/symgraph/GhidrAssist)

### What It Does
GhidrAssist is a Ghidra extension (Java plugin) providing:
- In-GUI LLM chat panel
- One-click function explanation
- Auto-renaming of functions and variables
- Protocol detection and YARA rule generation
- Right-click "Ask AI" on any code location

### Integration Plan
- Build the plugin from source using the provided `build.gradle`
- Install in the Ghidra container via extension ZIP
- Configure with same LLM endpoint as Rev·Deck
- Use for **interactive** (non-automated) analyst sessions
- Not part of the automated CI pipeline — analyst-facing only

### Build Steps
```bash
cd analysis/ghidra/ghidrassist
git clone https://github.com/symgraph/GhidrAssist
cd GhidrAssist
export GHIDRA_INSTALL_DIR=/opt/ghidra
gradle buildExtension
# Output: dist/ghidra_*_GhidrAssist.zip
```

---

## Phase 4 — Awesome-Ghidra Plugin Selection ⬜ Planned

### Source
[AllsafeCyberSecurity/awesome-ghidra](https://github.com/AllsafeCyberSecurity/awesome-ghidra)

### Selected Plugins for Automated Pipeline

| Plugin | Repo | Purpose | Integration Mode |
|--------|------|---------|------------------|
| `ghidra_scripts` (Allsafe) | [link](https://github.com/AllsafeCyberSecurity/ghidra_scripts) | Malware-specific scripts (MIPS, ARM, packing detection) | Headless script |
| `py-findcrypt-ghidra` | [link](https://github.com/AllsafeCyberSecurity/py-findcrypt-ghidra) | Detects crypto constants (AES, RC4, XOR keys) | Headless script |
| `ghidra_scripts` (0x6d696368) | [link](https://github.com/0x6d696368/ghidra_scripts) | RC4 decrypter, YARA search, stack string decoder | Headless script |
| `ghidra_scripts` (0xdea) | [link](https://github.com/0xdea/ghidra-scripts) | Vuln research: memcpy pattern, format string, ROP gadgets | Headless script |
| `CapaExplorer` | [link](https://github.com/reb311ion/CapaExplorer) | Import CAPA analysis results as Ghidra annotations | Post-process |
| `ghidra_bridge` | [link](https://github.com/justfoxing/ghidra_bridge) | Python 3 bridge — enables external orchestration scripts | Library |
| `GhidraAAS` (Cisco Talos) | [link](https://github.com/Cisco-Talos/Ghidraaas) | REST API wrapper for Ghidra (alternative to biniamfd image) | Service |
| `gotools` | [link](https://github.com/felberj/gotools) | Go binary support — honeypots see many Go-based botnets | Headless plugin |
| `VTgrepGHIDRA` | [link](https://github.com/Sentinel-One/VTgrepGHIDRA) | Search VirusTotal for similar code blocks from Ghidra | Interactive |

### Explicitly Excluded
- `Ghidra-evm` — no Ethereum payloads in honeypot context
- `JNI Helper` — no Android APK analysis currently
- `OOAnalyzer` — C++ OOP recovery, overkill for ELF botnet binaries
- `ret-sync` — debugger sync, interactive only, not automated

---

## Phase 5 — Report Generation ✅ Built (2026-08-01, #78)

Built as [`report/generate_report.py`](report/generate_report.py), reusing the
shape of [`sandbox/windows/orchestrate/generate_report.py`](../../sandbox/windows/orchestrate/generate_report.py)
(#56) rather than inventing a second reporting style: offline, one escaping
chokepoint (`esc()`), missing artifacts degrade to "not observed" instead of
raising. `worker/ghidra-worker.py`'s `generate_report()` wrapper calls it
(fail-soft, like `triage()`/`fuzzy_hash()`) as the last step of
`analyse_one()`, writing `{sha256}_ghidra_report.html` beside the result JSON
and recording its bare filename in the existing `report_pdf` field — the
dashboard's `attachGhidraDownload` already serves it correctly, since
`http.ServeContent` infers content-type from the filename extension rather
than the field name.

The original plan below described a single combined PDF pulling in VT,
JoeSandbox, and CAPA data. That data doesn't exist in this pipeline — there is
no Phase 0 VT/JoeSandbox stage and no CAPA integration (Phase 4 is still
planned) — so the report actually built is scoped to what
`worker/ghidra-worker.py` produces today:

```
{ghidra-results}/{sha256}_ghidra_report.html
  ├── Sample metadata (hash, exit status, timing, analyzer/schema versions,
  │     service_sha256 integrity check)
  ├── Functions (address, name, signature, size)
  ├── Strings
  ├── Imports (library!name)
  ├── Cryptographic constants (from scan_crypto())
  ├── Call graph (inlined SVG, if build_call_graph() produced one)
  ├── Structural info (lief: format, architecture, entry point, sections)
  ├── Fuzzy hashes (ssdeep/tlsh)
  └── AI triage (Rev·Deck / local-model output, if configured)
```

A PDF is optional, not the default: `generate_report.py --pdf` renders one via
WeasyPrint if it's installed, but the worker only ever produces the HTML file.
CAPA output and YARA rule suggestions are not sections here — CAPA integration
is still Phase 4 (`CapaExplorer`, unbuilt), and this pipeline does not generate
YARA rule suggestions at all.

---

## Dashboard/Worker Integration

Superseded by [#107](https://github.com/Xore/honeypot-stack/issues/107): this
section used to describe extending a `.github/workflows/analyze.yml` in a
different repo (`Xore/Honeypot`) to invoke `ghidra_analyze.py` against a REST
contract that issue #101 disproved against the real
`biniamfd/ghidra-headless-rest:1.2.1` image. That script and its bash sibling
`headless_analyze.sh` are deleted; there is no GitHub Actions integration.

The actual, deployed architecture is a host-based spool, not CI: the
dashboard (unprivileged, no credentials, no outbound calls) writes a
`.request` marker file into `GHIDRA_REQUEST_DIR`, and
[`worker/ghidra-worker.py`](worker/ghidra-worker.py) — running under the
`honeypot-ghidra-worker.path`/`.service` systemd units on the homeserver —
drains the spool and talks to the real Ghidra REST service. See
`DASHBOARD_INTEGRATION_PLAN.md` for the dashboard side and
`worker/ghidra-worker.py`'s module docstring for the verified REST contract.

---

## Tooling Summary

The ✅/⬜ column this table used to carry meant "which phase," not "is it
built," and it read as the latter. Phase is what it says now; nothing in this
table is deployed.

| Tool | Role | Mode | Phase |
|------|------|------|-------|
| `biniamfd/ghidra-headless-rest` | Ghidra REST backend | Automated (Docker) | 1 |
| `biniamf/ai-reverse-engineering` (Rev·Deck) | AI triage | Automated + Interactive | 2 |
| `symgraph/GhidrAssist` | In-GUI AI chat | Interactive only | 3 — [#78](https://github.com/Xore/honeypot-stack/issues/78) |
| `AllsafeCyberSecurity/ghidra_scripts` | Malware scripts | Headless | 4 — [#78](https://github.com/Xore/honeypot-stack/issues/78) |
| `py-findcrypt-ghidra` | Crypto detection | Headless | 4 — [#78](https://github.com/Xore/honeypot-stack/issues/78) |
| `0x6d696368/ghidra_scripts` | RC4/YARA/stack strings | Headless | 4 — [#78](https://github.com/Xore/honeypot-stack/issues/78) |
| `0xdea/ghidra-scripts` | Vuln research | Headless | 4 — [#78](https://github.com/Xore/honeypot-stack/issues/78) |
| `CapaExplorer` | CAPA import | Post-process | 4 — decide with [#85](https://github.com/Xore/honeypot-stack/issues/85) |
| `gotools` | Go binary support | Headless plugin | 4 — [#78](https://github.com/Xore/honeypot-stack/issues/78) |
| `VTgrepGHIDRA` | VT code search | Interactive | 4 — [#78](https://github.com/Xore/honeypot-stack/issues/78) |

`CapaExplorer` imports `capa` output into Ghidra, so it and #85's `capa`
decision are one decision. Deciding them apart produces either a plugin with no
tool behind it or a tool whose results never reach the analyst.

---

## Additional Static Analysis Tooling

> **`ssdeep`/`tlsh` and `lief` are built** (2026-08-01, [#138](https://github.com/Xore/honeypot-stack/issues/138)):
> a loopback-only sidecar, `analysis/ghidra/statictools/`, run alongside
> `ghidra`/`ollama` by `docker-compose.ghidra.yml`. The worker calls it after
> collection via `fuzzy_hash()`/`lief_parse()` and writes `fuzzy_hashes`/`lief`
> onto the result, fail-soft like `ai_triage`. `floss` is not — its risk
> profile (code emulation) needs its own sandboxing decision, tracked
> separately in #138.

Beyond Ghidra, nine tools were once listed as *considered* for the pipeline,
with no decision behind any of them. [#85](https://github.com/Xore/honeypot-stack/issues/85)
asked for a short list with reasons instead of a wish list; this is that
decision, made 2026-08-01. Each one added is third-party code that runs
against live malware on the analysis host and has to be pinned, updated and
trusted, so the burden of proof was on inclusion, not exclusion.

**Decided in:**

| Tool | Purpose | Why |
|------|---------|-----|
| `capa` | Behavior tagging (MITRE ATT&CK) | Strongest case: the tag vocabulary is what the LLM worker ([#66](https://github.com/Xore/honeypot-stack/issues/66)) and the dashboard already speak. Has a Ghidra integration path via `CapaExplorer`, so pin/scope this together with [#78](https://github.com/Xore/honeypot-stack/issues/78) phase 4 rather than separately. |
| `ssdeep` / `tlsh` | Fuzzy hashing for family clustering | Cheap, offline, never executes the sample. Gives family clustering exact SHA-256 dedup cannot — a real capability, not a duplicate of anything else in the pipeline. |
| `lief` | ELF/PE/Mach-O parsing | One library covers every format `pefile` would have been added for, so it replaces that entry rather than sitting beside it. |
| `floss` | Obfuscated string extraction | Genuinely useful on packed/obfuscated binaries, but it *emulates* code to unpack strings — a different risk class from the three above. Needs the sandbox boundary decided as part of integrating it, not a plain `pip install`. Replaces the `strings2` line below outright: `strings2` is the tool `floss` superseded, not a second option. |

**Decided out — each duplicates something already in the pipeline, not just something Ghidra could do:**

| Tool | Would have added | Why it's out |
|------|-------------------|---------------|
| `yara-python` | YARA rule matching | The stack already runs a dedicated, hardened YARA pipeline: `analysis/yara/` + `dashboard/yara.go` + the `hp-yara-scanner` service, vendored/pinned corpus ([#73](https://github.com/Xore/honeypot-stack/issues/73)/[#106](https://github.com/Xore/honeypot-stack/issues/106)), `network_mode: none`, `read_only: true`, rules baked in at build. Wrapping `yara-python` inside a Ghidra script would be a second, less-hardened YARA execution path with no scanning capability the existing one lacks. Not merely redundant with Ghidra — redundant with a more hardened system that already ships. |
| `pefile` | PE parsing | Fully subsumed by `lief` above; two PE parsers to pin and trust is worse than one. |
| `binwalk` | Firmware/packed binary unpacking | Ghidra's own loaders plus `lief` already cover the formats this pipeline is in scope for; no sample so far has needed firmware unpacking. |
| `radare2` | Cross-check disassembly, scripting | Duplicates the disassembler this whole pipeline is built on. A second disassembler to pin and trust, with no capability Ghidra lacks. |
| `exiftool` | File metadata extraction | Ghidra and `lief` already surface what matters for triage; standalone metadata extraction earns its keep on document-format malware, which is not this pipeline's samples today. |
| `strings2` | Advanced string extraction | Superseded by `floss` (see above); listing both was the original table conflating an old tool with the one that replaced it. |

Earlier revisions of this file ended with "See `analysis/ghidra/scripts/` for
implementations integrating these." There are none. That directory holds
`call_graph.py`, `export_functions.py`, `export_imports.py`,
`export_strings.py` and `yara_scan.py`, and nothing in it uses any tool
above. (`findcrypt.py` was deleted in
[#136](https://github.com/Xore/honeypot-stack/issues/136): it was superseded
by `scan_crypto()` in `worker/ghidra-worker.py`, whose comment records the
three bugs the old script had.)
