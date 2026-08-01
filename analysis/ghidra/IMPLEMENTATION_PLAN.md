# Ghidra Payload Analysis — Implementation Plan

> **Status**: Design document. Phases 3–5 are unbuilt, and phases 1–2 are
> partly built — `ghidra_analyze.py` and five of the six `scripts/` exporters
> exist; the import exporter, the Rev·Deck compose file and the whole `report/`
> tree do not.  
> **Tracked in**: [#78](https://github.com/Xore/honeypot-stack/issues/78)
> (phases 3–5), [#76](https://github.com/Xore/honeypot-stack/issues/76)
> (dashboard spool and entry points),
> [#85](https://github.com/Xore/honeypot-stack/issues/85) (non-Ghidra static
> tooling)  
> **Last updated**: 2026-07-31  
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
        ├── docker-compose.ghidra.yml
        ├── headless_analyze.sh      ← wrapper: runs Ghidra headless on a sample
        ├── scripts/                 ← Ghidra Python scripts (Jython / Pyhidra)
        │   ├── export_functions.py
        │   ├── export_strings.py
        │   ├── export_imports.py    ← MISSING
        │   ├── findcrypt.py         ← crypto constant detection
        │   ├── yara_scan.py         ← run YARA rules inside Ghidra
        │   └── call_graph.py
        ├── revdeck/                 ← biniamf/ai-reverse-engineering integration
        │   ├── docker-compose.revdeck.yml   ← MISSING
        │   └── README.md
        ├── ghidrassist/             ← symgraph/GhidrAssist plugin config
        │   └── README.md
        └── report/                  ← MISSING, entire directory (#78 phase 5)
            ├── generate_report.py   ← combines all analysis → PDF
            └── templates/
                └── ghidra_report.html
```

This is the *target* layout. Three entries marked MISSING do not exist:
`scripts/export_imports.py`, `revdeck/docker-compose.revdeck.yml`, and the
whole `report/` tree. The import table is listed as a Phase 1 export, so its
absence means Phase 1 is not actually complete.

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

## Phase 5 — Report Generation ⬜ Planned

Combine all analysis artifacts into a single PDF per sample:

```
reports/ghidra/{sha256}_ghidra.pdf
  ├── File metadata (hash, type, size, magic)
  ├── VT detection summary (from Phase 0 pipeline)
  ├── JoeSandbox score (from Phase 0 pipeline)
  ├── Ghidra: function list + suspicious function pseudocode
  ├── Ghidra: string table + interesting strings highlighted
  ├── Ghidra: import table
  ├── Ghidra: crypto constants (FindCrypt)
  ├── Ghidra: call graph (rendered as SVG/PNG)
  ├── CAPA results (behavior tags)
  ├── AI triage summary (Rev·Deck output)
  └── YARA rule suggestions
```

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

Beyond Ghidra, these tools have been *considered* for the pipeline. None is
integrated, and the useful next step is to cut the list rather than build all
nine — see [#85](https://github.com/Xore/honeypot-stack/issues/85), which
argues for `capa`, `ssdeep`/`tlsh` and `lief`, treats `floss` as a separate
risk class because it emulates code, and puts the burden of proof on the rest.

| Tool | Purpose | Install |
|------|---------|----------|
| `capa` | Behavior tagging (MITRE ATT&CK) | `pip install flare-capa` |
| `binwalk` | Firmware/packed binary unpacking | `apt install binwalk` |
| `strings2` / `floss` | Advanced string extraction (obfuscated) | `pip install flare-floss` |
| `radare2` | Cross-check disassembly, scripting | `apt install radare2` |
| `exiftool` | File metadata extraction | `apt install exiftool` |
| `ssdeep` / `tlsh` | Fuzzy hashing for family clustering | `pip install ssdeep tlsh-python` |
| `pefile` | PE parsing (for Windows samples) | `pip install pefile` |
| `lief` | ELF/PE/Mach-O parsing | `pip install lief` |
| `yara-python` | YARA rule matching | `pip install yara-python` |

Earlier revisions of this file ended with "See `analysis/ghidra/scripts/` for
implementations integrating these." There are none. That directory holds
`call_graph.py`, `export_functions.py`, `export_strings.py`, `findcrypt.py` and
`yara_scan.py`, and nothing in it uses any tool above.
