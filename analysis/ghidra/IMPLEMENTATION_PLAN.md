# Ghidra Payload Analysis — Implementation Plan

> **Status**: Planned / In Progress  
> **Last updated**: 2026-07-26  
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
        │   ├── export_imports.py
        │   ├── findcrypt.py         ← crypto constant detection
        │   ├── yara_scan.py         ← run YARA rules inside Ghidra
        │   └── call_graph.py
        ├── revdeck/                 ← biniamf/ai-reverse-engineering integration
        │   ├── docker-compose.revdeck.yml
        │   └── README.md
        ├── ghidrassist/             ← symgraph/GhidrAssist plugin config
        │   └── README.md
        └── report/
            ├── generate_report.py   ← combines all analysis → PDF
            └── templates/
                └── ghidra_report.html
```

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
| Endpoint | Purpose |
|----------|---------|
| `POST /analyze` | Submit binary for headless analysis |
| `GET /functions` | List all functions |
| `GET /decompile/{addr}` | Decompile a function |
| `GET /strings` | All strings |
| `GET /imports` | Dynamic imports |
| `GET /export/ghidra-zip` | Download full Ghidra project archive |

### Trigger
GitHub Actions in `Xore/Honeypot` already triggers on sample push.
The existing `analyze.yml` will be extended with a `ghidra` job that runs after
VirusTotal/JoeSandbox jobs complete.

---

## Phase 2 — AI-Assisted Analysis via Rev·Deck ✅ Ready to implement

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

## GitHub Actions Integration

Extend `.github/workflows/analyze.yml` in `Xore/Honeypot` with:

```yaml
ghidra:
  name: Ghidra Headless Analysis
  runs-on: ubuntu-latest
  needs: [analyze]   # run after VT/Joe
  services:
    ghidra:
      image: biniamfd/ghidra-headless-rest:latest
      ports:
        - 9090:9090
  steps:
    - uses: actions/checkout@v4
    - name: Run Ghidra analysis
      run: python3 .github/scripts/ghidra_analyze.py --file-list /tmp/changed_files.txt
```

---

## Tooling Summary

| Tool | Role | Mode | Status |
|------|------|------|--------|
| `biniamfd/ghidra-headless-rest` | Ghidra REST backend | Automated (Docker) | ✅ Phase 1 |
| `biniamf/ai-reverse-engineering` (Rev·Deck) | AI triage | Automated + Interactive | ✅ Phase 2 |
| `symgraph/GhidrAssist` | In-GUI AI chat | Interactive only | ⬜ Phase 3 |
| `AllsafeCyberSecurity/ghidra_scripts` | Malware scripts | Headless | ⬜ Phase 4 |
| `py-findcrypt-ghidra` | Crypto detection | Headless | ⬜ Phase 4 |
| `0x6d696368/ghidra_scripts` | RC4/YARA/stack strings | Headless | ⬜ Phase 4 |
| `0xdea/ghidra-scripts` | Vuln research | Headless | ⬜ Phase 4 |
| `CapaExplorer` | CAPA import | Post-process | ⬜ Phase 4 |
| `gotools` | Go binary support | Headless plugin | ⬜ Phase 4 |
| `VTgrepGHIDRA` | VT code search | Interactive | ⬜ Phase 4 |

---

## Additional Static Analysis Tooling

Beyond Ghidra, the following tools are planned for the pipeline:

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

See `analysis/ghidra/scripts/` for implementations integrating these.
