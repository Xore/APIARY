# GhidrAssist Plugin

Source: [symgraph/GhidrAssist](https://github.com/symgraph/GhidrAssist)

GhidrAssist is a Ghidra extension providing an in-GUI LLM chat panel,
auto-renaming, protocol detection, and YARA rule generation.

> ⚠️ **Interactive only** — GhidrAssist is for analyst-facing use in the
> Ghidra GUI. It is NOT part of the automated CI pipeline.

## Build & Install

```bash
# 1. Clone the plugin
git clone https://github.com/symgraph/GhidrAssist \
    analysis/ghidra/ghidrassist/GhidrAssist

# 2. Build
cd analysis/ghidra/ghidrassist/GhidrAssist
export GHIDRA_INSTALL_DIR=/opt/ghidra   # adjust to your Ghidra install path
gradle buildExtension

# 3. Install ZIP in Ghidra
# Ghidra → File → Install Extensions → select dist/ghidra_*_GhidrAssist.zip
```

## Features Used

| Feature | Usefulness for Honeypot Analysis |
|---------|----------------------------------|
| In-GUI chat panel | Ask questions about any function/string without leaving Ghidra |
| Auto-rename functions | Rename FUN_00401234 → `mirai_syn_flood` automatically |
| Auto-rename variables | Readable decompiled C output |
| Protocol detection | Identify C2 communication protocols |
| YARA rule generation | One-click YARA rule from selected code block |
| Right-click "Ask AI" | Instant explanation of any instruction or code block |

## Configuration

After installation, configure the LLM in Ghidra:
`Edit → Tool Options → GhidrAssist`

Use the same endpoint as Rev·Deck:
```
LLM Provider: OpenAI Compatible
Base URL: http://127.0.0.1:11434/v1   (Ollama) or OpenRouter
Model: qwen3:8b
API Key: not-used
```
