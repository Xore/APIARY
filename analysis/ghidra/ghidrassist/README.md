# GhidrAssist Plugin

Source: [symgraph/GhidrAssist](https://github.com/symgraph/GhidrAssist)

GhidrAssist is a Ghidra extension providing an in-GUI LLM chat panel,
auto-renaming, protocol detection, and YARA rule generation.

> ⚠️ **Interactive only** — GhidrAssist is for analyst-facing use in the
> Ghidra GUI. It is NOT part of the automated CI pipeline.

## Install

Use a pinned, checksummed [release](https://github.com/symgraph/GhidrAssist/releases)
build rather than cloning source and running `gradle buildExtension` — the
release assets are pre-built per Ghidra version (`ghidra_<version>_PUBLIC_<date>_GhidrAssist.zip`)
and match this repo's convention of pinning third-party artifacts by digest
(see the `@sha256:` pins on `ghidra`/`ollama` in `docker-compose.ghidra.yml`).
Pick the asset matching your local Ghidra's major.minor version.

```bash
cd analysis/ghidra/ghidrassist

# Adjust to the release and asset matching your installed Ghidra version.
GHIDRASSIST_VERSION=2.2.0
GHIDRASSIST_ZIP=ghidra_12.1_PUBLIC_20260530_GhidrAssist.zip
GHIDRASSIST_SHA256=02f888911730e4e07f55bac9475e8627b217f354e082b80a7d433b230797c547

curl -fsSL -o "$GHIDRASSIST_ZIP" \
    "https://github.com/symgraph/GhidrAssist/releases/download/${GHIDRASSIST_VERSION}/${GHIDRASSIST_ZIP}"
echo "${GHIDRASSIST_SHA256}  ${GHIDRASSIST_ZIP}" | sha256sum -c -
```

> ⚠️ **Strip leaked upstream dev artifacts before installing.** The 2.0.0,
> 2.1.0 and 2.2.0 release zips (the only ones checked) bundle the
> maintainer's own runtime state — real chat-session transcripts under
> `GhidrAssist/ghidrassist_chat_artifacts/`, a stale Lucene search index
> under `GhidrAssist/lucene/`, and `GhidrAssist/.claude/settings.local.json`,
> which leaks their local home directory path. None of these three paths are
> in the tracked source tree (`.gitignore`'d, or just never committed), so
> this is release-packaging leakage, not intentional content — but it's real
> data from another user's machine, not fixtures. See
> [#192](https://github.com/Xore/honeypot-stack/issues/192) for tracking.
> Strip it before installing:
>
> ```bash
> mkdir -p extracted && unzip -q "$GHIDRASSIST_ZIP" -d extracted
> rm -rf extracted/GhidrAssist/ghidrassist_chat_artifacts \
>        extracted/GhidrAssist/lucene \
>        extracted/GhidrAssist/.claude
> (cd extracted && zip -qr "../${GHIDRASSIST_ZIP%.zip}_clean.zip" GhidrAssist)
> ```

```
# Ghidra → File → Install Extensions → select the _clean.zip
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
