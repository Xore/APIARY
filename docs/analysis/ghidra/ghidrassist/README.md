# GhidrAssist Plugin

Source: [symgraph/GhidrAssist](https://github.com/symgraph/GhidrAssist)

GhidrAssist is a Ghidra extension providing an in-GUI LLM chat panel,
auto-renaming, protocol detection, and YARA rule generation.

> ⚠️ **Interactive only** — GhidrAssist is for analyst-facing use in the
> Ghidra GUI. It is NOT part of the automated CI pipeline. Your local Ghidra
> GUI is very likely a different install (and a different, probably newer,
> Ghidra version) than the pinned `biniamfd/ghidra-headless-rest:1.2.1`
> (Ghidra 11.3.2) this repo's own automated pipeline runs — see "Ghidra
> version compatibility" below for why that specifically matters here.

## Install — build from source (recommended)

Follow-up to [#192](https://github.com/Xore/APIARY/issues/192):
that issue's own release-zip-plus-strip fix works, but treats a symptom.
The leaked directories (`ghidrassist_chat_artifacts/`, `lucene/`,
`.claude/settings.local.json` — real data from the maintainer's own
machine, confirmed via the GitHub API against the tracked source tree) were
never in `symgraph/GhidrAssist`'s tracked source in the first place — they
are release-packaging pollution. Building from a pinned source commit
sidesteps the leak entirely, rather than every future install needing to
remember to strip three specific paths out of someone else's release
artifact by hand, and means installing what's actually in version control
rather than whatever local state was sitting in the maintainer's working
directory when they ran the release script.

**Verified**, not just documented: built `2.2.0`
(`c436fcb55d2b43f4341c7aa76c90d9be8c147da1`) from a fresh clone against a
real Ghidra 12.1 install (`gradle buildExtension`, Gradle 8.10 — Ghidra
11.3.2's own `application.properties` declares `application.gradle.min=8.5`).
The resulting `ghidra_12.1_PUBLIC_20260801_GhidrAssist.zip` (92 files, 40MB)
was inspected file-by-file: no `ghidrassist_chat_artifacts/`, `lucene/`
(the search-index *data* directory — `GhidrAssist/lib/lucene-*.jar`, the
actual *library* dependency, is expected and present), or `.claude/`
anywhere in it. `extension.properties` correctly declares `version=12.1`,
and the compiled `GhidrAssist.jar` contains `ghidrassist/GhidrAssistPlugin.class`,
the real plugin entry point.

```bash
git clone https://github.com/symgraph/GhidrAssist.git
cd GhidrAssist
git checkout c436fcb55d2b43f4341c7aa76c90d9be8c147da1   # tag 2.2.0

# Gradle >= 8.5 (see <your Ghidra install>/Ghidra/application.properties'
# application.gradle.min if unsure which version to use):
#   https://gradle.org/releases/

GHIDRA_INSTALL_DIR=/path/to/your/ghidra_<version>_PUBLIC gradle buildExtension
# -> dist/ghidra_<version>_PUBLIC_<date>_GhidrAssist.zip
```

```
# Ghidra → File → Install Extensions → select the built zip
```

### Ghidra version compatibility — a real constraint, not just a build option

`gradle buildExtension` must be pointed at **the same Ghidra install you'll
run the extension in** — Ghidra extensions are compiled against that
install's own API and are not portable across major versions. This isn't
hypothetical for this specific commit: building `2.2.0` against Ghidra
**11.3.2** (this repo's own pinned `biniamfd/ghidra-headless-rest` version)
**fails outright** —

```
error: cannot find symbol
import ghidra.program.model.listing.CommentType;
```

`CommentType` (an enum replacing older `int` comment-type constants) does
not exist in Ghidra 11.3.2's API at all. Confirmed independently by
`symgraph/GhidrAssist`'s own `2.2.0` release, which only ships prebuilt
zips for Ghidra `12.0` and `12.1` — no `11.3.2` asset exists, prebuilt or
buildable, for this GhidrAssist version. Building against Ghidra **12.1**
instead (verification above) succeeds cleanly.

This does not block real-world use: GhidrAssist runs in *your own local
Ghidra GUI*, not in the headless-rest container the automated pipeline
uses, and an analyst's own desktop Ghidra install is very likely 12.x
already. It does mean: point `GHIDRA_INSTALL_DIR` at your actual local
Ghidra, not at this repo's pinned analysis-host version, and don't expect
this exact commit to build against anything older than 12.0.

## Install — pinned release zip (alternative, faster, needs the strip step)

Still viable if a local `gradle` build isn't worth setting up — same pinned
version, same [#192](https://github.com/Xore/APIARY/issues/192)
digest-checking convention, but needs the leaked-path strip step below
every time, and only exists for whichever Ghidra versions upstream chose
to publish a prebuilt asset for (`12.0`/`12.1` for `2.2.0`, checked above).

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
> [#192](https://github.com/Xore/APIARY/issues/192) for tracking.
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
