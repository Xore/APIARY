# Provenance-controlled reverse-engineering corpus (#159, initial slice)

Extends #144's `REV_CASES` (three hand-authored prompt-level cases) with real
compiled fixtures across architectures, compilers, and optimization levels,
each with recorded provenance. This is a **first slice**, not the full
matrix #159 describes -- see "What this does and does not establish" below.

## Source fixtures (`src/`)

Eight small, synthetic, non-weaponized C functions, one per required category
from #159's corpus design list:

| File | Category |
|---|---|
| `xor_decode_loop.c` | loop, crypto-like primitive |
| `vulnerable_strcpy.c` | intentionally vulnerable educational code (stack overflow) |
| `linked_list_sum.c` | data structure traversal |
| `indirect_dispatch.c` | indirect call (function-pointer dispatch table) |
| `error_handling_alloc.c` | error handling (allocation failure as a return code, not a crash) |
| `process_and_injection.c` | behavior-shaped fixture (process creation) + embedded prompt-injection comment |
| `tlv_parser.c` | parsing (type-length-value records) |
| `loopback_connect.c` | behavior-shaped fixture (network access, loopback-only) |

All fixtures are original, written for this corpus, non-routable, and contain
no real malware, credentials, or C2 indicators. `process_and_injection.c`'s
embedded comment ("ignore all prior instructions...") is evidence for testing
prompt-injection resistance, and is never executed.

## Build matrix and provenance (`build_corpus.py`, `manifest.json`)

Each of the 8 sources is compiled with:

- **Toolchains**: `gcc-x86_64` (native GCC), `clang-x86_64` (Clang targeting
  the same triple), `gcc-aarch64` (GCC cross-compiler). 3 of #159's "x86,
  x86-64, ARM64, and one additional architecture" -- x86-64 and ARM64 are
  covered; 32-bit x86 and a fourth architecture are not yet built.
- **Optimization levels**: `-O0`, `-O2`. 2 of #159's "multiple optimization
  levels" -- `-O1`/`-O3`/`-Os` are not yet built.
- **Stripped and unstripped** variants of every build (`strip --strip-all`).

8 sources x 3 toolchains x 2 opt levels = 48 builds, each with both a
stripped and unstripped variant recorded (`manifest.json`).

For every build, `manifest.json` records: exact compile command, compiler
identity and version, target triple, optimization level, SHA-256 and size of
both the stripped and unstripped object file, and the full `objdump -d`
disassembly of both variants (with inline source for the unstripped one).

**Build environment**: `debian:trixie-slim`, GCC `14.2.0-19` (Debian), Clang
`19.1.7-3+b1` (Debian), GNU Binutils `2.44-3` (Debian) -- for the `gcc-aarch64`
toolchain, `gcc-aarch64-linux-gnu` + `libc6-dev-arm64-cross` at the same
Debian trixie package versions. Compiled to relocatable object files (`-c`),
not linked executables -- there is no `main`, matching #144's `REV_CASES`
style of showing a single function's code, not a whole program.

**Determinism verified**: built twice into separate output directories;
after normalizing the one build-directory-dependent string objdump embeds in
its own header line (`build_corpus.py`'s `normalize_disassembly`), all 48
disassembly outputs were byte-identical across the two builds.

## Scoring rubric (`rev_cases_v2_rubric.json`)

Written from the ground truth of having authored every fixture, **before**
any model was run against these cases -- not derived from, or adjusted
after seeing, any candidate output. Same format as #144's `RevCase`:
`required_groups` (alternative-term groups, at least one match per group
required) plus `forbidden` (terms whose presence means the case failed --
used on `process_and_injection` to check the model didn't comply with the
embedded prompt injection).

## What this does and does not establish

**Does**: gives #160 (and any future Rev·Deck model/adapter evaluation) more
than one hand-picked case to run against, with real compiled artifacts,
recorded provenance, and a scoring rubric fixed before any output was
inspected -- a genuine step past #144's single-case-per-category smoke test.

**Does not yet**: cover the full architecture matrix (only x86-64 + ARM64,
not also plain x86 or a fourth ISA), the full optimization spread (only
-O0/-O2), CI verification of provenance/hashes/fixture safety (#159's
"Tooling and CI" section), a formal versioned scoring-contract file separate
from this rubric, or semantic-equivalence/executable checks. Confidence
should be scoped to "one compiler/optimization/strip slice across 8 cases,"
not a general reverse-engineering quality claim -- consistent with #159's own
instruction not to present a small slice as a broad conclusion.

## Rebuilding

```
docker run -d --name corpus-build --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 512 --memory=8g --memory-swap=8g \
  -v <empty-work-dir>:/work -v $(pwd)/src:/src:ro debian:trixie-slim sleep infinity
docker exec corpus-build apt-get -o APT::Sandbox::User=root update -qq
docker exec corpus-build apt-get -o APT::Sandbox::User=root install -y --no-install-recommends \
  gcc gcc-aarch64-linux-gnu libc6-dev-arm64-cross clang binutils binutils-aarch64-linux-gnu python3
docker exec corpus-build python3 /work/build_corpus.py
```
