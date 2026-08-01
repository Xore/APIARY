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

- **Toolchains**: `gcc` and `clang` across five architectures --
  `x86_64`, `aarch64`, `i686` (32-bit x86), `mipsel`, and `armhf`. All 4 of
  #159's "x86, x86-64, ARM64, and one additional architecture" are now
  covered. `mipsel` and `armhf` were both built, one architecture beyond
  what #159 literally asks for: `mipsel` is the historically dominant
  architecture for router/IoT botnet malware (the Mirai family and its many
  derivatives overwhelmingly target MIPS home routers, matching this
  honeypot's own captured-sample profile) and `armhf` covers the broader
  modern embedded/IoT surface (IP cameras, newer routers, general Cortex-A
  devices) -- #195 names both as gaps in capa's own architecture coverage,
  not just one, so both were built rather than picking.
- **Optimization levels**: `-O0`, `-O2`. Still 2 of #159's "multiple
  optimization levels" -- `-O1`/`-O3`/`-Os` are not yet built.
- **Stripped and unstripped** variants of every build (`strip --strip-all`,
  using the architecture-specific `strip`/`objdump` for every non-native
  target -- the host's native tools silently misread a foreign-architecture
  object's own instruction set rather than erroring, so this matters for
  correctness, not just cleanliness).
- **Train/validation/test split**, recorded per case in `CASE_SPLITS` and
  carried onto every build variant of that case (`"split"` field). All 8
  cases are currently `"test"`: every one has already been used as scored
  evaluation data (#160's REx86 comparison), never shown to a model as a
  training example, so tagging any of them `"train"` now would be
  retroactively wrong. Splitting a single case's own toolchain/opt-level
  variants across train and test was deliberately avoided -- that would let
  a model see the same underlying case in both and leak exactly the
  case-level knowledge the split exists to prevent.

8 sources x 10 toolchains x 2 opt levels = 160 builds, each with both a
stripped and unstripped variant recorded (`manifest.json`). The original 48
`gcc-x86_64`/`clang-x86_64`/`gcc-aarch64` builds are unchanged (identical
SHA-256s) from before this expansion -- #160's already-published evaluation
results, which ran against the `gcc-x86_64 -O0` slice, are unaffected.

For every build, `manifest.json` records: exact compile command, compiler
identity and version, target triple, optimization level, train/validation/
test split, SHA-256 and size of both the stripped and unstripped object
file, and the full `objdump -d` disassembly of both variants (with inline
source for the unstripped one).

**Build environment**: `debian:trixie-slim`, GCC `14.2.0` (Debian), Clang
`19.1.7-3+b1` (Debian), GNU Binutils `2.44` (Debian). Cross-compilation
packages: `gcc-aarch64-linux-gnu`, `gcc-multilib-i686-linux-gnu`,
`gcc-mipsel-linux-gnu`, `gcc-arm-linux-gnueabihf`, and their matching
`libc6-dev-*-cross`/binutils packages, all at the same Debian trixie
versions. `clang` cross-compiles to every non-native target via its own
`--target=` flag, reusing whichever gcc-cross package's libc headers and
binutils are already installed -- no separate Clang cross-toolchain package
needed. Compiled to relocatable object files (`-c`), not linked executables
-- there is no `main`, matching #144's `REV_CASES` style of showing a single
function's code, not a whole program.

**Determinism verified**: built twice into separate output directories;
after normalizing the one build-directory-dependent string objdump embeds in
its own header line (`build_corpus.py`'s `normalize_disassembly`), all 160
disassembly outputs (the original 48 plus the 112 this expansion added) were
byte-identical across the two builds.

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

**Does not yet**: cover the full optimization spread (only -O0/-O2, not
-O1/-O3/-Os), CI verification of provenance/hashes/fixture safety (#159's
"Tooling and CI" section), a formal versioned scoring-contract file separate
from this rubric, or semantic-equivalence/executable checks. The case/category
breadth is still #144's original 8 (now built across 5 architectures and 2
compilers instead of 3 toolchains, not expanded with new source fixtures) --
narrower than the full "loops, data structures, parsing, crypto-like
primitives, indirect calls, error handling... benign, vulnerable,
behavior-shaped" breadth #159 asks for in the abstract. Confidence should be
scoped to "8 cases across 5 architectures, 2 compilers, 2 optimization
levels, stripped and unstripped," not a general reverse-engineering quality
claim -- consistent with #159's own instruction not to present a small slice
as a broad conclusion.

## Rebuilding

```
docker run -d --name corpus-build --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 512 --memory=8g --memory-swap=8g \
  -v <empty-work-dir>:/work -v $(pwd)/src:/src:ro debian:trixie-slim sleep infinity
# --cap-drop ALL takes CAP_SETUID/CAP_SETGID too, which apt's own internal
# privilege-drop sandbox (root -> _apt for fetches) needs -- the container
# is already the security boundary, so disable apt's redundant one instead
# of adding capabilities back.
docker exec -u root corpus-build apt-get -o APT::Sandbox::User=root update -qq
docker exec -u root corpus-build apt-get -o APT::Sandbox::User=root install -y --no-install-recommends \
  gcc clang binutils python3 \
  gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
  gcc-multilib-i686-linux-gnu \
  gcc-mipsel-linux-gnu \
  gcc-arm-linux-gnueabihf
docker exec corpus-build python3 /work/build_corpus.py
```
