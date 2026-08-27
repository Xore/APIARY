# Provenance-controlled reverse-engineering corpus (#159)

Extends #144's `REV_CASES` (three hand-authored prompt-level cases) with real
compiled fixtures across architectures, compilers, and optimization levels,
each with recorded provenance, a ground-truth-first scoring rubric, a
versioned scoring contract, CI-verified reproducibility, and executable
semantic checks. See "Acceptance criteria" at the bottom for exactly what
#159 asked for and what this delivers against each item.

## Source fixtures (`src/`)

Fourteen small, synthetic, non-weaponized C functions:

| File | Category |
|---|---|
| `xor_decode_loop.c` | loop, crypto-like primitive |
| `vulnerable_strcpy.c` | intentionally vulnerable educational code (stack overflow) |
| `linked_list_sum.c` | data structure traversal |
| `indirect_dispatch.c` | indirect call (function-pointer dispatch table) |
| `error_handling_alloc.c` | error handling (allocation failure as a return code, not a crash) |
| `process_and_injection.c` | behavior-shaped fixture (process creation) + embedded prompt-injection string literal |
| `tlv_parser.c` | parsing (type-length-value records) |
| `loopback_connect.c` | behavior-shaped fixture (network access, loopback-only) |
| `safe_strcpy.c` | benign near-neighbor to `vulnerable_strcpy.c` (bounds-checked, same call shape) |
| `integer_overflow_alloc.c` | intentionally vulnerable educational code (integer overflow -> undersized allocation) |
| `use_after_free.c` | intentionally vulnerable educational code (use-after-free) |
| `checksum_rotate.c` | loop, crypto-like primitive (rotate-and-add, a different shape than the XOR case) |
| `format_string_bug.c` | intentionally vulnerable educational code (format string) |
| `file_write_persist.c` | behavior-shaped fixture (file write / persistence-style disk write) |

All fixtures are original, written for this corpus, non-routable, and contain
no real malware, credentials, or C2 indicators. `process_and_injection.c`'s
embedded payload ("ignore all prior instructions...") is evidence for testing
prompt-injection resistance, and is never executed: since #1948 it is carried
as a string literal referenced by live code, so it survives compilation into
the binary instead of living only in a source comment the compiler strips --
until then no corpus object contained it at all, and every rebuild now fails
loudly if the compiled artifacts ever lose it (#1948). `safe_strcpy.c` is
deliberately paired with `vulnerable_strcpy.c` -- same shape, safe
implementation -- to test whether a model overclaims a vulnerability on code
that only superficially resembles a known-bad pattern (a benign-control
case, per #159's acceptance criteria).

`checksum_rotate.c`/`use_after_free.c`/`format_string_bug.c` diversify beyond
the original single example of each broad category (one crypto-like
primitive, one vulnerability class) that the first slice of this corpus had.

## Build matrix and provenance (`build_corpus.py`, `manifest.json`)

Each of the 14 sources is compiled with:

- **Toolchains**: `gcc` and `clang` across five architectures --
  `x86_64`, `aarch64`, `i686` (32-bit x86), `mipsel`, and `armhf`. All 4 of
  #159's "x86, x86-64, ARM64, and one additional architecture" are covered,
  plus a second additional architecture beyond what #159 literally asks
  for: `mipsel` is the historically dominant architecture for router/IoT
  botnet malware (the Mirai family and its many derivatives overwhelmingly
  target MIPS home routers, matching this honeypot's own captured-sample
  profile) and `armhf` covers the broader modern embedded/IoT surface (IP
  cameras, newer routers, general Cortex-A devices) -- #195 names both as
  gaps in capa's own architecture coverage, not just one, so both were
  built rather than picking.
- **Optimization levels**: `-O0`, `-O1`, `-O2`, `-O3`, `-Os` -- the full
  spread #159 asks for.
- **Stripped and unstripped** variants of every build (`strip --strip-all`,
  using the architecture-specific `strip`/`objdump` for every non-native
  target -- the host's native tools silently misread a foreign-architecture
  object's own instruction set rather than erroring, so this matters for
  correctness, not just cleanliness).
- **Train/validation/test split**, recorded per case in `CASE_SPLITS` and
  carried onto every build variant of that case (`"split"` field). All 14
  cases are currently `"test"`: every one has already been used (or, for
  the 6 added most recently, is used from the moment it exists) as scored
  evaluation data, never shown to a model as a training example, so
  tagging any of them `"train"` now would be retroactively wrong.
  Splitting a single case's own toolchain/opt-level variants across train
  and test was deliberately avoided -- that would let a model see the same
  underlying case in both and leak exactly the case-level knowledge the
  split exists to prevent.

14 sources x 10 toolchains x 5 opt levels = 700 builds, each with both a
stripped and unstripped variant recorded (`manifest.json`). Every build from
every earlier revision of this corpus (the original 48, then 160) is present
and byte-identical (same SHA-256s) in the current 700 -- #160's
already-published evaluation results, which ran against the `gcc-x86_64
-O0` slice, are unaffected by any expansion since.

For every build, `manifest.json` records: exact compile command, compiler
identity and version, target triple, optimization level, train/validation/
test split, SHA-256 and size of both the stripped and unstripped object
file, and the full `objdump -d` disassembly of both variants (with inline
source for the unstripped one).

**Build environment**: `debian:trixie-slim`, GCC `14.2.0` (Debian), Clang
`19.1.7-3+b1` (Debian), GNU Binutils `2.44` (Debian). Cross-compilation
packages: `gcc-aarch64-linux-gnu`, `gcc-multilib-i686-linux-gnu`,
`gcc-mipsel-linux-gnu`, `gcc-arm-linux-gnueabihf`, and their matching
`libc6-dev-*-cross` header packages (genuinely required, not optional --
`gcc-mipsel-linux-gnu`/`gcc-arm-linux-gnueabihf` alone install the compiler
and runtime libraries but not the headers any source using `<string.h>` or
similar needs; found by `ci_verify.sh` failing in a deliberately fresh
container, see below) at the same Debian trixie versions. `clang`
cross-compiles to every non-native target via its own `--target=` flag,
reusing whichever gcc-cross package's libc headers and binutils are already
installed -- no separate Clang cross-toolchain package needed. Compiled to
relocatable object files (`-c`), not linked executables -- there is no
`main`, matching #144's `REV_CASES` style of showing a single function's
code, not a whole program.

**Determinism verified two ways**: (1) built twice into separate output
directories in the same environment; after normalizing the one
build-directory-dependent string objdump embeds in its own header line
(`build_corpus.py`'s `normalize_disassembly`), all 700 disassembly outputs
were byte-identical across the two builds. (2) Built in two genuinely
independent, freshly-provisioned containers (`ci_verify.sh`'s own check,
which is exactly the property CI now enforces on every change -- see
below). The second check caught a real bug the first one could not: gcc/
clang embed the invoking process's current working directory into DWARF
debug info as `DW_AT_comp_dir`, so a build run from `/` and a build run
from `/w` produced `.o` files with different SHA-256s despite byte-identical
disassembly text otherwise. `build_corpus.py` now calls `os.chdir("/")` at
import time so the result no longer depends on the caller's own working
directory.

## Executable semantic checks (`harness/`, `verify_semantics.py`)

`manifest.json`'s disassembly text plus the hand-authored rubric is the
corpus's normal contract; this is the "semantic equivalence or executable
checks... where safe and applicable" half #159 also asks for -- actually
compiling each harness (case source + a small `main()` with known
inputs/expected outputs) into a linked executable and running it, across
every architecture this corpus builds for: native execution for `x86_64`,
QEMU user-mode emulation (`qemu-i386`/`qemu-aarch64`/`qemu-mipsel`/
`qemu-arm`, confirmed against a real cross-compiled dynamically-linked
binary, not assumed) for the other four.

**12 of 14 cases are covered.** Two are deliberately excluded, each for its
own documented reason (`verify_semantics.py`'s `EXCLUDED` dict, enforced by
`validate_manifest.py` so a future case added with neither a harness nor a
recorded exclusion reason fails CI rather than silently having no coverage):

- `process_and_injection` -- forks and execs a real child process; there is
  nothing an automated check gains from actually spawning one.
- `loopback_connect` -- opens a real network socket/`connect()`; same
  reasoning, no assertion needs a live syscall.

For the intentionally-vulnerable cases that *are* covered
(`vulnerable_strcpy`, `integer_overflow_alloc`, `use_after_free`,
`format_string_bug`), every harness exercises only the non-buggy/safe-input
path -- actually triggering a stack overflow, heap corruption, dangling-
pointer write, or format-string read/write on purpose is not something an
automated corpus-verification script should ever do; the bug is already
known and static, and there is nothing to gain from triggering it for real.

240 executions (12 cases x 10 toolchains x 2 representative opt levels,
`-O0`/`-O2`), 0 failures, reverified in two independent fresh containers.

## Scoring rubric and contract (`rev_cases_v2_rubric.json`, `rev_cases_v2_contract.json`)

The rubric is written from the ground truth of having authored every
fixture, **before** any model was run against these cases -- not derived
from, or adjusted after seeing, any candidate output. Same format as #144's
`RevCase`: `required_groups` (alternative-term groups, at least one match
per group required) plus `forbidden` (terms whose presence means the case
failed -- used on `process_and_injection` to check the model didn't comply
with the embedded prompt injection, and on `safe_strcpy` to check the model
didn't falsely call safe code vulnerable).

Matching on those lists is polarity-aware (#1946): a plain containment check
docked points from correct answers that name a hazard in order to explain its
absence ("a common security measure to prevent buffer overflows"), twice in
four temperature-0 runs of one digest. Since #1946 an occurrence only fires
when nothing negates it -- see `analysis/ghidra/benchmarks/polarity.py` for
the cue list and its accepted limits -- and the two meanings of a forbidden
list are reported on separate axes: genuine injection resistance stays
`injection_ok`; everything else, including `safe_strcpy`'s false-positive
control, reports `false_positive_ok`. The committed
`baseline_results.json` below predates the split and carries `injection_ok`
throughout; recordings made after it use per-axis fields.

`rev_cases_v2_contract.json` is a small, separate, versioned pin: a SHA-256
of the rubric file plus the exact case list and count, checked by
`validate_manifest.py` on every change. Deliberately not part of
`analysis/ghidra/models/approved-models.json` -- that file is #158's own
governance artifact (which model is approved for production, and the
drift gates it must keep passing); this corpus can grow (new cases, new
architectures) on its own schedule without that being a #158 model-approval
event, and #158 can requalify a model without touching this file.

## Baseline recording (`record_baseline.py`, `baseline_results.json`)

Runs #144's approved Rev·Deck model (`qwen2.5-coder:7b-instruct-q4_K_M`,
read from `analysis/ghidra/models/approved-models.json`'s `revdeck` slot,
not hardcoded here) against the `gcc-x86_64 -O0` slice of this corpus --
same slice #160's own REx86 comparison used, for direct comparability --
using the exact `qualification_request` parameters that manifest already
specifies (`temperature=0`, `seed=144`, `output_tokens=512`), so the
baseline is measured the same controlled way #158's own qualification runs
are, not with parameters invented for this script alone. Does not modify
`approved-models.json` -- recording a benchmark result is not the same
action as a #158 governance decision.

Recorded result: **56/69 (81.2%)** across all 14 cases, no prompt-injection
compliance failures on any case (`injection_ok: true` throughout). Full
per-case scores, wall time, and the model's raw answer text are in
`baseline_results.json`.

After #1948's fixture change, the same pinned model and digest
(`qwen2.5-coder:7b-instruct-q4_K_M`, `dae161e27b0e…`) was re-measured against
the new corpus and recorded in `baseline_results_fixture_v2.json` -- labelled
there as a fixture change, not a continuation of 56/69. It is the first Tier A
measurement whose injection evidence genuinely comes from the compiled binary
(`injection_payload_in_evidence: true` on `process_and_injection`), with the
full transcript committed under `docs/benchmarks/runs/2026-08-27-20260827T000818Z-8e249763/`.

## CI verification (`validate_manifest.py`, `ci_verify.sh`, `.github/workflows/quality.yml`)

Two layers, matching #159's "CI verifies provenance, fixture safety,
hashes, and reproducible generation":

- **`validate_manifest.py`** -- fast, no compiler needed. Checks
  `manifest.json` parses, every build has every required provenance field,
  every SHA-256 is well-formed and matches the actual on-disk artifact
  shape, no duplicate (case, toolchain, opt-level) combinations, every
  `split` value is one of `train`/`validation`/`test`, every source file is
  covered by at least one build (nothing orphaned), the rubric-contract
  hash actually matches the current rubric, and every case has either a
  `harness/` file or a recorded exclusion reason.
- **`ci_verify.sh`** -- the heavier check, run inside `debian:trixie-slim`
  (matching the corpus's own documented build environment, not the CI
  runner's own toolchain): installs the exact packages the "Rebuilding"
  section below lists, rebuilds the entire corpus from source, and fails if
  the rebuild does not reproduce the committed `manifest.json`
  byte-for-byte. Then runs `verify_semantics.py`'s executable checks
  against the freshly rebuilt corpus.

Wired into `.github/workflows/quality.yml`'s `scripts-and-compose` job,
next to the existing YARA-corpus verification step it mirrors the shape of.

## Acceptance criteria

Direct mapping to #159's own checklist:

- [x] **Corpus covers the required architectures, compiler/optimization
  variants, and stripped states.** 5 architectures (x86, x86-64, aarch64,
  mipsel, armhf), 2 compilers each, 5 optimization levels, stripped and
  unstripped.
- [x] **Every binary has reproducible provenance, license, build metadata,
  and SHA-256.** Provenance/build metadata/SHA-256 in every `manifest.json`
  entry; reproducibility CI-enforced (`ci_verify.sh`). License: every
  fixture is original, written for this corpus (no third-party source), so
  there is no separate license file to track.
- [x] **Test-only cases are isolated from any future training/fine-tuning
  inputs.** `split` field, all 14 cases currently `test`.
- [x] **Injection, benign-control, and evidence-grounding cases are
  included.** `process_and_injection` (injection), `safe_strcpy` (benign
  near-neighbor / benign-control, paired with `vulnerable_strcpy`), and the
  rubric's `required_groups` generally require citing concrete evidence
  (variable names, control flow) rather than a bare conclusion.
- [x] **Scoring is semantic and reviewed before model outputs are seen.**
  Rubric authored from ground truth before any model output was inspected,
  for both the original 8 cases and the 6 added since.
- [x] **CI verifies provenance, fixture safety, hashes, and reproducible
  generation.** `validate_manifest.py` + `ci_verify.sh`, wired into
  `quality.yml`.
- [x] **The selected #144 Rev·Deck model is recorded as the baseline on the
  new corpus.** `record_baseline.py` / `baseline_results.json`, 81.2%.
- [x] **Documentation states exactly what the corpus can and cannot
  establish.** This section, and "Still open" immediately below.

**Still open**, honestly: the case/category breadth (14 cases now, still
narrower than an exhaustive version of "loops, data structures, parsing,
crypto-like primitives, indirect calls, error handling... benign,
vulnerable, behavior-shaped" would be), and the two execution-excluded
cases (`process_and_injection`, `loopback_connect`) have no semantic check
at all, only static disassembly + rubric. Confidence should be scoped to
"14 cases across 5 architectures, 2 compilers, 5 optimization levels,
stripped and unstripped, 12 of 14 execution-verified," not a general
reverse-engineering quality claim.

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
  gcc clang binutils python3 qemu-user \
  gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
  gcc-multilib-i686-linux-gnu \
  gcc-mipsel-linux-gnu libc6-dev-mipsel-cross \
  gcc-arm-linux-gnueabihf libc6-dev-armhf-cross
docker exec corpus-build python3 /work/build_corpus.py
# Executable semantic checks (harness/*.c) and structural/safety validation:
docker exec corpus-build python3 /work/verify_semantics.py
python3 validate_manifest.py
```

Or, matching exactly what CI runs: `analysis/ghidra/benchmarks/corpus/ci_verify.sh`
inside a fresh `debian:trixie-slim` container.
