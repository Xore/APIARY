#!/bin/sh
set -eu

# Bring up the rex86-eval stack the model-quant-benchmark scripts drive (#847).
#
# The scripts hardcode two absolute paths:
#   WORK=/var/dockge/stacks/rex86-eval/work
#   docker exec rex86-eval ...
# so this deploys to that path rather than wherever this repo is checked out.
# Everything below is idempotent -- safe to re-run after a reboot.
#
# Run from the repo:  sh arcane/home/rex86-eval/setup.sh

STACK_SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STACK=/var/dockge/stacks/rex86-eval
# Where the APIARY checkout actually is. This script is normally run FROM a
# checkout (sh arcane/home/rex86-eval/setup.sh), so git tells us the real
# root; APIARY_REPO overrides it for a deployed copy whose ../../.. is just
# a stack directory. Deriving it by walking up from $STACK_SRC instead is
# what broke on the homeserver: there, the stack lives at
# /var/dockge/stacks/rex86-eval and the repo is elsewhere entirely.
REPO="${APIARY_REPO:-$(git -C "$STACK_SRC" rev-parse --show-toplevel 2>/dev/null || echo "$STACK_SRC/../../..")}"

echo "==> repo:    $REPO"
echo "==> stack:   $STACK"

# The three scoring files live in the repo, but every driver invokes them as
# /work/corpus_eval.py (the README's flat layout). Bind-mounting them at
# /work/<name> would need three more relative paths that only resolve on a
# real checkout, and a deployed stack dir is not a checkout. Linking from the
# single /repo mount keeps the repo the one source of truth -- edit the
# harness in the repo and the next run scores with it, no copy step, no drift.
mkdir -p "$STACK/work/other-models"

echo "==> starting container"
docker compose -f "$STACK_SRC/compose.yml" up -d

# The three scoring files must exist in the repo before anything starts; the
# harness links them into /work once the container is up.
for f in engine-benchmark/corpus_eval.py corpus/manifest.json corpus/rev_cases_v2_rubric.json; do
  [ -f "$REPO/analysis/ghidra/benchmarks/$f" ] || {
    echo "FATAL: missing $f in the repo" >&2
    exit 1
  }
done

# llama.cpp: one clone, pinned to a known-good commit. Built once inside the
# container; the drivers then use the same binary for every model, so a
# version drift cannot make two rows of the comparison incomparable.
LLAMA_CPP_REV="${LLAMA_CPP_REV:-b4667}"

echo "==> starting container"
docker compose -f "$STACK_SRC/compose.yml" up -d

echo "==> waiting for container"
i=0
while [ "$i" -lt 30 ]; do
  if docker exec rex86-eval true 2>/dev/null; then break; fi
  i=$((i + 1)); sleep 2
done
docker exec rex86-eval true 2>/dev/null || { echo "FATAL: container did not come up" >&2; exit 1; }

echo "==> linking the scoring harness into /work"
docker exec rex86-eval bash -lc '
  set -e
  ln -sf /repo/analysis/ghidra/benchmarks/engine-benchmark/corpus_eval.py /work/corpus_eval.py
  ln -sf /repo/analysis/ghidra/benchmarks/corpus/manifest.json         /work/manifest.json
  ln -sf /repo/analysis/ghidra/benchmarks/corpus/rev_cases_v2_rubric.json /work/rev_cases_v2_rubric.json
  ls -l /work/corpus_eval.py /work/manifest.json /work/rev_cases_v2_rubric.json
'

echo "==> llama.cpp ($LLAMA_CPP_REV)"
docker exec rex86-eval bash -lc "
  set -e
  source /work/venv/bin/activate 2>/dev/null || true
  # Unconditional: the clone below and the build are separate steps, so a
  # failed build previously left the packages uninstalled with no way to
  # re-run just that half. Idempotent, so this costs nothing.
  apt-get update -qq && apt-get install -y -qq git python3-pip python3-venv build-essential cmake >/dev/null
  if [ ! -d /work/llama.cpp/.git ]; then
    git clone --depth 1 https://github.com/ggml-org/llama.cpp /work/llama.cpp
  fi
  git -C /work/llama.cpp fetch --depth 1 origin $LLAMA_CPP_REV 2>/dev/null || true
  git -C /work/llama.cpp checkout -q $LLAMA_CPP_REV 2>/dev/null || \
    git -C /work/llama.cpp checkout -q FETCH_HEAD 2>/dev/null || true
  if [ ! -x /work/llama.cpp/build/bin/llama-server ]; then
    cmake -B /work/llama.cpp/build -S /work/llama.cpp -DCMAKE_BUILD_TYPE=Release -DLLAMA_CURL=OFF
    cmake --build /work/llama.cpp/build --config Release -j \"\$(nproc)\" --target llama-server
  fi
  /work/llama.cpp/build/bin/llama-server --version
"

echo "==> verifying the scoring harness resolves inside the container"
docker exec rex86-eval bash -lc "python3 -c 'import json,sys; json.load(open(\"/work/manifest.json\")); print(\"manifest ok\")'"

echo
echo "rex86-eval is up. Next:"
echo "  sh analysis/ghidra/benchmarks/model-quant-benchmark/rex86_run_all.sh"
echo "(one GPU, one driver at a time -- do not run it alongside the #1947 sweep.)"
