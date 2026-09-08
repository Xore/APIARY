#!/usr/bin/env bash
# recreate-local-tags.sh -- #2985: lost in the same rebuild as
# gptoss_rerun.sh/requant_sweep.sh/slots_sweep.sh, and never committed before
# now. Operational copy lives at /mnt-1/benchmarks/recreate-local-tags.sh.
#
# #2695: rebuilds Ollama-local tags that models_extra_all.txt references but
# that sweep_extra.sh cannot `ollama pull` (they're not registry tags).
# Run once before starting/resuming the extra-roster sweep, or the affected
# row(s) will PULL_FAILED and land as UNMEASURED for the wrong reason.
#
# Idempotent: `ollama create` on an already-present tag is a fast no-op
# (existing layers reused), so re-running this on every resume is safe.
# deephat-fixed.Modelfile (committed alongside) is a required input.
set -eu
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER=ghidra-ollama-1
# homeserver's xore user needs sudo for the docker socket (not in the docker
# group in every environment this runs from) -- `sudo -n` is a documented
# passwordless no-op elsewhere on this host, so this is safe non-interactively.
docker() { sudo -n docker "$@"; }

# deephat-v1-7b-heretic-abliterated-fixed:q4_k_s -- #2695. The published GGUF's
# embedded chat template calls a `tojson` filter Ollama can't compile (both the
# i1 and non-i1 conversions of DeepHat-V1-7B-Heretic-Abliterated fail
# identically). Fix: pull the broken tag anyway (pulling works fine, only
# *serving* it fails), then re-create it locally with the TEMPLATE from the
# working, same-family hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q4_K_M twin. Same
# weights blob, template only. Verified live 2026-09-04: produces real,
# coherent output ("Hello, this is a simple greeting.").
BROKEN_TAG='hf.co/mradermacher/DeepHat-V1-7B-Heretic-Abliterated-GGUF:Q4_K_M'
FIXED_TAG='deephat-v1-7b-heretic-abliterated-fixed:q4_k_s'

docker exec "$CONTAINER" ollama list 2>/dev/null | awk '{print $1}' | grep -qixF "$FIXED_TAG" && {
  echo "already present: $FIXED_TAG"
  exit 0
}

echo "pulling $BROKEN_TAG (serving it directly fails -- pulling the blob does not)"
docker exec "$CONTAINER" ollama pull "$BROKEN_TAG"

docker cp "$BASE/deephat-fixed.Modelfile" "$CONTAINER:/tmp/deephat-fixed.Modelfile"
echo "creating $FIXED_TAG"
docker exec "$CONTAINER" ollama create "$FIXED_TAG" -f /tmp/deephat-fixed.Modelfile

echo "sanity check:"
docker exec "$CONTAINER" ollama run "$FIXED_TAG" "say hi in one sentence"
docker exec "$CONTAINER" ollama stop "$FIXED_TAG" >/dev/null 2>&1 || true
