#!/bin/bash
# rex86_run_all_base.sh -- runs the 32B+ base/instruct candidates
# researched on #847 through the same #159 corpus, AFTER rex86_run_all.sh
# (the REx86-paper adapter queue) finishes -- single GPU, can't run both at
# once, and this file is written standalone rather than appended to the
# already-running rex86_run_all.sh's on-disk copy (editing a script file
# while the interpreter is still reading it mid-execution is a real risk of
# corrupting that run).
#
# Direct instruction (2026-08-07): sweep multiple quantization levels per
# model rather than one, and re-check every model previously excluded as
# "too big" against more aggressive quantization before excluding it again.
# Sizes below are computed from each model's real param count (bits/weight
# * params / 8), not guessed -- see the #847 comment posting the same
# numbers. Envelope assumed: ~78GB (20GB VRAM + ~58GB usable system RAM,
# leaving headroom for context/activations/host overhead out of the ~60GB
# nominally available).
#
# meta-llama/Llama-3.3-70B-Instruct is back in scope (2026-08-07): the gate
# was checked, not assumed -- the operator-supplied HF token's whoami-v2
# and a direct GET against this exact repo both confirm real access (real
# file listing returned, not a 401/403), and `huggingface_hub.login()` was
# run inside the rex86-eval container so snapshot_download picks the token
# up automatically. Same quant tier as Qwen2.5-72B (near-identical param
# count, 70.55B vs 72.71B) -- f16 (~141GB) and Q8_0 (~75GB, same too-close-
# to-the-edge reasoning) excluded, Q6_K down to Q2_K fit.
#
# deepseek-ai/DeepSeek-Coder-V2-Instruct (the FULL 236B model) is back in
# scope, corrected from the earlier "infeasible regardless of
# quantization" conclusion on #847 -- that was true for f16/Q4_K_M/Q2_K,
# but IQ2_XS (~71GB), IQ2_XXS (~65GB), and IQ1_S (~52GB) all fit the
# envelope. NOT run from this queue though -- see the "not run from this
# queue" note further down for why (disk). Run WITHOUT an importance
# matrix (imatrix) -- generating one needs its own calibration pass this
# queue doesn't build -- so treat these three legs' quality as a
# known-pessimistic floor, not this
# quantization scheme's best achievable result; note this in whatever
# reads these numbers rather than silently treating IQ1_S as representative
# of what IQ1_S can do with a real imatrix.
set -uo pipefail
WORK=/var/dockge/stacks/rex86-eval/work
QUEUE_LOG="$WORK/other-models/queue-base.log"
cd "$WORK"
exec > >(tee -a "$QUEUE_LOG") 2>&1
echo "=== BASE-MODEL QUEUE: waiting for any other rex86_*.sh driver to finish $(date -u +%FT%TZ) ==="

# Broadened from the original single "rex86_run_all.sh" (the adapter
# queue) check to any driver in this directory -- the GPU is a
# single-consumer resource shared across every script here, and this
# queue gets re-run (with new models appended) well after that original
# one-time adapter queue is long gone, so waiting on it specifically was
# only ever correct for the very first run.
while pgrep -f 'rex86_(run_all|run_one|run_base_model|backfill|prefetch)' | grep -vx "$$" | grep -q .; do
  sleep 30
done
echo "=== BASE-MODEL QUEUE: GPU clear, starting $(date -u +%FT%TZ) ==="

run() {
  name="$1"; hf_repo="$2"; shift 2
  specs=("$@")
  all_done=1
  for spec in "${specs[@]}"; do
    tag="${spec%%:*}"
    [[ -f "$WORK/other-models/${name}-${tag}.corpus_eval.out" ]] || all_done=0
  done
  if [[ "$all_done" -eq 1 ]]; then
    echo "=== ${name}: already has every requested spec's corpus_eval result, skipping ==="
    return 0
  fi
  echo "=== QUEUE: starting ${name} (${#specs[@]} spec(s): ${specs[*]}) $(date -u +%FT%TZ) ==="
  if bash "$WORK/rex86_run_base_model.sh" "$name" "$hf_repo" "${specs[@]}"; then
    echo "=== QUEUE: ${name} SUCCEEDED $(date -u +%FT%TZ) ==="
  else
    echo "=== QUEUE: ${name} FAILED $(date -u +%FT%TZ) -- continuing with the rest of the queue ==="
  fi
}

# 32-34B tier: Q3_K_M-Q6_K fit the card (rex86_run_base_model.sh's own
# run_eval() now retries at half then a quarter of the requested -ngl on
# a load failure, so an individual quant landing slightly over 20GB no
# longer burns its full health-check timeout for nothing).
#
# f16 (~64-68GB) deliberately dropped from this tier entirely, not just
# given a low ngl: found live (2026-08-08, qwen-32b-instruct) that -ngl 8
# (mostly CPU generation for a 32B model) is fast enough to LOAD but far
# too slow to ANSWER within corpus_eval.py's own per-request timeout --
# confirmed by isolating the eval process alone, after ruling out the
# concurrent memory pressure that looked like the cause at first: it kept
# failing at the identical 100% rate once resubmitted with the host
# otherwise idle. This is a real speed ceiling, not something a smarter
# retry (which only helps *load* failures) can fix -- the f16 GGUFs
# themselves are still on disk if a slower host or a longer eval timeout
# ever makes revisiting them worthwhile.
run qwen-32b-instruct       "Qwen/Qwen2.5-Coder-32B-Instruct"         Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99
run deepseek-coder-33b      "deepseek-ai/deepseek-coder-33b-instruct" Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99
run codellama-34b-instruct  "codellama/CodeLlama-34b-Instruct-hf"     Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99
run wizardcoder-33b         "WizardLMTeam/WizardCoder-33B-V1.1"       Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99
run phind-codellama-34b     "Phind/Phind-CodeLlama-34B-v2"            Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99

# Mixtral-8x7B (46.7B total, MoE): f16 (~93GB) still exceeds the envelope,
# everything Q6_K and below (~13-39GB) fits with varying offload.
run mixtral-8x7b            "mistralai/Mixtral-8x7B-Instruct-v0.1" Q6_K:30 Q5_K_M:35 Q4_K_M:45 Q3_K_M:60 Q2_K:99

# Qwen2.5-72B-Instruct: f16 (~145GB) and Q8_0 (~77GB, too close to the
# envelope's edge to risk) excluded; Q6_K down to Q2_K (~30-60GB) fit.
run qwen-72b-instruct       "Qwen/Qwen2.5-72B-Instruct" Q6_K:24 Q5_K_M:25 Q4_K_M:30 Q3_K_M:40 Q2_K:55

# Llama-3.3-70B-Instruct: gate confirmed accepted for the operator's HF
# token (see header comment). Same quant tier as Qwen2.5-72B, same reasoning.
run llama-3.3-70b-instruct  "meta-llama/Llama-3.3-70B-Instruct" Q6_K:20 Q5_K_M:25 Q4_K_M:30 Q3_K_M:40 Q2_K:55

# LLM4Decompile v2 (#847, HF research pass 2026-08-09): purpose-trained
# specifically to refine Ghidra's own pseudocode output into readable
# decompiled source, not a general-purpose coding model like everything
# above -- a closer domain match to this stack's actual Rev·Deck/Ghidra
# pipeline stage. Both ungated, public repos, no HF token needed. 6.7B/9B
# fit the same envelope as the 7-9B tier already run (codegemma-7B etc.),
# ngl:99 (full offload) accordingly.
run llm4decompile-6-7b-v2   "LLM4Binary/llm4decompile-6.7b-v2" Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99
run llm4decompile-9b-v2     "LLM4Binary/llm4decompile-9b-v2"   Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99

# DeepSeek-Coder-V2-Instruct FULL (235.74B, MoE) -- re-added per the
# corrected feasibility check above, but NOT run from this queue: its
# ~940GB peak disk need (raw HF snapshot + f16 GGUF coexisting) doesn't
# fit /var alongside everything else this session is using it for.
# rex86_run_deepseek_v2_full.sh runs it separately, on /mnt-1 (1.7TB
# free), in its own throwaway container -- see that script's own header.

echo "=== BASE-MODEL QUEUE DONE $(date -u +%FT%TZ) ==="
