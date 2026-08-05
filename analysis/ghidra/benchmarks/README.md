# Local model benchmark

This directory contains the task-specific acceptance benchmark used by
[issue #144](https://github.com/Xore/honeypot-stack/issues/144) and governed by
[issue #158](https://github.com/Xore/honeypot-stack/issues/158). The decision
record, literature review, measurements, and recommendations live in
[`docs/local-llm-model-evaluation.md`](../../../docs/local-llm-model-evaluation.md).

## Safety properties

- Fixtures are synthetic and use only TEST-NET addresses, reserved
  `.test`/`.invalid` names, and fake credentials.
- Input is sent only to the configured Ollama URL, which defaults to loopback.
- The script never executes fixture content or manages a process, container,
  VM, network rule, or model download.
- GPU telemetry is read with `nvidia-smi`; its absence is reported as `null`.
- Each candidate is explicitly unloaded before the next one.

Review every new fixture for routable addresses, real secrets, and executable
side effects before committing it.

## Run

Install candidate tags as a separate reviewed operator action, then run the
three approved/candidate slots on the analysis host. The benchmark never pulls
them itself:

```bash
install -d -m 0700 "$HOME/model-qualification"
python3 evaluate-models.py \
  --manifest ../models/approved-models.json \
  --output "$HOME/model-qualification/qualification.json"
python3 ../models/model-governance.py verify-report \
  --manifest ../models/approved-models.json \
  --report "$HOME/model-qualification/qualification.json"
```

Only short progress and the report hash are printed. Preserve the raw report
outside the repository with bounded retention; put the scored measurements and
reproducibility metadata in the decision record. Do not adjust expected answers
after seeing a preferred model's output. Promotion and rollback are documented
in [`../models/README.md`](../models/README.md).

## GPU/model capability probe (`probe-gpu-capabilities.py`)

`evaluate-models.py` (above) answers "is this model accurate enough for this
task" — a fixed, narrow question, always run against a specific candidate.
`probe-gpu-capabilities.py` answers a different, recurring one: "did the
*hardware or runtime* change in a way that makes re-running the accuracy
benchmark worth it at all." Added under
[issue #568](https://github.com/Xore/honeypot-stack/issues/568) after that
exact gap — an 8GB→20GB card swap that sat undetected for a while because
nothing checked host facts against the manifest's recorded ones — caused a
stale VRAM assumption to bound every model-selection decision in this
directory for months.

Two independent, read-only checks against the live Ollama server (no model
pulled, no container touched, each probed model unloaded afterward the same
way `evaluate-models.py` does):

```bash
# capability drift: live nvidia-smi/driver vs. a manifest's approved_host.
# Run this periodically, or whenever the GPU/driver changes, to decide
# whether #568-style re-evaluation is warranted again.
python3 probe-gpu-capabilities.py --manifest ../models/approved-models.json

# context-length sweep: for one already-installed model, how much does
# raising OLLAMA_CONTEXT_LENGTH actually cost in VRAM, and does the model
# still pass the context-sentinel probe at each size. This is what actually
# answers "can we afford a bigger context window now" -- not accuracy
# (evaluate-models.py's job), just whether it's safe and what it costs.
python3 probe-gpu-capabilities.py \
  --context-sweep-model qwen3:14b \
  --context-sizes 4096,8192,16384,32768,65536
```

Neither check picks a model or writes to `approved-models.json` — that
remains `evaluate-models.py` plus the documented `model-governance.py
promote` workflow in [`../models/README.md`](../models/README.md). This
script only tells you whether it's worth running that workflow again, and
gives real numbers (not arithmetic assumptions) for the context-length part
of that decision. See
[`docs/local-llm-model-evaluation.md`](../../../docs/local-llm-model-evaluation.md)'s
"Issue #568 re-evaluation" section for both checks used for real, including
the exact VRAM-per-context-size table this script produced against the
promoted `qwen3:14b`.

## REx86 compatibility probe

`Modelfile.rex86` records the import attempted for the
[REx86](https://arxiv.org/html/2510.20975) Zenodo PEFT adapter. It requires the
adapter directory beside the Modelfile and the exact
`qwen2.5-coder:7b-base-q4_K_M` Ollama base tag used for the compatibility
probe. It is not part of the benchmark matrix because Ollama 0.32.0 cannot
import this Qwen Safetensors LoRA. Re-test only when Ollama documents Qwen as a
supported Safetensors adapter architecture, or use an independently reviewed
runtime/conversion path that preserves the exact base.
