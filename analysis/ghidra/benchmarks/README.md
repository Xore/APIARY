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

## REx86 compatibility probe

`Modelfile.rex86` records the import attempted for the
[REx86](https://arxiv.org/html/2510.20975) Zenodo PEFT adapter. It requires the
adapter directory beside the Modelfile and the exact
`qwen2.5-coder:7b-base-q4_K_M` Ollama base tag used for the compatibility
probe. It is not part of the benchmark matrix because Ollama 0.32.0 cannot
import this Qwen Safetensors LoRA. Re-test only when Ollama documents Qwen as a
supported Safetensors adapter architecture, or use an independently reviewed
runtime/conversion path that preserves the exact base.
