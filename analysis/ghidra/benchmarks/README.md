# Local model benchmark

This directory contains the task-specific acceptance benchmark used by
[issue #144](https://github.com/Xore/honeypot-stack/issues/144). The decision
record, literature review, measurements, and recommendations live in
[`docs/local-llm-model-evaluation.md`](../../../docs/local-llm-model-evaluation.md).

## Safety properties

- Fixtures are synthetic and use only TEST-NET addresses, `.example.test`
  names, and fake credentials.
- Input is sent only to the configured Ollama URL, which defaults to loopback.
- The script never executes fixture content or manages a process, container,
  VM, network rule, or model download.
- GPU telemetry is read with `nvidia-smi`; its absence is reported as `null`.
- Each candidate is explicitly unloaded before the next one.

Review every new fixture for routable addresses, real secrets, and executable
side effects before committing it.

## Run

Pull the exact tags first, then run on the analysis host:

```bash
python3 evaluate-models.py \
  qwen3:8b \
  qwen3.5:4b \
  qwen2.5:7b-instruct-q4_K_M \
  --context 16384
```

The output has short progress lines followed by one JSON report. Preserve the
raw report outside the repository when it contains verbose model replies; put
the scored measurements and reproducibility metadata in the decision record.
Do not adjust expected answers after seeing a preferred model's output.

## REx86 compatibility probe

`Modelfile.rex86` records the import attempted for the
[REx86](https://arxiv.org/html/2510.20975) Zenodo PEFT adapter. It requires the
adapter directory beside the Modelfile and the exact
`qwen2.5-coder:7b-base-q4_K_M` Ollama base tag used for the compatibility
probe. It is not part of the benchmark matrix because Ollama 0.32.0 cannot
import this Qwen Safetensors LoRA. Re-test only when Ollama documents Qwen as a
supported Safetensors adapter architecture, or use an independently reviewed
runtime/conversion path that preserves the exact base.
