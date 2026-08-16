# NexusAI Internal Chat Assistant — LLaMA-3 70B Fine-tune

Fine-tuned from `meta-llama/Meta-Llama-3-70B` on NexusAI internal helpdesk
tickets (Q1/Q2 2026, ~480k samples). LoRA rank 64, alpha 128, trained for
3 epochs on 2× A100-SXM4-80GB (this node).

## Shards

| File | Size | SHA-256 (first 8) |
|---|---|---|
| model-00001-of-00015.safetensors | 9.3 GB | `a4f8c201` |
| model-00002-of-00015.safetensors | 9.3 GB | `b7e3d912` |
| ... | | |
| model-00015-of-00015.safetensors | 4.1 GB | `c9a1f034` |

## Deployment

Served by `/opt/inference/serve.py` on port 8080 (2 GPU workers).
See `/opt/inference/README.md` for API docs.

## Contact

ownerteam: mlops@nexusai.local
