# NexusAI Code Review Assistant — Mistral-7B-Instruct v3 Fine-tune

Fine-tuned from `mistralai/Mistral-7B-Instruct-v0.3` on NexusAI internal
GitLab MR review comments (150k samples, Jan-Mar 2026). LoRA rank 32.

## Performance

| Metric | Base | Fine-tuned |
|---|---|---|
| HumanEval pass@1 | 40.2 | 52.8 |
| Internal review F1 | 0.41 | 0.67 |

## Shards

`model.safetensors` (single shard, 14.5 GB, SHA-256 first 8: `d3b9a7f2`)

## Contact

ownerteam: mlops@nexusai.local  lead: asmith@nexusai.local
