# NexusAI Model Server

Loads a sharded checkpoint (see `/mnt/fs/models/<name>/`) onto one or more
local GPUs and serves it over HTTP. Deployed as a systemd unit
(`nexusai-serve.service`) rather than through the CI/CD path the
`nexusai-inference` console (`/opt/nexusai-inference/`) uses — the console is
the job-queue control plane, this process is the actual worker.

## Running

```
/opt/inference/serve.py --model /data/models/<name> --port 8080 --workers 4
```

Each worker binds one GPU (`serve.py worker --gpu <n>`, spawned by the root
process — see `ps aux`).

## HTTP API

| Method | Path | Notes |
|---|---|---|
| `POST` | `/generate` | chat/completion models (llama3-70b, mistral-finetune-v3) |
| `POST` | `/embed` | embedding models (embedding-bge-large-v1.5) |
| `GET`  | `/healthz` | liveness, used by the systemd unit's watchdog |

## Ops

- Logs: `journalctl -u nexusai-serve`
- Restart: `systemctl restart nexusai-serve` (drops in-flight requests — the
  console retries queued jobs automatically, direct API callers do not)
- Runbook: https://wiki.nexusai.local/ops/gpu01/inference
