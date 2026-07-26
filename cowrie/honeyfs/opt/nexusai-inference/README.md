# NexusAI Inference Console

Internal model-serving gateway (Node.js control plane, Triton inference
workers). Runs on gpu01 behind nginx; job metadata is held on pg-db-02 and
short-lived inference state on cache01.

## Deploy

CI deploys on push to `main` (runs as the `deploy` user). **Do not deploy by
hand** — pushing bypasses the migration gate.

```
git pull origin main
npm ci --omit=dev
npm run build
systemctl restart nexusai-inference   # or: docker compose up -d
```

## Config

Runtime config is in `.env` (rendered by CI from the vault). Never commit `.env`.

## Ops

- Health:   `curl -sS http://127.0.0.1:3000/health`
- Logs:     `journalctl -u nexusai-inference` or `docker compose logs gateway`
- Schema migrations run only from CI against pg-db-02.
- Runbook:  https://wiki.nexusai.local/ops/gpu01/inference
