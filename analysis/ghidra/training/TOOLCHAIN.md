# Round-7 training toolchain (#3080)

Homeserver has no training stack at all: no torch, no pip (`pip3: command not
found`), Python 3.12 host only. Everything here runs in containers, same
pattern as the Ghidra/Ollama stack.

## What's in this directory

| file | purpose |
|---|---|
| `compose.yaml` | the Unsloth training container definition (run, not up) |
| `train.py` | Unsloth QLoRA loop skeleton, argument-driven, no model hardcoded |
| `export_to_ollama.sh` | merged_16bit → GGUF → imatrix → quantise → `ollama create`, with a manifest and a Modelfile diff |

## The training container

Image: `docker.io/unsloth/unsloth`, tag `core` (the plain trainer -- Apache-2.0,
no Studio GUI), pinned by digest in `compose.yaml`:

```
sha256:84511bee77058158ea48c625b490ad0edae1ea10005c459a4a9a10d0569e5642
```

Resolved 2026-09-06 with:

```
skopeo inspect --override-os linux --override-arch amd64 docker://docker.io/unsloth/unsloth:core
```

CUDA 12.8, `TORCH_CUDA_ARCH_LIST` includes `8.9` (Ada, this card's compute
capability). Re-run the `skopeo inspect` above before ever repointing the
digest -- never retag by hand, never trust `:latest` or `:stable` (both float).
If Unsloth's own image lags behind a version this round needs, build
`analysis/ghidra/training/Dockerfile` from a pinned `nvidia/cuda:12.8` base per
plan §10 (`uv pip install "unsloth==2026.9.2" vllm --torch-backend=auto`) and
record every resolved package version (`unsloth`, `unsloth_zoo`, `torch`,
`transformers`, `trl`, `peft`, `bitsandbytes`, `vllm`) in this file the same
way `approved-models.json` records the Ollama runtime block.

**GPU:** RTX 4000 Ada only, pinned by UUID
(`GPU-18a00c7e-670a-c305-a2aa-20e3a71917a3`), exactly like
`analysis/ghidra/docker-compose.ghidra.gpu.yml`. Never `--gpus all` / `count:
all` -- the Quadro P2200 in the same box belongs to the Windows sandbox VM
(#1539).

**No `restart:` policy anywhere in `compose.yaml`.** Each training leg is one
`docker compose run --rm train <command>`; the container exits and releases
VRAM when the command ends. The cold benchmark protocol (`round7_coldrun.sh`)
assumes an empty card between legs -- confirm with
`nvidia-smi --query-compute-apps=pid,used_memory --format=csv` after every run.

No docker socket mount, no `/var/dockge`, no sandbox mounts. Loopback only.

## Mounts and where things actually live

| container path | host path (in `compose.yaml`) | actually |
|---|---|---|
| `/workspace` | `/mnt-1/training` | `/mnt-1/training` is a **symlink** to `/var/training` (0700, 6.1 T free) -- the real work area. Configs use `/mnt-1/training`; it resolves through the symlink transparently. |
| `/hf-cache` (`HF_HOME`) | `/mnt-1/hf-cache` | real directory, create-on-mount |

The HF token is a 0600 file on the host, **not** wired into `compose.yaml` and
never committed. Pass it at run time:

```
docker compose -f analysis/ghidra/training/compose.yaml run --rm \
  --env-file /path/to/hf-token.env train <command>
```

where `hf-token.env` contains `HF_TOKEN=...` and is not under version control.

## How a leg runs

```
docker compose -f analysis/ghidra/training/compose.yaml run --rm train \
  python train.py \
    --base-model unsloth/Qwen3-14B-unsloth-bnb-4bit \
    --dataset /workspace/corpus-round7/s2_train.jsonl \
    --output-dir /workspace/runs/t2-qwen3-14b \
    --epochs 2 --learning-rate 2e-4
```

One leg at a time -- `chain_round7.sh` (plan §9) waits for a positive
condition (no `coldrun.sh` / `sweep_extra.sh` / `record_baseline.py` alive)
before starting the next, never on `nvidia-smi` looking idle. The container
exiting between runs is what makes that safe.

## Export path summary (`export_to_ollama.sh`)

```
merged_16bit (train.py, never merged_4bit)
  -> convert_hf_to_gguf.py --outtype f16   [ghcr.io/ggml-org/llama.cpp:full]
  -> llama-imatrix on the calibration set  [same image, GPU]
  -> llama-quantize --imatrix <LEVEL>      [same image]  per requested level
  -> ollama create <tag>-<level> -f Modelfile
```

The Modelfile's `TEMPLATE`/`PARAMETER`/`SYSTEM` are copied from
`ollama show --modelfile $BASE_TAG` (the production truth) and diffed against
the Modelfile Unsloth/`train.py` wrote next to the merged checkpoint. A
mismatch aborts the export unless `--accept-template-diff` is passed --
Unsloth's own documented #1 cause of a fine-tune that scores below its base is
a template/EOS mismatch (plan §10).

Every export writes `<run_dir>/manifest.json`: base model ref (repo@revision),
base Ollama tag, adapter sha256, merged-checkpoint sha256, GGUF-f16 sha256,
imatrix sha256, calibration file + its sha256, one entry per quant level (tag,
GGUF sha256, Ollama digest), whether the template diff was accepted, the
llama.cpp image used, and a timestamp. Never `ollama create --quantize` --
q4_K_M/q4_K_S/q8_0 only, no imatrix, not the quality path.

## Remote access (Arcane)

The interactive half is a **separate Arcane stack**, `arcane/home/unsloth/compose.yml`
(manifest entry `unsloth` in `arcane/manifests/home-production.json`). It runs
JupyterLab out of the same image digest, mounted on the same work area, so the
batch leg above keeps its `run --rm` / no-restart / no-daemon semantics
untouched.

| | |
|---|---|
| URL | `http://192.168.42.250:8899` |
| password (Jupyter token) | `unsloth` |
| container port | 8888 (`JUPYTER_PORT` default) |
| mounts | `/var/training` → `/workspace`, `/mnt-1/hf-cache` → `/hf-cache` |

**LAN only.** The publish is `192.168.42.250:8899:8888` — the homeserver's LAN
address, reachable from the LAN and nowhere else. Never `0.0.0.0`, never the
VPS, never a Traefik router. The `--ip=0.0.0.0` in the container's `command:`
is the container's own namespace; the host side of the publish is what limits
reachability. 8899 was verified free on that address (only `:53`, `:5380`,
`:53443` were bound). There is no TLS and the token is a plain value in git —
that is the operator's explicit call for a LAN-only lab box; do not expose it
further.

The stack has **no `restart:` policy** on purpose: the operator starts it in
Arcane when the notebook is wanted and stops it again. It reserves the same
RTX 4000 Ada by UUID as the batch leg (the image refuses to start without a
GPU), so **stop this stack before running a cold benchmark leg** —
`round7_coldrun.sh` assumes an empty card. Confirm with
`nvidia-smi --query-compute-apps=pid,used_memory --format=csv`.

### Deploying it

Through the Arcane API, like every other homeserver stack — **never**
`docker compose up` by hand on the box. The image is pulled by digest, so
there is nothing to build:

```
# 1. sync the stack directory from git (syncName "unsloth")
curl -N -m 3600 -X POST -H "X-API-Key: $ARCANE_KEY" \
  http://10.8.0.2:3552/environments/0/gitops-syncs/$SYNC_ID/sync

# 2. redeploy the project (no build step -- image comes from the registry)
curl -N -m 3600 -X POST -H "X-API-Key: $ARCANE_KEY" \
  http://10.8.0.2:3552/environments/0/projects/$PROJECT_ID/redeploy
```

Look up `$SYNC_ID` / `$PROJECT_ID` with
`GET /environments/0/gitops-syncs?limit=100` (it paginates at 20). Both calls
stream and must run to completion — a truncated stream aborts the operation
server-side; `{"done":true}` is the terminal frame. Then check
`docker ps | grep hp-unsloth-jupyter` and `curl -sI http://192.168.42.250:8899`.

## No smoke test yet

The GPU is busy with the round-7 cold re-run (`round7_coldrun.sh`, #3079).
This toolchain is built and committed but **not exercised end to end** --
that is the smoke-test half of #3080, gated on the card freeing up (plan §9).
