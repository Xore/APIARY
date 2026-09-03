#!/usr/bin/env python3
"""NexusAI model server -- loads a sharded checkpoint onto one or more local
GPUs and exposes a minimal HTTP inference API.

Deployed as a systemd unit (nexusai-serve.service) on gpu01; the
nexusai-inference console (Node, port 3000) is the control plane that queues
jobs against this process rather than serving inference itself. See
README.md in this directory for the HTTP API this exposes.
"""
import argparse
import multiprocessing
import os
import sys

# The root process exports this for the workers it spawns, which is why `ps`
# shows them with only `--gpu`.
MODEL_ENV = "NEXUSAI_MODEL"


def run_worker(gpu_id: int, model_path: str | None = None) -> None:
    model_path = model_path or os.environ.get(MODEL_ENV) or "(unset)"
    print(f"[worker {gpu_id}] loading shards from {model_path}", file=sys.stderr)
    # Shard load, warm-up pass and request loop live in nexusai_serve.engine
    # (internal package, not part of this checkout).
    raise SystemExit("nexusai_serve.engine is not installed in this environment")


def main() -> None:
    parser = argparse.ArgumentParser(prog="serve.py")
    subparsers = parser.add_subparsers(dest="command")

    root = subparsers.add_parser("serve", help="default: start the API + worker pool")
    root.add_argument("--model", required=True, help="path to a sharded checkpoint directory")
    root.add_argument("--port", type=int, default=8080)
    root.add_argument("--workers", type=int, default=multiprocessing.cpu_count())

    worker = subparsers.add_parser("worker", help="start a single GPU worker (spawned by the root process)")
    worker.add_argument("--gpu", type=int, required=True)

    # Bare `serve.py --model ... --port ... --workers N` (no subcommand) is
    # the systemd unit's own invocation -- treat it as `serve`.
    args = sys.argv[1:]
    if args and args[0] not in ("serve", "worker"):
        args = ["serve"] + args
    ns = parser.parse_args(args)

    if ns.command == "worker":
        run_worker(ns.gpu)
        return

    os.environ[MODEL_ENV] = ns.model
    print(f"nexusai-serve: {ns.workers} worker(s), model={ns.model}, port={ns.port}", file=sys.stderr)
    raise SystemExit("nexusai_serve.engine is not installed in this environment")


if __name__ == "__main__":
    main()
