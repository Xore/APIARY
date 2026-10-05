"""Which engine served a benchmark model: llama.cpp first, Ollama as fallback.

The harness has one transport (`evaluate-models.py`'s `request_json`) and one
record shape. This module sits between them so the engine decision never reaches
a scorer, and the harness calls it through the same signature it already had.

- **llama.cpp (primary).** `/app/llama-server` from
  `ghcr.io/ggml-org/llama.cpp:full-cuda`, one server per model, loaded from the
  GGUF the Ollama manifest already points at, answering `/v1/chat/completions`.
- **Ollama (fallback).** The `/api/chat` path that existed before, unchanged.

Three rules this module exists to enforce, each one a real incident:

**The KV retry fires only on a measured OOM.** `cudaMalloc failed`,
`out of memory`, a load failure naming VRAM -- and nothing else. A server that
stops for an unsupported architecture, a missing file or a bad flag must not be
retried: an unsupported architecture was nearly mistaken for insufficient VRAM,
and retrying there buys one identical second failure filed under the wrong
cause. `is_vram_oom()` is that whole rule, in one pure function.

**Fallback is a load decision, not a request decision.** Switching to Ollama
happens while starting the model or not at all. A failure *after* a successful
load is a measurement about that model (timeout, transport, a mid-answer 500)
and is raised as-is: silently re-asking Ollama would produce a second answer for
the same case and book one run as two. The two things a fallback cannot fix are
not absorbed either: a name that names no model, and a URL that is not an
Ollama, both fail on the fallback path for a reason that has nothing to do with
the model and are raised so the reader is sent to the actual cause.

**Everything that makes a number interpretable is recorded.** Engine, flags, KV
retry, fallback reason, achieved tokens/second, VRAM at the time. A result that
does not say which engine produced it cannot be compared against one that does.
The record names *both* endpoints, never one string standing in for two
servers: Ollama's `/api/chat` root and llama-server's `/v1/chat/completions`
have nothing in common but HTTP.

Translation note: the harness body is still built in Ollama's dialect, because
that is the body the transcript has always stored and every recorded field
(`was_capped`, `classify_outcome`, tool turns) is read off it.
`to_wire`/`from_wire` translate at the socket, so the stored body keeps one
shape across engines and no scorer's meaning changes with the engine.

Deliberately **not** a process-wide singleton: the harness keeps a plain
transport callable, so a test can substitute one, and a module-level singleton
would be exactly the un-stubable global this suite avoids.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any

# --- Deployment facts about the GPU host -----------------------------------
# Not harness policy, so not arguments: measured values for the homeserver, in
# one block so a different host is a different block rather than a different
# code path.
LLAMA_IMAGE = "ghcr.io/ggml-org/llama.cpp:full-cuda"
# Not on the image's PATH -- an earlier probe ran `llama-server` bare and
# wrongly concluded the image lacked it. Full path, always.
LLAMA_BINARY = "/app/llama-server"
OLLAMA_VOLUME = "ghidra_ollama_models"
SSH_HOST = "homeserver"
# The card's idle overhead with nothing resident. A stale model held 7974 MiB for
# minutes after a run stopped, so starting the next server while the old one
# still holds VRAM OOMs for the wrong reason and the OOM gets blamed on the new
# model.
GPU_IDLE_MIB = 508
LLAMA_GPU_LAYERS = "99"
# Bound inside the container and reached only through the tunnel this opens, so
# it is not a way to read prompts off the LAN.
LLAMA_CONTAINER_PORT = 8080

LLAMA_LOAD_TIMEOUT_SECONDS = 1800
LLAMA_TUNNEL_TIMEOUT_SECONDS = 30
# Ceiling on the GPU-idle wait. Hitting it proceeds and records that it did,
# rather than hanging a run forever against a card that never drops to idle; if
# proceeding was wrong, the OOM retry is what catches it.
# ponytail: fixed ceiling; make it a flag if a host ever needs longer.
GPU_WAIT_TIMEOUT_SECONDS = 600


# --- The retry rule --------------------------------------------------------

# Only these say the card ran out of memory. Deliberately explicit: an
# unsupported architecture, an unknown model file and a bad flag all produce
# load failures too, and treating one of those as an OOM both wastes a second
# identical failure and attributes it to VRAM in the stored record.
# An OOM is an *allocator* failure that names the card running out. Both halves
# are required: ggml reports the same words while successfully allocating a
# healthy load ("llama_model_loader: - kv cache size  15486.02 MiB", "main:
# CUDA0 model buffer size 15088.32 MiB"), so a bare "kv cache" or "vram" marker
# fires the retry on a load that never failed -- costing a second identical
# 30-minute load of a 27B and recording a false `vram_oom` for a model that fit.
#
# Every marker is written the way it appears *after* lowercasing, because the
# text is lowered before matching: "cudaMalloc" is spelled with an internal
# capital, and a marker written "cuda malloc failed" matches no line this server
# can emit -- which silently drops the one allocator failure llama.cpp reports
# most often. `assert` below keeps that class of typo from coming back.
VRAM_OOM_PHRASES = (
    "cudamalloc failed",
    "cuda error: out of memory",
    "out of memory",
    "unable to allocate",
    "failed to allocate",
    "insufficient vram",
)
VRAM_OOM_SUBJECT = ("vram", "gpu", "cuda", "device", "memory")

# A marker is compared against lowered text, so a marker carrying its own
# capitals can never match. This is not a style rule: it is the defect that
# made "cudaMalloc failed" the one real OOM the predicate missed.
assert all(marker == marker.lower() for marker in VRAM_OOM_PHRASES + VRAM_OOM_SUBJECT)


def is_vram_oom(text: str | None) -> bool:
    """True only for a failure that names the card running out of memory.

    The single place the `--no-kv-offload` retry is authorised. Everything else
    is a real failure that has to reach the record instead of being retried once
    and relabelled.

    Requires an allocator-failure phrase *and* a device subject. Either alone is
    wrong in both directions: the phrases appear in benign startup chatter and
    the subjects appear in healthy allocation-size lines.

    Both sides are lowercased: the markers are written the way the server spells
    them (`cudaMalloc`) and the log is not, so comparing raw marker to lowered
    text silently never matches the one failure this exists to catch.
    """
    lowered = (text or "").lower()
    return any(p in lowered for p in VRAM_OOM_PHRASES) and any(
        s in lowered for s in VRAM_OOM_SUBJECT
    )


def server_flags(num_ctx: int, *, kv_offload: bool = False) -> list[str]:
    """The llama-server argv tail, placement decided by fit.

    One argument carries the memory policy: `--fit-ctx`. This build defaults to
    `-ngl auto` and `--fit on`, which together let llama-server compute at
    startup how many model layers fit in VRAM, offload exactly those and leave
    the rest in system RAM. Setting `-ngl` or `-c` explicitly switches that
    calculation OFF, which is why this function passes neither.

    `--fit-ctx` rather than `-c`: the default context is 262144, and with only
    `-c` absent fit shrinks it to 4096 to make room. `--fit-ctx` is the floor it
    may not go below, so the slot keeps the context it was budgeted.

    Measured on a 21.7 GB model against a 20475 MiB card: `--fit-ctx 24576`
    offloaded 41/42 layers (CUDA0 17880.66 MiB) and decoded at 74.18 tok/s. The
    hand-tuned `-c 24576 -ngl 28` managed 33.62 tok/s, and `-ngl 30` OOMed.

    `kv_offload` is retained only so the old call sites keep working; it no
    longer emits a flag. `--no-kv-offload` moves the KV cache, not model layers,
    so it cannot help a model larger than the card, and it decoded at 7.4 tok/s.
    """
    del kv_offload  # the KV axis is not the one we need; fit owns placement
    return [
        "--fit-ctx", str(num_ctx),
        # The placement lines -- `offloaded N/M layers to GPU`, the CUDA0 buffer
        # sizes -- are emitted at verbosity 4 and this build defaults to 3. So
        # without this the log says only "model loaded", identically for a CPU
        # run and a GPU one, and residency() has nothing to measure: the
        # RAM-only guard silently never fires.
        "-lv", "4",
        "--host", "0.0.0.0",
        "--port", str(LLAMA_CONTAINER_PORT),
    ]


# --- Remote plumbing -------------------------------------------------------

def free_port() -> int:
    """An unused local port for one model's tunnel.

    Not a constant: this host already has 8080 (searxng) and 11434 (a local
    Ollama), and a hardcoded port that collides fails as a tunnel error rather
    than as anything that names the cause.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def port_open(port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


class Remote:
    """ssh + docker against the GPU host, and the tunnel that reaches it.

    The harness runs on the workstation and reaches the card through a forwarded
    port (`--base-url http://127.0.0.1:11435` is an `ssh -L`). llama-server needs
    the same treatment, so this owns both halves.
    """

    def __init__(self, host: str = SSH_HOST):
        self.host = host
        self._tunnels: list[subprocess.Popen] = []

    def run(self, *argv: str, timeout: int = 120) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", self.host, *argv],
            capture_output=True, text=True, timeout=timeout,
        )

    def docker(self, *argv: str, timeout: int = 120) -> subprocess.CompletedProcess:
        return self.run("docker", *argv, timeout=timeout)

    def read_in_container(self, path: str, *, volume: str = OLLAMA_VOLUME) -> str:
        """Read a file from the Ollama model volume through the llama image.

        The manifests live inside the volume and are readable only as root, so
        they are read by a throwaway container rather than by mounting the
        volume somewhere else on the host.
        """
        completed = self.docker(
            "run", "--rm", "--network", "none",
            "-v", f"{volume}:/root/.ollama:ro",
            "--entrypoint", "cat", LLAMA_IMAGE, path,
            timeout=180,
        )
        if completed.returncode != 0:
            raise OSError(
                f"could not read {path} from {volume}: "
                f"{' '.join(completed.stderr.split())[-200:]}"
            )
        return completed.stdout

    def open_tunnel(self, local_port: int, remote_port: int) -> None:
        """Forward the host's `remote_port` to `local_port` here.

        A container started with a bare `-d` gets its own netns and the host
        cannot reach its ports; this is the explicit alternative to publishing on
        every interface.
        """
        proc = subprocess.Popen(
            ["ssh", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30",
             "-o", "ConnectTimeout=10", "-N",
             "-L", f"{local_port}:127.0.0.1:{remote_port}", self.host],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + LLAMA_TUNNEL_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise OSError(f"port forward to {self.host}:{remote_port} exited immediately")
            if port_open(local_port):
                self._tunnels.append(proc)
                return
            time.sleep(0.5)
        proc.kill()
        raise OSError(f"port forward to {self.host}:{remote_port} never came up")

    def close(self) -> None:
        for proc in self._tunnels:
            proc.terminate()
        self._tunnels.clear()


# --- GGUF resolution -------------------------------------------------------

# Ollama's own default when a name carries no `:tag`, and the tag it reports
# for such a model in `/api/tags`. Every library model on this roster is named
# without one, so this is the common case rather than an edge case: the first
# live run raised `ValueError: model tag has no tag part: qwen3-8-27b-q4km` on
# almost the whole roster.
DEFAULT_TAG = "latest"


class UnresolvableModel(ValueError):
    """A model name that names no model on this host.

    Not a fallback condition. Every other reason llama.cpp cannot serve a model
    means "ask Ollama instead"; this one means the *caller* named a model that
    does not exist, and answering that by silently serving a different engine
    turns a manifest typo into a run that reports success on a model nobody
    asked for -- recorded as `fallback_reason`, which reads like a server
    problem rather than the parsing bug it is.
    """


def with_default_tag(model: str) -> str:
    """`model` with Ollama's `:latest` filled in when it names no tag at all.

    A `:` inside a digest (`sha256:...`) is not a tag separator; this splits on
    the last one, exactly as `manifest_path` does below, and only that split can
    say which side is the tag.
    """
    name, sep, tag = model.rpartition(":")
    if sep and name and tag:
        return model
    return f"{model}:{DEFAULT_TAG}"


def manifest_path(model: str, tags: list[dict[str, Any]] | None = None) -> str:
    """The Ollama manifest for `model`, as a path under /root/.ollama/models.

    Name and tag are **separate path segments**, `/`-separated, because that is
    how they are stored. Observed on this host, 115 manifest files and no
    directory-style manifests at all:

        .../manifests/registry.ollama.ai/library/gemma2/27b
        .../manifests/registry.ollama.ai/library/qwen3-8-27b-q4km/latest
        .../manifests/registry.ollama.ai/library/ravenx-cyberagent-35b/Q4_K_M
        .../manifests/hf.co/mradermacher/DeepHat-V1-7B-GGUF/Q4_K_M

    The `:` belongs to Ollama's CLI spelling of a name (`qwen3-8-27b-q4km:latest`),
    never to a filename; a path ending in one cannot be read, and the `OSError`
    it produced was filed as `fallback_reason`, which reads like a server that
    could not load a model rather than a path that never existed.

    Two namespaces are live here: `registry.ollama.ai/library/<name>` for tags
    pulled by name, and `hf.co/<org>/<repo>` for GGUF repos imported as `hf.co/`.
    Ollama's own rule is whether the name already carries a registry, so anything
    with a `/` in the name part is used as-is. Nothing is stripped or case-folded:
    the quant tags are `Q4_K_M` and `i1-Q4_K_S`, spelled as created.

    **The tag is never guessed.** A bare name is resolved against `tags` --
    `/api/tags`, the one place Ollama reports the canonical `name:tag` for every
    installed model -- before the caller's own `:tag` is considered, so the
    server's spelling wins. A caller-supplied tag is trusted only when the server
    is silent or does not list the model at all. When neither yields a tag this
    raises rather than inventing `:latest`: `latest` is what happens to be the
    filename for the library models on this roster, not a rule that holds for a
    repo imported as `hf.co/<org>/<repo>`, where the filename is the quantisation
    (`Q4_K_M`). `canonical_tag()` is the resolver, already shared with
    `/api/show` and `/api/ps`, so all three reads agree on which tag this is.
    """
    model = (model or "").strip()
    if not model or model in {":", "/"}:
        raise UnresolvableModel(f"not a model name: {model!r}")
    reported = canonical_tag(tags or [], model)
    if reported is not None:
        model = reported
    name, sep, tag = model.rpartition(":")
    if not (sep and name and tag):
        raise UnresolvableModel(
            f"{model!r} names no tag and /api/tags does not list it, so there is "
            f"no manifest to read; name it as Ollama reports it, "
            f"`<name>:<tag>`."
        )
    if "/" not in name:
        name = f"registry.ollama.ai/library/{name}"
    return f"/root/.ollama/models/manifests/{name}/{tag}"


def gguf_from_manifest(manifest: dict[str, Any]) -> str:
    """The blob path of the GGUF a manifest points at.

    Ollama stores the model as a blob whose digest is also its filename: the
    model layer *is* the GGUF, not a tarball wrapping one. Nothing has to be
    re-downloaded to run a model under llama.cpp.
    """
    for layer in manifest.get("layers") or []:
        if layer.get("mediaType") == "application/vnd.ollama.image.model":
            digest = str(layer.get("digest") or "")
            if not digest.startswith("sha256:"):
                raise ValueError(f"model layer is not a sha256 blob: {digest!r}")
            return f"/root/.ollama/models/blobs/sha256-{digest.split(':', 1)[1]}"
    raise ValueError("manifest has no model layer")


def installed_tags(base_url: str, request_json) -> list[dict[str, Any]]:
    """What `/api/tags` lists, or raise the reason it could not be read.

    Only ever used to *improve* a name (`manifest_path`, and `/api/show` and
    `/api/ps` via `canonical_tag`). A read that fails raises on purpose rather
    than being swallowed: a bare name with nothing to resolve it from would then
    have to be guessed, and a guessed tag is a path that does not exist whose
    `OSError` `open()` files as `fallback_reason` -- a server problem on the
    record for what is an unreadable metadata endpoint. That is the same
    misreading `require_ollama_endpoint()` exists to prevent one layer up.
    """
    payload = request_json(f"{base_url}/api/tags",
                          timeout=ENDPOINT_PROBE_TIMEOUT_SECONDS)
    if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
        raise WrongEndpoint(
            f"{base_url}/api/tags did not answer with an Ollama tag list "
            f"(got {type(payload).__name__}); it is not an Ollama endpoint."
        )
    return payload["models"]


def resolve_gguf(remote: Remote, model: str, tags: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """The GGUF to load for `model`, plus what the record needs to name it."""
    path = manifest_path(model, tags)
    gguf = gguf_from_manifest(json.loads(remote.read_in_container(path)))
    return {"gguf": gguf, "manifest_path": path, "gguf_sha256": gguf.rsplit("sha256-", 1)[-1]}


def canonical_tag(tags: list[dict[str, Any]], model: str) -> str | None:
    """The exact `name:tag` Ollama itself reports for `model`, if it reports one.

    A name Ollama lists is authoritative and always carries its tag; a name in a
    manifest is a human's shorthand. Reading the server's own spelling closes the
    class of mismatch rather than this instance of it: `qwen3-8-27b-q4km` and
    `qwen3-8-27b-q4km:latest` are the same model and different strings, and every
    place that string is used -- the manifest path, the `/api/show` probe, the
    `/api/ps` lookup -- wants the second one.

    An exact match wins over a bare-name match, so a caller that already wrote
    the full tag is never moved onto a different model -- which is what keeps
    `qwen3-8-27b-q4km:q5` off `:latest`. A bare name matching *two* listed tags
    is ambiguous and stays a miss, because guessing there would load different
    weights under a name that asked for a third.

    None means the server does not list it, which is not an error here: this
    only ever *improves* a name, and a model the server cannot list is one that
    will fail louder and more specifically later.
    """
    only = None
    # `with_default_tag` first, so a bare `qwen3-8-27b-q4km` and Ollama's
    # `qwen3-8-27b-q4km:latest` reduce to the same name part instead of to
    # `""` and itself.
    wanted = with_default_tag(model).rpartition(":")[0]
    for item in tags:
        reported = item.get("name") or item.get("model") or ""
        if not reported:
            continue
        if reported == model:
            return reported
        # Compared against the *name part* of every listed tag, which is what
        # makes `qwen3-8-27b-q4km` find `qwen3-8-27b-q4km:latest`.
        if reported.rpartition(":")[0] == wanted:
            if only is not None and only != reported:
                return None  # ambiguous; a miss beats a coin flip
            only = reported
    return only


# --- Wire translation ------------------------------------------------------

def to_wire(body: dict[str, Any]) -> dict[str, Any]:
    """Ollama-shaped harness body -> llama.cpp's /v1/chat/completions.

    Sampling translates name-for-name where both sides agree (temperature, seed,
    repeat_penalty, repeat_last_n), so a llama.cpp answer is decoded the way the
    record says it was. `format` becomes `response_format`. `think` is dropped:
    it is Ollama's analysis-channel switch with no llama.cpp equivalent, and
    llama.cpp's own templates own the channel. `keep_alive` is dropped because
    the process *is* the lifetime here.

    Tool turns need ids llama.cpp pairs a result to a call with, and Ollama's
    shape carries none. Ids are synthesized from the call's position in the
    history, which is stable because the same list is re-translated every round.
    """
    options = body.get("options") or {}
    messages: list[dict[str, Any]] = []
    calls_seen = 0
    for message in body.get("messages") or []:
        role = message.get("role")
        entry: dict[str, Any] = {"role": role, "content": message.get("content") or ""}
        if role == "tool":
            entry["tool_call_id"] = f"call_{calls_seen - 1}"
        elif message.get("tool_calls"):
            entry["tool_calls"] = [
                {
                    "id": f"call_{calls_seen + offset}",
                    "type": "function",
                    "function": {
                        "name": (call.get("function") or {}).get("name"),
                        "arguments": json.dumps(
                            (call.get("function") or {}).get("arguments") or {}
                        ),
                    },
                }
                for offset, call in enumerate(message["tool_calls"])
            ]
            calls_seen += len(message["tool_calls"])
            entry["content"] = message.get("content") or None
        messages.append(entry)
    wire: dict[str, Any] = {
        "messages": messages,
        "stream": False,
        "temperature": options.get("temperature", 0),
        "max_tokens": options.get("num_predict", 512),
        "seed": options.get("seed", 0),
        # llama-server's own rate, server-side, so it excludes this harness's
        # HTTP and queue overhead. The same quantity rex86_bench.sh labels
        # predicted_tps_server_measured for the same reason.
        "return_timings": True,
    }
    for key in ("repeat_penalty", "repeat_last_n", "top_p", "top_k", "min_p"):
        if key in options:
            wire[key] = options[key]
    if body.get("format") is not None:
        wire["response_format"] = (
            {"type": "json_object"} if body["format"] == "json" else body["format"]
        )
    if body.get("tools"):
        wire["tools"] = body["tools"]
    return wire


# finish_reason -> the done_reason chat(), classify_outcome() and was_capped()
# already read. The mapping is the whole point: an untranslated "length_cap"
# would be stored as a generation the harness cannot vouch for instead of a
# truncated answer, scoring cap-cut text as a real one.
FINISH_REASONS = {"stop": "stop", "length": "length", "tool_calls": "stop"}


def from_wire(payload: dict[str, Any]) -> dict[str, Any]:
    """llama.cpp's response -> the Ollama-shaped dict the harness reads."""
    choice = (payload.get("choices") or [{}])[0] or {}
    timings = payload.get("timings") or {}
    usage = payload.get("usage") or {}
    prompt_tokens = usage.get("prompt_tokens") or timings.get("prompt_n")
    output_tokens = usage.get("completion_tokens") or timings.get("predicted_n")
    predicted_ms = timings.get("predicted_ms")
    finish = choice.get("finish_reason")
    return {
        "message": dict(choice.get("message") or {}),
        "done_reason": FINISH_REASONS.get(finish, finish),
        "prompt_eval_count": prompt_tokens,
        "eval_count": output_tokens,
        # The harness reads these as nanoseconds and divides by 1e9; llama.cpp
        # reports milliseconds. Converting here keeps one unit everywhere.
        "eval_duration": int(predicted_ms * 1e6) if predicted_ms else 0,
        "prompt_eval_duration": int(timings["prompt_ms"] * 1e6) if timings.get("prompt_ms") else 0,
    }


# --- The server ------------------------------------------------------------

class EngineUnavailable(RuntimeError):
    """This model cannot be served by llama.cpp; the caller may fall back."""


class LlamaCppServer:
    """One llama-server per model, on the card, torn down when its slot ends.

    Implements `request_json(url, body)` so the harness hands it to chat() and
    to bench_tools.conduct_tool_rounds unchanged: the multi-round tool exchange
    is one code path for both engines rather than two that can drift.
    """

    def __init__(
        self,
        remote: Remote,
        model: str,
        gguf: dict[str, Any],
        *,
        num_ctx: int,
        request_timeout=None,
        log=None,
    ):
        self.remote = remote
        self.model = model
        self.gguf = gguf
        self.num_ctx = num_ctx
        # The harness's own request_timeout(), so how long a generation is
        # allowed stays one rule rather than two. It is a pure function of the
        # body; it is passed in because importing evaluate-models.py from here
        # would be a cycle.
        self._request_timeout = request_timeout
        self.log = log or (lambda _message: None)
        self.name = "ghidra-llamacpp-" + "".join(
            char if char.isalnum() else "-" for char in model
        )
        self.port = LLAMA_CONTAINER_PORT
        self.local_port = free_port()
        # The one endpoint this server answers on, reached through the tunnel.
        # A llama-server has no /api/* surface at all, so nothing here may be
        # built from the Ollama base URL: an OpenAI-shaped server reached at an
        # Ollama path is how "Unknown endpoint: GET /api/tags" was produced by
        # a fallback that had nowhere to fall back to.
        self.api_root = f"http://127.0.0.1:{self.local_port}"
        self.kv_retry = False
        self.vram_oom_first_attempt = False
        self.gpu_wait: dict[str, Any] = {}
        self.started_at: str | None = None
        # Published, because the record has to name the URL that answered. The
        # Ollama endpoint the operator configured is a different server and is
        # never this one.
        self.endpoint: str | None = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        """Load the model, retrying once with KV in host RAM if that OOMs.

        Raises EngineUnavailable if the model cannot be served at all. This never
        falls back on its own: the fallback has to be recorded against a reason
        the caller puts in the record, and this object has no record.
        """
        self.teardown()
        self.gpu_wait = self.wait_for_gpu()
        try:
            self._launch(kv_offload=False)
        except RuntimeError as first:
            if not is_vram_oom(str(first)):
                # Not the card's fault: an unsupported architecture, a missing
                # file, a bad flag. Retrying buys one identical failure and
                # files the real cause under VRAM.
                raise EngineUnavailable(str(first)) from first
            self.log(f"llama.cpp OOM loading {self.model}; retrying with --no-kv-offload")
            self.vram_oom_first_attempt = True
            self.teardown()
            # The failed container still holds whatever it managed to allocate.
            self.gpu_wait = self.wait_for_gpu()
            self.kv_retry = True
            try:
                self._launch(kv_offload=True)
            except RuntimeError as second:
                # The retry failing is a failure of this model, reported the same
                # way as any other load failure. Left as a bare RuntimeError it
                # would escape past ModelSession.open()'s handling as a different
                # exception type than the first attempt raises, so the two
                # failures a model can have would be recorded two different ways.
                raise EngineUnavailable(str(second)) from second

    def _launch(self, *, kv_offload: bool) -> None:
        # `--entrypoint` overrides the image's own, which is `/app/tools.sh`: a
        # subcommand *dispatcher*, not a passthrough. Handing it the binary as an
        # argument made it treat `/app/llama-server` as a tool name and exit 0
        # having printed its usage list -- so the container "started" and then
        # exited while loading, every model, on the first real run.
        # `read_in_container` overrides the same way for the same reason.
        # The override is the absolute path because tools.sh's own branch runs a
        # RELATIVE `./llama-server` and so depends on WORKDIR; this one must not.
        argv = [
            "run", "-d", "--name", self.name, "--gpus", "all",
            "-v", f"{OLLAMA_VOLUME}:/root/.ollama:ro",
            "-p", f"127.0.0.1:{self.port}:{self.port}",
            "--entrypoint", LLAMA_BINARY,
            LLAMA_IMAGE,
            "-m", self.gguf["gguf"],
            *server_flags(self.num_ctx, kv_offload=kv_offload),
        ]
        completed = self.remote.docker(*argv, timeout=180)
        if completed.returncode != 0:
            raise RuntimeError(
                "llama-server container failed to start: "
                f"{' '.join(completed.stderr.split())[-400:]}"
            )
        self.started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # The tunnel goes up before the readiness poll, not after: the health
        # check runs here, and here cannot reach the host's published port
        # until the forward exists. Docker's proxy is already listening at that
        # point even though llama-server is still loading the model, so
        # connecting early is not the same as the model being ready -- which is
        # why the poll below still has to distinguish the two.
        self.remote.open_tunnel(self.local_port, self.port)
        try:
            self._await_ready()
        except RuntimeError as exc:
            # An OOM is reported by the server's own log, not by the health poll,
            # so the text that decides the retry has to be assembled from both.
            raise RuntimeError(f"{exc}; server log: {self.server_log()}") from exc
        # Published only once the model is loaded, not once the tunnel is up. A
        # load that failed leaves the endpoint unpublished, so a run that fell
        # back records no llama.cpp URL rather than one nothing ever answered
        # on -- which is the same claim "the fallback engine served this" makes,
        # and must not be contradicted by a stale field beside it.
        self.endpoint = f"{self.api_root}/v1/chat/completions"
        self._require_gpu_residency()

    def _require_gpu_residency(self) -> None:
        """Refuse a model that came up with nothing in VRAM.

        llama-server prints "model loaded" for a CPU-only run exactly as it does
        for a GPU one, and fit can reach that state by shedding every layer:

            load_tensors: offloaded 0/42 layers to GPU

        A grade produced by CPU decode is worthless here, so this is a failure
        rather than a slow path. Partial offload -- some layers in RAM -- is the
        intended behaviour for a model larger than the card and is allowed.

        Only acts when the log states a layer count. A missing line means the
        measurement is unavailable, which is not the same as zero layers, and
        inventing a verdict from an absent line would fail models for the wrong
        reason.
        """
        place = self.residency()
        in_vram, total = place.get("gpu_layers"), place.get("layers_total")
        if in_vram is None or not total or in_vram > 0:
            return
        raise EngineUnavailable(
            f"{self.model}: llama.cpp loaded with 0/{total} layers in VRAM "
            f"(CPU-only); refusing to record a CPU-decoded grade"
        )

    def _await_ready(self) -> None:
        """Poll /health until the model is loaded.

        A 27B takes minutes and that is not a failure: there is no early exit on
        "not ready yet", only on a timeout or a container that stopped. A
        container that *exited* is the other half: a load OOM kills the process,
        so waiting on it would burn the whole 1800s to learn nothing.
        """
        deadline = time.monotonic() + LLAMA_LOAD_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            state = self.container_state()
            if state is None:
                raise RuntimeError("llama-server container does not exist")
            if state == "exited":
                raise RuntimeError(
                    f"llama-server exited while loading (status "
                    f"{self.exit_code()}): {self.server_log()}"
                )
            if state != "running":
                raise RuntimeError(f"llama-server container is {state}")
            if self.healthy():
                return
            time.sleep(5)
        raise RuntimeError(
            f"llama-server was still loading after {LLAMA_LOAD_TIMEOUT_SECONDS}s"
        )

    def exit_code(self) -> Any:
        completed = self.remote.docker(
            "inspect", "-f", "{{.State.ExitCode}}", self.name, timeout=30
        )
        return completed.stdout.strip() if completed.returncode == 0 else None

    def healthy(self) -> bool:
        try:
            with urllib.request.urlopen(
                f"{self.api_root}/health", timeout=5
            ) as response:
                return json.loads(response.read()).get("status") == "ok"
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            return False

    def wait_for_gpu(self) -> dict[str, Any]:
        """Block until the card is free, or the ceiling; record which happened.

        Returns whether it waited and what it saw, because "proceeded anyway",
        "the card was already free" and "the card could not be read at all" are
        three different facts about a run, and `reached_idle` is the field meant
        to tell them apart.

        An unreadable card is not an idle one. `vram_used_mib()` returns None
        when nvidia-smi fails over ssh, and treating that as free recorded
        `reached_idle: true` for a wait that measured nothing -- which then reads
        as "the card was verified free", the opposite of the truth, on a card
        that may well be holding a stale 7974 MiB.

        `unmeasurable` records that case so a reader can tell an unread card from
        a read one that simply stayed busy.
        """
        reached_idle = False
        unmeasurable = False
        used: int | None = None
        deadline = time.monotonic() + GPU_WAIT_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            used = self.vram_used_mib()
            if used is None:
                # Cannot be improved by waiting: the same call fails the same way.
                # Stop rather than burn the ceiling on a dead probe.
                unmeasurable = True
                break
            if used <= GPU_IDLE_MIB:
                reached_idle = True
                break
            time.sleep(5)
        return {
            "reached_idle": reached_idle,
            "vram_used_mib": used,
            "idle_threshold_mib": GPU_IDLE_MIB,
            "unmeasurable": unmeasurable,
        }

    def vram_used_mib(self) -> int | None:
        completed = self.remote.run(
            "nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits",
            timeout=20,
        )
        if completed.returncode != 0:
            return None
        try:
            return int(completed.stdout.splitlines()[0].strip())
        except (IndexError, ValueError):
            return None

    def container_state(self) -> str | None:
        completed = self.remote.docker(
            "inspect", "-f", "{{.State.Status}}", self.name, timeout=30
        )
        value = completed.stdout.strip()
        return value if completed.returncode == 0 and value else None

    def server_log(self, lines: int = 60) -> str:
        """The tail of the server's own log -- where the OOM text lives."""
        completed = self.remote.docker("logs", "--tail", str(lines), self.name, timeout=30)
        return " ".join((completed.stdout + completed.stderr).split())[-2000:]

    def residency(self) -> dict[str, Any]:
        """Where the model actually lives, measured from the server's own log.

        "model loaded" is printed whether the run is on the GPU or on the CPU,
        so it proves nothing on its own. llama-server states the placement in
        one line at load:

            load_tensors: offloaded 41/42 layers to GPU

        and sizes the buffers per device:

            load_tensors:        CUDA0 model buffer size = 17880.66 MiB
            llama_context: n_ctx                 = 24576
            llama_kv_cache:      CUDA0 KV buffer size =    480.00 MiB

        These are measurements, so they are what the record carries. A flag is
        a request, and copying the requested `-ngl` into a field named
        "layers in VRAM" would be a guess dressed as a fact.

        Ignore `CPU_Mapped model buffer size`: it reports the mmap'd file and
        appears in a healthy 41/42 run too, so its presence means nothing.
        """
        text = self.server_log(lines=400)
        layers = re.search(r"offloaded (\d+)/(\d+) layers", text)
        vram = re.search(r"CUDA0 model buffer size = ([\d.]+) MiB", text)
        kv = re.search(r"CUDA0 KV buffer size =\s*([\d.]+) MiB", text)
        ctx = re.search(r"n_ctx\s*=\s*(\d+)", text)
        in_vram, total = (int(layers.group(1)), int(layers.group(2))) if layers else (None, None)
        return {
            "gpu_layers": in_vram,
            "layers_total": total,
            "vram_mib": float(vram.group(1)) if vram else None,
            "kv_cache_mib": float(kv.group(1)) if kv else None,
            "n_ctx": int(ctx.group(1)) if ctx else None,
            # True when fit had to leave model layers in RAM, which is the
            # intended behaviour for a model larger than the card.
            "ram_offloaded": None if in_vram is None or not total else in_vram < total,
        }

    def teardown(self) -> None:
        self.remote.close()
        self.remote.docker("rm", "-f", self.name, timeout=180)

    # -- the record --------------------------------------------------------
    def provenance(self) -> dict[str, Any]:
        """Everything that has to travel with a number for it to mean anything.

        Per model, not per record: the flags, the KV retry and the fallback are
        properties of how the model was served, and every record of that model
        would otherwise repeat them.
        """
        # Engine-level facts only. ModelSession.provenance() owns the full record
        # and merges these with the fallback and VRAM fields, so there is one
        # place that decides what a serving record contains and it cannot be
        # satisfied by whichever branch remembered to add a field.
        return {
            "image": LLAMA_IMAGE,
            "binary": LLAMA_BINARY,
            "gguf": self.gguf["gguf"],
            "gguf_sha256": self.gguf["gguf_sha256"],
            "flags": server_flags(self.num_ctx, kv_offload=self.kv_retry),
            "kv_offload_disabled": self.kv_retry,
            "vram_oom_on_first_attempt": self.vram_oom_first_attempt,
            "gpu_wait": self.gpu_wait,
            "started_at": self.started_at,
            # Measured placement, not the flags we asked for. See residency().
            **self.residency(),
            # The URL that answered, so the record names the endpoint rather
            # than only the engine. `ModelSession.provenance()` merges this
            # with the Ollama endpoint; the two are different servers.
            "llamacpp_endpoint": self.endpoint,
        }

    # -- the transport -----------------------------------------------------
    def request_json(self, _url: str, body: dict[str, Any] | None = None,
                     timeout: int | None = None) -> dict[str, Any]:
        """Drop-in for the harness's `request_json(url, body, timeout)`.

        `url` is ignored: this is one model on one server, so there is exactly
        one endpoint. `timeout` comes from the harness's request_timeout() so a
        16000-token budget and an 8-token probe are not cut at the same wall
        clock, exactly as on the Ollama path.
        """
        if timeout is None:
            if self._request_timeout is None:
                raise RuntimeError("no request_timeout bound for sizing the wait")
            timeout = self._request_timeout(body)
        data = json.dumps(to_wire(body or {})).encode()
        request = urllib.request.Request(
            self.endpoint or f"{self.api_root}/v1/chat/completions",
            data=data, headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return from_wire(json.loads(response.read()))


def ollama_transport(base_url: str, request_json) -> Any:
    """The fallback's transport: Ollama's /api/chat, byte-identical to before.

    Not a class. The fallback has no lifecycle and no translation, so anything
    more would be a second implementation of nothing.
    """
    def post(url: str, body: dict[str, Any] | None = None,
             timeout: int | None = None) -> dict[str, Any]:
        return request_json(url, body, timeout)
    return post


class WrongEndpoint(RuntimeError):
    """The URL answers, but it is not an Ollama.

    Its own exception type because it is not a fact about any model: nothing is
    wrong with `qwen3-8-27b-q4km`, and reporting a probe of the wrong server as
    `model tag is not installed` sends the reader to debug a model that was
    never the problem. `Unknown endpoint: GET /api/tags` is the OpenAI-shaped
    server's own wording, and it is how this box's llama.cpp-shaped service on
    11434 identifies itself.
    """


# A metadata read, not a generation: this has to answer about a server that is
# not serving anything, so it gets the same short explicit wait
# evaluate-models.py's own metadata calls use rather than a generation's.
ENDPOINT_PROBE_TIMEOUT_SECONDS = 10


def probe_ollama_endpoint(base_url: str, request_json) -> dict[str, Any]:
    """Confirm `base_url` is Ollama before a run depends on it, or say why not.

    A 404 from `GET /api/tags` is the load-bearing case and the reason this
    exists. Ollama always serves that path; a server that 404s it is
    OpenAI-shaped -- llama.cpp's server, vLLM, an OpenAI-compatible gateway --
    and every Ollama call this harness makes (`/api/chat`, `/api/tags`,
    `/api/show`, `/api/ps`, `/api/generate`) will fail on it with a message
    about the model rather than about the URL. Verified live on this box:
    `GET /api/tags` on the local 11434 answers
    `{"message": "Unknown endpoint: GET /api/tags", "type": "invalid_request_error",
      "code": "not_found"}`.

    Returns the parsed tags payload on success; raises `WrongEndpoint` when the
    server is reachable and is not Ollama. A transport failure is *not* a wrong
    endpoint -- it is reported to the caller as the exception it already was, so
    one rule decides what "unreachable" means everywhere in the harness.
    """
    try:
        payload = request_json(f"{base_url}/api/tags", timeout=ENDPOINT_PROBE_TIMEOUT_SECONDS)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise WrongEndpoint(
                f"{base_url} answered 404 for GET /api/tags, so it is not Ollama. "
                f"Ollama is the homeserver's `ghidra-ollama-1` reached through an "
                f"`ssh -L` forward; point --base-url at that, not at a local "
                f"llama.cpp or OpenAI-compatible server."
            ) from exc
        raise
    if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
        raise WrongEndpoint(
            f"{base_url}/api/tags did not answer with an Ollama tag list "
            f"(got {type(payload).__name__} with keys "
            f"{sorted(payload)[:6] if isinstance(payload, dict) else 'n/a'}); "
            f"it is not an Ollama endpoint."
        )
    return payload


# --- Selection -------------------------------------------------------------

class ModelSession:
    """One model, served by whichever engine can serve it, for one slot's run.

    This is what the harness holds instead of a base_url: `transport` is the
    callable chat() and bench_tools already call, and `provenance` is what the
    record carries alongside every answer so a number can be traced to the
    engine, flags, KV retry, fallback and VRAM that produced it.

    The order is fixed by decision, not by preference: llama.cpp first for
    every model, one `--no-kv-offload` retry if and only if the load genuinely
    OOMed, then Ollama. Nothing here inspects parameter count, tag or filename
    to guess -- a wrong guess there is the class of bug that produced wrong
    answers earlier, and the OOM is observable rather than predictable.
    """

    def __init__(
        self,
        model: str,
        base_url: str,
        *,
        num_ctx: int,
        request_json,
        request_timeout,
        remote: Remote | None = None,
        log=None,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.num_ctx = num_ctx
        self.request_json = request_json
        self.request_timeout = request_timeout
        self.log = log or (lambda _message: None)
        self.transport: Any = None
        self.engine = None
        self.server: LlamaCppServer | None = None
        self.fallback_reason: str | None = None
        self.fallback_engine: str | None = None
        self._provenance: dict[str, Any] = {}
        self._remote = remote

    # -- selection ---------------------------------------------------------
    def open(self) -> Any:
        """Serve this model, on llama.cpp if at all possible, else Ollama.

        Returns the transport to use. Raises nothing for a model the *engine*
        cannot serve: an unresolvable GGUF or a model llama.cpp cannot load
        falls back to Ollama, and a model neither can serve fails later on the
        Ollama call itself -- which is a failure of that model, not of the run,
        and is reported by the slot that hit it.

        `UnresolvableModel` is the one exception that escapes rather than
        falling back: the caller named something that is not a model at all,
        and Ollama cannot serve that either -- answering by falling back would
        score whichever model happened to be resident and report success,
        which is what the first live run did.
        """
        try:
            self.server = self._start_llama_cpp()
        except UnresolvableModel:
            raise
        except Exception as exc:  # noqa: BLE001 -- any start failure may fall back
            # Includes an unresolved GGUF (a tag with no manifest) and any
            # transport failure reaching the host: both are "llama.cpp cannot
            # serve this", which is what the fallback is for. The reason is kept
            # verbatim in the record, because "fell back" without the cause is
            # not reproducible.
            self.fallback_reason = f"{type(exc).__name__}: {exc}"
            self.fallback_engine = "ollama"
            self.engine = "ollama"
            self.log(f"{self.model}: llama.cpp unavailable ({self.fallback_reason}); "
                     f"falling back to Ollama")
            # Tear down here rather than leaving it to close(). A start that
            # raises *after* `docker run -d` leaves a live container holding
            # whatever VRAM it allocated, and this function is about to return a
            # working Ollama transport -- the caller has no reason to know a
            # container exists, and the next model's load OOMs against it. That
            # is the "stale model held 7974 MiB for minutes" incident; releasing
            # it is best-effort, because a teardown failure here must not lose
            # the fallback the caller is about to use.
            try:
                self.close()
            except Exception as teardown_exc:  # noqa: BLE001 -- best-effort
                self.log(f"{self.model}: llama-server teardown after a failed "
                         f"start did not complete: {teardown_exc}")
            self.transport = ollama_transport(self.base_url, self.request_json)
            return self.transport
        self.engine = "llama.cpp"
        self.transport = self.server.request_json
        return self.transport

    def _start_llama_cpp(self) -> LlamaCppServer:
        remote = self._remote or Remote()
        self._remote = remote
        # The tag comes from the server's own tag list, not from the caller's
        # spelling and not from a default: `manifest_path` needs a tag it did not
        # invent, and this session already holds the transport that reads it.
        tags = installed_tags(self.base_url, self.request_json)
        gguf = resolve_gguf(remote, self.model, tags)
        server = LlamaCppServer(
            remote, self.model, gguf,
            num_ctx=self.num_ctx,
            request_timeout=self.request_timeout,
            log=self.log,
        )
        # Assigned *before* start() so a start failure still leaves close() a
        # handle on the container that is running. A load that times out or
        # raises after `docker run -d` leaves that container alive and holding
        # whatever VRAM it allocated; if the handle is only set on success,
        # every fallback-after-load-attempt leaks one, which is the "stale model
        # held 7974 MiB for minutes" incident this work exists to prevent.
        self.server = server
        server.start()
        return server

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        """Tear the model down so the next one is not blocked by it.

        Always called, whatever the slot did: a model that failed mid-slot still
        holds its container, and the next model's load would OOM against it.
        """
        if self.server is not None:
            # Snapshot before the handle goes, not after: the server's engine
            # facts are gone the moment the container does, and the model row in
            # the report is assembled after this runs.
            self._provenance = self.server.provenance()
            try:
                self.server.teardown()
            except Exception as exc:  # noqa: BLE001 -- teardown must not mask a result
                self.log(f"{self.model}: llama-server teardown failed: {exc}")
            self.server = None
        elif self._remote is not None:
            self._remote.close()

    def __enter__(self) -> "ModelSession":
        self.open()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- the record --------------------------------------------------------
    def provenance(self, vram_used_mib: int | None = None) -> dict[str, Any]:
        """The per-model engine facts, for the transcript and the report.

        Every field here is something a reader cannot infer from the score:
        which engine produced it, with which flags, whether the KV retry fired,
        whether and why Ollama took over, and what the card held at the time.

        `engine`, `fallback_engine` and `fallback_reason` are read live off this
        object; the llama.cpp half (image, binary, GGUF, flags, KV retry, GPU
        wait) comes from `self.server` while the server is up and from the
        snapshot taken at open() time once it is not. Both paths build the same
        key set, because a reader comparing two rows must not have to know which
        engine skipped a field.

        The snapshot is what makes a read after close() correct: close() tears the
        server down and clears the handle, so a read that trusted `self.server`
        alone reported a llama.cpp run as an Ollama one -- the misattribution
        that makes a mixed-engine table unreadable.

        Only `vram_used_mib`, which is a measurement of the moment, is merged
        live; the serving facts are fixed the moment the model starts.
        """
        record = dict(self._provenance)
        if self.server is not None:
            record.update(self.server.provenance())
        elif not record:
            # Nothing was ever opened (a caller that pinned the engine without
            # serving). Still the same shape, so a comparison does not have to
            # special-case it.
            record.update({
                "image": None, "binary": None, "gguf": None, "gguf_sha256": None,
                "flags": None, "kv_offload_disabled": False,
                "vram_oom_on_first_attempt": False, "gpu_wait": {}, "started_at": None,
            })
        record["engine"] = self.engine
        record["fallback_engine"] = self.fallback_engine
        record["fallback_reason"] = self.fallback_reason
        # Two servers, two endpoints, never one string reused for both. Ollama
        # answers /api/chat and /api/tags; llama.cpp answers
        # /v1/chat/completions and has no /api/* at all. The record named one
        # field for both, so a run that fell back to Ollama recorded the URL it
        # was *meant* to use rather than the one that answered -- and a reader
        # could not tell a llama.cpp-shaped endpoint pointed at by an Ollama
        # fallback from a working one. `base_url` is kept for the committed
        # report's own key; `ollama_base_url` is what the fallback actually used.
        record["base_url"] = self.base_url
        record["ollama_base_url"] = self.base_url
        record.setdefault("llamacpp_endpoint", None)
        # Present even when unmeasured, because "two rows a reader has to
        # compare must have the same shape" is the rule the rest follows.
        record["vram_used_mib"] = vram_used_mib
        return record

    def unload(self) -> None:
        """The Ollama-side teardown for a fallback run.

        The llama.cpp path has no /api/generate to call: the container *is* the
        lifetime and close() removes it.
        """
        if self.engine == "ollama":
            try:
                self.request_json(
                    f"{self.base_url}/api/generate",
                    {"model": self.model, "keep_alive": 0},
                    timeout=60,
                )
            except Exception:  # noqa: BLE001 -- unload is best-effort by design
                pass
