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
the same case and book one run as two.

**Everything that makes a number interpretable is recorded.** Engine, flags, KV
retry, fallback reason, achieved tokens/second, VRAM at the time. A result that
does not say which engine produced it cannot be compared against one that does.

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


def server_flags(num_ctx: int, *, kv_offload: bool) -> list[str]:
    """The llama-server argv tail, KV placement included.

    `--no-kv-offload` appears for exactly one reason: the load OOMed. There is no
    per-run configuration for it, because a flag an operator sets by hand is a
    flag that quietly diverges from what the record says ran.
    """
    flags = [
        "-ngl", LLAMA_GPU_LAYERS,
        "-c", str(num_ctx),
        "--host", "0.0.0.0",
        "--port", str(LLAMA_CONTAINER_PORT),
    ]
    if kv_offload:
        flags.append("--no-kv-offload")
    return flags


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

def manifest_path(model: str) -> str:
    """The Ollama manifest for `model`, as a path under /root/.ollama/models.

    Two namespaces are live on this host: `registry.ollama.ai/library/<name>` for
    tags pulled by name, and `hf.co/<repo>:<quant>` for GGUF repos imported as
    `hf.co/`. Ollama's own rule is whether the name already carries a registry,
    so a tag containing `/` is treated as namespaced.
    """
    name, _, tag = model.rpartition(":")
    if not name:
        raise ValueError(f"model tag has no tag part: {model}")
    if "/" not in name:
        name = f"registry.ollama.ai/library/{name}"
    return f"/root/.ollama/models/manifests/{name}:{tag}"


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


def resolve_gguf(remote: Remote, model: str) -> dict[str, Any]:
    """The GGUF to load for `model`, plus what the record needs to name it."""
    path = manifest_path(model)
    gguf = gguf_from_manifest(json.loads(remote.read_in_container(path)))
    return {"gguf": gguf, "manifest_path": path, "gguf_sha256": gguf.rsplit("sha256-", 1)[-1]}


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
        self.kv_retry = False
        self.vram_oom_first_attempt = False
        self.gpu_wait: dict[str, Any] = {}
        self.started_at: str | None = None

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
        argv = [
            "run", "-d", "--name", self.name, "--gpus", "all",
            "-v", f"{OLLAMA_VOLUME}:/root/.ollama:ro",
            "-p", f"127.0.0.1:{self.port}:{self.port}",
            LLAMA_IMAGE, LLAMA_BINARY,
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
                f"http://127.0.0.1:{self.local_port}/health", timeout=5
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
            f"http://127.0.0.1:{self.local_port}/v1/chat/completions",
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

        Returns the transport to use. Raises nothing for an unservable model:
        an unresolvable GGUF or a model llama.cpp cannot load falls back to
        Ollama, and a model neither can serve fails later on the Ollama call
        itself -- which is a failure of that model, not of the run, and is
        reported by the slot that hit it.
        """
        try:
            self.server = self._start_llama_cpp()
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
        gguf = resolve_gguf(remote, self.model)
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
        record["base_url"] = self.base_url
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
