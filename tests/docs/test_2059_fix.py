#!/usr/bin/env python3
"""Regression test for #2059: probe-real-session-run.sh posted real-session
prompts to Ollama's /api/chat without setting num_ctx, so a prompt built
from up to MAX_CONTENT_CHARS (12000) chars of captured commands went to
whatever context the target Ollama server happened to be configured with --
2048 tokens on a default install. The head of the evidence (the system
prompt and the earliest commands) was silently dropped before generation,
and the human judge this probe exists to feed was rating an incomplete
transcript without any signal that anything was missing.

The fix sets options.num_ctx in the POST body and checks the response's
done/truncated fields, failing loud instead of handing a partial result to
the judge. These tests drive the real script end-to-end with a fake `curl`
placed first on PATH (no network call, no live Ollama server needed) and
assert on the captured request body and the script's exit behavior.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "analysis" / "ghidra" / "benchmarks" / "probe-real-session-run.sh"

# MAX_CONTENT_CHARS defaults to 12000 chars; at ~4 chars/token for code-like
# attacker command text that's ~3000 tokens of transcript alone, before the
# system/user prompt scaffolding on top. This is the floor the issue asks
# for -- not necessarily the exact value the script picks.
MIN_NUM_CTX = 4096

STAGE1_OUTPUT = {
    "prompts": [
        {
            "session_id": "abc123",
            "real_command_count": 5,
            "transcript_truncated": False,
            "system_prompt": "SYS PROMPT",
            "user_prompt": "USER PROMPT",
        }
    ]
}


def _write_fake_curl(bin_dir: Path, response_file: Path, capture_file: Path) -> Path:
    """A `curl` stand-in for probe-real-session-run.sh's `curl -s URL -d @-`
    call: captures the POST body (read from stdin, since @- means "read
    data from stdin") to `capture_file`, then prints `response_file`'s
    contents back as the "server" response. Ignores its argv entirely --
    the real script always invokes curl the same way, so no arg parsing is
    needed, and this never makes a real network call."""
    fake_curl = bin_dir / "curl"
    fake_curl.write_text(
        "#!/usr/bin/env bash\n"
        f"cat > {capture_file}\n"
        f"cat {response_file}\n"
    )
    fake_curl.chmod(0o755)
    return fake_curl


def _run_script(tmp_path: Path, response_body: dict):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    capture_file = tmp_path / "captured_body.json"
    response_file = tmp_path / "response.json"
    response_file.write_text(json.dumps(response_body))
    _write_fake_curl(bin_dir, response_file, capture_file)

    stage1_file = tmp_path / "stage1.json"
    stage1_file.write_text(json.dumps(STAGE1_OUTPUT))

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"

    proc = subprocess.run(
        ["bash", str(SCRIPT), str(stage1_file), "qwen3:14b", "http://fake-ollama.invalid:11434"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    captured_body = json.loads(capture_file.read_text()) if capture_file.exists() else None
    return proc, captured_body


@pytest.fixture(autouse=True)
def _require_jq():
    # Graceful degrade where the binary itself is unavailable, mirroring
    # test_probe_real_session.py's StageZeroMergeFixturesTest -- the script
    # itself hard-requires jq, so there's nothing to test without it.
    if shutil.which("jq") is None:
        pytest.skip("jq binary not available on this executor")


def _ok_response(content: str = "hello judge") -> dict:
    return {
        "model": "qwen3:14b",
        "message": {"role": "assistant", "content": content},
        "done": True,
        "done_reason": "stop",
    }


def test_post_body_sets_num_ctx(tmp_path):
    """The whole bug: options.num_ctx was missing entirely, so the request
    silently used whatever context the target Ollama server defaulted to
    (2048 on a stock install) instead of a value sized for the prompt."""
    proc, body = _run_script(tmp_path, _ok_response())
    assert proc.returncode == 0, f"stderr: {proc.stderr}"
    assert body is not None, "fake curl never received a request body"
    assert "options" in body, "POST body must carry an options block"
    assert "num_ctx" in body["options"], "options block must set num_ctx (#2059)"


def test_num_ctx_is_large_enough_for_max_content_chars(tmp_path):
    """MAX_CONTENT_CHARS=12000 chars is ~3000 tokens of transcript alone at
    ~4 chars/token, before the system/user prompt scaffolding and response
    budget on top. num_ctx must clear that floor with real headroom."""
    _proc, body = _run_script(tmp_path, _ok_response())
    num_ctx = body["options"]["num_ctx"]
    assert isinstance(num_ctx, int) and not isinstance(num_ctx, bool)
    assert num_ctx >= MIN_NUM_CTX, (
        f"num_ctx={num_ctx} is not enough headroom for MAX_CONTENT_CHARS=12000 "
        f"(~3000 tokens) plus prompt scaffolding and the response"
    )


def test_done_false_fails_loud_instead_of_passing_a_partial_result(tmp_path):
    """Ollama's context-exceeded signal on a chat completion is done=false.
    The probe must refuse to print the (partial) content and must exit
    non-zero, not hand a silently truncated transcript to the judge."""
    response = _ok_response("partial, do not trust me")
    response["done"] = False
    proc, _body = _run_script(tmp_path, response)
    assert proc.returncode != 0, "done:false must cause a non-zero exit"
    assert "partial, do not trust me" not in proc.stdout, (
        "a truncated response must not be printed as if it were complete"
    )


def test_truncated_true_fails_loud_instead_of_passing_a_partial_result(tmp_path):
    """The other half of Ollama's truncation signal: an explicit
    truncated:true (even alongside done:true) must be treated the same as
    done:false -- both mean the judge would be reading an incomplete
    transcript."""
    response = _ok_response("partial, do not trust me")
    response["truncated"] = True
    proc, _body = _run_script(tmp_path, response)
    assert proc.returncode != 0, "truncated:true must cause a non-zero exit"
    assert "partial, do not trust me" not in proc.stdout


def test_normal_response_still_succeeds(tmp_path):
    """Guards against an over-eager truncation check breaking the happy
    path: a normal, complete response must still print and exit 0."""
    proc, _body = _run_script(tmp_path, _ok_response("this session shows reconnaissance"))
    assert proc.returncode == 0, f"stderr: {proc.stderr}"
    assert "this session shows reconnaissance" in proc.stdout


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
