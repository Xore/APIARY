"""The llm-worker's pinned model digest must match the approved-models authority.

`analysis/ghidra/models/approved-models.json` is the source of truth for which
model artifact each slot is qualified to run: tag, digest, schema hash, prompt
hash, request settings. `llm-worker/docker-compose.*.yml` re-states one of those
digests as a literal in `LLM_EXPECTED_MODEL_DIGEST`, and worker.py fails closed
when the installed model's digest does not equal it.

Two copies of the same fact drifted apart. The compose files pinned
`6488c96f...`, the digest of the older `qwen3.5:9b`, while the authority file
and the deployed host had long since moved to
`qwen3:14b@bdbd181c...`. Because the pin names no tag, nothing looked wrong --
until `_tag_digest()` compared them at runtime and raised:

    configured model digest does not match the installed model

That surfaced only as `stage daily_report failed ... ModelRequestError` in the
worker's cycle summary, with Ollama itself returning HTTP 200 throughout. The
daily report had been failing on every cycle, and was twice misdiagnosed --
first as an Ollama grammar-compiler bug, then as CPU inference timing out --
because the visible symptom names neither the digest nor the model.

Session analysis kept working the whole time, which is what made the drift
survive: `model_digest()` is reached on the report path but not on every stage,
so the deployment looked mostly healthy.

This test asserts the two agree. It does NOT assert any particular digest
value: when the fleet qualifies a new model, approved-models.json is what
changes, and this test then requires the compose pins to be moved with it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPROVED = REPO / "analysis" / "ghidra" / "models" / "approved-models.json"

# The compose files that hardcode a digest. docker-compose.yml is excluded on
# purpose: it passes the value through from the environment
# (`${LLM_EXPECTED_MODEL_DIGEST:-}`) rather than stating one.
PINNING_COMPOSE_FILES = [
    "llm-worker/docker-compose.captured-data.yml",
    "llm-worker/docker-compose.production-session-canary.yml",
    "llm-worker/docker-compose.synthetic-canary.yml",
]

DIGEST_RE = re.compile(
    r"^\s*LLM_EXPECTED_MODEL_DIGEST:\s*['\"]?([0-9a-f]{64})['\"]?\s*$", re.MULTILINE
)


def _approved_sessions_artifact() -> tuple[str, str]:
    """(tag, digest) for the slot the llm-worker runs."""
    data = json.loads(APPROVED.read_text(encoding="utf-8"))
    artifact = data["slots"]["sessions"]["artifact"]
    return artifact["tag"], artifact["digest"]


def test_approved_models_file_is_readable():
    """Guard against the scan passing vacuously if the authority file moves."""
    assert APPROVED.exists(), f"{APPROVED} is missing; if it moved, update this test"
    tag, digest = _approved_sessions_artifact()
    assert re.fullmatch(r"[0-9a-f]{64}", digest), f"sessions digest is not a sha256: {digest!r}"
    assert tag, "sessions artifact has no tag"


def test_compose_pins_match_the_approved_sessions_digest():
    _, approved_digest = _approved_sessions_artifact()
    offenders = []
    checked = 0
    for rel in PINNING_COMPOSE_FILES:
        path = REPO / rel
        assert path.exists(), f"{rel} is missing; if it moved, update this test"
        found = DIGEST_RE.findall(path.read_text(encoding="utf-8"))
        if not found:
            offenders.append(f"{rel}: no LLM_EXPECTED_MODEL_DIGEST literal found")
            continue
        for digest in found:
            checked += 1
            if digest != approved_digest:
                offenders.append(
                    f"{rel}: pins {digest} but approved-models.json's sessions slot "
                    f"is {approved_digest}. worker.py fails closed on this mismatch "
                    f"with 'configured model digest does not match the installed "
                    f"model', which surfaces only as a ModelRequestError in a stage "
                    f"summary."
                )
    assert checked, "no digest literals were checked -- the regex or the file list has drifted"
    assert not offenders, "llm-worker model digest pins disagree with the authority:\n  " + "\n  ".join(offenders)


def test_docs_quote_the_approved_artifact():
    """The README states the qualified default; keep it in step with the authority."""
    tag, digest = _approved_sessions_artifact()
    readme = REPO / "docs" / "llm-worker" / "README.md"
    assert readme.exists(), "docs/llm-worker/README.md is missing"
    text = readme.read_text(encoding="utf-8")
    assert f"{tag}@{digest}" in text, (
        f"docs/llm-worker/README.md does not name the approved artifact "
        f"{tag}@{digest}. It previously advertised a stale model/digest pair, "
        f"which is how the compose drift went unnoticed."
    )
