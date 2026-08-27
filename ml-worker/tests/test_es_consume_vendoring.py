"""#1971: ml-worker's copy of the shared ES consume module must match the
canonical one byte-for-byte -- the gpu_queue.py vendoring discipline
(llm-worker/tests/test_worker.py::GPUQueueVendoringTests is this repo's
precedent for exactly this check).

The checkpoint semantics this worker pioneered (#168/#188/#190) now live in
the vendored module and are additionally asserted against the cross-language
fixture stream in analysis/es-consume/fixtures/es-consume-parity.json by
analysis/es-consume/tests/test_es_consume.py (Python half) and
arcane/home/honeypot-attacker-identity-worker/attacker-identity-worker/
esconsume_test.go (Go half). This file only guards the copy itself.

Run: python -m pytest ml-worker/tests/test_es_consume_vendoring.py -v
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ml-worker"))

import es_consume  # noqa: E402


def test_vendored_es_consume_matches_canonical():
    canonical = (ROOT / "analysis/es-consume/es_consume.py").read_text()
    vendored = (ROOT / "ml-worker/es_consume.py").read_text()
    assert canonical == vendored, (
        "ml-worker/es_consume.py drifted from analysis/es-consume/es_consume.py -- "
        "re-copy the canonical file, do not edit the vendored one"
    )


def test_vendored_copy_is_registered():
    """A new consumer copies the module AND adds its path to
    VENDORED_COPY_REGISTRY so analysis/es-consume/tests/test_es_consume.py
    keeps watching every copy in CI."""
    assert "ml-worker/es_consume.py" in es_consume.VENDORED_COPY_REGISTRY
