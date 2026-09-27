"""#3334: the injection corpus against the model that is actually served.

The other half of the lane. `test_injection_suite.py` proves the judge and the
corpus are right without a model; this file is the only place the corpus meets
the served model, which is the thing #3334 says nothing was measuring.

The whole design here is about the OFFLINE case, and the rule is narrow:

- Ollama is absent, unreachable, is not Ollama, or does not serve the pinned
  model  ->  SKIP, with a reason that names the endpoint, the model and the pin,
  and says in words that the suite did not run.
- Ollama serves the pinned model and a case fails  ->  FAIL.

A skip is never a pass. `skip_reason()` is a pure function of a `ModelProbe`,
so every branch of it is unit-tested offline in `SkipReasonTests` without a
network, and the model-touching test below is a thin shell: it asks for a reason
and skips with it verbatim, or runs the suite and asserts. Nothing in
`skip_reason()` can see a corpus result, so a failing case can never be
converted into a skip -- that separation is what makes a green run mean
something, and it is asserted rather than assumed in
`test_skip_reason_cannot_see_a_case_result`.

The default unit-test lane on a GitHub runner has no Ollama, so this file skips
there with a reason on purpose. `run-llm-injection-suite.sh` on the analysis
host is what measures the model weekly and on a pin change.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import injection_suite  # noqa: E402
import worker  # noqa: E402
from tests.test_worker import config  # noqa: E402

# Short on purpose: an offline box must skip in seconds, not hold the unit lane
# open on a connect timeout. This is a reachability probe, not the analysis call.
PROBE_TIMEOUT_SECONDS = 5

NOT_RUN = "the behavioural suite did NOT run"


@dataclass(frozen=True)
class ModelProbe:
    """What a single reachability probe learned. No verdict, no corpus."""

    url: str
    model: str
    expected_digest: str
    # None when no HTTP response came back at all (refused, DNS, timeout).
    status: int | None
    error: str | None
    served: tuple[str, ...]
    digest: str | None


def skip_reason(probe: ModelProbe) -> str | None:
    """Why the real-model suite must not run, or None to run it.

    Every non-None answer is an explicit, self-describing skip. None of it reads
    a case, a verdict, or a failure count, so "the model was steered" can never
    be reclassified as "the model was not here".
    """
    if probe.error is not None:
        return (
            f"Ollama at {probe.url} did not answer ({probe.error}); {NOT_RUN}. "
            f"This is an offline or absent-model skip, not a pass: the pinned "
            f"{probe.model} was never measured."
        )
    if probe.status != 200:
        return (
            f"something is listening at {probe.url} but /api/tags answered HTTP {probe.status}; "
            f"{NOT_RUN}, because that endpoint is not an Ollama the suite can drive. "
            f"An OpenAI-compatible server is not a substitute: the corpus needs the pinned {probe.model}."
        )
    if probe.model not in probe.served:
        return (
            f"Ollama at {probe.url} serves {sorted(probe.served) or 'nothing'}, not the pinned "
            f"{probe.model}; {NOT_RUN}. Pull and pin the model before treating this as a pass."
        )
    if probe.digest is None:
        return (
            f"Ollama at {probe.url} serves {probe.model} but returned no usable digest; {NOT_RUN}. "
            f"Without a digest the run could not be attributed to the pin "
            f"{probe.expected_digest[:12]}..., so it is not a measurement of the pinned model."
        )
    if probe.expected_digest and probe.digest != probe.expected_digest:
        return (
            f"Ollama at {probe.url} serves {probe.model} at digest {probe.digest[:12]}..., but the pin is "
            f"{probe.expected_digest[:12]}...; {NOT_RUN}. A verdict from an unpinned model is not a verdict "
            f"on the approved one."
        )
    return None


def probe_model(cfg, http_get=None) -> ModelProbe:
    """Ask the endpoint what it serves. Never raises; failures become reasons."""
    getter = http_get or _http_get
    try:
        response = getter(f"{cfg.ollama_url}/api/tags", PROBE_TIMEOUT_SECONDS)
    except Exception as exc:  # requests raises a family of these; be total
        return ModelProbe(cfg.ollama_url, cfg.model, cfg.expected_model_digest, None, f"{type(exc).__name__}: {exc}", (), None)

    status = int(getattr(response, "status_code", 0) or 0)
    if status != 200:
        return ModelProbe(cfg.ollama_url, cfg.model, cfg.expected_model_digest, status, None, (), None)
    try:
        models = response.json().get("models", [])
    except Exception as exc:
        return ModelProbe(cfg.ollama_url, cfg.model, cfg.expected_model_digest, status, f"unreadable /api/tags body: {exc}", (), None)

    served: list[str] = []
    digest: str | None = None
    for item in models:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("model") or "")
        if not name:
            continue
        served.append(name)
        if name == cfg.model and digest is None:
            candidate = str(item.get("digest") or "")[:128]
            if worker.MODEL_DIGEST_RE.fullmatch(candidate):
                digest = candidate
    return ModelProbe(cfg.ollama_url, cfg.model, cfg.expected_model_digest, status, None, tuple(sorted(served)), digest)


def _http_get(url: str, timeout: int):
    import requests

    session = requests.Session()
    # Same rule as OllamaClient: an operator's proxy must not carry this probe,
    # and a redirect is a misconfiguration to report, not to follow.
    session.trust_env = False
    return session.get(url, timeout=timeout, allow_redirects=False)


APPROVED_MODELS = Path(__file__).resolve().parents[2] / "analysis" / "ghidra" / "models" / "approved-models.json"


def approved_pin() -> dict[str, str]:
    """The sessions slot of the approved manifest: the model this suite is for.

    Without this the skip reason would name the unit-test fixture's model and a
    reader could take "did not run" as a statement about the wrong artifact. If
    the manifest is not reachable (a container built from llm-worker/ alone does
    not ship it), the caller's own config stands and `worker.py --injection-suite`
    is the path that matters there.
    """
    try:
        with APPROVED_MODELS.open(encoding="utf-8") as handle:
            artifact = json.load(handle)["slots"]["sessions"]["artifact"]
        return {"model": str(artifact["tag"]), "expected_model_digest": str(artifact["digest"])}
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def suite_config():
    """Config for the real model, overridable for a local/analysis host."""
    changes = dict(enabled=True, dry_run=True, allow_captured_data=False)
    changes.update(approved_pin())
    for env, key in (
        ("LLM_INJECTION_SUITE_OLLAMA_URL", "ollama_url"),
        ("LLM_INJECTION_SUITE_MODEL", "model"),
        ("LLM_INJECTION_SUITE_DIGEST", "expected_model_digest"),
    ):
        value = os.environ.get(env)
        if value:
            changes[key] = value
    return config(**changes)


class SkipReasonTests(unittest.TestCase):
    """Every branch, offline. A skip must always be explainable."""

    def probe(self, **changes) -> ModelProbe:
        base = dict(
            url="http://ollama:11434",
            model="qwen3:14b",
            expected_digest="b" * 64,
            status=200,
            error=None,
            served=("qwen3:14b",),
            digest="b" * 64,
        )
        base.update(changes)
        return ModelProbe(**base)

    def test_a_serving_pinned_model_runs(self):
        self.assertIsNone(skip_reason(self.probe()))

    def test_offline_is_an_explicit_skip(self):
        reason = skip_reason(self.probe(status=None, error="ConnectionError: refused", served=(), digest=None))
        self.assertIn(NOT_RUN, reason)
        self.assertIn("ConnectionError: refused", reason)
        self.assertIn("qwen3:14b", reason)

    def test_a_non_ollama_endpoint_is_named_as_such(self):
        reason = skip_reason(self.probe(status=404, served=(), digest=None))
        self.assertIn(NOT_RUN, reason)
        self.assertIn("HTTP 404", reason)
        self.assertIn("not an Ollama", reason)

    def test_absent_model_is_a_skip_not_a_pass(self):
        reason = skip_reason(self.probe(served=("llama3:8b",), digest=None))
        self.assertIn(NOT_RUN, reason)
        self.assertIn("llama3:8b", reason)

    def test_missing_digest_is_a_skip(self):
        reason = skip_reason(self.probe(digest=None))
        self.assertIn(NOT_RUN, reason)

    def test_digest_mismatch_is_a_skip(self):
        reason = skip_reason(self.probe(digest="c" * 64))
        self.assertIn(NOT_RUN, reason)
        self.assertIn("b" * 12, reason)
        self.assertIn("c" * 12, reason)

    def test_every_reason_says_the_suite_did_not_run(self):
        probes = [
            self.probe(),
            self.probe(status=None, error="refused", served=(), digest=None),
            self.probe(status=500, served=(), digest=None),
            self.probe(served=(), digest=None),
            self.probe(digest=None),
            self.probe(digest="c" * 64),
        ]
        for probe in probes:
            reason = skip_reason(probe)
            if reason is None:
                continue
            self.assertIn(NOT_RUN, reason, f"unexplained skip for {probe}")
            self.assertGreater(len(reason), 80, f"skip reason too terse to act on: {reason}")

    def test_skip_reason_cannot_see_a_case_result(self):
        # The separation that makes a green run mean something: the gate takes
        # only endpoint state. A steered model cannot become a skip, because a
        # skip has nowhere to put a verdict.
        import inspect

        self.assertEqual(
            list(inspect.signature(skip_reason).parameters),
            ["probe"],
        )
        self.assertFalse({"CASES", "CORPUS", "report", "judge"} & set(inspect.signature(skip_reason).parameters))


class ProbeTests(unittest.TestCase):
    def test_probe_reports_a_transport_failure_instead_of_raising(self):
        def boom(url, timeout):
            raise OSError("no route to host")

        probe = probe_model(config(ollama_url="http://ollama:11434"), http_get=boom)
        self.assertIsNone(probe.status)
        self.assertIn("no route to host", probe.error or "")
        self.assertIn(NOT_RUN, skip_reason(probe) or "")

    def test_probe_reads_the_served_digest(self):
        class Response:
            status_code = 200

            def json(self):
                return {"models": [{"name": "qwen3:14b", "digest": "d" * 64}, {"name": "nomic-embed-text", "digest": "e" * 64}]}

        probe = probe_model(config(ollama_url="http://ollama:11434", model="qwen3:14b", expected_model_digest="d" * 64), http_get=lambda url, timeout: Response())
        self.assertEqual(probe.digest, "d" * 64)
        self.assertIsNone(skip_reason(probe))

    def test_probe_ignores_a_malformed_digest(self):
        class Response:
            status_code = 200

            def json(self):
                return {"models": [{"name": "qwen3:14b", "digest": "not-a-digest"}]}

        probe = probe_model(config(ollama_url="http://ollama:11434", model="qwen3:14b", expected_model_digest="d" * 64), http_get=lambda url, timeout: Response())
        self.assertIsNone(probe.digest)
        self.assertIn(NOT_RUN, skip_reason(probe) or "")


class ServedModelCorpusTests(unittest.TestCase):
    """The one test that loads the model. Skips, loudly, when it cannot."""

    def test_corpus_against_the_served_model(self):
        if os.environ.get("LLM_INJECTION_SUITE", "").strip().lower() in {"off", "0", "false"}:
            self.skipTest(
                f"LLM_INJECTION_SUITE is off, so {NOT_RUN}. This is an operator opt-out, "
                "not a result: the pinned model is unmeasured until the weekly or pin-change run."
            )
        cfg = suite_config()
        reason = skip_reason(probe_model(cfg))
        if reason is not None:
            self.skipTest(reason)

        client = worker.OllamaClient(cfg)
        report = injection_suite.run_all(client.analyze, cfg.max_content_chars)
        failed = [case for case in report["cases"] + report["control"]["cases"] if not case["passed"]]
        self.assertEqual(
            [],
            [
                {"name": case["name"], "failures": case["failures"], "raw_intent": case["raw_intent"], "raw_severity": case["raw_severity"]}
                for case in failed
            ],
            f"the served {cfg.model} did not hold the injection corpus: "
            f"{json.dumps([{'name': c['name'], 'failures': c['failures']} for c in failed], indent=2)}",
        )
        self.assertTrue(injection_suite.all_passed(report))


if __name__ == "__main__":
    unittest.main()
