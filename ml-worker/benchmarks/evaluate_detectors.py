#!/usr/bin/env python3
"""Tier 1 contract benchmark for ml-worker detectors (issue #1794).

We have an acceptance bar for LLM model selection that works -- fixed fixtures,
a gate a higher raw score can never override, a verified report, a decision
record. There is no equivalent for the anomaly detectors, which is what makes
every "evaluate this candidate offline against real data" proposal
undecidable: there is nothing to decide *against*.

This is the ruler, not a detector. It answers **"does this candidate behave
correctly"**, which is a different and more basic question than "is it
accurate". Accuracy needs labels; see Tier 2 below.

## Why behaviour first, and why these behaviours

Three of the checks here encode failures that would be invisible in an accuracy
number and catastrophic in production:

- **Abstention is not a low score.** A detector with no usable opinion --
  `LSTMAEModel.score()` before its first accepted fit or before `SEQ_LEN`
  events exist for a source, any untrained detector -- must not assert
  anything at all, let alone normality. Under the #1969 contract it returns
  `None`, the composite excludes it and renormalises over the detectors that
  did opine. A candidate that returns a small-but-nonzero score there is
  asserting normality about a source it has barely seen, and the difference
  never shows up in AUPRC.
- **A failure must read as absence, not safety.** On an inference exception a
  detector returns `None` (#1969): excluded from the blend rather than
  counted. The v1 harness demanded the neutral `0.5` here; a constant that
  keeps its full ensemble weight is its own quiet defect -- #1959 measured
  6,669 alerts partly clearing the bar on exactly such a floor (untrained
  IsoForest at 0.5). What a broken detector must never do remains the same:
  return a confident low value.
- **Every sensor's schema must survive.** Dionaea and Conpot documents have
  gaps the Cowrie-shaped ones do not. A detector that throws on one sensor's
  events silently stops scoring that sensor, and the alert count merely goes
  down -- which looks like good news.

And one check encodes the ensemble itself:

- **The composite renormalises over present detectors.** Absent inputs are
  dropped from BOTH numerator and denominator (the old skipped-LSTM-as-0.0
  acted as an undocumented veto capping every composite below threshold);
  an all-absent event composites to 0.0 and cannot fire.

## Two tiers, deliberately not conflated

- **Tier 1 (this file): contract fixtures, synthetic, in-repo.** Answers
  "does it behave correctly". No labels needed, so it runs today.
- **Tier 2: a labelled ranking corpus.** Answers "is it accurate", and needs
  AUPRC as the headline (anomalies are rare and AUROC flatters under skew),
  alert-budget precision at the operating threshold, and seed variance over
  >= 3 seeds. **Blocked on #1797** -- if BETH does not map onto our feature
  extractors, this benchmark ships as Tier 1 only, and that is said out loud
  rather than shipping a harness that quietly cannot rank.

## Rules inherited from the LLM side rather than reinvented

The benchmark never trains or downloads anything; the operator prepares
candidates as a separate reviewed step; the raw report is preserved outside the
repo; results land in a decision record; promotion goes through the existing
versioning path, never a hand-edit.

## Banned, with a reason

**Point-adjusted F1.** Under the PA protocol a random anomaly score becomes
state-of-the-art (Kim et al., AAAI 2022, arXiv:2109.05257): PA marks an entire
anomalous segment detected if any single point in it is flagged, which rewards
trigger-happy detectors. Had we built the obvious thing, we would have shipped
a harness that ranks a coin flip above the LSTM-AE and looks rigorous doing it.
If a segment-level metric is wanted, use PA%K with K stated. Also banned: any
metric computed on a random or time-shuffled split.

## The split rule, for Tier 2 and for any retrain

Partition **first**, then build windows -- never the reverse. Group by
`src_ip`. Preserve temporal order. Hold the anomalous population out of
training. Disclose the padding convention in the report.

This applies to our existing code, not only to future candidates:
`LSTMAEModel.retrain()` builds overlapping length-15 windows per `src_ip`, and
building those before the split reproduces exactly the leakage that motivates
the rule -- worth up to 0.23 macro-F1 and a 67x false-alarm difference on the
data where it was measured.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

BENCHMARK_VERSION = "apiary-ml-worker-tier1-v2"

# The v1 sentinels are gone from production (#1969): "no signal yet" was
# ABSTENTION == 0.0 (LSTM-AE below SEQ_LEN), an untrained detector or an
# inference failure returned NEUTRAL == 0.5. All three states now collapse
# into ONE honest semantic -- no opinion, encoded as None -- which the
# ensemble excludes before renormalising over the detectors that did opine.
ABSENT = None


class ContractViolation(RuntimeError):
    pass


@dataclass
class Candidate:
    """A detector under test, reduced to the one call the harness needs.

    The production contract is not uniform -- `LSTMAEModel.score()` takes a raw
    ES `_source` dict, while `IsoForestModel.score()` takes an already-extracted
    feature vector -- so each candidate supplies the adapter rather than the
    harness guessing. Keeping that explicit is the point: a harness that
    silently adapted would hide a real difference between the detectors.
    """

    name: str
    score_event: Callable[[dict, int], Any]  # float in [0,1], or None = no opinion (#1969)
    # Every production detector now abstains pre-calibration (#1969). The
    # flag stays declared per candidate so a future hard-opinion detector
    # can opt out of the abstention checks explicitly.
    abstains: bool = True
    # True when this candidate carries real fitted state (loaded weights),
    # which the fault-injection check needs to be meaningful: on an
    # untrained model, pre-fault and post-fault both return None and the
    # check would pass vacuously.
    trained: bool = False
    # Events needed before the candidate stops abstaining and actually runs
    # inference. The fault-injection check is meaningless below this.
    prime_events: int = 0
    notes: str = ""


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str
    observed: Any = None
    # A check that could not run is not a check that passed. Recorded
    # separately so a partially-exercised candidate cannot read as a clean one.
    skipped: bool = False


@dataclass
class Report:
    candidate: str
    checks: list[CheckResult] = field(default_factory=list)
    # Any bound the run applied. A truncated run that reads as full coverage is
    # the failure mode; state it rather than letting the reader assume.
    caps: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks if not c.skipped)

    def as_dict(self) -> dict[str, Any]:
        return {
            "candidate": self.candidate,
            "passed": self.passed,
            "checks": [
                {"name": c.name, "passed": c.passed, "skipped": c.skipped,
                 "detail": c.detail, "observed": c.observed}
                for c in self.checks
            ],
            "caps": self.caps,
            "counts": {
                "total": len(self.checks),
                "passed": sum(1 for c in self.checks if c.passed and not c.skipped),
                "failed": sum(1 for c in self.checks if not c.passed and not c.skipped),
                "skipped": sum(1 for c in self.checks if c.skipped),
            },
        }


def _bounded(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0.0 <= float(value) <= 1.0


def check_scores_are_bounded(candidate: Candidate, documents: list[dict]) -> CheckResult:
    """Every opinion must be a real number in [0, 1]; absence must be None.

    The composite blends the detectors that opine; one returning a NaN or an
    out-of-range value poisons the blend rather than failing visibly. Under
    #1969 a detector may also decline to opine -- but it must do so with None,
    not with a low score that reads as normal.
    """
    bad = []
    absent = 0
    for index, doc in enumerate(documents):
        try:
            value = candidate.score_event(doc, 0)
        except Exception as exc:  # a throw is covered by its own check
            bad.append(f"doc[{index}] raised {type(exc).__name__}")
            continue
        if value is None:
            absent += 1
            continue
        if not _bounded(value):
            bad.append(f"doc[{index}] -> {value!r}")
    if bad:
        return CheckResult("scores_are_bounded", False, f"out of range: {bad[:5]}", observed=len(documents))
    return CheckResult(
        "scores_are_bounded",
        True,
        f"every score is a float in [0, 1] ({absent}/{len(documents)} abstained as None)",
        observed=len(documents),
    )


def check_survives_every_sensor_schema(candidate: Candidate, by_sensor: dict[str, dict]) -> CheckResult:
    """No sensor's document shape may raise.

    A detector that throws on one sensor stops scoring it, and the alert count
    merely drops -- which looks like an improvement.
    """
    failures = {}
    for sensor, doc in by_sensor.items():
        try:
            candidate.score_event(doc, 0)
        except Exception as exc:
            failures[sensor] = f"{type(exc).__name__}: {exc}"
    return CheckResult(
        "survives_every_sensor_schema",
        not failures,
        "every sensor schema scored without raising" if not failures else f"raised: {failures}",
        observed=sorted(by_sensor),
    )


def check_survives_malformed_document(candidate: Candidate, malformed: dict) -> CheckResult:
    """A document missing its timestamp must not take the worker down."""
    try:
        value = candidate.score_event(malformed, 0)
    except Exception as exc:
        return CheckResult("survives_malformed_document", False,
                           f"raised {type(exc).__name__}: {exc}")
    # None (absence) is a legal outcome on a hopeless document; a raise is
    # not, and neither is a non-[0,1] opinion (#1969 contract).
    passed = value is None or _bounded(value)
    return CheckResult("survives_malformed_document", passed,
                       "malformed document scored without raising", observed=value)


def check_abstains_without_history(candidate: Candidate, doc: dict) -> CheckResult:
    """Fewer than SEQ_LEN events for a source must abstain (None), not score low.

    A small-but-nonzero score asserts normality about a source barely seen, and
    no accuracy metric would show it (#1969: absence is None, never 0.0).
    """
    if not candidate.abstains:
        return CheckResult("abstains_without_history", True,
                           "candidate declares it does not abstain",
                           skipped=True)
    value = candidate.score_event(doc, 0)
    passed = value is None
    return CheckResult(
        "abstains_without_history", passed,
        "first event for a source returns no opinion (None)" if passed
        else f"returned {value!r}, which asserts normality about an unseen source",
        observed=repr(value),
    )


def check_abstains_on_inference_failure(candidate: Candidate, doc: dict,
                                        break_inference: Callable[[], None] | None,
                                        prime: int = 0) -> CheckResult:
    """An inference error must abstain (None), never return a confident value.

    Failing to a low score reads as "confirmed normal" -- the one answer a broken
    detector must never give. The v1 harness demanded neutral 0.5 here; #1969
    replaced that with exclusion-plus-renormalisation, since a placeholder that
    keeps its ensemble weight is a vote from nothing (exactly what #1959 measured
    doing damage with untrained IsoForest's constant).

    `prime` events are scored *before* the fault is injected. Without that this
    check is worthless for an abstaining detector: `LSTMAEModel.score()` returns
    None and never reaches inference until SEQ_LEN events have accumulated, so a
    broken model would look like a failing one. Getting this wrong the first time
    produced exactly that false result. Even primed, an UNTRAINED candidate never
    reaches inference either (#1969), so on one this check is skipped rather than
    allowed to pass vacuously -- pre-fault and post-fault would both be None.
    """
    if break_inference is None:
        return CheckResult("abstains_on_inference_failure", True,
                           "candidate supplied no fault injector", skipped=True)
    if not getattr(candidate, "trained", False):
        return CheckResult("abstains_on_inference_failure", True,
                           "candidate is untrained; it never reaches inference, so the "
                           "fault cannot be exercised (skipped, not vacuously passed)",
                           skipped=True)
    for _ in range(prime):
        try:
            candidate.score_event(doc, 0)
        except Exception as exc:
            return CheckResult("abstains_on_inference_failure", False,
                               f"raised {type(exc).__name__} while priming, before any fault")
    break_inference()
    try:
        value = candidate.score_event(doc, 0)
    except Exception as exc:
        return CheckResult("abstains_on_inference_failure", False,
                           f"propagated {type(exc).__name__} instead of abstaining")
    passed = value is None
    return CheckResult(
        "abstains_on_inference_failure", passed,
        "inference failure abstains (None), excluded from the composite" if passed
        else f"returned {value!r}; a scoring error must not read as any confidence",
        observed=repr(value),
    )


def check_composite_renormalises_over_present_detectors() -> CheckResult:
    """The ensemble itself must treat absence as absence (#1969).

    Runs production worker.compute_composite() directly against
    score-with-detector-absent cases so candidates are always compared under
    the rules they will actually run with:

    - skipped/untrained/failed detectors drop out of BOTH numerator and
      denominator (the old skipped-LSTM-as-0.0 encoding acted as an
      undocumented veto, capping every composite at 0.6 under the default
      threshold);
    - an event where NO detector opines composites to 0.0 and cannot fire;
    - single-detector opinions stand at face value (weights renormalise to 1).
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import worker

    cases = [
        ({}, 0.0),
        ({"isolation_forest": None, "lstm_ae": None, "hbos": None}, 0.0),
        ({"isolation_forest": 1.0, "lstm_ae": None, "hbos": 1.0}, 1.0),   # renorm over {iso,hbos}
        ({"isolation_forest": 1.0, "lstm_ae": None, "hbos": None}, 1.0),  # single-opinion stands
        ({"isolation_forest": 0.5, "lstm_ae": None, "hbos": None}, 0.5),
        ({"isolation_forest": 1.0, "lstm_ae": 1.0, "hbos": 1.0}, 1.0),    # full ensemble unchanged
    ]
    bad = []
    for scores, expected in cases:
        got = worker.compute_composite(scores)
        contributors = worker.contributing_detectors(scores)
        expected_contributors = sorted(k for k, v in scores.items() if v is not None)
        if abs(got - expected) > 1e-9 or contributors != expected_contributors:
            bad.append(f"{scores} -> composite={got} contributors={contributors}")
    passed = not bad
    return CheckResult(
        "composite_renormalises_over_present_detectors",
        passed,
        "absent detectors excluded from numerator AND denominator; all-absent -> 0.0"
        if passed else f"violations: {bad}",
        observed=len(cases),
    )


def run_checks(candidate: Candidate, fixtures: dict[str, Any],
               break_inference: Callable[[], None] | None = None) -> Report:
    report = Report(candidate=candidate.name)
    documents = fixtures["documents"]
    report.checks.append(check_abstains_without_history(candidate, fixtures["single_event"]))
    report.checks.append(check_scores_are_bounded(candidate, documents))
    report.checks.append(check_survives_every_sensor_schema(candidate, fixtures["by_sensor"]))
    report.checks.append(check_survives_malformed_document(candidate, fixtures["malformed"]))
    report.checks.append(check_abstains_on_inference_failure(
        candidate, fixtures["single_event"], break_inference, candidate.prime_events))
    report.checks.append(check_composite_renormalises_over_present_detectors())
    report.caps.append(f"{len(documents)} contract fixtures; this tier does not measure accuracy")
    return report


def write_atomic(path: str, value: dict[str, Any]) -> str:
    destination = os.path.abspath(path)
    os.makedirs(os.path.dirname(destination) or ".", exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    handle, temporary = tempfile.mkstemp(prefix=".detectors-", dir=os.path.dirname(destination) or ".")
    try:
        with os.fdopen(handle, "wb") as output:
            output.write(payload)
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return hashlib.sha256(payload).hexdigest()


def load_fixtures() -> dict[str, Any]:
    """Contract fixtures, reusing ml-worker/tests/fixtures.py.

    Those documents are already the per-sensor shapes the worker sees, already
    reviewed, and already use TEST-NET addresses and reserved names. Writing a
    second set would mean two things to keep in step with the sensors.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from tests import fixtures as f  # noqa: E402

    # The fixtures are whole ES hits (_index/_id/_source); the detectors take
    # the raw _source dict. Unwrapping here rather than at each call site is
    # deliberate -- feeding a hit where a _source is expected does not raise,
    # it just silently finds none of the fields and scores a document that is
    # effectively empty.
    def src(hit: dict) -> dict:
        return hit.get("_source", hit)

    by_sensor = {
        "cowrie-login": src(f.COWRIE_LOGIN_FAILED),
        "cowrie-command": src(f.COWRIE_COMMAND_INPUT),
        "dionaea-connection": src(f.DIONAEA_CONNECTION_ACCEPT),
        "dionaea-incident": src(f.DIONAEA_INCIDENT_RAW),
        "conpot-modbus": src(f.CONPOT_MODBUS_REQUEST),
        "http-login": src(f.HTTP_HONEYPOT_LOGIN_ATTEMPT),
        "suricata-alert": src(f.SURICATA_ALERT),
    }
    return {
        "documents": [src(d) for d in f.ALL_REAL_DOCUMENTS],
        "by_sensor": by_sensor,
        "malformed": src(f.MALFORMED_MISSING_TIMESTAMP),
        "single_event": src(f.COWRIE_COMMAND_INPUT),
        "sequence": [src(d) for d in f.COWRIE_SAME_IP_SEQUENCE],
    }


def build_candidates(names: list[str]) -> list[tuple[Candidate, Callable[[], None] | None]]:
    """Wrap the deployed detectors in the harness's uniform view.

    Imported lazily so the module stays usable -- and testable -- without torch
    present.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    built = []
    for name in names:
        if name == "lstm-ae":
            from models.lstm_autoencoder import LSTMAEModel

            model = LSTMAEModel()

            def broken(m=model):
                m.net = None  # any inference call now raises

            from models.lstm_autoencoder import SEQ_LEN

            built.append((Candidate("lstm-ae", lambda src, n, m=model: m.score(src, n),
                                    abstains=True, prime_events=SEQ_LEN,
                                    trained=bool(getattr(model, "_trained", False)),
                                    notes="abstains (None) untrained/below SEQ_LEN/on failure (#1969)"),
                          broken))
        elif name == "isolation-forest":
            from models.isolation_forest import IsoForestModel

            model = IsoForestModel()
            trained = bool(getattr(model, "iso", None))
            built.append((Candidate(
                "isolation-forest",
                lambda src, n, m=model: m.score(m.extract_features(src, n)),
                abstains=True,
                trained=trained,
                notes="abstains (None) before first retrain; takes a feature vector, not a raw doc",
            ), None))
        else:
            raise SystemExit(f"unknown candidate: {name}")
    return built


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("candidates", nargs="*", default=["lstm-ae", "isolation-forest"],
                        help="detectors to check (default: the deployed set)")
    parser.add_argument("--output", help="path for the JSON report")
    args = parser.parse_args()

    fixtures = load_fixtures()
    reports = []
    for candidate, breaker in build_candidates(args.candidates or ["lstm-ae", "isolation-forest"]):
        report = run_checks(candidate, fixtures, breaker)
        reports.append(report.as_dict())
        print(f"{candidate.name}: {'PASS' if report.passed else 'FAIL'}")
        for check in report.checks:
            mark = "skip" if check.skipped else ("ok" if check.passed else "FAIL")
            print(f"  [{mark:4s}] {check.name}: {check.detail}")

    document = {
        "benchmark": BENCHMARK_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tier": 1,
        "tier_2_status": "blocked on #1797 (labelled corpus); this run does not measure accuracy",
        "reports": reports,
    }
    if args.output:
        digest = write_atomic(args.output, document)
        print(json.dumps({"report_sha256": digest, "written": args.output}))
    return 0 if all(r["passed"] for r in reports) else 1


if __name__ == "__main__":
    sys.exit(main())
