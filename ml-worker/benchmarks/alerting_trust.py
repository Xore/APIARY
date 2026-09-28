"""#3451: alerting trust -- precision/recall of raised alerts vs operator dispositions.

This is the held measurement the #1974 epic's second half of acceptance asked
for. It answers one question about the alerts the system actually raised:

    when ml-worker raised an alert and an operator has since closed it out,
    how often was the operator right?

## Why this is a separate module and not a flag on the tier 2 rail

`disposition_tier2.py` scores a *calibrator*: it fits Platt scaling on a
group-disjoint fit split and reports `precision_within_alerts` on a **held-out
split** of that calibrator's own output. That is the right number for judging
calibration, and the wrong number for this issue, which asks what the
**deployed** scorer's raised alerts are worth. It needs no calibrator, no
split, and no seed: precision over a disposition is a property of the alert
population. It is also available on a snapshot that `disposition_tier2` would
refuse -- one `model_state_id`, or a single class -- because neither condition
affects a count over the labelled population.

So the two share a label mapping and a snapshot loader, and nothing else. They
must agree on the mapping: if the exporter and this module disagreed about what
`benign_known` means, one of them would be publishing a number the other
contradicts.

## The two legs, and why only one of them can run

**Precision** is `TP / (TP + FP)` over labelled, persisted, above-threshold
alerts. It is computable today.

**Recall is UNMEASURED, permanently, and that is a property of the data rather
than a gap in this file.** `write_anomaly()` returns before persistence below
`ML_ALERT_THRESHOLD`, so the `ml-anomalies` index contains only alerts the
system chose to raise. The denominator recall needs -- the true positives that
*never became alerts* -- was never written anywhere. There is no table holding
it, no counter, and no way to reconstruct it after the fact: the events that
would have populated it were discarded at the persistence boundary.

This is why there is no `recall()` function here. The only way to produce a
recall number from this corpus is to divide by a denominator that was never
persisted, and the quotient is not a measurement -- it is arithmetic performed
on a missing number. Anyone can write it; `TP / (all_events_seen)` is one line.
The refusal to emit it is the deliverable, and it is structural: the leg is a
constant, the report validator raises if a value is ever attached to it, and
`assert_recall_not_requested` rejects a request to compute it. A future reader
who wants recall needs a below-threshold population to be persisted first, and
then a different denominator, not a division here.

The distinction that matters for reading a report: recall is UNMEASURED *by
construction* -- it would read UNMEASURED even against a fully populated,
perfectly labelled corpus. Precision is UNMEASURED only when this run had no
labelled rows to score. Those are different failures and the report says which
one occurred.

## The reporting rule, enforced in code

> Record UNMEASURED for any leg that did not run. Never write zeros for a leg
> that was skipped, OOM'd, or truncated. A zero is a claim about a result; a
> failed run is not a result.

`unmeasured()` is the only way to build an absent leg and it hard-codes
`value=None`. `as_record()` raises if a leg carries a value without a status or
a status without its value, so a `0.0` cannot reach a report through a skipped
leg. The place this bites hardest is `unlabelled_alerts`: the NDJSON snapshot
contains **closed dispositions only**, so a consumer that counted `open` rows
in the snapshot would report `0` open alerts every time -- an invented
denominator. It is UNMEASURED unless the census report from
`disposition_corpus.py`, which does carry the open count, is supplied.

## What `benign_known` means here, and why it is not dropped

`benign_known` is a real operator disposition: the alert was reasonable to
raise, and the activity underneath is known-benign. An operator explicitly
declined to call it an attack.

It is scored as a **negative** (`LABEL_MAPPING` in `disposition_tier2.py`:
`true_positive -> 1`, `false_positive -> 0`, `benign_known -> 0`), and it stays
in the denominator. Two alternatives were rejected:

- **Excluding it** is the dangerous one. Dropping rows that are negatives from
  `TP / (TP + FP)` can only raise the quotient, and it raises it silently --
  a corpus that is mostly `benign_known` would report a near-perfect precision
  for a detector that is not close. The report carries
  `precision_if_benign_known_excluded` as an explicitly-labelled counterfactual
  so that the inflation is visible rather than hypothetical, and a test asserts
  the exclusion variant is never lower than the headline.
- **Counting it as a positive** would be defensible on the "the alert was
  correct" reading, and it also raises the number. It is not adopted, because
  the detector's job is to call attacks, and the disposition that exists to say
  "not an attack" is the one that should lower precision. The decision is
  recorded in `BENIGN_KNOWN_TREATMENT` and in the per-status counts in every
  report, so a reader who disagrees can recompute rather than guess.

This is a decision, not a fact, and it is a decision the repo already made once
in `disposition_tier2.py`. Duplicating it here is the bug; this module imports
that mapping rather than restating it.

## Uncertainty

A precision from a handful of labelled alerts is not a number, it is noise, and
`#3451`'s whole premise is that a confidently wrong alerting number is worse
than none. Every precision is reported with its Wilson score interval at 95%
and its sample size, so `3/3 = 1.000 [0.44, 1.00]` cannot be mistaken for a
deployment claim. A rate with no negative examples at all is additionally
flagged, because `1.000` with zero false positives is a statement about the
sample and not about the detector.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

# The label mapping, the snapshot loader and the precision-only constant are
# imported, not restated: two consumers of one snapshot must not disagree about
# what a disposition means. The dual spelling matches the sibling modules so
# this resolves both as a script and as `benchmarks.alerting_trust` under the
# tests.
try:
    from benchmarks.disposition_corpus import PRECISION_ONLY
    from benchmarks.disposition_tier2 import (
        LABEL_MAPPING,
        POSITIVE_STATUS,
        DispositionError,
        LabelledRow,
        Snapshot,
        load_snapshot,
        validate_disposition_metrics,
    )
    from benchmarks.evaluate_accuracy import _inside_repository, _md5, write_report
except ImportError:  # executed as a script, with benchmarks/ on sys.path
    from disposition_corpus import PRECISION_ONLY  # type: ignore[no-redef]
    from disposition_tier2 import (  # type: ignore[no-redef]
        LABEL_MAPPING,
        POSITIVE_STATUS,
        DispositionError,
        LabelledRow,
        Snapshot,
        load_snapshot,
        validate_disposition_metrics,
    )
    from evaluate_accuracy import (  # type: ignore[no-redef]
        _inside_repository,
        _md5,
        write_report,
    )


ALERTING_TRUST_VERSION = "apiary-ml-worker-alerting-trust-v1"
ISSUE = 3451

#: The literal a leg carries when it did not run. Not a number, and never
#: rendered as one.
UNMEASURED = "UNMEASURED"

#: Recall has no denominator anywhere in this system. It is a constant rather
#: than a computed result so that no code path can produce a recall figure.
RECALL_DENOMINATOR_AVAILABLE = False

RECALL_REASON = (
    f"{PRECISION_ONLY} Deployment recall needs the true positives that never "
    "became alerts, and those events are discarded at the persistence boundary "
    "before they are ever stored. No table, counter or index holds that "
    "denominator, so the quotient cannot be formed. This is UNMEASURED by "
    "construction: it would read UNMEASURED against a fully labelled corpus "
    "too, and stays UNMEASURED until a below-threshold population is persisted."
)

BENIGN_KNOWN_TREATMENT = {
    "status": "benign_known",
    "scored_as": "negative",
    "in_denominator": True,
    "rationale": (
        "benign_known is a real operator disposition -- the alert was reasonable "
        "to raise and the activity underneath is known-benign -- so an operator "
        "explicitly declined to call it an attack. It is scored as a negative and "
        "retained in the denominator. Excluding it would remove only negatives "
        "from TP/(TP+FP) and therefore inflate precision silently; the excluded "
        "variant is reported beside the headline so that inflation is visible, "
        "and counted as a positive it would equally raise the number. This "
        "reproduces the mapping already reviewed in disposition_tier2.py rather "
        "than introducing a second reading of the same dispositions."
    ),
}

# Wilson score interval, 95%. Hand-rolled rather than pulled from SciPy: this
# harness must not grow a dependency to put an interval on four counts.
_Z_95 = 1.959963984540054


class AlertingTrustError(RuntimeError):
    """An unusable snapshot, census report, or request."""


@dataclass(frozen=True)
class Leg:
    """One measurement, or the recorded fact that it did not happen.

    `value` is None whenever `status` is UNMEASURED. That pairing is enforced
    in `as_record`, not merely by convention, because the whole reporting rule
    is about this one field.
    """

    metric: str
    status: str
    value: float | int | None
    reason: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def measured(self) -> bool:
        return self.status != UNMEASURED


def measured(metric: str, value: float | int, **detail: Any) -> Leg:
    """A leg that ran. A `None` here is a bug, not an absent measurement."""
    if value is None:
        raise AlertingTrustError(
            f"{metric} was marked measured with no value; use unmeasured() instead"
        )
    return Leg(metric=metric, status="measured", value=value, reason=None, detail=detail)


def unmeasured(metric: str, reason: str) -> Leg:
    """A leg that did not run. Always `value=None` -- never 0, never 0.0."""
    if not reason or not reason.strip():
        raise AlertingTrustError(
            f"{metric} is UNMEASURED and must carry a reason; an unexplained "
            "absence reads as a result of zero"
        )
    return Leg(metric=metric, status=UNMEASURED, value=None, reason=reason, detail={})


def as_record(leg: Leg) -> dict[str, Any]:
    """Serialise a leg, refusing any pairing that would fake a result."""
    if leg.status == UNMEASURED:
        if leg.value is not None:
            raise AlertingTrustError(
                f"{leg.metric} is UNMEASURED but carries value {leg.value!r}; a leg "
                "that did not run has no value, and a zero would be a claim about "
                "a result"
            )
        if not leg.reason:
            raise AlertingTrustError(f"{leg.metric} is UNMEASURED without a reason")
        return {
            "metric": leg.metric,
            "status": UNMEASURED,
            "value": None,
            "reason": leg.reason,
            **leg.detail,
        }
    if leg.value is None:
        raise AlertingTrustError(f"{leg.metric} is {leg.status} with no value")
    return {
        "metric": leg.metric,
        "status": leg.status,
        "value": leg.value,
        "reason": leg.reason,
        **leg.detail,
    }


def assert_recall_not_requested(metrics: Iterable[str]) -> None:
    """Refuse a request to compute recall, on the existing banned-metric rail.

    Delegates to `disposition_tier2`'s allowlist so the refusal lives in one
    reviewed place rather than a second, drifting copy of it. The recall check
    runs first: recall is rejected here for a different reason than a banned
    metric, and that reason is the one an operator needs to read.
    """
    if any(metric.lower().replace("-", "_") in {"recall", "sensitivity", "tpr"}
           for metric in metrics):
        raise AlertingTrustError(
            f"recall is not computable from the {PRECISION_ONLY} It is reported as "
            f"{UNMEASURED} with a reason; this is not a banned-metric refusal, it has "
            "no denominator."
        )
    validate_disposition_metrics(metrics)


def wilson_interval(successes: int, total: int) -> tuple[float, float] | None:
    """95% Wilson score interval; None when the denominator is empty."""
    if total <= 0:
        return None
    phat = successes / total
    denominator = 1.0 + _Z_95**2 / total
    centre = (phat + _Z_95**2 / (2 * total)) / denominator
    margin = (
        _Z_95
        * math.sqrt(phat * (1 - phat) / total + _Z_95**2 / (4 * total**2))
        / denominator
    )
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def status_counts(rows: Sequence[LabelledRow]) -> dict[str, int]:
    counts = {status: 0 for status in LABEL_MAPPING}
    for row in rows:
        counts[row.status] = counts.get(row.status, 0) + 1
    return counts


def precision_leg(rows: Sequence[LabelledRow]) -> Leg:
    """Deployment precision over every labelled alert, plus its sample size.

    The denominator is the labelled, persisted, above-threshold population --
    no split, no calibrator, no seed. `open` alerts are absent by construction
    (the exporter only emits closed dispositions) and are never counted as
    negatives.
    """
    counts = status_counts(rows)
    labelled = sum(counts.values())
    true_positive = counts.get(POSITIVE_STATUS, 0)
    false_positive = counts.get("false_positive", 0)
    benign_known = counts.get("benign_known", 0)

    if labelled == 0:
        return unmeasured(
            "precision",
            "the snapshot contains zero labelled dispositions, so there is no "
            f"denominator for TP/(TP+FP). Recorded {UNMEASURED} rather than 0.0: "
            "an absent run is not a measurement of zero precision.",
        )

    denominator = true_positive + false_positive + benign_known
    value = true_positive / denominator
    interval = wilson_interval(true_positive, denominator)

    detail: dict[str, Any] = {
        "labelled_alerts": labelled,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "benign_known": benign_known,
        "positives": true_positive,
        "negatives": false_positive + benign_known,
        "denominator": denominator,
        "wilson_95": list(interval) if interval else None,
        "denominator_population": (
            "labelled, persisted, above-threshold alerts. Below-threshold events "
            "were never persisted and unlabelled `open` alerts are not negatives."
        ),
    }
    if benign_known:
        # Shown so the silent-inflation vector is a number on the page rather
        # than a footnote. Never the headline.
        excluded_denominator = true_positive + false_positive
        detail["precision_if_benign_known_excluded"] = (
            true_positive / excluded_denominator if excluded_denominator else None
        )
        detail["exclusion_note"] = (
            "Counterfactual only. Excluding benign_known removes negatives from "
            "the denominator and inflates precision; it is reported so the size of "
            "that inflation is visible, never because it is defensible."
        )
    if true_positive == 0:
        detail["caveat"] = (
            "No true positives in this snapshot. The rate below describes the "
            "sample, not the detector."
        )
    elif false_positive + benign_known == 0:
        detail["caveat"] = (
            "No negative dispositions in this snapshot. Precision of 1.0 here is "
            "a statement about a sample with no counter-examples, not a "
            "measurement of detector quality."
        )
    return measured("precision", value, **detail)


def recall_leg() -> Leg:
    """Always UNMEASURED. There is deliberately no path that returns a number."""
    return unmeasured("recall", RECALL_REASON)


def open_alerts_leg(census: dict[str, Any] | None) -> Leg:
    """Count the alerts operators have not closed yet.

    UNMEASURED unless the census report from `disposition_corpus.py` is
    supplied. The NDJSON snapshot holds closed dispositions only, so counting
    `open` rows there yields zero every time -- a fabricated denominator
    presented as a clean sweep of the queue.
    """
    if census is None:
        return unmeasured(
            "unlabelled_alerts",
            "the NDJSON snapshot contains closed dispositions only, so the count "
            "of alerts an operator has not yet disposed of cannot be read from "
            f"it. Pass --census with the report from disposition_corpus.py. "
            f"Recorded {UNMEASURED} rather than 0: seeing no open rows in a "
            "closed-only export is not evidence that none exist.",
        )
    alerts = census.get("census", {}).get("alerts")
    if not isinstance(alerts, dict):
        return unmeasured(
            "unlabelled_alerts",
            "the supplied census report has no census.alerts object, so it is "
            "not the disposition_corpus.py census it claims to be",
        )
    by_status = alerts.get("by_disposition_status")
    if not isinstance(by_status, dict):
        return unmeasured(
            "unlabelled_alerts",
            "the supplied census report carries no by_disposition_status counts",
        )
    # `<missing>` is the term-aggregation bucket for documents with no status
    # field at all; they are undisposed just as `open` alerts are.
    unlabelled = int(by_status.get("open", 0)) + int(by_status.get("<missing>", 0))
    return measured(
        "unlabelled_alerts",
        unlabelled,
        open_alerts=int(by_status.get("open", 0)),
        missing_status=int(by_status.get("<missing>", 0)),
        total_alerts=alerts.get("total"),
        labelled_alerts=alerts.get("labelled_count"),
        note=(
            "Undisposed alerts are excluded from every rate here. They are not "
            "negatives and not positives; scoring them either way would be a "
            "guess about an operator decision that has not been made."
        ),
    )


def load_census(path: str | Path) -> dict[str, Any] | None:
    """Read the census report `disposition_corpus.py` wrote, if one is given."""
    if path is None:
        return None
    source = Path(path).expanduser()
    if _inside_repository(source):
        raise AlertingTrustError("the census report must live outside the repository")
    if not source.is_file():
        raise AlertingTrustError(f"census report not found: {source}")
    try:
        with source.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except json.JSONDecodeError as exc:
        raise AlertingTrustError(f"{source} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AlertingTrustError(f"{source} is not a JSON object")
    return value


def make_report(rows: Sequence[LabelledRow], *, source: dict[str, Any],
                census: dict[str, Any] | None, snapshot_sha256: str,
                elapsed_seconds: float, started_at: str) -> dict[str, Any]:
    legs = {
        "precision": precision_leg(rows),
        "recall": recall_leg(),
        "unlabelled_alerts": open_alerts_leg(census),
    }
    records = {name: as_record(leg) for name, leg in legs.items()}
    counts = status_counts(rows)
    precision = records["precision"]
    return {
        "benchmark": ALERTING_TRUST_VERSION,
        "issue": ISSUE,
        "question": (
            "When ml-worker raises an alert and an operator closes it out, how "
            "often is the operator calling it a true positive?"
        ),
        "corpus": {
            "name": "operator disposition corpus",
            "exported_by": "benchmarks/disposition_corpus.py",
            **source,
            "sha256": snapshot_sha256,
        },
        "label_mapping": dict(LABEL_MAPPING),
        "benign_known": dict(BENIGN_KNOWN_TREATMENT),
        "census": {
            "by_status": counts,
            "labelled_rows": len(rows),
            "class_balance": {
                "counts": counts,
                "denominator": len(rows),
                "fractions": {
                    status: (count / len(rows) if rows else None)
                    for status, count in counts.items()
                },
            },
        },
        "legs": records,
        "headline": _headline(records),
        "recall_denominator_available": RECALL_DENOMINATOR_AVAILABLE,
        "reporting_rule": (
            "A leg that did not run is recorded UNMEASURED with a reason. A zero "
            "is a claim about a result; a failed run is not a result."
        ),
        "package_note": (
            "This harness counts dispositions. It fits nothing, trains nothing and "
            "evaluates no model; calibration is disposition_tier2.py's job."
        ),
        "elapsed_seconds": elapsed_seconds,
        "generated_at": started_at,
    }


def _headline(records: dict[str, dict[str, Any]]) -> str:
    precision = records["precision"]
    recall = records["recall"]
    if precision["status"] == UNMEASURED:
        return (
            f"precision: {UNMEASURED} ({precision['reason']}) recall: {UNMEASURED} "
            f"({recall['reason']})"
        )
    interval = precision.get("wilson_95")
    bounds = f" 95% CI [{interval[0]:.3f}, {interval[1]:.3f}]" if interval else ""
    return (
        f"precision: {precision['value']:.4f} "
        f"({precision['true_positive']} TP / {precision['negatives']} negatives of "
        f"{precision['labelled_alerts']} labelled alerts){bounds} | "
        f"recall: {UNMEASURED}"
    )


def print_report(report: dict[str, Any]) -> None:
    records = report["legs"]
    print(f"Alerting trust (issue #{report['issue']}): {report['question']}")
    print(f"Corpus: {report['corpus'].get('kind', 'snapshot')} "
          f"sha256 {report['corpus']['sha256'][:12]}; "
          f"labelled alerts {report['census']['labelled_rows']}; "
          f"by status {json.dumps(report['census']['by_status'], sort_keys=True)}")
    print(f"benign_known: scored as {report['benign_known']['scored_as']}, "
          f"in denominator={report['benign_known']['in_denominator']}")
    precision = records["precision"]
    if precision["status"] == UNMEASURED:
        print(f"precision: {UNMEASURED} -- {precision['reason']}")
    else:
        interval = precision.get("wilson_95")
        bounds = f" 95% CI [{interval[0]:.3f}, {interval[1]:.3f}]" if interval else ""
        print(f"precision: {precision['value']:.4f}{bounds} "
              f"(TP {precision['true_positive']}, FP {precision['false_positive']}, "
              f"benign_known {precision['benign_known']}, "
              f"n={precision['labelled_alerts']})")
        if precision.get("precision_if_benign_known_excluded") is not None:
            print(f"  counterfactual, benign_known excluded: "
                  f"{precision['precision_if_benign_known_excluded']:.4f} "
                  f"(inflated; not the headline)")
        if precision.get("caveat"):
            print(f"  caveat: {precision['caveat']}")
    recall = records["recall"]
    print(f"recall: {UNMEASURED} -- {recall['reason']}")
    unlabelled = records["unlabelled_alerts"]
    if unlabelled["status"] == UNMEASURED:
        print(f"unlabelled alerts: {UNMEASURED} -- {unlabelled['reason']}")
    else:
        print(f"unlabelled alerts: {unlabelled['value']} "
              f"(open {unlabelled['open_alerts']}, no status "
              f"{unlabelled['missing_status']}, of {unlabelled['total_alerts']} total)")
    print(report["reporting_rule"])


def run_alerting_trust(snapshot_path: str | Path | None, census_path: str | Path | None,
                       output: str | Path) -> tuple[dict[str, Any], str]:
    """Produce the #3451 record. A missing snapshot yields UNMEASURED, not a zero.

    The snapshot is optional so that a box with no Elasticsearch can still emit
    an honest record naming why the measurement did not happen. It is never
    substituted with invented data, and no network call is made from here --
    `disposition_corpus.py` is the only ES client in this path.
    """
    started = time.perf_counter()
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    census = load_census(census_path)
    if snapshot_path is None:
        raise AlertingTrustError(
            "no disposition snapshot supplied; the corpus is read-only and exists "
            "only in the ml-anomalies index. Export it with disposition_corpus.py "
            f"first. Both legs are {UNMEASURED} until then, and no number will be "
            "invented in the meantime."
        )
    try:
        snapshot: Snapshot = load_snapshot(snapshot_path)
    except DispositionError as exc:
        raise AlertingTrustError(str(exc)) from exc
    source = {"kind": "snapshot", "path": str(Path(snapshot_path).expanduser().resolve())}
    report = make_report(
        snapshot.rows,
        source=source,
        census=census,
        snapshot_sha256=snapshot.sha256 or _md5(Path(snapshot_path)),
        elapsed_seconds=time.perf_counter() - started,
        started_at=started_at,
    )
    digest = write_report(str(output), report)
    return report, digest
