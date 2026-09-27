"""Tier 2 accuracy/calibration over the operator-disposition corpus.

`disposition_corpus.py` exports the closed-disposition population and stops at
an eligibility gate: it reports whether a calibration *could* be run and never
fits or scores one. This module is the other half of that pair -- it consumes
that exact NDJSON snapshot and produces the deployment-labelled Tier 2 numbers
#2986 asks for.

## What this can and cannot measure, and why

Only **above-threshold** alerts are persisted: `write_anomaly()` returns before
persistence below `ML_ALERT_THRESHOLD`. So this corpus is *precision-only*. It
can describe how trustworthy a raised alert is and how well a score maps to the
probability that an operator will call it a true positive. It can **never**
measure deployment recall, and it cannot calibrate ordinary below-threshold
traffic. An unlabelled alert is not a negative and an absent below-threshold
event is not evidence it was correctly rejected. That limitation is reproduced
in every report this module writes, not just this docstring.

## The calibration itself

Platt scaling (`scikit-learn`'s unpenalised logistic regression on the single
`composite_score` feature) is fit on a group-disjoint fit split and evaluated
once on a held-out split. Grouping is by `model_state_id`: two alerts scored by
the same fitted checkpoint must not straddle the fit/evaluation boundary, or
the calibrator is partly grading its own homework. Temporal order is preserved
inside each side; only the *group assignment* is seeded, which is the partition
step the split rule requires to come first.

The comparison baseline is deliberately the cheapest possible one: a constant
predictor emitting the fit split's own positive rate. Any calibrator that cannot
beat "always guess the fit-split base rate" on held-out labelled data is not
calibrating anything, and that is asserted per seed rather than on the mean.

## What is deliberately absent

No recall, no AUROC, no AUPRC. They are not merely discouraged here -- they are
unavailable. A precision-only corpus has no below-threshold negatives, so a
ranking metric computed over it would silently describe a *different* problem
(the ranking of alerts among alerts) while wearing the deployed metric's name.
The point-adjusted-F1 ban and the random/shuffled-split ban in
`evaluate_accuracy.py` apply here too and are enforced through the same
`ensure_metric_allowed` guard.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
from sklearn.linear_model import LogisticRegression

# The harness primitives are shared with the BETH rail on purpose -- this is
# the same entry point, not a second framework. Both spellings are supported so
# the command works as `python3 ml-worker/benchmarks/evaluate_accuracy.py
# disposition ...` and as `benchmarks.evaluate_accuracy` under the tests.
try:
    from benchmarks.evaluate_accuracy import (
        BethError,
        BannedMetricError,
        _inside_repository,
        _md5,
        _summary,
        ensure_metric_allowed,
        package_versions,
        validate_seeds,
        write_report,
    )
except ImportError:  # executed as a script, with benchmarks/ on sys.path
    from evaluate_accuracy import (  # type: ignore[no-redef]
        BethError,
        BannedMetricError,
        _inside_repository,
        _md5,
        _summary,
        ensure_metric_allowed,
        package_versions,
        validate_seeds,
        write_report,
    )


DISPOSITION_TIER2_VERSION = "apiary-ml-worker-disposition-tier2-v1"

# A raised alert is a true positive only when an operator said so.
# `benign_known` is the disposition that means "this alert was reasonable to
# raise, the activity underneath is known-benign" -- an operator explicitly
# declined to call it an attack, so it is a negative for the detector. That
# reading is a decision, not a fact, so the per-status counts travel in the
# report and the mapping is printed on every run.
POSITIVE_STATUS = "true_positive"
NEGATIVE_STATUSES = ("false_positive", "benign_known")
LABEL_MAPPING = {POSITIVE_STATUS: 1, "false_positive": 0, "benign_known": 0}

REQUIRED_FIELDS = ("status", "composite_score", "@timestamp", "_id")
HOLDOUT_FRACTION = 0.5
RELIABILITY_BINS = 10

# Metrics this path is allowed to emit. Ranking metrics are absent on purpose;
# see the module docstring.
DISPOSITION_METRICS = frozenset({"precision", "brier", "ece", "reliability", "monotonicity"})

PRECISION_ONLY = (
    "PRECISION-ONLY: only above-threshold alerts are persisted, so this corpus "
    "cannot measure deployment recall or ordinary below-threshold calibration."
)
NOT_GROUND_TRUTH = (
    "BETH is a parallel-corpus architecture sanity rail and is never production "
    "ground truth; nothing in this report is a deployment accuracy claim for "
    "traffic BETH does not describe."
)


class DispositionError(ValueError):
    """An unusable or absent labelled disposition snapshot."""


@dataclass(frozen=True)
class LabelledRow:
    """One closed disposition, reduced to what Tier 2 is allowed to look at."""

    identifier: str
    status: str
    label: int
    score: float
    timestamp: str
    group: str
    sensor: str | None = None
    model_state_id: str | None = None
    alert_threshold: float | None = None


@dataclass
class Snapshot:
    path: Path
    sha256: str
    rows: list[LabelledRow] = field(default_factory=list)

    @property
    def labels(self) -> np.ndarray:
        return np.asarray([row.label for row in self.rows], dtype=np.int64)

    @property
    def scores(self) -> np.ndarray:
        return np.asarray([row.score for row in self.rows], dtype=float)

    @property
    def positive_count(self) -> int:
        return int(self.labels.sum())

    @property
    def groups(self) -> list[str]:
        return sorted({row.group for row in self.rows})

    def as_census(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for row in self.rows:
            status_counts[row.status] = status_counts.get(row.status, 0) + 1
        sensors: dict[str, int] = {}
        for row in self.rows:
            if row.sensor:
                sensors[row.sensor] = sensors.get(row.sensor, 0) + 1
        return {
            "labelled_rows": len(self.rows),
            "by_status": status_counts,
            "label_mapping": dict(LABEL_MAPPING),
            "positive": self.positive_count,
            "negative": len(self.rows) - self.positive_count,
            "positive_rate": self.positive_count / len(self.rows) if self.rows else None,
            "distinct_model_state_ids": len(self.groups),
            "by_sensor": dict(sorted(sensors.items())),
            "sha256": self.sha256,
        }


def _optional_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if np.isfinite(number) else None


def parse_rows(lines: Iterable[str], *, path: Path, sha256: str) -> Snapshot:
    """Read the NDJSON snapshot written by `disposition_corpus.py`."""
    rows: list[LabelledRow] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DispositionError(f"{path} line {number} is not valid JSON: {exc}") from exc
        if not isinstance(record, dict):
            raise DispositionError(f"{path} line {number} is not a JSON object")
        status = record.get("status")
        if status not in LABEL_MAPPING:
            # The exporter only emits closed dispositions. Anything else means
            # the snapshot is not what this path claims to measure, and quietly
            # skipping would hide rows from the denominator.
            raise DispositionError(
                f"{path} line {number} has status {status!r}; the export must contain only "
                f"closed dispositions ({', '.join(sorted(LABEL_MAPPING))})"
            )
        missing = [field for field in REQUIRED_FIELDS if record.get(field) in (None, "")]
        if missing:
            raise DispositionError(f"{path} line {number} is missing: {', '.join(missing)}")
        score = _optional_float(record.get("composite_score"))
        if score is None:
            raise DispositionError(f"{path} line {number} has a non-numeric composite_score")
        if not 0.0 <= score <= 1.0:
            raise DispositionError(
                f"{path} line {number} has composite_score {score!r} outside [0, 1]"
            )
        rows.append(
            LabelledRow(
                identifier=str(record["_id"]),
                status=str(status),
                label=LABEL_MAPPING[str(status)],
                score=score,
                timestamp=str(record["@timestamp"]),
                # An alert with no model state cannot be grouped. It is kept
                # under its own identity rather than merged into a shared
                # bucket, so grouping stays honest without dropping the row.
                group=str(record.get("model_state_id") or f"__ungrouped__{record['_id']}"),
                sensor=record.get("sensor"),
                model_state_id=record.get("model_state_id"),
                alert_threshold=_optional_float(record.get("alert_threshold")),
            )
        )
    if not rows:
        raise DispositionError(
            f"{path} contains no labelled dispositions. {PRECISION_ONLY} A zero-label "
            "snapshot is not calibratable and this command will not invent a result."
        )
    return Snapshot(path=path, sha256=sha256, rows=rows)


def load_snapshot(path: str | Path) -> Snapshot:
    source = Path(path).expanduser()
    if _inside_repository(source):
        raise DispositionError("the disposition snapshot must live outside the repository")
    if not source.is_file():
        raise DispositionError(f"disposition snapshot not found: {source}")
    with source.open(encoding="utf-8") as handle:
        return parse_rows(handle, path=source, sha256=_md5(source))


def partition(snapshot: Snapshot, seed: int,
              holdout_fraction: float = HOLDOUT_FRACTION) -> tuple[list[int], list[int]]:
    """Group-disjoint, time-ordered fit/holdout indices for one seed.

    Whole `model_state_id` groups move together, so no fitted checkpoint is
    scored on both sides. The group *order* is seeded; the rows inside each side
    are returned in timestamp order, because the split rule forbids shuffling
    across time and only the partition is permitted to vary per seed.
    """
    groups = snapshot.groups
    if len(groups) < 2:
        raise DispositionError(
            "a group-disjoint split needs at least two distinct model_state_ids; "
            f"the snapshot has {len(groups)}. A single model state cannot calibrate itself."
        )
    by_group: dict[str, list[int]] = {group: [] for group in groups}
    for index, row in enumerate(snapshot.rows):
        by_group[row.group].append(index)

    order = list(np.random.default_rng(seed).permutation(len(groups)))
    target = holdout_fraction * len(snapshot.rows)
    holdout_groups: list[str] = []
    holdout_rows = 0
    for position in order:
        group = groups[position]
        if holdout_rows >= target:
            break
        holdout_groups.append(group)
        holdout_rows += len(by_group[group])
    if not holdout_groups or holdout_rows == len(snapshot.rows):
        raise DispositionError("could not form a non-empty, group-disjoint holdout split")

    holdout = set(holdout_groups)
    def ordered(indices: Iterable[int]) -> list[int]:
        return sorted(indices, key=lambda i: (snapshot.rows[i].timestamp, snapshot.rows[i].identifier))

    return (
        ordered([i for i in range(len(snapshot.rows)) if snapshot.rows[i].group not in holdout]),
        ordered([i for i in range(len(snapshot.rows)) if snapshot.rows[i].group in holdout]),
    )


def brier_score(labels: np.ndarray, probabilities: np.ndarray) -> float:
    return float(np.mean((np.asarray(probabilities, dtype=float) - np.asarray(labels, dtype=float)) ** 2))


def reliability(labels: np.ndarray, probabilities: np.ndarray,
                bins: int = RELIABILITY_BINS) -> list[dict[str, Any]]:
    """Equal-width confidence bins over [0, 1]."""
    labels = np.asarray(labels, dtype=float)
    probabilities = np.asarray(probabilities, dtype=float)
    table: list[dict[str, Any]] = []
    edges = np.linspace(0.0, 1.0, bins + 1)
    for index in range(bins):
        low, high = edges[index], edges[index + 1]
        # The last bin is closed on the right so a probability of exactly 1.0
        # is counted rather than dropped.
        selected = (probabilities >= low) & (
            probabilities <= high if index == bins - 1 else probabilities < high
        )
        count = int(selected.sum())
        table.append(
            {
                "bin": index,
                "low": float(low),
                "high": float(high),
                "count": count,
                "mean_predicted": float(probabilities[selected].mean()) if count else None,
                "observed_precision": float(labels[selected].mean()) if count else None,
            }
        )
    return table


def expected_calibration_error(labels: np.ndarray, probabilities: np.ndarray,
                               bins: int = RELIABILITY_BINS) -> float:
    total = len(labels)
    if not total:
        return float("nan")
    error = 0.0
    for entry in reliability(labels, probabilities, bins):
        if not entry["count"]:
            continue
        error += (entry["count"] / total) * abs(
            entry["observed_precision"] - entry["mean_predicted"]
        )
    return float(error)


def reliability_is_monotonic(table: list[dict[str, Any]]) -> dict[str, Any]:
    """Does a higher predicted probability actually mean a higher precision?

    This is the one calibration property that is wrong or right regardless of
    sample size: a curve that slopes the wrong way is broken, not noisy.
    """
    populated = [
        entry for entry in table
        if entry["count"] and entry["observed_precision"] is not None
    ]
    if len(populated) < 3:
        # Reported as not exercised rather than as a pass. A curve checked on
        # two points proves nothing, and reading it as a pass is how a rail
        # turns into decoration.
        return {"exercised": False, "reason": f"{len(populated)} populated bins, need 3",
                "monotonic": None, "spearman": None}
    predicted = np.asarray([entry["mean_predicted"] for entry in populated], dtype=float)
    observed = np.asarray([entry["observed_precision"] for entry in populated], dtype=float)
    if np.allclose(predicted, predicted[0]) or np.allclose(observed, observed[0]):
        return {"exercised": True, "reason": "degenerate bin sequence",
                "monotonic": None, "spearman": None}
    ranks_predicted = np.argsort(np.argsort(predicted)).astype(float)
    ranks_observed = np.argsort(np.argsort(observed)).astype(float)
    rho = float(np.corrcoef(ranks_predicted, ranks_observed)[0, 1])
    return {
        "exercised": True,
        "reason": None,
        "monotonic": bool(rho > 0),
        "spearman": rho,
        "populated_bins": len(populated),
    }


def _precision_bins(labels: np.ndarray, scores: np.ndarray,
                    bins: int = RELIABILITY_BINS) -> list[dict[str, Any]]:
    """Precision of raised alerts, bucketed by the score that raised them."""
    table = reliability(labels, scores, bins)
    for entry in table:
        # In this table `mean_predicted` holds the mean raw composite score, so
        # relabel rather than leaving a misleading key in the report.
        entry["mean_score"] = entry.pop("mean_predicted")
    return table


def evaluate_seed(snapshot: Snapshot, seed: int) -> dict[str, Any]:
    """Fit Platt scaling on the fit split, score the holdout split once."""
    fit_index, holdout_index = partition(snapshot, seed)
    fit_scores = snapshot.scores[fit_index]
    fit_labels = snapshot.labels[fit_index]
    holdout_scores = snapshot.scores[holdout_index]
    holdout_labels = snapshot.labels[holdout_index]
    for side, labels in (("fit", fit_labels), ("holdout", holdout_labels)):
        if len(np.unique(labels)) < 2:
            raise DispositionError(
                f"seed {seed}: the {side} split has a single class "
                f"({int(labels.sum())} positive of {len(labels)}); Platt scaling and every "
                "ranking metric are undefined there"
            )

    # Unpenalised maximum likelihood is what Platt scaling means; `C=inf` is
    # how scikit-learn spells it from 1.8 on (`penalty=None` is deprecated and
    # removed in 1.10). Note the honest consequence: on a linearly separable
    # fit split the coefficients diverge and the probabilities saturate at 0/1.
    # That is not a bug to hide -- it makes the held-out Brier worse than the
    # constant baseline, which is exactly what the calibration gate is for.
    calibrator = LogisticRegression(C=float("inf"), solver="lbfgs", max_iter=1000)
    calibrator.fit(fit_scores.reshape(-1, 1), fit_labels)
    probabilities = calibrator.predict_proba(holdout_scores.reshape(-1, 1))[:, 1]

    # The baseline is the cheapest honest competitor: the fit split's own base
    # rate, held constant. Beating it is a real requirement, not a target.
    base_rate = float(fit_labels.mean())
    constant = np.full(len(holdout_labels), base_rate, dtype=float)

    table = reliability(holdout_labels, probabilities)
    return {
        "seed": seed,
        "fit_rows": len(fit_index),
        "holdout_rows": len(holdout_index),
        "fit_groups": len({snapshot.rows[i].group for i in fit_index}),
        "holdout_groups": len({snapshot.rows[i].group for i in holdout_index}),
        "group_overlap": sorted({snapshot.rows[i].group for i in fit_index}
                                & {snapshot.rows[i].group for i in holdout_index}),
        "fit_positive_rate": base_rate,
        "holdout_positive_rate": float(holdout_labels.mean()),
        "coefficients": [float(value) for value in np.ravel(calibrator.coef_)],
        "intercept": float(calibrator.intercept_[0]),
        "brier": brier_score(holdout_labels, probabilities),
        "baseline_brier": brier_score(holdout_labels, constant),
        "brier_improvement": brier_score(holdout_labels, constant) - brier_score(holdout_labels, probabilities),
        "ece": expected_calibration_error(holdout_labels, probabilities),
        "baseline_ece": expected_calibration_error(holdout_labels, constant),
        "precision_within_alerts": float(holdout_labels.mean()),
        "reliability": table,
        "monotonicity": reliability_is_monotonic(table),
        "precision_by_score": _precision_bins(holdout_labels, holdout_scores),
    }


def validate_disposition_metrics(metrics: Iterable[str]) -> None:
    names = tuple(metrics)
    for metric in names:
        ensure_metric_allowed(metric)
    if not set(names) <= DISPOSITION_METRICS:
        raise BannedMetricError(
            "the disposition tier may only emit "
            f"{', '.join(sorted(DISPOSITION_METRICS))}; ranking metrics such as AUROC, "
            "AUPRC and recall are undefined on a precision-only corpus"
        )


def evaluate_eligibility(snapshot: Snapshot, seed_results: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The gate from `disposition_corpus.py`, re-derived against the labels actually used.

    Structural conditions only. No expected accuracy value is asserted here,
    because inventing one is the failure this whole tier exists to prevent.
    """
    classes = sorted({row.label for row in snapshot.rows})
    problems: list[str] = []
    if len(classes) < 2:
        problems.append(
            f"single labelled class present ({classes}); a calibrator cannot be scored"
        )
    if len(snapshot.groups) < 2:
        problems.append(
            f"{len(snapshot.groups)} distinct model_state_id; no group-disjoint split is possible"
        )
    overlapping = sorted({
        group
        for result in seed_results
        for group in result["group_overlap"]
    })
    if overlapping:
        problems.append(f"model_state_id groups straddle fit and holdout: {overlapping}")
    one_sided = [
        result["seed"] for result in seed_results
        if result["fit_positive_rate"] in (0.0, 1.0)
    ]
    if one_sided:
        problems.append(f"seeds {one_sided} produced a single-class fit split")
    return {
        "eligible": not problems,
        "labelled_rows": len(snapshot.rows),
        "classes_present": classes,
        "distinct_model_state_ids": len(snapshot.groups),
        "problems": problems,
    }


def evaluate_gates(snapshot: Snapshot, seed_results: Sequence[dict[str, Any]],
                   precision_floor: float | None) -> dict[str, Any]:
    """The assertions that can fail. No expected value is invented in here.

    - **calibration**: on every seed the Platt calibrator must beat the
      constant fit-split base rate on held-out labelled data. Beating "always
      guess the fit-split base rate" is a mathematical requirement, not a
      target chosen after seeing results.
    - **monotonicity**: where the reliability curve has enough populated bins to
      judge, higher predicted probability must not correspond to lower
      observed precision.
    - **precision**: a regression condition against a floor the operator sets
      explicitly. It is *unarmed* when no floor is supplied, and an unarmed gate
      is reported as unarmed rather than as passed.
    """
    failed_seeds = [
        result["seed"] for result in seed_results if not result["brier_improvement"] > 0.0
    ]
    calibration_passed = not failed_seeds
    monotonicity = [result["monotonicity"] for result in seed_results]
    exercised = [entry for entry in monotonicity if entry["exercised"]]
    monotonicity_violations = [
        result["seed"]
        for result, entry in zip(seed_results, monotonicity)
        if entry["exercised"] and entry["monotonic"] is not True
    ]
    precisions = [result["precision_within_alerts"] for result in seed_results]
    if precision_floor is None:
        precision = {
            "armed": False,
            "floor": None,
            "passed": None,
            "reason": "no --precision-floor supplied; precision is reported, not gated",
        }
    else:
        breaches = [value for value in precisions if value < precision_floor]
        precision = {
            "armed": True,
            "floor": precision_floor,
            "passed": not breaches,
            "reason": None if not breaches else
            f"precision {min(precisions):.4f} below the operator floor {precision_floor:.4f}",
        }
    return {
        "calibration": {
            "rule": "held-out Brier must beat the constant fit-split base-rate predictor, per seed",
            "passed": calibration_passed,
            "failed_seeds": failed_seeds,
            "min_improvement": min(result["brier_improvement"] for result in seed_results),
        },
        "monotonicity": {
            "rule": "reliability curve must not slope the wrong way where it is judgeable",
            "exercised_seeds": len(exercised),
            "passed": not monotonicity_violations,
            "failed_seeds": monotonicity_violations,
            "not_exercised": [result["seed"] for result, entry in zip(seed_results, monotonicity)
                              if not entry["exercised"]],
        },
        "precision_regression": precision,
        "passed": calibration_passed and not monotonicity_violations
        and precision["passed"] is not False,
    }


def make_report(snapshot: Snapshot, seeds: tuple[int, ...], seed_results: list[dict[str, Any]],
                precision_floor: float | None, elapsed_seconds: float, *,
                started_at: str) -> dict[str, Any]:
    validate_disposition_metrics(sorted(DISPOSITION_METRICS))
    eligibility = evaluate_eligibility(snapshot, seed_results)
    gates = evaluate_gates(snapshot, seed_results, precision_floor)
    precisions = [result["precision_within_alerts"] for result in seed_results]
    return {
        "benchmark": DISPOSITION_TIER2_VERSION,
        "tier": 2,
        "corpus": {
            "name": "operator disposition corpus",
            "source_issue": ["#1968", "#2395"],
            "exported_by": "benchmarks/disposition_corpus.py",
            "path": str(snapshot.path),
            "sha256": snapshot.sha256,
        },
        "label_mapping": dict(LABEL_MAPPING),
        "protocol": {
            "calibrator": "Platt scaling (unpenalised logistic regression on composite_score)",
            "partition": "group-disjoint by model_state_id, timestamp-ordered within each side",
            "seeded": "only the group assignment varies per seed; rows are never shuffled",
            "holdout_fraction": HOLDOUT_FRACTION,
            "reliability_bins": RELIABILITY_BINS,
            "baseline": "constant predictor emitting the fit split's own positive rate",
            "metrics": sorted(DISPOSITION_METRICS),
            "seeds": list(seeds),
            "seed_count": len(seeds),
            "deployment_recall_available": False,
            "beth_ground_truth_used": False,
        },
        "census": snapshot.as_census(),
        "eligibility": eligibility,
        "results": {
            "per_seed": seed_results,
            "summary": {
                "brier": _summary(result["brier"] for result in seed_results),
                "baseline_brier": _summary(result["baseline_brier"] for result in seed_results),
                "brier_improvement": _summary(result["brier_improvement"] for result in seed_results),
                "ece": _summary(result["ece"] for result in seed_results),
                "precision_within_alerts": _summary(precisions),
            },
        },
        "gates": gates,
        "package_versions": package_versions(),
        "elapsed_seconds": elapsed_seconds,
        "generated_at": started_at,
        "caps": [
            PRECISION_ONLY,
            "Unlabelled alerts and below-threshold events are not negatives.",
            NOT_GROUND_TRUTH,
            "No AUROC, AUPRC, recall or point-adjusted F1: undefined or meaningless here.",
            "A precision floor is operator-supplied; this harness asserts none of its own.",
        ],
    }


def print_report(report: dict[str, Any]) -> None:
    census = report["census"]
    summary = report["results"]["summary"]
    print(PRECISION_ONLY)
    print(f"Labelled dispositions: {census['labelled_rows']} "
          f"(positive {census['positive']}, negative {census['negative']}, "
          f"rate {census['positive_rate']:.4f}); snapshot sha256 {census['sha256'][:12]}")
    print(f"by status: {json.dumps(census['by_status'], sort_keys=True)}; "
          f"model states: {census['distinct_model_state_ids']}")
    print("Deployment recall: not available from this corpus (above-threshold alerts only).")
    for name in ("brier", "baseline_brier", "brier_improvement", "ece",
                 "precision_within_alerts"):
        entry = summary[name]
        print(f"{name}: {entry['mean']:.6f} +/- {entry['std']:.6f} over {entry['count']} seeds")
    gates = report["gates"]
    print(f"gate [calibration] {'ok' if gates['calibration']['passed'] else 'FAIL'}: "
          f"{gates['calibration']['rule']}")
    print(f"gate [monotonicity] {'ok' if gates['monotonicity']['passed'] else 'FAIL'}: "
          f"exercised on {gates['monotonicity']['exercised_seeds']} seeds")
    precision = gates["precision_regression"]
    if precision["armed"]:
        print(f"gate [precision] {'ok' if precision['passed'] else 'FAIL'}: "
              f"floor {precision['floor']:.4f}")
    else:
        print(f"gate [precision] unarmed: {precision['reason']}")
    print(f"rail: {'PASS' if gates['passed'] else 'FINDING'}")


def run_disposition(snapshot_path: str | Path, output: str | Path,
                    seeds: tuple[int, ...], precision_floor: float | None = None
                    ) -> tuple[dict[str, Any], str]:
    try:
        seeds = validate_seeds(seeds)
    except BethError as exc:
        raise DispositionError(str(exc)) from exc
    started = time.perf_counter()
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    snapshot = load_snapshot(snapshot_path)
    seed_results = [evaluate_seed(snapshot, seed) for seed in seeds]
    report = make_report(snapshot, seeds, seed_results, precision_floor,
                         time.perf_counter() - started, started_at=started_at)
    digest = write_report(str(output), report)
    return report, digest
