#!/usr/bin/env python3
"""BETH Tier 2 architecture sanity rail for ml-worker.

This command is deliberately a *parallel-corpus* check. BETH contains eBPF
process events, whereas deployed ml-worker detectors consume honeypot and
network events. The feature mapping is intentionally not invented: the
published BETH process features are used to check that the architecture and
evaluation pipeline behave sanely against a labelled corpus.

The command never downloads data, talks to Elasticsearch, writes model state,
or changes deployment configuration. A local BETH directory containing the
three published benchmark CSVs is required.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score


BENCHMARK_VERSION = "apiary-ml-worker-beth-tier2-v1"
REPORT_VERSION = 1
DEFAULT_SEEDS = (1, 2, 3, 4, 5)
PAPER_AUROC = 0.850
SANITY_RAIL_TOLERANCE = 0.05
PAPER_BASE_RATES = {
    "train": 0.0017,
    "val": 0.0042,
    "test": 0.907,
}
PAPER_BASE_RATE_LABELS = {
    "train": "0.17% sus",
    "val": "0.42% sus",
    "test": "90.7% sus",
}
PUBLISHED_TEST_HOST = "ip-10-100-1-217"
PUBLISHED_SPLIT_COUNTS = {
    "train": {"rows": 763_144, "sus": 1_269, "evil": 0, "hosts": 8},
    "val": {"rows": 188_967, "sus": 786, "evil": 0, "hosts": 4},
    "test": {"rows": 188_967, "sus": 171_459, "evil": 158_432, "hosts": 1},
}
SPLIT_FILES = {
    "train": "labelled_training_data.csv",
    "val": "labelled_validation_data.csv",
    "test": "labelled_testing_data.csv",
}
FEATURE_COLUMNS = (
    "processId",
    "parentProcessId",
    "userId",
    "mountNamespace",
    "eventId",
    "argsNum",
    "returnValue",
)
REQUIRED_COLUMNS = set(FEATURE_COLUMNS) | {"sus", "evil", "hostName"}


class BethError(ValueError):
    """An invalid or absent local BETH corpus."""


class BannedMetricError(ValueError):
    """Raised before a forbidden metric can enter a run."""


@dataclass(frozen=True)
class SplitData:
    name: str
    path: Path
    md5: str
    frame: pd.DataFrame
    features: np.ndarray
    labels: np.ndarray
    positive_count: int
    negative_count: int

    @property
    def row_count(self) -> int:
        return len(self.frame)

    @property
    def positive_rate(self) -> float:
        return self.positive_count / self.row_count if self.row_count else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "file": self.path.name,
            "path": str(self.path),
            "md5": self.md5,
            "rows": self.row_count,
            "sus": self.positive_count,
            "evil": int(self.frame["evil"].sum()),
            "not_sus": self.negative_count,
            "positive_rate": self.positive_rate,
            "positive_base_rate": f"{self.positive_rate * 100:.2f}% sus",
            "paper_positive_rate": PAPER_BASE_RATES[self.name],
            "published_base_rate": PAPER_BASE_RATE_LABELS[self.name],
            "hosts": sorted(self.frame["hostName"].astype(str).unique().tolist()),
        }


def parse_seeds(value: str) -> tuple[int, ...]:
    """Parse a comma-separated seed list, rejecting underspecified runs."""
    try:
        seeds = tuple(int(part.strip()) for part in value.split(",") if part.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("seeds must be comma-separated integers") from exc
    try:
        return validate_seeds(seeds)
    except BethError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    beth = subparsers.add_parser(
        "beth",
        help="run the offline BETH architecture sanity rail",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    beth.add_argument(
        "--data-dir",
        required=True,
        type=Path,
        help="directory containing the three published BETH CSV files",
    )
    beth.add_argument(
        "--output",
        required=True,
        help="path for the hashed JSON run report (must be outside the repository)",
    )
    beth.add_argument(
        "--archive",
        type=Path,
        help="optional prepared BETH archive to checksum for the run report",
    )
    beth.add_argument(
        "--seeds",
        type=parse_seeds,
        default=DEFAULT_SEEDS,
        metavar="N,N,N,N,N",
        help="comma-separated seeds (default: 1,2,3,4,5; at least five)",
    )
    return parser


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _inside_repository(path: Path) -> bool:
    try:
        path.resolve().relative_to(_repository_root().resolve())
        return True
    except ValueError:
        return False


def _md5(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def encode_features(frame: pd.DataFrame) -> np.ndarray:
    """Apply the feature encoding published in the authors' dataset.py."""
    data = frame.loc[:, list(FEATURE_COLUMNS)].copy()
    data["processId"] = data["processId"].map(lambda value: 0 if value in [0, 1, 2] else 1)
    data["parentProcessId"] = data["parentProcessId"].map(
        lambda value: 0 if value in [0, 1, 2] else 1
    )
    data["userId"] = data["userId"].map(lambda value: 0 if value < 1000 else 1)
    data["mountNamespace"] = data["mountNamespace"].map(
        lambda value: 0 if value == 4026531840 else 1
    )
    data["returnValue"] = data["returnValue"].map(
        lambda value: 0 if value == 0 else (1 if value > 0 else 2)
    )
    try:
        values = data.to_numpy(dtype=np.int64)
    except (TypeError, ValueError) as exc:
        raise BethError("BETH feature columns must contain integer values") from exc
    if not np.isfinite(values).all():
        raise BethError("BETH feature columns contain a non-finite value")
    return values


def _validate_labels(frame: pd.DataFrame, split: str) -> np.ndarray:
    if frame["sus"].isna().any():
        raise BethError(f"{split} split has missing sus labels")
    try:
        labels = frame["sus"].astype(np.int64).to_numpy()
    except (TypeError, ValueError) as exc:
        raise BethError(f"{split} split sus labels must be binary integers") from exc
    if not np.array_equal(labels, frame["sus"].to_numpy()):
        raise BethError(f"{split} split sus labels must be binary integers")
    if not np.isin(labels, (0, 1)).all():
        raise BethError(f"{split} split sus labels must contain only 0 or 1")
    if frame["evil"].isna().any():
        raise BethError(f"{split} split has missing evil labels")
    try:
        evil = frame["evil"].astype(np.int64).to_numpy()
    except (TypeError, ValueError) as exc:
        raise BethError(f"{split} split evil labels must be binary integers") from exc
    if not np.array_equal(evil, frame["evil"].to_numpy()):
        raise BethError(f"{split} split evil labels must be binary integers")
    if not np.isin(evil, (0, 1)).all():
        raise BethError(f"{split} split evil labels must contain only 0 or 1")
    return labels


def _validate_frame(frame: pd.DataFrame, split: str) -> None:
    missing = REQUIRED_COLUMNS - set(frame.columns)
    if missing:
        raise BethError(f"{split} split is missing required columns: {', '.join(sorted(missing))}")
    if frame.empty:
        raise BethError(f"{split} split is empty")
    for column in FEATURE_COLUMNS:
        if frame[column].isna().any():
            raise BethError(f"{split} split has missing values in {column}")
    if frame["hostName"].isna().any() or (frame["hostName"].astype(str).str.len() == 0).any():
        raise BethError(f"{split} split has missing hostName values")
    try:
        for column in (*FEATURE_COLUMNS, "sus", "evil"):
            frame[column] = pd.to_numeric(frame[column], errors="raise")
    except (TypeError, ValueError) as exc:
        raise BethError(f"{split} split has non-numeric feature or label values") from exc


def load_split(data_dir: Path, split: str) -> SplitData:
    filename = SPLIT_FILES[split]
    path = data_dir / filename
    if not path.is_file():
        raise BethError(
            f"BETH dataset absent or incomplete: expected {path}. "
            "Prepare the published BETH CSVs outside the repository; this command does not download them."
        )
    try:
        frame = pd.read_csv(path)
    except (OSError, ValueError, pd.errors.ParserError) as exc:
        raise BethError(f"could not read BETH {split} file {path}: {exc}") from exc
    _validate_frame(frame, split)
    labels = _validate_labels(frame, split)
    features = encode_features(frame)
    return SplitData(
        name=split,
        path=path,
        md5=_md5(path),
        frame=frame,
        features=features,
        labels=labels,
        positive_count=int(labels.sum()),
        negative_count=int(len(labels) - labels.sum()),
    )


def load_splits(data_dir: Path) -> dict[str, SplitData]:
    """Load exactly the three published files; no row-level partitioning."""
    if _inside_repository(data_dir):
        raise BethError("BETH data directory must be outside the repository")
    if not data_dir.exists():
        raise BethError(
            f"BETH dataset absent: data directory does not exist: {data_dir}. "
            "Prepare the published BETH CSVs outside the repository; this command does not download them."
        )
    if not data_dir.is_dir():
        raise BethError(f"BETH dataset absent: data path is not a directory: {data_dir}")
    splits = {split: load_split(data_dir, split) for split in ("train", "val", "test")}
    validate_published_split_integrity(splits)
    return splits


def validate_seeds(seeds: Iterable[int]) -> tuple[int, ...]:
    values = tuple(int(seed) for seed in seeds)
    if len(values) < 5:
        raise BethError("at least five seeds are required for a BETH run")
    if len(set(values)) != len(values):
        raise BethError("BETH seeds must be unique")
    if any(seed < 0 for seed in values):
        raise BethError("BETH seeds must be non-negative")
    return values


def validate_published_split_integrity(splits: dict[str, SplitData]) -> dict[str, Any]:
    """Assert split identity without re-splitting, shuffling, or row sampling."""
    if set(splits) != set(SPLIT_FILES):
        raise BethError("BETH evaluation requires exactly train, val, and test splits")
    if any(split.frame.empty for split in splits.values()):
        raise BethError("published BETH splits must not be empty")
    if splits["train"].positive_count == 0 or splits["val"].positive_count == 0:
        raise BethError("train and val must retain their published sus labels")
    host_sets = {name: set(split.frame["hostName"].astype(str)) for name, split in splits.items()}
    evil_hosts = {}
    evil_labels = {}
    for name, split in splits.items():
        evil_labels[name] = split.frame["evil"].astype(np.int64).to_numpy()
        evil_hosts[name] = set(
            split.frame.loc[evil_labels[name] == 1, "hostName"].astype(str)
        )
    overlaps = {
        "train_val": host_sets["train"] & host_sets["val"],
        "train_test": host_sets["train"] & host_sets["test"],
        "val_test": host_sets["val"] & host_sets["test"],
    }
    if overlaps["train_test"] or overlaps["val_test"]:
        raise BethError(
            "published BETH host split integrity failed: "
            f"test host overlap train={sorted(overlaps['train_test'])}, "
            f"val={sorted(overlaps['val_test'])}"
        )
    if overlaps["train_val"] - {"ubuntu"}:
        raise BethError(
            "published BETH host split integrity failed: "
            f"unexpected train/val overlap {sorted(overlaps['train_val'])}"
        )
    if evil_hosts["train"] or evil_hosts["val"]:
        raise BethError("attack holdout failed: evil events appear in train or val")
    if not evil_hosts["test"]:
        raise BethError("attack holdout failed: test has no published evil events")
    if evil_hosts["test"] != {PUBLISHED_TEST_HOST}:
        raise BethError(
            "published BETH attack holdout failed: "
            f"expected test evil host {PUBLISHED_TEST_HOST}, observed {sorted(evil_hosts['test'])}"
        )
    if host_sets["test"] != {PUBLISHED_TEST_HOST}:
        raise BethError(
            "published BETH test host integrity failed: "
            f"expected only {PUBLISHED_TEST_HOST}, observed {sorted(host_sets['test'])}"
        )
    for name in ("train", "val", "test"):
        evil = evil_labels[name]
        if not np.isin(evil, (0, 1)).all():
            raise BethError(f"{name} split evil labels must contain only 0 or 1")
        if np.any(evil > splits[name].labels):
            raise BethError(f"{name} split has evil events without sus=1")
    for left, right in (("train", "val"), ("train", "test"), ("val", "test")):
        overlap = evil_hosts[left] & evil_hosts[right]
        if overlap:
            raise BethError(f"attack host leaked between {left} and {right}: {sorted(overlap)}")
    observed = {
        name: {
            "rows": split.row_count,
            "sus": split.positive_count,
            "evil": int(split.frame["evil"].sum()),
            "hosts": split.frame["hostName"].nunique(),
        }
        for name, split in splits.items()
    }
    for name, expected in PUBLISHED_SPLIT_COUNTS.items():
        if observed[name] != expected:
            raise BethError(
                f"published BETH {name} split integrity failed: "
                f"expected {expected}, observed {observed[name]}"
            )

    return {
        "files_loaded": list(SPLIT_FILES.values()),
        "rows": {name: split.row_count for name, split in splits.items()},
        "observed": observed,
        "row_integrity": "published files loaded in place; no row re-splitting or shuffling",
        "host_integrity": "published host names checked; benign ubuntu overlap is recorded without re-partitioning",
        "evil_hosts": {name: sorted(hosts) for name, hosts in evil_hosts.items()},
        "hosts": {name: sorted(hosts) for name, hosts in host_sets.items()},
        "host_overlap": {name: sorted(hosts) for name, hosts in overlaps.items()},
    }


def ensure_metric_allowed(metric: str) -> None:
    normalized = metric.lower().replace("_", " ").replace("-", " ")
    if "point adjusted f1" in normalized:
        raise BannedMetricError("the banned adjusted-segment F1 metric is not available")
    if normalized in {"shuffled split", "random split", "random split metrics"}:
        raise BannedMetricError("random or shuffled split metrics are banned from the BETH harness")


def validate_report_metrics(metrics: Iterable[str]) -> None:
    metric_names = tuple(metrics)
    for metric in metric_names:
        ensure_metric_allowed(metric)
    if not set(metric_names) <= {"auroc", "auprc"}:
        raise BannedMetricError("BETH reports may contain only AUROC and AUPRC")


def _rate_labels(labels: np.ndarray) -> np.ndarray:
    if not np.isin(labels, (0, 1)).all() or len(np.unique(labels)) != 2:
        raise BethError("AUROC/AUPRC require both sus and non-sus test labels")
    return labels


def _assert_no_row_partitioning() -> None:
    """Runtime guard against the banned row-level split path."""
    forbidden = {"train_test_split", "StratifiedKFold", "KFold", "GroupKFold", "sample", "shuffle"}
    if forbidden.intersection(set(globals())):
        raise BannedMetricError("row-level partitioning is banned; use the published BETH files")


def _run_seed(
    train: SplitData,
    val: SplitData,
    test: SplitData,
    seed: int,
    *,
    evaluate_validation: bool = False,
) -> dict[str, float]:
    ensure_metric_allowed("auroc")
    ensure_metric_allowed("auprc")
    whitener = PCA(whiten=True)
    whitener.fit(train.features)
    model = IsolationForest(contamination=0.05, random_state=seed)
    model.fit(whitener.transform(train.features))
    validation_scores = -model.decision_function(whitener.transform(val.features))
    test_scores = -model.decision_function(whitener.transform(test.features))
    if evaluate_validation:
        roc_auc_score(_rate_labels(val.labels), validation_scores)
        average_precision_score(_rate_labels(val.labels), validation_scores)
    return {
        "auroc": float(roc_auc_score(_rate_labels(test.labels), test_scores)),
        "auprc": float(average_precision_score(_rate_labels(test.labels), test_scores)),
        "validation_auroc": float(roc_auc_score(_rate_labels(val.labels), validation_scores)),
        "validation_auprc": float(
            average_precision_score(_rate_labels(val.labels), validation_scores)
        ),
    }


def _summary(values: Iterable[float]) -> dict[str, float | int]:
    array = np.asarray(list(values), dtype=float)
    return {
        "mean": float(array.mean()),
        "std": float(array.std(ddof=1)) if len(array) > 1 else 0.0,
        "count": int(len(array)),
    }


def _print_metrics(
    *,
    seed_results: list[dict[str, Any]],
    summary: dict[str, Any],
    split_rates: dict[str, float],
) -> None:
    validate_report_metrics(("auroc", "auprc"))
    rates = " / ".join(
        f"{name} {PAPER_BASE_RATE_LABELS[name]}" for name in ("train", "val", "test")
    )
    print(f"BETH base rates: {rates}")
    for result in seed_results:
        print(
            f"seed {result['seed']}: AUROC {result['auroc']:.6f} "
            f"(base rates {rates}); AUPRC {result['auprc']:.6f} "
            f"(base rates {rates})"
        )
    print(
        f"AUROC headline: {summary['auroc']['mean']:.6f} ± {summary['auroc']['std']:.6f} "
        f"(base rates {rates})"
    )
    print(
        f"AUPRC alongside: {summary['auprc']['mean']:.6f} ± {summary['auprc']['std']:.6f} "
        f"(base rates {rates})"
    )


def package_versions() -> dict[str, str]:
    versions = {"python": platform.python_version()}
    for name in ("numpy", "pandas", "scikit-learn"):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = "unavailable"
    return versions


def make_report(
    data_dir: Path,
    splits: dict[str, SplitData],
    seeds: tuple[int, ...],
    seed_results: list[dict[str, Any]],
    split_census: dict[str, Any],
    elapsed_seconds: float,
    archive: Path | None = None,
    *,
    started_at: str,
) -> dict[str, Any]:
    validate_report_metrics(("auroc", "auprc"))
    split_reports = {name: split.as_dict() for name, split in splits.items()}
    auroc_values = [result["auroc"] for result in seed_results]
    auprc_values = [result["auprc"] for result in seed_results]
    validation_auroc_values = [result["validation_auroc"] for result in seed_results]
    validation_auprc_values = [result["validation_auprc"] for result in seed_results]
    mean_auroc = float(np.mean(auroc_values))
    mean_auprc = float(np.mean(auprc_values))
    summary = {
        "auroc": _summary(auroc_values),
        "auprc": _summary(auprc_values),
        "validation_auroc": _summary(validation_auroc_values),
        "validation_auprc": _summary(validation_auprc_values),
    }
    gate_passed = abs(mean_auroc - PAPER_AUROC) <= SANITY_RAIL_TOLERANCE
    report = {
        "benchmark": BENCHMARK_VERSION,
        "report_version": REPORT_VERSION,
        "tier": 2,
        "generated_at": started_at,
        "data_dir": str(data_dir),
        "corpus": {
            "name": "BETH",
            "source": "katehighnam/beth-dataset",
            "licence": "CC0 1.0 Public Domain",
            "published_version": 3,
            "published_split_fingerprint": dict(PUBLISHED_SPLIT_COUNTS),
            "published_files": list(SPLIT_FILES.values()),
            "md5": {name: split["md5"] for name, split in split_reports.items()},
            "archive_md5": _md5(archive) if archive is not None else None,
            "archive": str(archive) if archive is not None else "not provided; prepared CSV directory only",
        },
        "splits": split_reports,
        "split_integrity": validate_published_split_integrity(splits),
        "features": {
            "source": "BETH_Dataset_Analysis/dataset.py",
            "columns": list(FEATURE_COLUMNS),
            "encoding": {
                "processId": "0 for 0/1/2, otherwise 1",
                "parentProcessId": "0 for 0/1/2, otherwise 1",
                "userId": "0 for values below 1000, otherwise 1",
                "mountNamespace": "0 for 4026531840, otherwise 1",
                "eventId": "raw value",
                "argsNum": "raw value",
                "returnValue": "0 for zero, 1 for positive, 2 for negative",
            },
        },
        "protocol": {
            "detector": "sklearn.ensemble.IsolationForest",
            "fit_split": "train",
            "validation_split": "val",
            "test_split": "test",
            "test_scored_once_per_seed": True,
            "test_seed_ensemble": list(seeds),
            "validation_use": "diagnostic only; IsolationForest has no early-stopping or calibration step",
            "pca": "fit on train only, whiten=True, matching the authors' WhitenedBenchmark",
            "contamination": 0.05,
            "metrics": ["auroc", "auprc"],
            "test_metric_scored_once": True,
            "seeds": list(seeds),
            "seed_count": len(seeds),
        },
        "results": {
            "per_seed": seed_results,
            "summary": summary,
            "headline_auroc": mean_auroc,
            "headline_auprc": mean_auprc,
            "sanity_gate": {
                "paper_auroc": PAPER_AUROC,
                "tolerance": SANITY_RAIL_TOLERANCE,
                "lower": PAPER_AUROC - SANITY_RAIL_TOLERANCE,
                "upper": PAPER_AUROC + SANITY_RAIL_TOLERANCE,
                "passed": gate_passed,
                "decision": "sanity rail only; not deployment promotion evidence",
            },
        },
        "split_census": split_census,
        "base_rates": {name: split["positive_rate"] for name, split in split_reports.items()},
        "published_base_rates": PAPER_BASE_RATES,
        "package_versions": package_versions(),
        "elapsed_seconds": elapsed_seconds,
        "caps": [
            "BETH is a parallel-corpus architecture sanity rail, never production ground truth.",
            "The eBPF process modality does not map to deployed honeypot/network features.",
            "No composite weight or ML_ALERT_THRESHOLD change is inferred or permitted.",
            "The published split is consumed as-is; the benign ubuntu overlap is recorded, never re-partitioned.",
            "Only the approved AUROC and AUPRC ranking metrics are emitted.",
            "The CSV directory is external; archive MD5 is unavailable unless an archive path is supplied.",
        ],
    }
    return report


def write_report(path: str | os.PathLike[str], report: dict[str, Any]) -> str:
    destination = Path(path).expanduser().resolve()
    if _inside_repository(destination):
        raise BethError("run report must be written outside the repository")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    handle, temporary = tempfile.mkstemp(prefix=".beth-", dir=destination.parent)
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


def run_beth(
    data_dir: Path,
    output: str,
    seeds: tuple[int, ...] = DEFAULT_SEEDS,
    archive: Path | None = None,
) -> tuple[dict[str, Any], str]:
    seeds = validate_seeds(seeds)
    started = time.perf_counter()
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _assert_no_row_partitioning()
    splits = load_splits(data_dir)
    validate_published_split_integrity(splits)
    if archive is not None:
        archive = archive.expanduser().resolve()
        if _inside_repository(archive):
            raise BethError("BETH archive must be outside the repository")
        if not archive.is_file():
            raise BethError(f"BETH archive does not exist: {archive}")
    seed_results = []
    for seed in seeds:
        result = _run_seed(splits["train"], splits["val"], splits["test"], seed)
        result["seed"] = seed
        seed_results.append(result)
    elapsed = time.perf_counter() - started
    split_census = {
        name: {
            "rows": split.row_count,
            "sus": split.positive_count,
            "evil": int(split.frame["evil"].sum()),
            "not_sus": split.negative_count,
            "positive_rate": split.positive_rate,
            "positive_base_rate": f"{split.positive_rate * 100:.2f}% sus",
            "published_base_rate": PAPER_BASE_RATE_LABELS[name],
        }
        for name, split in splits.items()
    }
    report = make_report(
        data_dir,
        splits,
        seeds,
        seed_results,
        split_census,
        elapsed,
        archive=archive,
        started_at=started_at,
    )
    digest = write_report(output, report)
    return report, digest


def _print_dataset_error(exc: Exception) -> None:
    print(f"error: {exc}", file=sys.stderr)
    print(
        "BETH data is external to this repository; no download was attempted. "
        "Place the three published labelled CSVs in the supplied --data-dir and retry.",
        file=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report, digest = run_beth(args.data_dir, args.output, args.seeds, args.archive)
    except (BethError, BannedMetricError, ValueError) as exc:
        _print_dataset_error(exc)
        return 2
    split_rates = {name: float(split["positive_rate"]) for name, split in report["splits"].items()}
    _print_metrics(
        seed_results=report["results"]["per_seed"],
        summary=report["results"]["summary"],
        split_rates=split_rates,
    )
    gate = report["results"]["sanity_gate"]
    print(
        f"iForest sanity gate: {'PASS' if gate['passed'] else 'FINDING'} "
        f"(paper {PAPER_AUROC:.3f}, range {gate['lower']:.3f}-{gate['upper']:.3f})"
    )
    print(json.dumps({"report_sha256": digest, "written": str(Path(args.output).resolve())}))
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
