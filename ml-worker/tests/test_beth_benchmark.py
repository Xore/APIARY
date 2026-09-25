"""Focused tests for the BETH Tier 2 sanity rail.

The fixtures are synthetic and deliberately small. They prove the protocol
contract without pretending to provide BETH results: the three published files
are loaded in place, the attack-holdout invariant is checked, and the banned
adjusted-segment metric cannot enter the report.
"""

import json
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.evaluate_accuracy import (  # noqa: E402
    BannedMetricError,
    BethError,
    PUBLISHED_SPLIT_COUNTS,
    SPLIT_FILES,
    build_parser,
    encode_features,
    ensure_metric_allowed,
    load_splits,
    parse_seeds,
    run_beth,
    validate_published_split_integrity,
)


@pytest.fixture(autouse=True)
def small_published_profile(monkeypatch):
    """Use a small deterministic stand-in for the published row fingerprint."""
    monkeypatch.setattr(
        "benchmarks.evaluate_accuracy.PUBLISHED_SPLIT_COUNTS",
        {
            "train": {"rows": 12, "sus": 2, "evil": 0, "hosts": 1},
            "val": {"rows": 10, "sus": 2, "evil": 0, "hosts": 1},
            "test": {"rows": 12, "sus": 4, "evil": 4, "hosts": 1},
        },
    )


def _frame(host: str, count: int = 8, *, evil: int = 0) -> pd.DataFrame:
    rows = []
    for index in range(count):
        rows.append(
            {
                "processId": 0 if index % 2 else 500,
                "parentProcessId": 1 if index % 2 else 501,
                "userId": 0 if index % 2 else 1001,
                "mountNamespace": 4026531840 if index % 2 else 4026531841,
                "eventId": 10 + index,
                "argsNum": index % 4,
                "returnValue": 0 if index % 3 == 0 else (-1 if index % 3 == 1 else 2),
                "sus": 1 if index < max(2, evil) else 0,
                "evil": 1 if evil and index < evil else 0,
                "hostName": host,
            }
        )
    return pd.DataFrame(rows)


def _write_published_layout(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    data_dir = tmp_path / "beth"
    data_dir.mkdir()
    # The benign `ubuntu` overlap is documented in the published split; the
    # attack host remains absent from train and validation.
    pd.DataFrame(_frame("ubuntu", count=12)).to_csv(
        data_dir / SPLIT_FILES["train"], index=False
    )
    pd.DataFrame(_frame("ubuntu", count=10)).to_csv(
        data_dir / SPLIT_FILES["val"], index=False
    )
    pd.DataFrame(_frame("ip-10-100-1-217", count=12, evil=4)).to_csv(
        data_dir / SPLIT_FILES["test"], index=False
    )
    return data_dir


class TestLoaderAndProtocol:
    def test_absent_data_is_a_clear_error_without_a_traceback(self, tmp_path):
        with pytest.raises(BethError, match="BETH dataset absent"):
            load_splits(tmp_path / "absent")

    def test_published_files_are_loaded_without_re_splitting(self, tmp_path):
        data_dir = _write_published_layout(tmp_path)
        splits = load_splits(data_dir)
        assert [split.name for split in splits.values()] == ["train", "val", "test"]
        assert validate_published_split_integrity(splits)["row_integrity"].startswith(
            "published files loaded in place"
        )
        assert splits["train"].path.name == SPLIT_FILES["train"]
        assert splits["val"].path.name == SPLIT_FILES["val"]
        assert splits["test"].path.name == SPLIT_FILES["test"]

    def test_published_fingerprint_rejects_a_resplit(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "benchmarks.evaluate_accuracy.PUBLISHED_SPLIT_COUNTS", PUBLISHED_SPLIT_COUNTS
        )
        with pytest.raises(BethError, match="expected"):
            load_splits(_write_published_layout(tmp_path))

    def test_attack_leak_and_arbitrary_host_overlap_are_rejected(self, tmp_path):
        data_dir = _write_published_layout(tmp_path)
        train = pd.read_csv(data_dir / SPLIT_FILES["train"])
        train.loc[0, "evil"] = 1
        train.to_csv(data_dir / SPLIT_FILES["train"], index=False)
        with pytest.raises(BethError, match="attack holdout"):
            load_splits(data_dir)

        overlap_root = tmp_path / "overlap"
        data_dir = _write_published_layout(overlap_root)
        val = pd.read_csv(data_dir / SPLIT_FILES["val"])
        val.loc[0, "hostName"] = "unexpected-host"
        train = pd.read_csv(data_dir / SPLIT_FILES["train"])
        train.loc[0, "hostName"] = "unexpected-host"
        train.to_csv(data_dir / SPLIT_FILES["train"], index=False)
        val.to_csv(data_dir / SPLIT_FILES["val"], index=False)
        with pytest.raises(BethError, match="host split integrity"):
            load_splits(data_dir)

    def test_authors_encoding_is_explicit(self):
        frame = pd.DataFrame(
            [
                {
                    "processId": 0,
                    "parentProcessId": 1,
                    "userId": 999,
                    "mountNamespace": 4026531840,
                    "eventId": 1010,
                    "argsNum": 3,
                    "returnValue": 0,
                },
                {
                    "processId": 500,
                    "parentProcessId": 501,
                    "userId": 1000,
                    "mountNamespace": 4026531841,
                    "eventId": 1011,
                    "argsNum": 4,
                    "returnValue": -2,
                },
                {
                    "processId": 2,
                    "parentProcessId": 2,
                    "userId": 1001,
                    "mountNamespace": 0,
                    "eventId": 0,
                    "argsNum": 0,
                    "returnValue": 7,
                },
            ]
        )
        encoded = encode_features(frame)
        assert encoded.shape == (len(frame), 7)
        assert encoded.tolist() == [
            [0, 0, 0, 0, 1010, 3, 0],
            [1, 1, 1, 1, 1011, 4, 2],
            [0, 0, 1, 1, 0, 0, 1],
        ]


class TestBannedMetricGuard:
    def test_point_adjusted_metric_is_refused(self):
        with pytest.raises(BannedMetricError):
            ensure_metric_allowed("point-adjusted F1")
        with pytest.raises(BannedMetricError):
            ensure_metric_allowed("point_adjusted_f1")

    def test_report_metric_set_is_allowlisted(self):
        with pytest.raises(BannedMetricError):
            from benchmarks.evaluate_accuracy import validate_report_metrics

            validate_report_metrics(["auroc", "point-adjusted F1"])

    def test_serialized_report_contains_no_banned_metric_key(self, tmp_path):
        data_dir = _write_published_layout(tmp_path)
        archive = tmp_path / "beth.zip"
        archive.write_bytes(b"prepared archive")
        report, digest = run_beth(data_dir, str(tmp_path / "outside.json"), archive=archive)
        payload = json.dumps(report)
        assert "point_adjusted_f1" not in payload
        assert "point-adjusted F1" not in payload
        assert report["protocol"]["metrics"] == ["auroc", "auprc"]
        assert report["results"]["summary"]["auroc"]["count"] >= 5
        assert report["corpus"]["md5"].keys() == {"train", "val", "test"}
        assert report["corpus"]["archive_md5"]
        assert report["protocol"]["test_scored_once_per_seed"] is True
        assert len(digest) == 64

    def test_print_keeps_published_base_rates_beside_each_metric(self, capsys):
        from benchmarks.evaluate_accuracy import _print_metrics

        _print_metrics(
            seed_results=[{"seed": 1, "auroc": 0.8, "auprc": 0.7}],
            summary={
                "auroc": {"mean": 0.8, "std": 0.01},
                "auprc": {"mean": 0.7, "std": 0.02},
            },
            split_rates={"train": 0.0017, "val": 0.0042, "test": 0.907},
        )
        output = capsys.readouterr().out
        assert "train 0.17% sus / val 0.42% sus / test 90.7% sus" in output
        assert output.count("base rates train") == 4


class TestArgumentValidation:
    def test_at_least_five_seeds_are_required(self):
        assert parse_seeds("1,2,3,4,5") == (1, 2, 3, 4, 5)
        with pytest.raises(Exception, match="at least five"):
            parse_seeds("1,2,3,4")
        with pytest.raises(Exception, match="unique"):
            parse_seeds("1,1,2,3,4")

    def test_parser_is_importable_without_data(self):
        parser = build_parser()
        args = parser.parse_args(
            ["beth", "--data-dir", "/tmp/beth", "--output", "/tmp/beth-report.json"]
        )
        assert args.command == "beth"
        assert args.data_dir == Path("/tmp/beth")
        assert args.output == "/tmp/beth-report.json"
