"""
#65: retrain() acceptance gate, versioning/retention, and the standalone
lifecycle helpers. See docs/ml-worker-plan.md §11 for the design this
proves against.

Run: python3 -m pytest ml-worker/tests/test_model_lifecycle.py -v
"""
import json
import os
import sys
from pathlib import Path

import numpy as np
import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from unittest.mock import MagicMock

import fixtures  # noqa: E402
import models.isolation_forest as iso_mod  # noqa: E402
import models.lstm_autoencoder as lstm_mod  # noqa: E402
import worker  # noqa: E402
from models.isolation_forest import CONTAMINATION, IsoForestModel, RetrainResult  # noqa: E402
from models.lstm_autoencoder import LSTMAEModel  # noqa: E402
from models import lifecycle  # noqa: E402


def _lstm_sources(n=140):
    """n real-shaped, time-ordered, same-IP Cowrie events -- enough windows
    (n - SEQ_LEN + 1) to clear BATCH_SIZE + HOLDOUT_MIN for a real
    train/holdout split."""
    return [fixtures._cowrie_command_at(i * 2.0, f"cmd-{i}")["_source"] for i in range(n)]


class TestAcceptDecisionPolicy:
    """The acceptance policy in isolation from any real model fit -- pure
    function of two floats, so these are exact and deterministic rather
    than relying on IsolationForest's stochastic behavior to land on a
    particular outcome."""

    def test_within_tolerance_of_previous_rate_is_accepted(self):
        accepted, reason = iso_mod._accept_decision(candidate_rate=0.02, previous_rate=0.01)
        assert accepted is True
        assert reason == "accepted"

    def test_far_above_previous_rate_is_rejected(self):
        accepted, reason = iso_mod._accept_decision(candidate_rate=0.40, previous_rate=0.01)
        assert accepted is False
        assert "exceeds" in reason

    def test_exactly_at_the_tolerance_ceiling_is_accepted(self):
        previous = 0.02
        ceiling = previous * iso_mod.ACCEPT_TOLERANCE
        accepted, _ = iso_mod._accept_decision(candidate_rate=ceiling, previous_rate=previous)
        assert accepted is True, "the boundary itself must accept, not just values strictly below it"

    def test_no_previous_model_falls_back_to_contamination_as_reference(self):
        # First-ever retrain: nothing to compare against, so CONTAMINATION
        # (the model's own declared expected rate) is the reference.
        just_under = CONTAMINATION * iso_mod.ACCEPT_TOLERANCE - 0.001
        just_over = CONTAMINATION * iso_mod.ACCEPT_TOLERANCE + 0.001
        assert iso_mod._accept_decision(just_under, None)[0] is True
        assert iso_mod._accept_decision(just_over, None)[0] is False

    def test_reference_never_drops_below_contamination_even_if_previous_was_lower(self):
        # A previous model with an unusually low rate (e.g. 0.001) must not
        # make the ceiling stricter than CONTAMINATION itself would allow --
        # otherwise a healthy model would fail its own model's baseline.
        accepted, _ = iso_mod._accept_decision(
            candidate_rate=CONTAMINATION * iso_mod.ACCEPT_TOLERANCE - 0.0001,
            previous_rate=0.001,
        )
        assert accepted is True


class TestRetrainAcceptanceGate:
    """retrain() end to end, with _anomaly_rate monkeypatched to force a
    deterministic outcome -- avoids relying on IsolationForest's stochastic
    fit to happen to produce a rejection on real feature data."""

    def _sources(self, n=120):
        return [fixtures.COWRIE_LOGIN_FAILED["_source"]] * n

    def test_first_ever_retrain_is_accepted_and_saves(self, tmp_path):
        model = IsoForestModel(model_dir=str(tmp_path))
        assert model.iso is None  # nothing loaded, no prior model on disk

        result = model.retrain(self._sources())

        assert result.accepted is True
        assert model.iso is not None and model.hbos is not None
        assert (tmp_path / "current_isoforest.joblib").exists()
        assert (tmp_path / "current_hbos.joblib").exists()

    def test_rejected_candidate_does_not_replace_the_active_model(self, tmp_path, monkeypatch):
        model = IsoForestModel(model_dir=str(tmp_path))
        first = model.retrain(self._sources())
        assert first.accepted is True
        active_iso, active_hbos = model.iso, model.hbos

        # Force the second retrain's CANDIDATE to look badly broken while
        # the ACTIVE (previous) model still reports its real low rate --
        # distinguished by which model object _anomaly_rate was called
        # with, so this isn't just "both sides go up together."
        real_anomaly_rate = iso_mod._anomaly_rate

        def rigged(iso, hbos, X):
            if iso is active_iso:
                return real_anomaly_rate(iso, hbos, X)
            return 0.9

        monkeypatch.setattr(iso_mod, "_anomaly_rate", rigged)
        second = model.retrain(self._sources())

        assert second.accepted is False
        assert model.iso is active_iso and model.hbos is active_hbos, \
            "a rejected candidate must never replace the currently active model"

    def test_rejected_candidate_writes_no_new_version_files(self, tmp_path, monkeypatch):
        model = IsoForestModel(model_dir=str(tmp_path))
        model.retrain(self._sources())
        active_iso = model.iso
        before = set(os.listdir(tmp_path))

        real_anomaly_rate = iso_mod._anomaly_rate

        def rigged(iso, hbos, X):
            if iso is active_iso:
                return real_anomaly_rate(iso, hbos, X)
            return 0.9

        monkeypatch.setattr(iso_mod, "_anomaly_rate", rigged)
        second = model.retrain(self._sources())
        after = set(os.listdir(tmp_path))

        assert second.accepted is False
        assert after == before, "a rejected candidate must not be saved to disk at all"

    def test_too_little_data_is_rejected_without_raising(self, tmp_path):
        model = IsoForestModel(model_dir=str(tmp_path))
        result = model.retrain([fixtures.COWRIE_LOGIN_FAILED["_source"]])  # n=1, no split possible
        assert result.accepted is False
        assert result.holdout_samples == 0

    def test_accepted_version_gets_metadata_evidence(self, tmp_path):
        model = IsoForestModel(model_dir=str(tmp_path))
        result = model.retrain(self._sources())
        meta_files = list(tmp_path.glob("isoforest_*.meta.json"))
        assert len(meta_files) == 1
        meta = json.loads(meta_files[0].read_text())
        assert meta["accepted"] is True
        assert meta["train_samples"] == result.train_samples
        assert meta["holdout_samples"] == result.holdout_samples


class TestLifecycleHelpers:
    def test_prune_old_versions_keeps_only_the_newest_n(self, tmp_path):
        for ts in [100, 200, 300, 400, 500]:
            (tmp_path / f"isoforest_{ts}.joblib").write_text("x")
            (tmp_path / f"isoforest_{ts}.meta.json").write_text("{}")

        lifecycle.prune_old_versions(str(tmp_path), "isoforest", keep=2)

        remaining = sorted(p.name for p in tmp_path.glob("isoforest_*"))
        assert remaining == ["isoforest_400.joblib", "isoforest_400.meta.json",
                              "isoforest_500.joblib", "isoforest_500.meta.json"], \
            "must keep exactly the 2 newest versions (by embedded timestamp) and their sidecars"

    def test_prune_ignores_unrelated_prefixes(self, tmp_path):
        (tmp_path / "isoforest_100.joblib").write_text("x")
        (tmp_path / "hbos_100.joblib").write_text("x")
        lifecycle.prune_old_versions(str(tmp_path), "isoforest", keep=0)
        assert not (tmp_path / "isoforest_100.joblib").exists()
        assert (tmp_path / "hbos_100.joblib").exists(), "pruning one model's prefix must not touch another's files"

    def test_write_version_metadata_round_trips(self, tmp_path):
        lifecycle.write_version_metadata(str(tmp_path), "isoforest", 123, {"accepted": True, "rate": 0.02})
        data = json.loads((tmp_path / "isoforest_123.meta.json").read_text())
        assert data == {"accepted": True, "rate": 0.02}


class TestRetrainRetentionIntegration:
    def test_repeated_accepted_retrains_prune_to_max_retained_versions(self, tmp_path, monkeypatch):
        model = IsoForestModel(model_dir=str(tmp_path))
        sources = [fixtures.COWRIE_LOGIN_FAILED["_source"]] * 120

        # _save()'s version timestamp is int(time.time()); five retrains in
        # the same test would otherwise collide on the same second and
        # overwrite each other's files rather than accumulating versions to
        # prune. Force strictly increasing timestamps instead.
        counter = [1_700_000_000]

        def fake_time():
            counter[0] += 10
            return counter[0]

        monkeypatch.setattr(iso_mod.time, "time", fake_time)
        for _ in range(lifecycle.MAX_RETAINED_VERSIONS + 3):
            result = model.retrain(sources)
            assert result.accepted is True

        joblib_files = list(tmp_path.glob("isoforest_*.joblib"))
        assert len(joblib_files) == lifecycle.MAX_RETAINED_VERSIONS, \
            f"expected pruning to {lifecycle.MAX_RETAINED_VERSIONS} retained versions, found {len(joblib_files)}"


class TestLSTMRetrainAcceptanceGate:
    """Same acceptance-gate contract as IsoForestModel, but LSTM-AE
    fine-tunes in place (optimiser.step() mutates self.net's weights
    directly) rather than fitting a separate candidate object -- these
    prove a rejected fine-tune is actually rolled back, not just ignored."""

    def test_first_ever_retrain_is_accepted_and_saves(self, tmp_path):
        model = LSTMAEModel(model_dir=str(tmp_path))
        assert model._trained is False

        result = model.retrain(_lstm_sources())

        assert result.accepted is True
        assert model._trained is True
        assert (tmp_path / "current_lstm_ae.pt").exists()

    def test_rejected_finetune_is_rolled_back_to_the_original_weights(self, tmp_path, monkeypatch):
        model = LSTMAEModel(model_dir=str(tmp_path))
        first = model.retrain(_lstm_sources())
        assert first.accepted is True
        original_state = {k: v.clone() for k, v in model.net.state_dict().items()}
        original_threshold = model.threshold

        # Unlike IsoForest's candidate_iso (a distinct object), LSTM fine-
        # tunes self.net in place -- the "previous" and "candidate" calls
        # both receive the SAME object reference, so they're distinguished
        # by call order instead: first call is the pre-finetune score,
        # second is the candidate's.
        real_anomaly_rate = lstm_mod._anomaly_rate
        calls = []

        def rigged(net, threshold, X):
            calls.append(1)
            if len(calls) == 1:
                return real_anomaly_rate(net, threshold, X)
            return 0.9

        monkeypatch.setattr(lstm_mod, "_anomaly_rate", rigged)
        second = model.retrain(_lstm_sources())

        assert second.accepted is False
        assert model.threshold == original_threshold
        for key, value in model.net.state_dict().items():
            assert torch.equal(value, original_state[key]), \
                f"parameter {key} was left mutated by a rejected fine-tune instead of being rolled back"

    def test_rejected_finetune_writes_no_new_version_files(self, tmp_path, monkeypatch):
        model = LSTMAEModel(model_dir=str(tmp_path))
        first = model.retrain(_lstm_sources())
        assert first.accepted is True
        before = set(os.listdir(tmp_path))

        # A naive constant mock (return 0.9 unconditionally) is a trap here:
        # if the *previous* rate is also mocked to 0.9, 0.9 <= 0.9*ACCEPT_TOLERANCE
        # is trivially true and the "rejected" premise never actually holds --
        # this test would then only pass by accident, contingent on whether
        # the FIRST (real, unmocked) retrain happened to be accepted, which
        # depends on unseeded model initialization. Same call-order rig as
        # the rollback test above: real score for the first (previous) call,
        # forced-high for the second (candidate).
        real_anomaly_rate = lstm_mod._anomaly_rate
        calls = []

        def rigged(net, threshold, X):
            calls.append(1)
            return real_anomaly_rate(net, threshold, X) if len(calls) == 1 else 0.9

        monkeypatch.setattr(lstm_mod, "_anomaly_rate", rigged)
        second = model.retrain(_lstm_sources())
        after = set(os.listdir(tmp_path))

        assert second.accepted is False
        assert after == before, "a rejected fine-tune must not be saved to disk at all"

    def test_too_few_windows_is_rejected_without_raising(self, tmp_path):
        model = LSTMAEModel(model_dir=str(tmp_path))
        result = model.retrain(_lstm_sources(n=20))  # far fewer than BATCH_SIZE+HOLDOUT_MIN windows
        assert result.accepted is False
        assert result.holdout_samples == 0

    def test_accepted_version_gets_metadata_evidence(self, tmp_path):
        model = LSTMAEModel(model_dir=str(tmp_path))
        result = model.retrain(_lstm_sources())
        meta_files = list(tmp_path.glob("lstm_ae_*.meta.json"))
        assert len(meta_files) == 1
        meta = json.loads(meta_files[0].read_text())
        assert meta["accepted"] is True
        assert meta["train_samples"] == result.train_samples


class TestWriteRetrainMetric:
    """#65: METRICS_INDEX was declared in worker.py but never written to
    until now -- proves the evidence actually reaches ml-worker-metrics in
    the shape docs/ml-worker-plan.md §11.4 documents, for both outcomes."""

    def test_accepted_result_is_written_with_both_rates(self):
        es = MagicMock()
        result = RetrainResult(
            accepted=True, reason="accepted", train_samples=900, holdout_samples=100,
            anomaly_rate_new=0.012, anomaly_rate_previous=0.009,
        )
        worker.write_retrain_metric(es, "isolation_forest_hbos", result)

        doc = es.index.call_args.kwargs["document"]
        assert doc["kind"] == "retrain"
        assert doc["model"] == "isolation_forest_hbos"
        assert doc["accepted"] is True
        assert doc["anomaly_rate_new"] == 0.012
        assert doc["anomaly_rate_previous"] == 0.009

    def test_first_ever_retrain_has_no_previous_rate(self):
        es = MagicMock()
        result = RetrainResult(
            accepted=True, reason="accepted", train_samples=900, holdout_samples=100,
            anomaly_rate_new=0.012, anomaly_rate_previous=None,
        )
        worker.write_retrain_metric(es, "isolation_forest_hbos", result)
        assert es.index.call_args.kwargs["document"]["anomaly_rate_previous"] is None

    def test_metrics_write_failure_does_not_raise(self):
        es = MagicMock()
        es.index.side_effect = ConnectionError("ES unreachable")
        result = RetrainResult(
            accepted=False, reason="candidate failed to fit", train_samples=10, holdout_samples=5,
            anomaly_rate_new=0.0, anomaly_rate_previous=None,
        )
        worker.write_retrain_metric(es, "lstm_ae", result)  # must not raise


class TestDriftDetection:
    """#65, docs/ml-worker-plan.md §11.4: a rolling window of real composite
    scores, sustained above DRIFT_ANOMALY_RATE, should trigger an early
    retrain. drift_rate_if_triggered() is the pure decision extracted from
    run_worker()'s loop so this is testable without driving the whole
    infinite polling loop."""

    def test_below_threshold_rate_does_not_trigger(self):
        flags = [False] * 90 + [True] * 10  # 10% anomaly rate
        assert worker.drift_rate_if_triggered(flags, window=100, rate_threshold=0.15) is None

    def test_above_threshold_rate_triggers_with_the_observed_rate(self):
        flags = [False] * 80 + [True] * 20  # 20% anomaly rate
        rate = worker.drift_rate_if_triggered(flags, window=100, rate_threshold=0.15)
        assert rate == pytest.approx(0.20)

    def test_incomplete_window_never_triggers(self):
        flags = [True] * 50  # 100% rate, but window not yet full
        assert worker.drift_rate_if_triggered(flags, window=100, rate_threshold=0.15) is None

    def test_write_drift_metric_records_window_and_rate(self):
        es = MagicMock()
        worker.write_drift_metric(es, window=500, rate=0.23)
        doc = es.index.call_args.kwargs["document"]
        assert doc["kind"] == "drift"
        assert doc["drift_window"] == 500
        assert doc["drift_rate"] == 0.23

    def test_drift_metric_write_failure_does_not_raise(self):
        es = MagicMock()
        es.index.side_effect = ConnectionError("ES unreachable")
        worker.write_drift_metric(es, window=500, rate=0.5)  # must not raise
