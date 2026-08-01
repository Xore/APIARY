"""
#63 evaluation fixtures: proves the temporal (LSTM-AE) side of the pipeline
against the real schema and the sequence-window/bounded-CPU-fallback
contract, the same way test_schema_contract.py proves it for the point
(IsoForest/HBOS) side.

Run: python3 -m pytest ml-worker/tests/test_temporal_features.py -v
"""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fixtures  # noqa: E402
import worker  # noqa: E402
from models.lstm_autoencoder import (  # noqa: E402
    LSTMAEModel, MAX_TRAIN_WINDOWS, SEQ_LEN, featurise_temporal,
)


class TestFeaturiseTemporalReadsTheRealSchema:
    """featurise_temporal() must read the same real fields
    models/isolation_forest.py's _get_* helpers do (#62), not the flat
    schema no real document has."""

    def test_port_and_proto_resolve_against_a_real_cowrie_event(self):
        src = fixtures.COWRIE_LOGIN_FAILED["_source"]
        vec = featurise_temporal(src, inter_arrival_s=60.0)
        assert vec[1] == pytest.approx(22 / 65535.0)   # dst_port_norm
        assert vec[2] == pytest.approx(0 / 3.0)         # tcp -> 0

    def test_inter_arrival_is_log_normalised_and_caller_supplied(self):
        src = fixtures.COWRIE_LOGIN_FAILED["_source"]
        near_zero = featurise_temporal(src, inter_arrival_s=0.0)[4]
        one_hour  = featurise_temporal(src, inter_arrival_s=3600.0)[4]
        assert near_zero < one_hour, "a longer gap between events must score higher, not be ignored"


class TestLSTMScoreTakesTheRealSourceDict:
    """#63: score()'s old contract took a slice of IsoForest's unrelated
    15-dim vector; it now takes the raw src dict, like extract_features()."""

    def test_score_returns_zero_before_the_window_fills(self):
        model = LSTMAEModel(model_dir="/tmp/does-not-matter-1")
        src = fixtures.COWRIE_LOGIN_FAILED["_source"]
        for _ in range(SEQ_LEN - 1):
            assert model.score(src) == 0.0

    def test_score_produces_a_real_value_once_the_window_fills(self):
        model = LSTMAEModel(model_dir="/tmp/does-not-matter-2")
        src = fixtures.COWRIE_LOGIN_FAILED["_source"]
        scores = [model.score(src) for _ in range(SEQ_LEN + 1)]
        assert scores[:SEQ_LEN - 1] == [0.0] * (SEQ_LEN - 1)
        assert 0.0 <= scores[-1] <= 1.0

    def test_inter_arrival_is_tracked_per_ip_across_calls(self):
        model = LSTMAEModel(model_dir="/tmp/does-not-matter-3")
        for doc in fixtures.COWRIE_SAME_IP_SEQUENCE[:3]:
            model.score(doc["_source"])
        ip = "203.0.113.9"
        assert ip in model._last_seen
        # events are 2s apart in the fixture
        first_ts = model._last_seen[ip]
        model.score(fixtures.COWRIE_SAME_IP_SEQUENCE[3]["_source"])
        assert model._last_seen[ip] > first_ts


class TestBoundedCPUFallback:
    """#63 hard requirement: inference failures must fall back to a defined
    neutral value, never propagate and take the batch down, and never read
    as "confirmed normal" (0.0) -- must be indistinguishable from the
    documented pre-training neutral default (0.5) used elsewhere."""

    def test_inference_exception_returns_the_documented_neutral_score(self, monkeypatch):
        model = LSTMAEModel(model_dir="/tmp/does-not-matter-4")
        src = fixtures.COWRIE_LOGIN_FAILED["_source"]
        for _ in range(SEQ_LEN - 1):
            model.score(src)

        def broken_forward(self, x):
            raise RuntimeError("simulated inference failure")

        monkeypatch.setattr(type(model.net), "forward", broken_forward)
        assert model.score(src) == 0.5

    def test_retrain_never_fits_more_than_max_train_windows(self, monkeypatch):
        import torch
        import models.lstm_autoencoder as lstm_mod

        # #65 split retrain() into train/holdout: MAX_TRAIN_WINDOWS still
        # bounds the total considered, but what DataLoader actually sees is
        # the train split (total - holdout). HOLDOUT_MIN is imported into
        # this module's namespace from isolation_forest.py, so it has to be
        # patched here, not on the module it was originally defined in.
        monkeypatch.setattr(lstm_mod, "MAX_TRAIN_WINDOWS", 40)
        monkeypatch.setattr(lstm_mod, "HOLDOUT_MIN", 5)
        model = LSTMAEModel(model_dir="/tmp/does-not-matter-5")
        sources = [doc["_source"] for doc in fixtures.COWRIE_SAME_IP_SEQUENCE] * 5  # far over the patched cap

        seen_dataset_sizes = []
        orig_loader = torch.utils.data.DataLoader

        def spy_loader(dataset, *a, **kw):
            seen_dataset_sizes.append(len(dataset))
            return orig_loader(dataset, *a, **kw)

        monkeypatch.setattr(torch.utils.data, "DataLoader", spy_loader)
        result = model.retrain(sources)

        assert seen_dataset_sizes, "retrain() must have actually trained given >BATCH_SIZE+HOLDOUT_MIN windows"
        assert seen_dataset_sizes[0] <= 40
        assert result.train_samples + result.holdout_samples <= 40, \
            "MAX_TRAIN_WINDOWS must still bound the total (train + holdout) considered"


class TestComputeCompositeIsTheSingleSourceOfTruth:
    """#63: the 0.4/0.4/0.2 ensemble formula (docs/ml-worker-plan.md §4.4)
    was duplicated verbatim in write_anomaly() and the main loop -- now both
    call worker.compute_composite()."""

    def test_matches_the_documented_formula(self):
        scores = {"isolation_forest": 1.0, "lstm_ae": 0.5, "hbos": 0.25}
        expected = 0.4 * 1.0 + 0.4 * 0.5 + 0.2 * 0.25
        assert worker.compute_composite(scores) == pytest.approx(expected)

    def test_missing_model_score_defaults_to_zero_not_an_error(self):
        assert worker.compute_composite({"isolation_forest": 1.0}) == pytest.approx(0.4)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
