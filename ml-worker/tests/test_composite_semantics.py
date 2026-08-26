"""
#1969 -- composite scoring semantics: "detector didn't run" must never read
as "detector scored benign", an untrained detector keeps no vote, and the
severity bands derive from ML_ALERT_THRESHOLD instead of drifting beside it.

The three acceptance pins the issue names live here:
1. untrained IsoForest + saturated LSTM + passing HBOS => composite computed
   over {lstm_ae, hbos} RENORMALIZED, not over a 0.5 placeholder constant;
2. changing ML_ALERT_THRESHOLD moves the medium band boundary with it;
3. (docs §4.4) the shipped SEVERITY_BANDS equal the derivation from
   THRESHOLD, so code and plan text cannot silently disagree.

Run: python3 -m pytest ml-worker/tests/test_composite_semantics.py -v
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import worker  # noqa: E402
from worker import (_severity_bands, compute_composite, contributing_detectors,
                    severity, write_anomaly)  # noqa: E402


# A real-shaped honeypot-v2-* document (multipot handshake), same structure as
# the one in test_worker_audit.py -- field nesting verified live against the
# homeserver ES; values synthetic. Duplicated here rather than imported so a
# refactor of one audit test can't break these pins.
REAL_SHAPED_DOCUMENT = {
    "_index": ".ds-honeypot-v2-2026.07.31-2026.07.31-000001",
    "_id": "synthetic-fixture-1",
    "_source": {
        "@timestamp": "2026-07-31T19:14:12.531Z",
        "pipeline": "honeypot",
        "honeypot": {
            "src_ip": "203.0.113.9",
            "port": 5900,
            "proto": "vnc",
            "sensor": "multipot",
            "event": "handshake",
        },
        "source": {
            "ip": "203.0.113.9",
            "geo": {"country_iso_code": "CN"},
            "as": {"organization_name": "Example Networks", "type": "network"},
        },
        "destination": {"port": 5900},
        "network": {"protocol": "vnc"},
        "event": {"sensor": "multipot"},
    },
}


class TestComputeCompositeRenormalizesOverPresentDetectors:
    """Acceptance pin 1, unit level (#1969 'What needs to change'): scores
    values become optional (None = didn't run / untrained); compute_composite
    renormalizes over present detectors."""

    def test_all_detectors_present_is_the_unchanged_weighted_sum(self):
        # (0.4 + 0.4 + 0.2) / 1.0 -- weights still sum to 1, so the full
        # ensemble's arithmetic is bit-for-bit what it always was.
        scores = {"isolation_forest": 0.8, "lstm_ae": 0.6, "hbos": 1.0}
        expected = 0.4 * 0.8 + 0.4 * 0.6 + 0.2 * 1.0
        assert compute_composite(scores) == pytest.approx(expected)

    def test_untrained_isoforest_is_excluded_and_weights_renormalize(self):
        # THE acceptance case: hbos and lstm opine, iso has none. Under the
        # old encoding the missing detector was a 0.5 constant keeping its
        # full 0.4 weight; now its weight vanishes from BOTH terms.
        scores = {"isolation_forest": None, "lstm_ae": 1.0, "hbos": 0.9}
        assert compute_composite(scores) == pytest.approx((0.4 * 1.0 + 0.2 * 0.9) / 0.6)

    def test_skipped_lstm_no_longer_acts_as_a_hidden_veto(self):
        # Pre-#1969 this exact input composed to 0.4*1.0 + 0.2*0.49 + 0.0 =
        # 0.498 < 0.75 ALWAYS -- nothing could ever alert without LSTM
        # running. Renormalised, the same opinions cross the default bar.
        scores = {"isolation_forest": 1.0, "lstm_ae": None, "hbos": 0.49}
        assert compute_composite(scores) == pytest.approx((0.4 * 1.0 + 0.2 * 0.49) / 0.6)
        assert compute_composite(scores) >= worker.THRESHOLD

    def test_everything_absent_composites_to_zero(self):
        assert compute_composite({}) == 0.0
        assert compute_composite({"isolation_forest": None, "lstm_ae": None, "hbos": None}) == 0.0

    def test_single_detector_opinion_stands_at_face_value(self):
        assert compute_composite({"isolation_forest": 0.9, "lstm_ae": None, "hbos": None}) == pytest.approx(0.9)


class TestContributingDetectors:
    """The contributing set is written onto every anomaly doc (#1969) --
    a flat aggregatable answer to 'which detector fired this'."""

    def test_lists_exactly_the_detectors_that_opined_sorted(self):
        scores = {"isolation_forest": None, "lstm_ae": 1.0, "hbos": 0.9}
        assert contributing_detectors(scores) == ["hbos", "lstm_ae"]

    def test_empty_when_nobody_opined(self):
        assert contributing_detectors({"isolation_forest": None, "lstm_ae": None, "hbos": None}) == []


class TestSeverityBandsDeriveFromThreshold:
    """Acceptance pins 2 and 3 (#1969): THRESHOLD and the bands cannot drift
    apart -- medium starts AT the alerting bar, high/critical sit above it,
    and the module-level bands ARE the derivation applied to THRESHOLD."""

    def test_default_threshold_reproduces_the_historical_absolute_bands(self):
        # Backwards-compatibility anchor: the constants this derivation
        # replaces were (0.95 critical) / (0.85 high) / (0.75 medium).
        bands = dict((round(t, 10), label) for t, label in _severity_bands(0.75))
        assert bands[0.95] == "critical"
        assert bands[0.85] == "high"
        assert bands[0.75] == "medium"

    def test_raising_the_threshold_moves_the_medium_boundary_with_it(self):
        bands = dict((round(t, 10), label) for t, label in _severity_bands(0.85))
        assert bands[0.85] == "medium"
        assert bands[0.95] == "high"
        assert bands[1.05] == "critical"
        # ...and the old "high" boundary of 0.85 must NOT survive as high.
        assert dict((round(t, 10), label) for t, label in _severity_bands(0.85))[0.85] != "high"

    def test_module_bands_are_the_derivation_of_threshold_no_drift(self):
        derived = [(t, label) for t, label in _severity_bands(worker.THRESHOLD)]
        assert [(t, label) for t, label in worker.SEVERITY_BANDS] == [
            (pytest.approx(t), label) for t, label in derived
        ]

    def test_severity_labels_track_the_derived_bands(self):
        assert severity(0.99) == "critical"
        assert severity(0.90) == "high"
        assert severity(0.80) == "medium"
        assert severity(0.10) == "low"


class TestEndToEndDetectorAbsenceSemantics:
    """score_and_write_events() under mocked batches: absence propagates from
    the model layer into the stored document exactly as documented."""

    SRC = dict(REAL_SHAPED_DOCUMENT["_source"])

    def _events(self, n=1):
        return [{"_id": f"e{i}", "_index": "honeypot-v2-2026.07.31",
                 "_source": dict(self.SRC)} for i in range(n)]

    @staticmethod
    def _models(iso_batch, hbos_batch, lstm_value):
        iso_model = MagicMock()
        iso_model.extract_features.side_effect = lambda src, **kw: np.zeros((1, 15), dtype=np.float32)
        iso_model.score_batch.return_value = iso_batch
        iso_model.hbos_score_batch.return_value = hbos_batch
        lstm_model = MagicMock()
        lstm_model.score.return_value = lstm_value
        return iso_model, lstm_model

    def test_untrained_isoforest_excluded_contributors_recorded(self):
        # Acceptance pin 1 end-to-end: an untrained IsoForest batch arrives
        # as None (not an array of 0.5); hbos opines 0.9 past the execution
        # gate so saturated LSTM runs; the alert composites over
        # {lstm_ae, hbos} alone. Pre-#1969 the same opinions scored
        # 0.4*0.5 + 0.4*1.0 + 0.2*0.9 = 0.78 -- a number made partly of a
        # detector that had never been trained.
        iso_model, lstm_model = self._models(None, np.array([0.9]), 1.0)
        es = MagicMock()
        recent_flags = []

        worker.score_and_write_events(es, None, iso_model, lstm_model,
                                      self._events(), recent_flags)

        assert len(recent_flags) == 1 and recent_flags[0] is True
        doc = es.index.call_args.kwargs["document"]
        assert doc["model_scores"] == {"isolation_forest": None, "lstm_ae": 1.0, "hbos": 0.9}
        assert doc["contributing_detectors"] == ["hbos", "lstm_ae"]
        assert doc["composite_score"] == pytest.approx(round((0.4 * 1.0 + 0.2 * 0.9) / 0.6, 4))

    def test_absent_everything_writes_nothing(self):
        # A fresh deployment before any accepted retrain: nobody has an
        # opinion, so NOTHING is written -- silence for the honest reason,
        # vs the old faked 0.5/0.5/0.0 unanimity-that-was-not.
        iso_model, lstm_model = self._models(None, None, None)
        es = MagicMock()

        worker.score_and_write_events(es, None, iso_model, lstm_model,
                                      self._events(), [])

        es.index.assert_not_called()


class TestWriteAnomalyNullContract:
    """write_anomaly() stores absence as null, never 0.0 (#1969) -- a reader
    of an old document after the fact must distinguish 'didn't run' from
    'ran and saw nothing', which model_scores nulls carry losslessly."""

    EVENT = {"_id": "x", "_index": "honeypot-v2-2026.07.31", "_source": dict(REAL_SHAPED_DOCUMENT["_source"])}

    def test_null_scores_survive_into_the_document(self):
        es = MagicMock()
        scores = {"isolation_forest": None, "lstm_ae": 1.0, "hbos": 0.9}
        # Composite 0.967 >= any sane threshold, so the early return stays out of the way.
        write_anomaly(es, None, self.EVENT, scores, "explanation")

        doc = es.index.call_args.kwargs["document"]
        assert doc["model_scores"]["isolation_forest"] is None
        assert doc["model_scores"]["lstm_ae"] == 1.0
        assert doc["contributing_detectors"] == ["hbos", "lstm_ae"]
