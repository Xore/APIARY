"""#1968: an anomaly document must be actionable without a second query.

Before this change an alert carried no dst context, no producing sensor,
no record of which deployment threshold or model checkpoints produced its
score, and no disposition lifecycle -- and because id= is deterministic
(#168), a later operator verdict would have been wiped by any re-scoring of
the same source event. These tests pin the enrichment, the preservation
semantics, the state-id derivation, and the retention-policy shape.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from elasticsearch import NotFoundError  # noqa: E402

import worker  # noqa: E402


SCORES = {"isolation_forest": 1.0, "lstm_ae": 1.0, "hbos": 1.0}  # composite well above THRESHOLD

# Synthetic RFC5737 source against a home-LAN decoy: no captured indicators.
def _event(**src_extra):
    src = {
        "@timestamp": "2026-07-31T00:00:00Z",
        "sensor": "cowrie",
        "source": {"ip": "203.0.113.7", "port": 51234},
        "destination": {"ip": "192.168.1.50", "port": 2222},
        "network": {"transport": "tcp", "community_id": "1:synthetic-flow-key"},
    }
    src.update(src_extra)
    return {"_id": "doc-1", "_index": "honeypot-v2-test", "_source": src}


def _writing_es(existing=None, get_error=None):
    es = MagicMock()
    if get_error is not None:
        es.get.side_effect = get_error
    else:
        es.get.return_value = {"_source": existing or {}}
    return es


def _written_doc(es):
    assert es.index.call_args.kwargs["index"] == worker.ANOMALY_INDEX
    return es.index.call_args.kwargs["document"]


class TestNewAlertAnswersWithoutSecondQuery:
    def test_context_fields_are_stamped(self):
        es = _writing_es(get_error=NotFoundError("absent", None, {"found": False}))
        worker.write_anomaly(es, None, _event(), SCORES, "explanation",
                             checkpoint_id="iso:1756000000|hbos:1756000000|lstm:1756000001")
        doc = _written_doc(es)

        assert doc["dst_ip"] == "192.168.1.50"         # our side of the flow
        assert doc["src_port"] == 51234                # remote ephemeral port
        assert doc["sensor"] == "cowrie"
        assert doc["community_id"] == "1:synthetic-flow-key"
        assert doc["alert_threshold"] == pytest.approx(worker.THRESHOLD)
        assert doc["model_state_id"] == "iso:1756000000|hbos:1756000000|lstm:1756000001"
        assert doc["src_internal"] is False            # external source wrote the alert
        assert doc["status"] == "open"                 # lifecycle starts here
        # Unset disposition detail stays absent rather than null-padded.
        assert "disposition_reason" not in doc
        assert "disposed_at" not in doc

    def test_threshold_stamp_follows_the_configured_value_not_a_constant(self, monkeypatch):
        monkeypatch.setattr(worker, "THRESHOLD", 0.61)
        es = _writing_es(get_error=NotFoundError("absent", None, {"found": False}))
        worker.write_anomaly(es, None, _event(), SCORES, "explanation")
        assert _written_doc(es)["alert_threshold"] == pytest.approx(0.61)

    def test_internal_source_is_classified_as_such(self):
        es = _writing_es(get_error=NotFoundError("absent", None, {"found": False}))
        # An address we own reaching write_anomaly can only happen while
        # #1959 suppression is off; the stamp must classify it regardless.
        worker.write_anomaly(es, None, _event(source={"ip": "127.0.0.1"}), SCORES, "explanation")
        assert _written_doc(es)["src_internal"] is True

    def test_sensor_falls_back_to_event_namespace(self):
        es = _writing_es(get_error=NotFoundError("absent", None, {"found": False}))
        ev = _event()
        del ev["_source"]["sensor"]
        ev["_source"]["event"] = {"category": "authentication", "sensor": "dionaea"}
        worker.write_anomaly(es, None, ev, SCORES, "explanation")
        assert _written_doc(es)["sensor"] == "dionaea"

    def test_sensor_stays_null_when_absent_from_both_namespaces(self):
        # #2423 residue item 2: a zeek v1-conn document carries no sensor
        # identity anywhere (no top-level "sensor", no "event.sensor").
        # sensor must stay honestly null rather than defaulting to a guess,
        # while the rest of the context still lands from the flow fields.
        es = _writing_es(get_error=NotFoundError("absent", None, {"found": False}))
        ev = _event()
        del ev["_source"]["sensor"]
        worker.write_anomaly(es, None, ev, SCORES, "explanation")
        doc = _written_doc(es)
        assert doc.get("sensor") is None
        assert doc["dst_ip"] == "192.168.1.50"
        assert doc["src_port"] == 51234
        assert doc["community_id"] == "1:synthetic-flow-key"


class TestDispositionSurvivesScoringRewrites:
    def test_operator_verdict_survives_a_deterministic_replay(self):
        existing = {"status": "true_positive",
                    "disposition_reason": "matches known campaign",
                    "disposed_at": "2026-08-27T10:00:00Z"}
        es = _writing_es(existing=existing)
        worker.write_anomaly(es, None, _event(), SCORES, "re-scored explanation")
        doc = _written_doc(es)
        for key, value in existing.items():
            assert doc[key] == value          # analyst input intact
        assert doc["composite_score"] == pytest.approx(
            round(sum(SCORES.values()) / len(SCORES), 4))  # score itself stays fresh

    def test_absent_previous_doc_defaults_open(self):
        es = _writing_es(get_error=NotFoundError("absent", None, {"found": False}))
        worker.write_anomaly(es, None, _event(), SCORES, "first time")
        assert _written_doc(es)["status"] == "open"

    def test_transient_read_failure_never_blocks_the_alert(self):
        es = _writing_es(get_error=ConnectionError("es flapped"))
        worker.write_anomaly(es, None, _event(), SCORES, "still must land")
        doc = _written_doc(es)                 # alert written ...
        assert doc["status"] == "open"         # ... conservatively fresh, not stale-silent


class TestModelStateId:
    class _FakeModel:
        def __init__(self, model_dir):
            self.model_dir = model_dir

    @pytest.fixture
    def model_dirs(self, tmp_path):
        iso = tmp_path / "iso"
        lstm = tmp_path / "lstm"
        iso.mkdir(); lstm.mkdir()
        # _save() promotes through realpath'd timestamped files behind the
        # atomic symlink pointer -- mirror exactly that shape.
        self._promote(iso, "current_isoforest.joblib", "isoforest_1756000000.joblib")
        self._promote(iso, "current_hbos.joblib",     "hbos_1756000000.joblib")
        self._promote(lstm, "current_lstm_ae.pt",     "lstm_ae_1756000001.pt")
        return str(iso), str(lstm)

    @staticmethod
    def _promote(directory, link_name, target_name):
        (directory / target_name).write_bytes(b"checkpoint bytes")
        link = directory / link_name
        try:
            link.symlink_to(target_name)
        except OSError:                            # CI filesystem without symlinks
            import os
            os.link((directory / target_name).resolve(), link)

    def test_identity_names_the_promoted_trio(self, model_dirs):
        iso_dir, lstm_dir = model_dirs
        assert worker.model_state_id(self._FakeModel(iso_dir), self._FakeModel(lstm_dir)) == \
            "iso:1756000000|hbos:1756000000|lstm:1756000001"

    def test_untrained_detectors_read_as_none(self, tmp_path):
        # Nothing promoted yet -- exactly the condition whose invisibility
        # made #1959's constant scores hard to attribute afterwards.
        iso_dir = tmp_path / "empty-a"; iso_dir.mkdir()
        lstm_dir = tmp_path / "empty-b"; lstm_dir.mkdir()
        assert worker.model_state_id(self._FakeModel(str(iso_dir)),
                                     self._FakeModel(str(lstm_dir))) is None

    def test_partial_trio_also_reads_as_none(self, model_dirs):
        # One pointer wiped (e.g. manual rollback mid-flight) must not yield
        # an id that pretends the remaining pair is the full picture.
        iso_dir, lstm_dir = model_dirs
        (Path(lstm_dir) / "current_lstm_ae.pt").unlink()
        assert worker.model_state_id(self._FakeModel(iso_dir),
                                     self._FakeModel(lstm_dir)) is None


class TestRetentionPolicies:
    def test_policy_shape_is_delete_only(self):
        policy = worker.build_ilm_policy(365)
        phase = policy["policy"]["phases"]["delete"]
        assert phase["min_age"] == "365d"
        assert list(phase["actions"]) == ["delete"]
        # Classic indices need no rollover action (unlike honeypot-30d's
        # data-stream backing index).
        assert set(policy["policy"]["phases"]) == {"delete"}

    def test_installation_is_idempotent(self):
        es = MagicMock()
        es.ilm.get_lifecycle.side_effect = [NotFoundError("absent", None, {"found": False}), None]
        policy = worker.build_ilm_policy(90)

        worker.ensure_ilm_policy(es, "ml-worker-metrics-retention", policy)
        worker.ensure_ilm_policy(es, "ml-worker-metrics-retention", policy)

        # #2579: the wire body is the policy definition itself (ES >= 9.0
        # parses PUT _ilm/policy unwrapped); the {"policy": ...} envelope is
        # stripped by ensure_ilm_policy before the client call.
        es.ilm.put_lifecycle.assert_called_once_with(
            name="ml-worker-metrics-retention", policy=policy["policy"])
