"""
#1968 -- ml-anomalies carries the context that makes an alert actionable
and auditable, WITHOUT a second query against a source index that expires
under it after 30 days:

- "what was attacked": sensor, dst_ip, src_port;
- "which model said so": model_state_id (checkpoint identity stamp);
- "under what configuration": alert_threshold of that scoring moment;
- "is this even routable": src_internal/src_scope classification;
- flow pivot: community_id copied off the source event when present;
- lifecycle: status/disposition_reason/disposed_at, born open, and an
  idempotent rewrite (#168 deterministic ID) may never reset them.

Run: python3 -m pytest ml-worker/tests/test_anomaly_schema_1968.py -v
"""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from elastic_transport import ApiResponseMeta
from elasticsearch import NotFoundError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import worker  # noqa: E402
from worker import (_carry_forward_disposition, _get_dst_ip, _get_sensor,
                    _get_src_port, attach_metrics_retention, classify_source_address,
                    model_state_id, write_anomaly)  # noqa: E402


def not_found():
    """No such document -- es-py 8.x ApiError signature (message, meta, body),
    same construction test_worker_fixes.py uses for load_checkpoint()."""
    meta = ApiResponseMeta(status=404, http_version="1.1",
                           headers={}, duration=0.0, node=None)
    return NotFoundError("document_missing_exception", meta, {"found": False})


# A real-shaped honeypot-v2-* document (multipot handshake), same structure
# as the audit tests' fixture; values synthetic -- TEST-NET for remote hosts,
# unrelated RFC1918 hosts for our own side (never this deployment's subnet).
def shaped_src(**over):
    src = {
        "@timestamp": "2026-08-01T10:00:00.000Z",
        "@timestamp_real": None,
        "honeypot": {"src_ip": "203.0.113.9", "src_port": 51422, "port": 5900,
                     "proto": "vnc", "sensor": "multipot", "event": "handshake"},
        "source": {"ip": "203.0.113.9",
                   "geo": {"country_iso_code": "CN"}},
        "destination": {"port": 5900},
        "network": {"protocol": "vnc", "community_id": "1:hRQPPXnFe+UxVlMLpaudi6QGpo4="},
        "event": {"category": "network"},
    }
    src.update(over)
    return src


def threshold_passing_scores():
    # Only IsoForest opines and it says 0.9 -- crosses the default bar under
    # the #1969 renormalised composite.
    return {"isolation_forest": 0.9, "hbos": None, "lstm_ae": None}


class TestContextFields:
    """Acceptance bullet 1: one document answers what/who/config/internal."""

    def test_a_written_alert_carries_the_full_context(self):
        es = MagicMock()
        es.get.side_effect = not_found()  # first write: nothing to preserve
        event = {"_id": "evt-1", "_index": "honeypot-v2-2026.08.01",
                 "_source": shaped_src()}
        write_anomaly(es, None, event, threshold_passing_scores(), "explanation")

        doc = es.index.call_args.kwargs["document"]
        assert doc["sensor"] == "multipot"
        assert doc["src_port"] == 51422
        assert doc["community_id"] == "1:hRQPPXnFe+UxVlMLpaudi6QGpo4="
        assert doc["alert_threshold"] == worker.THRESHOLD
        # No model dir configured here -> no trained state -> honest null.
        assert doc["model_state_id"] is None or isinstance(doc["model_state_id"], str)
        assert doc["src_internal"] is False        # TEST-NET address
        assert doc["src_scope"] == "external"
        assert doc["status"] == "open"

    def test_sensor_falls_back_to_event_sensor_when_honeypot_is_silent(self):
        # #132: some sensors don't populate honeypot.sensor (and zeek conn
        # logs carry neither) -- event.sensor is the next honest read.
        assert _get_sensor({"event": {"sensor": "zeek"}}) == "zeek"
        assert _get_sensor({}) is None

    def test_dst_ip_reads_the_local_side_not_the_flow_swapped_one(self):
        # Suricata netflow logs BOTH directions (#174): the side resolution
        # must say OUR side for dst_ip even when source.ip is our own.
        netflow_inbound = {
            "source": {"ip": "198.51.100.7"},      # genuinely remote here
            "destination": {"ip": "192.168.100.10", "port": 22},
            "network": {"transport": "tcp"},
        }
        # Without ML_HOME_NET knowledge in this unit, exercise the helper's
        # ECS chain directly: local side wins when present positionally.
        assert _get_dst_ip(netflow_inbound) == "192.168.100.10"
        # ...and honeypot-shaped docs without destination.ip still resolve:
        assert _get_dst_ip({"honeypot": {"dst_ip": "10.8.0.1"}}) == "10.8.0.1"
        assert _get_dst_ip(
            {"suricata": {"eve": {"dest_ip": "172.17.0.5"}}}) == "172.17.0.5"

    def test_src_port_reads_the_remote_side_chain(self):
        assert _get_src_port({"source": {"ip": "198.51.100.7", "port": 40001},
                              "destination": {"port": 23}}) == 40001
        assert _get_src_port({"honeypot": {"src_port": 33333}}) == 33333
        assert _get_src_port({"suricata": {"eve": {"src_port": 47712}}}) == 47712
        assert _get_src_port({}) is None

    def test_a_flow_record_with_no_sensor_still_answers_everything_else(self):
        # zeek-v1-conn-* carries no sensor identity at all (#132's unreliable-
        # sensor rule in its purest form): sensor stays honestly null while
        # the rest of the context -- sides, port pair, flow key -- lands.
        es = MagicMock()
        es.get.side_effect = not_found()
        zeek_conn = {"_id": "z1", "_index": "zeek-v1-conn-2026.08.01", "_source": {
            "@timestamp": "2026-08-01T11:00:00.000Z",
            "source": {"ip": "198.51.100.23", "port": 53088},
            "destination": {"ip": "192.168.100.20", "port": 445},
            "network": {"transport": "tcp",
                        "community_id": "1:t9KrdB3IhcTPeUrdJvQhThKV0ok="},
            "event": {"category": "network"},
        }}
        write_anomaly(es, None, zeek_conn,
                      {"isolation_forest": 0.92, "hbos": None, "lstm_ae": None}, "why")
        doc = es.index.call_args.kwargs["document"]
        assert doc["sensor"] is None
        assert doc["dst_ip"] == "192.168.100.20"
        assert doc["src_port"] == 53088
        assert doc["dst_port"] == 445
        assert doc["community_id"] == "1:t9KrdB3IhcTPeUrdJvQhThKV0ok="


class TestClassifySourceAddress:
    """The suppression decision (#1959) and the recorded classification
    must come from ONE definition of 'ours'."""

    def test_loopback(self):
        assert classify_source_address("127.0.0.1") == ("loopback", True)

    def test_home_net_lan_and_wireguard_both_read_as_owned(self):
        assert classify_source_address("192.168.100.7") == ("home_net", True)
        assert classify_source_address("10.8.0.2") == ("home_net", True), (
            "WireGuard-vs-LAN separation is deliberately not pretended: both "
            "mean 'we own it' through the same CIDR list")

    def test_external_test_net_addresses_are_not_ours(self):
        assert classify_source_address("203.0.113.9") == ("external", False)

    def test_garbage_and_empty_degrade_to_unclassified_external(self):
        assert classify_source_address("") == (None, False)
        assert classify_source_address("not-an-ip") == (None, False)


class TestModelStateId:
    """'Which model said so' -- a stamp derived from exactly the artifacts
    save/_load_latest() use, stable across restarts, changed by promotion."""

    def test_none_before_any_checkpoint_exists(self, tmp_path):
        assert model_state_id(str(tmp_path)) is None

    @staticmethod
    def _promote(model_dir: Path):
        # Reproduce what isolation_forest.save()/_symlink and the LSTM
        # writer actually leave behind: versioned files + current_* symlinks.
        (model_dir / "isoforest_1.joblib").write_bytes(b"iso")
        (model_dir / "current_isoforest.joblib").symlink_to(model_dir / "isoforest_1.joblib")
        (model_dir / "hbos_1.joblib").write_bytes(b"hbos")
        (model_dir / "current_hbos.joblib").symlink_to(model_dir / "hbos_1.joblib")

    def test_stat_follows_the_promotion_symlinks(self, tmp_path):
        self._promote(tmp_path)
        first = model_state_id(str(tmp_path))
        assert isinstance(first, str) and len(first) == 16

        # Same content: the stamp depends on identity metadata, not bytes,
        # so equal mtime+size stays stable across process restarts...
        assert model_state_id(str(tmp_path)) == first

        # ...while an accepted retrain's atomic promotion replaces targets
        # behind the SAME symlink names, and the stamp MUST move with it:
        (tmp_path / "isoforest_2.joblib").write_bytes(b"iso-retrained")
        os.utime(tmp_path / "isoforest_2.joblib", ns=(2_000_000_000, 2_000_000_000))
        tmp_path.joinpath("current_isoforest.joblib").unlink()
        tmp_path.joinpath("current_isoforest.joblib").symlink_to(tmp_path / "isoforest_2.joblib")
        assert model_state_id(str(tmp_path)) != first

    def test_one_trained_detector_still_stamps_even_if_others_absent(self, tmp_path):
        # IsoForest trained, LSTM never retrained: part-trained states get
        # identities too -- they are real scoring configurations.
        (tmp_path / "current_isoforest.joblib").write_bytes(b"only-iso")
        assert isinstance(model_state_id(str(tmp_path)), str)


class TestDispositionLifecycle:
    """Born open; survives rewrites. This is acceptance bullet 2's
    worker-side half: whatever writes dispositions later, #168's
    deterministic-ID upsert can never wipe them again."""

    EVENT = {"_id": "evt-9", "_index": "honeypot-v2-2026.08.01",
             "_source": shaped_src()}
    DOC_ID = None  # filled by anomaly_doc_id at call sites below

    def test_every_alert_is_born_open(self):
        es = MagicMock()
        es.get.side_effect = not_found()
        write_anomaly(es, None, dict(self.EVENT), threshold_passing_scores(), "why")
        doc = es.index.call_args.kwargs["document"]
        assert doc["status"] == "open"
        assert "disposition_reason" not in doc      # absent until spoken for
        assert "disposed_at" not in doc

    def test_a_rewrite_preserves_an_operator_verdict(self):
        es = MagicMock()
        doc_id = worker.anomaly_doc_id(self.EVENT["_index"], self.EVENT["_id"])
        reviewed = {
            "_id": doc_id,
            "_source": {"status": "false_positive",
                        "disposition_reason": "Nmap scan of a decoy port",
                        "disposed_at": "2026-08-02T09:15:00Z"},
        }

        def get(index, id):
            if id == doc_id:
                return reviewed
            raise not_found()

        es.get.side_effect = get
        event = dict(self.EVENT)
        event["_source"] = shaped_src()  # rescored: possibly different numbers
        rescored = {"isolation_forest": 0.95, "hbos": None, "lstm_ae": None}
        write_anomaly(es, None, event, rescored, "rescored why")

        doc = es.index.call_args.kwargs["document"]
        assert doc["status"] == "false_positive"
        assert doc["disposition_reason"] == "Nmap scan of a decoy port"
        assert doc["disposed_at"] == "2026-08-02T09:15:00Z"
        # ...machine fields STILL updated to the newest opinion:
        assert doc["composite_score"] == pytest.approx(round(worker.compute_composite(rescored), 4))

    def test_open_status_carries_no_information_and_is_not_copied_back(self):
        es = MagicMock()
        doc_id = worker.anomaly_doc_id(self.EVENT["_index"], self.EVENT["_id"])
        es.get.return_value = {"_id": doc_id,
                               "_source": {"status": "open"}}
        write_anomaly(es, None, dict(self.EVENT), threshold_passing_scores(), "why")
        doc = es.index.call_args.kwargs["document"]
        assert doc["status"] == "open"

    def test_no_prior_document_writes_cleanly(self):
        es = MagicMock()
        es.get.side_effect = not_found()
        write_anomaly(es, None, dict(self.EVENT), threshold_passing_scores(), "why")
        es.index.assert_called_once()

    def test_disposition_read_failure_does_not_block_the_alert_write(self):
        # ES flaking between get and index must degrade to 'preserve
        # nothing', not cost the whole finding (#188/#2236 convention).
        es = MagicMock()
        es.get.side_effect = ConnectionError("flaky")
        write_anomaly(es, None, dict(self.EVENT), threshold_passing_scores(), "why")
        es.index.assert_called_once()

    def test_carry_forward_is_field_scoped(self):
        # The operator's fields ride through; machine fields from the old
        # document do NOT leak into the rewrite.
        es = MagicMock()
        es.get.return_value = {"_source": {"status": "true_positive",
                                           "composite_score": 0.01}}
        fresh = {}
        _carry_forward_disposition(es, "ml-anomalies", "abc", fresh)
        assert fresh == {"status": "true_positive"}


class TestMetricsRetention:
    """Acceptance bullet 3: both indices have a RECORDED retention decision
    (see the RETENTION block in worker.py); metrics' is also enforced."""

    def test_policy_is_installed_and_bound_on_success(self):
        es = MagicMock()
        settings = attach_metrics_retention(es)
        assert settings == {"index.lifecycle.name": worker.METRICS_RETENTION_POLICY}
        kwargs = es.ilm.put_lifecycle.call_args.kwargs
        assert kwargs["policy"] == worker.METRICS_RETENTION_POLICY
        delete_phase = kwargs["body"]["policy"]["phases"]["delete"]
        assert delete_phase["min_age"] == worker.METRICS_RETENTION
        assert "delete" in delete_phase["actions"]

    def test_failure_degrades_to_unbounded_metrics_not_a_dead_worker(self):
        es = MagicMock()
        es.ilm.put_lifecycle.side_effect = ConnectionError("old cluster")
        assert attach_metrics_retention(es) == {}

    def test_run_worker_binds_settings_only_through_attach(self):
        # ensure_index gained settings purely so METRICS_INDEX creation can
        # carry the binding; make sure the merge shape is right.
        es = MagicMock()
        es.indices.exists.return_value = False
        worker.ensure_index(es, "some-index", {"mappings": {}},
                            settings={"index.lifecycle.name": "p"})
        body = es.indices.create.call_args.kwargs["body"]
        assert body["settings"]["index.lifecycle.name"] == "p"
        assert body["mappings"] == {}
