"""
#65: rollback.py, the standalone operator script for repointing a model's
current_* symlink back to a previously retained version. See
docs/ml-worker-plan.md §11.3 for why this is a script rather than an
HTTP endpoint (ml-worker has no control surface, deliberately).

Run: python3 -m pytest ml-worker/tests/test_rollback.py -v
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import rollback  # noqa: E402


@pytest.fixture
def model_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(rollback, "MODEL_DIR", str(tmp_path))
    return tmp_path


class TestRollback:
    def test_repoints_current_symlink_to_the_requested_version(self, model_dir):
        (model_dir / "isoforest_100.joblib").write_text("old")
        (model_dir / "isoforest_200.joblib").write_text("new")
        current = model_dir / "current_isoforest.joblib"
        os.symlink(model_dir / "isoforest_200.joblib", current)

        rc = rollback.main(["rollback.py", "isoforest", "100"])

        assert rc == 0
        assert os.path.realpath(current) == str(model_dir / "isoforest_100.joblib")

    def test_missing_version_is_rejected_without_touching_the_symlink(self, model_dir):
        (model_dir / "isoforest_200.joblib").write_text("new")
        current = model_dir / "current_isoforest.joblib"
        os.symlink(model_dir / "isoforest_200.joblib", current)

        rc = rollback.main(["rollback.py", "isoforest", "999"])

        assert rc == 1
        assert os.path.realpath(current) == str(model_dir / "isoforest_200.joblib"), \
            "a rollback to a version that doesn't exist must not change the active symlink"

    def test_unknown_model_name_is_rejected(self, model_dir):
        rc = rollback.main(["rollback.py", "not-a-real-model", "100"])
        assert rc == 2

    def test_listing_versions_marks_the_current_one(self, model_dir, capsys):
        (model_dir / "isoforest_100.joblib").write_text("old")
        (model_dir / "isoforest_200.joblib").write_text("new")
        os.symlink(model_dir / "isoforest_200.joblib", model_dir / "current_isoforest.joblib")

        rc = rollback.main(["rollback.py", "isoforest"])
        out = capsys.readouterr().out

        assert rc == 0
        assert "isoforest_200.joblib (current)" in out
        assert "isoforest_100.joblib" in out and "isoforest_100.joblib (current)" not in out

    def test_lstm_ae_uses_the_pt_extension(self, model_dir):
        (model_dir / "lstm_ae_100.pt").write_text("old")
        rc = rollback.main(["rollback.py", "lstm_ae", "100"])
        assert rc == 0
        assert os.path.realpath(model_dir / "current_lstm_ae.pt") == str(model_dir / "lstm_ae_100.pt")
