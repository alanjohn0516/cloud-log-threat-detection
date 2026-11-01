# tests/test_bootstrap.py
# Tests for the cloud first-start builder.  Run:  python -m pytest tests/test_bootstrap.py -v
import os

from cloud import database
from dashboard import bootstrap
from security import alert_store, pipeline


def test_enabled_flag(monkeypatch):
    monkeypatch.delenv("AUTO_BOOTSTRAP", raising=False)
    assert bootstrap.enabled() is False
    monkeypatch.setenv("AUTO_BOOTSTRAP", "1")
    assert bootstrap.enabled() is True
    monkeypatch.setenv("AUTO_BOOTSTRAP", "0")
    assert bootstrap.enabled() is False


def test_ensure_ready_builds_everything(tmp_path, monkeypatch):
    db = str(tmp_path / "boot.db")
    model_path = str(tmp_path / "rf.joblib")
    monkeypatch.setenv("CLOUD_DB_PATH", db)
    monkeypatch.setattr(pipeline, "DEFAULT_MODEL", model_path)

    done = bootstrap.ensure_ready(db_path=db, days=10, train_seeds=(1,), train_days=10)
    assert done["logs_created"] and done["model_trained"]
    assert done["alerts_created"] > 0
    assert os.path.exists(model_path)
    assert database.get_stats(db)["total_events"] > 0
    assert len(alert_store.load_alerts(db)) == done["alerts_created"]

    again = bootstrap.ensure_ready(db_path=db, days=10, train_seeds=(1,), train_days=10)
    assert again == {"logs_created": False, "model_trained": False, "alerts_created": 0}
