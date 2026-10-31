# tests/test_dashboard.py
# Tests the Streamlit dashboard without a browser.
# Run:  python -m pytest tests/test_dashboard.py -v
import os
from datetime import datetime

import joblib
import pytest
from streamlit.testing.v1 import AppTest

from cloud import database
from cloud.generate_logs import Generator
from ml.experiment import make_synthetic_dataset
from ml.features import FEATURES_FULL, build_features
from ml.models import fit_model, make_model
from security import alert_store, pipeline

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "dashboard", "app.py")


def run_app(timeout=120):
    return AppTest.from_file(APP, default_timeout=timeout).run()


def find(elements, text):
    return next(e for e in elements if text in e.label)


@pytest.fixture(scope="module")
def trained_model():
    train = build_features(make_synthetic_dataset(1, days=10))
    train["is_attack"] = train["is_attack"].astype(int)
    y = train["is_attack"]
    model = make_model("Random Forest", attack_rate=float(y.mean()),
                       scale_pos_weight=float((y == 0).sum() / (y == 1).sum()))
    fit_model("Random Forest", model, train[FEATURES_FULL], y)
    return model


@pytest.fixture
def env(tmp_path, monkeypatch, trained_model):
    """An empty temporary database plus a temporary saved model."""
    monkeypatch.setenv("CLOUD_DB_PATH", str(tmp_path / "dash.db"))
    model_path = str(tmp_path / "rf.joblib")
    joblib.dump({"name": "Random Forest", "features": FEATURES_FULL,
                 "model": trained_model}, model_path)
    monkeypatch.setattr(pipeline, "DEFAULT_MODEL", model_path)
    database.init_db()
    return model_path


@pytest.fixture
def seeded(env):
    """Logs and alerts stored in the temporary database. Returns the alert count."""
    gen = Generator(seed=2, days=10, start=datetime(2026, 9, 1))
    gen.run()
    database.insert_records([rec for rec, _ in gen.events])
    alerts, _ = pipeline.detect(database.load_events_df())
    alert_store.save_alerts(alerts)
    return len(alerts)


def test_dashboard_loads_with_alerts(seeded):
    assert seeded > 0
    at = run_app()
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Alerts"] == str(seeded)
    assert metrics["Events analysed"] != "0"
    assert len(at.tabs) == 4


def test_dashboard_empty_database(env):
    at = run_app()
    assert not at.exception
    assert len(at.warning) >= 1
    assert len(at.metric) == 0


def test_status_change_is_saved(seeded):
    at = run_app()
    at.radio[0].set_value("acknowledged").run()
    assert not at.exception
    loaded = alert_store.load_alerts()
    assert (loaded["status"] == "acknowledged").sum() == 1


def test_severity_filter_with_no_matches(seeded):
    at = run_app()
    find(at.multiselect, "Severity").set_value([]).run()
    assert not at.exception
    assert any("No alerts" in i.value for i in at.info)


def test_run_detection_button(seeded):
    at = run_app()
    find(at.button, "Run detection").click().run()
    assert not at.exception
    assert any("alerts saved" in s.value for s in at.success)


def test_run_detection_without_model(seeded, monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "DEFAULT_MODEL", str(tmp_path / "missing.joblib"))
    at = run_app()
    find(at.button, "Run detection").click().run()
    assert not at.exception
    assert any("ml.train" in e.value for e in at.error)
