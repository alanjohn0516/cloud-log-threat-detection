# tests/test_dashboard.py
# Tests the upload-first dashboard without a browser.
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


def run_app(timeout=180):
    return AppTest.from_file(APP, default_timeout=timeout).run()


def find(elements, text):
    return next(e for e in elements if text in e.label)


def has(elements, text):
    return any(text in e.label for e in elements)


def open_stored():
    at = run_app()
    find(at.button, "stored demo").click().run()
    return at


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


def test_landing_is_shown_first(seeded):
    at = run_app()
    assert not at.exception
    assert len(at.metric) == 0                 # no dashboard before a file is added
    assert has(at.button, "Try it with")
    assert has(at.button, "stored demo")


def test_landing_without_stored_data(env):
    at = run_app()
    assert not at.exception
    assert has(at.button, "Try it with")
    assert not has(at.button, "stored demo")


def test_stored_data_opens_dashboard(seeded):
    at = open_stored()
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Alerts"] == str(seeded)
    assert len(at.tabs) == 4
    assert has(at.button, "Load another file")


def test_sample_file_opens_dashboard(env):
    at = run_app()
    find(at.button, "Try it with").click().run()
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Events analysed"] != "0"


def test_status_change_is_session_only(seeded):
    at = open_stored()
    at.radio[0].set_value("acknowledged").run()
    assert not at.exception
    alerts = at.session_state["dataset"]["alerts"]
    assert (alerts["status"] == "acknowledged").sum() == 1
    assert (alert_store.load_alerts()["status"] == "open").all()   # database untouched


def test_severity_filter_with_no_matches(seeded):
    at = open_stored()
    find(at.multiselect, "Severity").set_value([]).run()
    assert not at.exception
    assert any("No alerts" in i.value for i in at.info)


def test_load_another_file_returns_to_landing(seeded):
    at = open_stored()
    find(at.button, "Load another file").click().run()
    assert not at.exception
    assert len(at.metric) == 0
    assert has(at.button, "Try it with")
