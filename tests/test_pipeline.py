# tests/test_pipeline.py
# Tests for the integrated pipeline.  Run:  python -m pytest tests/test_pipeline.py -v
import itertools
from datetime import datetime, timedelta

import joblib
import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from cloud import database
from cloud.api import app
from cloud.generate_logs import Generator
from ml.experiment import make_synthetic_dataset
from ml.features import FEATURES_FULL, build_features
from ml.models import fit_model, make_model
from security import alert_store, pipeline
from security.rules import HIDDEN, to_seconds

T0 = datetime(2026, 9, 1, 10, 0, 0)
_n = itertools.count()


def ev(sec, ip="1.1.1.1", user="alice", name="ConsoleLogin", outcome="Failure",
       utype="IAMUser", err=""):
    t = T0 + timedelta(seconds=sec)
    return {"event_id": f"e{next(_n)}",
            "event_time": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_name": name, "source_ip": ip, "user_type": utype,
            "user_name": user, "outcome": outcome, "error_code": err}


def timed(events):
    df = pd.DataFrame(events)
    df["t"] = to_seconds(df["event_time"])
    return df.sort_values("t", kind="stable").reset_index(drop=True)


def with_flags(events):
    """Events as the pipeline sees them after scoring: failures are flagged by ML."""
    df = timed(events)
    df["flagged"] = df["outcome"] == "Failure"
    df["ml_score"] = np.where(df["flagged"], 0.9, 0.1)
    df["ml_flag"] = df["flagged"]
    df["rule_flag"] = False
    return df


# ---------------------------------------------------------- grouping
def test_group_incidents_links_by_ip_and_user():
    df = timed([ev(0, ip="1.1.1.1", user="a"), ev(10, ip="1.1.1.1", user="b"),
                ev(20, ip="2.2.2.2", user="b"), ev(100000, ip="9.9.9.9", user="z")])
    labels = pipeline.group_incidents(df)
    assert labels[0] == labels[1] == labels[2]
    assert labels[3] != labels[0]


def test_group_incidents_ignores_hidden_users():
    df = timed([ev(0, ip="1.1.1.1", user=HIDDEN), ev(10, ip="2.2.2.2", user=HIDDEN)])
    labels = pipeline.group_incidents(df)
    assert labels[0] != labels[1]


def test_group_incidents_respects_gap():
    df = timed([ev(0), ev(7200)])            # same IP and user, two hours apart
    assert len(set(pipeline.group_incidents(df, gap=3600))) == 2
    assert len(set(pipeline.group_incidents(df, gap=10800))) == 1


# ---------------------------------------------------------- classification
def test_classify_incident():
    def c(events):
        return pipeline.classify_incident(pd.DataFrame(events))
    assert c([ev(i * 10) for i in range(25)]) == "password_guessing"
    assert c([ev(i * 10, user=f"user{i}") for i in range(10)]) == "password_spraying"
    assert c([ev(i * 10, user=HIDDEN) for i in range(10)]) == "credential_stuffing"
    assert c([ev(i * 10, ip=f"7.7.7.{i}", user="admin")
              for i in range(10)]) == "distributed_brute_force"
    assert c([ev(i * 10, name="AssumeRole", err="AccessDenied")
              for i in range(5)]) == "role_enumeration"
    assert c([ev(i * 10, user="root", utype="Root")
              for i in range(12)]) == "root_brute_force"


# ---------------------------------------------------------- incidents and alerts
def test_build_incidents_severity():
    plain = [ev(i * 10) for i in range(25)]
    a = pipeline.build_incidents(with_flags(plain)).iloc[0]
    assert a["severity"] == "MEDIUM"
    assert a["attack_type"] == "password_guessing"
    assert a["failed_events"] == 25

    hit = pipeline.build_incidents(with_flags(plain + [ev(300, outcome="Success")])).iloc[0]
    assert hit["severity"] == "HIGH"            # a sign-in followed the attack
    assert bool(hit["success_after"]) is True

    admin = [ev(i * 10, user="admin") for i in range(25)]
    crit = pipeline.build_incidents(
        with_flags(admin + [ev(300, user="admin", outcome="Success")])).iloc[0]
    assert crit["severity"] == "CRITICAL"       # privileged account compromised
    assert crit["detected_by"] == "ML only"
    assert crit["confidence"] == pytest.approx(90.0)
    assert "URGENT" in crit["recommended_action"]


def test_build_incidents_min_events_and_empty():
    two = with_flags([ev(0), ev(10)])
    assert len(pipeline.build_incidents(two)) == 0               # too small: noise
    assert len(pipeline.build_incidents(two, min_events=2)) == 1
    none = pipeline.build_incidents(with_flags([ev(0, outcome="Success")]))
    assert len(none) == 0
    assert list(none.columns) == pipeline.ALERT_COLUMNS


def test_alert_store_roundtrip(tmp_path):
    db = str(tmp_path / "alerts.db")
    alerts = pipeline.build_incidents(with_flags([ev(i * 10, user="admin") for i in range(25)]))
    assert alert_store.save_alerts(alerts, db_path=db) == 1
    loaded = alert_store.load_alerts(db_path=db)
    assert len(loaded) == 1
    assert loaded.iloc[0]["attack_type"] == "password_guessing"
    assert loaded.iloc[0]["status"] == "open"
    assert alert_store.set_status("ALERT-0001", "acknowledged", db_path=db) is True
    assert alert_store.load_alerts(db_path=db).iloc[0]["status"] == "acknowledged"
    assert alert_store.set_status("NOPE", "resolved", db_path=db) is False
    with pytest.raises(ValueError):
        alert_store.set_status("ALERT-0001", "bogus", db_path=db)
    alert_store.save_alerts(alerts.iloc[0:0], db_path=db)
    assert len(alert_store.load_alerts(db_path=db)) == 0


def test_detect_rejects_bad_policy():
    with pytest.raises(ValueError):
        pipeline.detect(pd.DataFrame([ev(0)]), policy="magic")


# ---------------------------------------------------------- on generated data
@pytest.fixture(scope="module")
def bundle_and_test():
    train = build_features(make_synthetic_dataset(1, days=10))
    train["is_attack"] = train["is_attack"].astype(int)
    y = train["is_attack"]
    model = make_model("Random Forest", attack_rate=float(y.mean()),
                       scale_pos_weight=float((y == 0).sum() / (y == 1).sum()))
    fit_model("Random Forest", model, train[FEATURES_FULL], y)
    test = make_synthetic_dataset(2, days=10)
    return (model, FEATURES_FULL), test


def test_detect_end_to_end(bundle_and_test):
    bundle, test = bundle_and_test
    alerts, scored = pipeline.detect(test, policy="ml", model_bundle=bundle)
    assert len(alerts) > 0
    assert set(alerts["severity"]) <= {"MEDIUM", "HIGH", "CRITICAL"}
    assert set(alerts["attack_type"]) <= set(pipeline.RESPONSE_PLAYBOOK)
    assert alerts["confidence"].between(0, 100).all()
    assert int(scored["alerted"].sum()) == int(alerts["event_count"].sum())
    att = scored[scored["is_attack"].astype(bool)]
    per_attack = att.groupby("attack_id")["alerted"].any()
    assert len(per_attack) == 16
    assert int(per_attack.sum()) >= 10


# ---------------------------------------------------------- API
@pytest.fixture
def api_env(tmp_path, monkeypatch, bundle_and_test):
    bundle, _ = bundle_and_test
    monkeypatch.setenv("CLOUD_DB_PATH", str(tmp_path / "api.db"))
    database.init_db()
    gen = Generator(seed=2, days=10, start=datetime(2026, 9, 1))
    gen.run()
    database.insert_records([rec for rec, _ in gen.events])      # unlabelled, like real logs
    model_path = str(tmp_path / "rf.joblib")
    joblib.dump({"name": "Random Forest", "features": bundle[1], "model": bundle[0]},
                model_path)
    monkeypatch.setattr(pipeline, "DEFAULT_MODEL", model_path)
    return TestClient(app)


def test_api_detect_and_alerts(api_env):
    client = api_env
    r = client.post("/detect")
    assert r.status_code == 200
    body = r.json()
    assert body["alerts_raised"] > 0
    assert body["events_analysed"] > 0

    got = client.get("/alerts").json()
    assert got["count"] == body["alerts_raised"]
    first = got["alerts"][0]
    for key in ["alert_id", "attack_type", "severity", "confidence", "recommended_action"]:
        assert key in first
    assert "event_ids" not in first

    sev = first["severity"]
    only = client.get("/alerts", params={"severity": sev}).json()
    assert 1 <= only["count"] <= got["count"]
    assert all(a["severity"] == sev for a in only["alerts"])


def test_api_detect_without_model(api_env, monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "DEFAULT_MODEL", str(tmp_path / "missing.joblib"))
    assert api_env.post("/detect").status_code == 503


def test_api_detect_bad_policy(api_env):
    assert api_env.post("/detect", params={"policy": "magic"}).status_code == 422
