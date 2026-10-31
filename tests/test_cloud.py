# tests/test_cloud.py
# Tests for the cloud module (database + API).
# Run from the project root:  python -m pytest tests/test_cloud.py -v
import random
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from cloud import database
from cloud.api import app
from cloud.generate_logs import Generator, console_login, assume_role

T0 = datetime(2026, 9, 1, 10, 0, 0)


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Every test gets its own empty temporary database."""
    path = str(tmp_path / "test.db")
    monkeypatch.setenv("CLOUD_DB_PATH", path)
    database.init_db()
    return path


def login(seed, who="alice", ip="1.1.1.1", success=False, t=T0):
    return console_login(random.Random(seed), t, who, ip, "test-agent", success)


def role(seed, who="alice", ip="1.1.1.1", error=None, t=T0):
    return assume_role(random.Random(seed), t, who, ip, "test-agent", "DevRole", error)


def make_events():
    gen = Generator(seed=1, days=5, start=datetime(2026, 9, 1))
    gen.run()
    return gen.events  # list of (record, label)


def labels_for(events):
    return {
        rec["eventID"]: {
            "is_attack": int(lab["attack_type"] != "normal"),
            "attack_type": lab["attack_type"],
            "attack_id": lab["attack_id"],
            "scenario": lab["scenario"],
        }
        for rec, lab in events
    }


# ---------------------------------------------------------- parsing
def test_parse_failed_login():
    row = database.parse_record(login(1))
    assert row["event_name"] == "ConsoleLogin"
    assert row["outcome"] == "Failure"
    assert row["user_name"] == "alice"
    assert row["source_ip"] == "1.1.1.1"


def test_parse_denied_assume_role():
    row = database.parse_record(role(2, error="AccessDenied"))
    assert row["event_name"] == "AssumeRole"
    assert row["outcome"] == "Failure"
    assert row["error_code"] == "AccessDenied"
    assert row["role_arn"].endswith("role/DevRole")


def test_parse_root_login():
    row = database.parse_record(login(3, who="root"))
    assert row["user_type"] == "Root"
    assert row["user_name"] == "root"


def test_parse_rejects_bad_records():
    with pytest.raises(ValueError):
        database.parse_record({"eventName": "ConsoleLogin"})  # no ID or time
    with pytest.raises(ValueError):
        database.parse_record({"eventID": "x", "eventTime": "2026-09-01T10:00:00Z",
                               "eventName": "RunInstances"})  # unsupported event


# ---------------------------------------------------------- database
def test_insert_and_duplicates(db):
    rec = login(4)
    first = database.insert_records([rec])
    assert first["inserted"] == 1
    second = database.insert_records([rec])
    assert second["inserted"] == 0
    assert second["duplicates"] == 1


def test_labels_are_stored(db):
    rec = login(5)
    labels = {rec["eventID"]: {"is_attack": 1, "attack_type": "password_guessing",
                               "attack_id": "password_guessing-01",
                               "scenario": "password_guessing"}}
    database.insert_records([rec], labels=labels)
    ev = database.query_events()[0]
    assert ev["is_attack"] == 1
    assert ev["attack_type"] == "password_guessing"


def test_bulk_load_with_labels(db):
    events = make_events()
    result = database.insert_records([r for r, _ in events], labels=labels_for(events))
    assert result["inserted"] == len(events)
    assert result["skipped"] == 0
    stats = database.get_stats()
    assert stats["total_events"] == len(events)
    expected_attacks = sum(1 for _, lab in events if lab["attack_type"] != "normal")
    assert expected_attacks > 0
    assert stats["labelled_attack_events"] == expected_attacks


def test_load_events_df(db):
    events = make_events()
    database.insert_records([r for r, _ in events], labels=labels_for(events))
    df = database.load_events_df()
    assert len(df) == len(events)
    for col in ["event_time", "source_ip", "user_name", "outcome", "is_attack", "attack_type"]:
        assert col in df.columns


# ---------------------------------------------------------- API
def test_api_health(db):
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_api_post_then_filter(db):
    recs = [
        login(10, who="alice", ip="1.1.1.1", success=False),
        login(11, who="bob", ip="2.2.2.2", success=True),
        role(12, who="alice", ip="1.1.1.1", error="AccessDenied"),
    ]
    client = TestClient(app)
    r = client.post("/logs", json={"Records": recs})
    assert r.status_code == 200
    assert r.json()["inserted"] == 3

    assert client.get("/logs").json()["count"] == 3
    assert client.get("/logs", params={"outcome": "Failure"}).json()["count"] == 2
    assert client.get("/logs", params={"source_ip": "2.2.2.2"}).json()["count"] == 1
    assert client.get("/logs", params={"event_name": "AssumeRole"}).json()["count"] == 1
    assert client.get("/stats").json()["total_events"] == 3


def test_api_time_filter(db):
    recs = [login(20, t=T0), login(21, t=T0 + timedelta(hours=2))]
    client = TestClient(app)
    client.post("/logs", json={"Records": recs})
    r = client.get("/logs", params={"start": "2026-09-01T11:00:00Z"})
    assert r.json()["count"] == 1


def test_api_pagination(db):
    recs = [login(30 + i) for i in range(3)]
    client = TestClient(app)
    client.post("/logs", json={"Records": recs})
    assert client.get("/logs", params={"limit": 2}).json()["count"] == 2
    assert client.get("/logs", params={"limit": 2, "offset": 2}).json()["count"] == 1


def test_api_rejects_bad_input(db):
    client = TestClient(app)
    assert client.post("/logs", json={"wrong": []}).status_code == 422
    assert client.get("/logs", params={"limit": 0}).status_code == 422
    r = client.post("/logs", json={"Records": [{"eventName": "ConsoleLogin"}]})
    assert r.status_code == 200
    assert r.json()["skipped"] == 1
    assert r.json()["inserted"] == 0
