# tests/test_auth.py
# Tests for API key protection and the dashboard login.
# Run:  python -m pytest tests/test_auth.py -v
import os

import pytest
from fastapi.testclient import TestClient
from streamlit.testing.v1 import AppTest

from cloud import database
from cloud.api import app
from dashboard import auth

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "dashboard", "app.py")
KEY = "test-key-123"
ENDPOINTS = [("get", "/stats"), ("get", "/logs"), ("get", "/alerts"),
             ("post", "/logs"), ("post", "/detect")]


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Temporary database, with authentication switched off by default."""
    monkeypatch.setenv("CLOUD_DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)
    database.init_db()
    return monkeypatch


def call(client, method, path, headers=None):
    if (method, path) == ("post", "/logs"):
        return client.post(path, json={"Records": []}, headers=headers)
    return getattr(client, method)(path, headers=headers)


def run_app():
    return AppTest.from_file(APP, default_timeout=120).run()


def test_check_password():
    assert auth.check_password("secret", "secret") is True
    assert auth.check_password("Secret", "secret") is False
    assert auth.check_password("", "secret") is False


def test_api_open_in_dev_mode(env):
    client = TestClient(app)
    assert call(client, "get", "/stats").status_code == 200
    assert call(client, "get", "/logs").status_code == 200


@pytest.mark.parametrize("method,path", ENDPOINTS)
def test_api_requires_key(env, method, path):
    env.setenv("API_KEY", KEY)
    client = TestClient(app)
    assert call(client, method, path).status_code == 401
    assert call(client, method, path, {"X-API-Key": "wrong"}).status_code == 401


def test_api_accepts_correct_key(env):
    env.setenv("API_KEY", KEY)
    client = TestClient(app)
    headers = {"X-API-Key": KEY}
    assert call(client, "get", "/stats", headers).status_code == 200
    assert call(client, "get", "/logs", headers).status_code == 200
    posted = call(client, "post", "/logs", headers)
    assert posted.status_code == 200
    assert posted.json()["inserted"] == 0


def test_health_stays_open(env):
    env.setenv("API_KEY", KEY)
    assert TestClient(app).get("/health").status_code == 200


def test_dashboard_login_required(env):
    env.setenv("DASHBOARD_PASSWORD", "s3cret")
    at = run_app()
    assert not at.exception
    assert len(at.text_input) == 1          # the password box
    assert len(at.metric) == 0              # no data is shown before signing in


def test_dashboard_wrong_password(env):
    env.setenv("DASHBOARD_PASSWORD", "s3cret")
    at = run_app()
    at.text_input[0].input("wrong")
    at.button[0].click().run()
    assert any("Incorrect" in e.value for e in at.error)
    assert len(at.metric) == 0


def test_dashboard_correct_password(env):
    env.setenv("DASHBOARD_PASSWORD", "s3cret")
    at = run_app()
    at.text_input[0].input("s3cret")
    at.button[0].click().run()
    assert not at.exception
    assert len(at.text_input) == 0          # the login form is gone
    assert any("sample" in b.label for b in at.button)   # past the login (empty test DB)
