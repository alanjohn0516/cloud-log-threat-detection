# tests/conftest.py
# Runs before every test: removes authentication and bootstrap variables that
# may be set in the terminal, so the tests behave the same on every machine.
import pytest


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for name in ("API_KEY", "DASHBOARD_PASSWORD", "AUTO_BOOTSTRAP"):
        monkeypatch.delenv(name, raising=False)
