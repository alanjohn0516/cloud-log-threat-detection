# tests/test_analyze.py
# Tests for the "Analyze your logs" tab logic.  Run:  python -m pytest tests/test_analyze.py -v
import gzip
import json
from datetime import datetime

import joblib
import pytest

from cloud.generate_logs import Generator
from dashboard import analyze
from ml.experiment import make_synthetic_dataset
from ml.features import FEATURES_FULL, build_features
from ml.models import fit_model, make_model
from security import pipeline


def records(seed=3, days=5):
    gen = Generator(seed=seed, days=days, start=datetime(2026, 9, 1))
    gen.run()
    return [rec for rec, _ in gen.events]


def test_parse_plain_records():
    recs = records()
    df, info = analyze.parse_uploads(
        [("a.json", json.dumps({"Records": recs}).encode())])
    assert len(df) == len(recs)
    assert info["files"] == 1 and info["skipped"] == 0 and info["errors"] == []


def test_parse_gzip():
    recs = records()
    raw = gzip.compress(json.dumps({"Records": recs}).encode())
    df, info = analyze.parse_uploads([("a.json.gz", raw)])
    assert len(df) == len(recs)


def test_parse_list_and_json_lines():
    sub = records()[:50]
    as_list, _ = analyze.parse_uploads([("l.json", json.dumps(sub).encode())])
    as_lines, _ = analyze.parse_uploads(
        [("l.jsonl", "\n".join(json.dumps(r) for r in sub).encode())])
    assert len(as_list) == 50 and len(as_lines) == 50


def test_parse_wrapped_cloudtrail_events():
    wrapped = [{"CloudTrailEvent": json.dumps(r)} for r in records()[:10]]
    df, _ = analyze.parse_uploads([("w.json", json.dumps(wrapped).encode())])
    assert len(df) == 10


def test_parse_skips_other_events_and_duplicates():
    recs = records()
    other = {"eventID": "zzz", "eventTime": "2026-09-01T00:00:00Z",
             "eventName": "RunInstances"}
    data = recs[:20] + [other] + [recs[0]]
    df, info = analyze.parse_uploads([("m.json", json.dumps(data).encode())])
    assert len(df) == 20
    assert info["records"] == 22 and info["skipped"] == 2


def test_parse_bad_file_is_reported():
    df, info = analyze.parse_uploads([("bad.json", b"this is not json")])
    assert df.empty
    assert info["files"] == 0 and len(info["errors"]) == 1


def test_parse_rejects_oversized_upload(monkeypatch):
    monkeypatch.setattr(analyze, "MAX_EVENTS", 5)
    with pytest.raises(ValueError):
        analyze.parse_uploads([("big.json", json.dumps(records()[:50]).encode())])


def test_sample_file_is_readable():
    df, info = analyze.parse_uploads([("sample.json", analyze.make_sample())])
    assert len(df) > 500
    assert info["skipped"] == 0


@pytest.fixture(scope="module")
def model_path(tmp_path_factory):
    train = build_features(make_synthetic_dataset(1, days=10))
    train["is_attack"] = train["is_attack"].astype(int)
    y = train["is_attack"]
    model = make_model("Random Forest", attack_rate=float(y.mean()),
                       scale_pos_weight=float((y == 0).sum() / (y == 1).sum()))
    fit_model("Random Forest", model, train[FEATURES_FULL], y)
    path = str(tmp_path_factory.mktemp("model") / "rf.joblib")
    joblib.dump({"name": "Random Forest", "features": FEATURES_FULL, "model": model}, path)
    return path


def test_analyze_finds_attacks(model_path, monkeypatch):
    monkeypatch.setattr(pipeline, "DEFAULT_MODEL", model_path)
    events, _ = analyze.parse_uploads(
        [("t.json", json.dumps({"Records": records(seed=2, days=10)}).encode())])
    alerts = analyze.analyze(events)
    assert len(alerts) > 0
    assert set(alerts["status"]) == {"open"}
    assert set(alerts["severity"]) <= {"MEDIUM", "HIGH", "CRITICAL"}
