# tests/test_ml.py
# Tests for the ML module.  Run:  python -m pytest tests/test_ml.py -v
import itertools
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import pytest

from ml.experiment import evaluate_flags, make_synthetic_dataset
from ml.features import FEATURES_FULL, FEATURES_NO_HISTORY, build_features
from ml.models import ALL_MODELS, fit_model, make_model, predict_flags

T0 = datetime(2026, 9, 1, 10, 0, 0)
_n = itertools.count()


def ev(sec, ip="1.1.1.1", user="alice", name="ConsoleLogin", outcome="Failure",
       utype="IAMUser", err=""):
    t = T0 + timedelta(seconds=sec)
    return {"event_id": f"e{next(_n)}",
            "event_time": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_name": name, "source_ip": ip, "user_type": utype,
            "user_name": user, "outcome": outcome, "error_code": err}


def feats(events):
    return build_features(pd.DataFrame(events))


# ---------------------------------------------------------- features
def test_feature_columns_exist_and_have_no_nans():
    f = feats([ev(0), ev(10, outcome="Success"),
               ev(20, name="AssumeRole", err="AccessDenied")])
    for col in FEATURES_FULL:
        assert col in f.columns
    assert not f[FEATURES_FULL].isna().any().any()
    assert set(FEATURES_NO_HISTORY) < set(FEATURES_FULL)


def test_ip_fail_counts_are_trailing():
    f = feats([ev(i * 10) for i in range(30)])
    assert f["ip_login_fail_5m"].iloc[0] == 1
    assert f["ip_login_fail_5m"].iloc[-1] == 30
    assert f["ip_login_fail_1h"].iloc[-1] == 30
    g = feats([ev(i * 10) for i in range(40)])      # first 10 events fall out of 5 min
    assert g["ip_login_fail_5m"].iloc[-1] == 30


def test_features_use_only_the_past():
    short = [ev(i * 10) for i in range(10)]
    longer = short + [ev(1000 + i * 10, ip="9.9.9.9", user="bob") for i in range(20)]
    a = feats(short)[FEATURES_FULL].to_numpy()
    b = feats(longer)[FEATURES_FULL].to_numpy()[:10]
    assert np.allclose(a, b)      # adding future events changes nothing in the past


def test_distinct_users_in_window():
    f = feats([ev(i * 20, user=f"user{i}") for i in range(12)])   # 12 users in 220 s
    assert f["ip_distinct_users_fail_5m"].iloc[-1] == 12
    assert f["ip_distinct_users_fail_5m"].iloc[0] == 1


def test_history_features():
    events = [ev(0, outcome="Success"),                  # alice logs in from her usual IP
              ev(100, outcome="Failure"),                # a typo from the same IP
              ev(200, ip="2.2.2.2", outcome="Failure")]  # same user, brand-new IP
    f = feats(events)
    assert f["pair_prior_success"].tolist() == [0, 1, 0]
    assert f["ip_prior_success"].tolist() == [0, 1, 0]


def test_user_distinct_ips():
    f = feats([ev(i * 1800, ip=f"7.7.7.{i}", user="admin") for i in range(4)])
    assert f["user_distinct_ips_fail_6h"].iloc[-1] == 4   # four IPs attack one user
    assert f["ip_login_fail_5m"].iloc[-1] == 1            # but each IP looks harmless


def test_old_events_leave_the_window():
    f = feats([ev(0), ev(7200)])
    assert f["ip_login_fail_1h"].tolist() == [1, 1]
    assert f["user_fail_6h"].tolist() == [1, 2]


# ---------------------------------------------------------- models
@pytest.fixture(scope="module")
def small_sets():
    train = build_features(make_synthetic_dataset(1, days=10))
    test = build_features(make_synthetic_dataset(2, days=10))
    train["is_attack"] = train["is_attack"].astype(int)
    test["is_attack"] = test["is_attack"].astype(int)
    return train, test


def _fit(name, train):
    y = train["is_attack"]
    model = make_model(name, attack_rate=float(y.mean()),
                       scale_pos_weight=float((y == 0).sum() / (y == 1).sum()))
    return fit_model(name, model, train[FEATURES_FULL], y)


def test_all_models_train_and_predict(small_sets):
    train, test = small_sets
    for name in ALL_MODELS:
        flags = predict_flags(name, _fit(name, train), test[FEATURES_FULL])
        assert len(flags) == len(test)
        assert flags.dtype == bool


def test_random_forest_detects_attacks(small_sets):
    train, test = small_sets
    flags = predict_flags("Random Forest", _fit("Random Forest", train), test[FEATURES_FULL])
    m, by_type, wrong = evaluate_flags(test, flags)
    assert m["recall"] > 0.5
    assert m["precision"] > 0.5


def test_evaluate_flags_perfect_and_empty(small_sets):
    _, test = small_sets
    perfect = test["is_attack"].to_numpy() == 1
    m, by_type, wrong = evaluate_flags(test, perfect)
    assert m["recall"] == 1.0 and m["precision"] == 1.0
    assert m["attacks_detected"] == m["attacks_total"] == 16
    m0, _, _ = evaluate_flags(test, np.zeros(len(test), dtype=bool))
    assert m0["recall"] == 0.0 and m0["attacks_detected"] == 0
