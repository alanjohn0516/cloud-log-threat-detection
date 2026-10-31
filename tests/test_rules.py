# tests/test_rules.py
# Tests for the rule engine.  Run:  python -m pytest tests/test_rules.py -v
import itertools
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import pytest

from cloud.generate_logs import Generator, flatten
from security.metrics import event_metrics
from security.rules import (HIDDEN, run_rules, sliding_window_flags, split_episodes)

T0 = datetime(2026, 9, 1, 10, 0, 0)
_counter = itertools.count()


def ev(sec, ip="1.1.1.1", user="alice", name="ConsoleLogin", outcome="Failure",
       utype="IAMUser", err=""):
    t = T0 + timedelta(seconds=sec)
    return {"event_id": f"e{next(_counter)}",
            "event_time": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_name": name, "source_ip": ip, "user_type": utype,
            "user_name": user, "outcome": outcome, "error_code": err}


def mk(events):
    return pd.DataFrame(events)


# --------------------------------------------------- window algorithm
def test_window_flags_threshold_boundary():
    assert sliding_window_flags(np.arange(0, 200, 10.0), 20, 300).all()          # 20 events
    assert not sliding_window_flags(np.arange(0, 190, 10.0), 20, 300).any()      # 19 events


def test_window_flags_too_spread_out():
    # 20 events, 25 s apart = 475 s span, but never 20 inside any 300 s window
    assert not sliding_window_flags(np.arange(20) * 25.0, 20, 300).any()


def test_split_episodes():
    times = np.array([0, 10, 20, 5000, 5010, 5020], dtype=float)
    flagged = np.ones(6, dtype=bool)
    eps = split_episodes(times, flagged, 300)
    assert eps == [[0, 1, 2], [3, 4, 5]]


# --------------------------------------------------- rule R2
def test_r2_fires_at_20_but_not_19():
    alerts = run_rules(mk([ev(i * 10) for i in range(20)]))
    assert len(alerts) == 1
    assert alerts.iloc[0]["rule_id"] == "R2"
    assert alerts.iloc[0]["event_count"] == 20
    assert len(run_rules(mk([ev(i * 10) for i in range(19)]))) == 0


def test_r2_groups_by_ip():
    # 45 failures in total, but only 15 per IP: no single IP reaches 20
    events = [ev(i * 10, ip=f"9.9.9.{k}") for k in range(3) for i in range(15)]
    assert len(run_rules(mk(events))) == 0


def test_two_bursts_give_two_alerts():
    events = [ev(i * 10) for i in range(20)] + [ev(10000 + i * 10) for i in range(20)]
    assert len(run_rules(mk(events))) == 2


# --------------------------------------------------- rule R1
def test_r1_root_rule():
    events = [ev(i * 100, user="root", utype="Root") for i in range(10)]   # 900 s
    alerts = run_rules(mk(events))
    assert len(alerts) == 1
    assert alerts.iloc[0]["rule_id"] == "R1"
    assert alerts.iloc[0]["attack_type"] == "root_brute_force"
    assert alerts.iloc[0]["severity"] == "HIGH"


def test_r1_not_enough_or_too_slow():
    nine = [ev(i * 100, user="root", utype="Root") for i in range(9)]
    assert len(run_rules(mk(nine))) == 0
    slow = [ev(i * 150, user="root", utype="Root") for i in range(10)]     # 1350 s span
    assert len(run_rules(mk(slow))) == 0


# --------------------------------------------------- rule R3
def test_r3_role_enumeration():
    events = [ev(i * 60, name="AssumeRole", err="MalformedPolicyDocumentException")
              for i in range(3)]
    alerts = run_rules(mk(events))
    assert len(alerts) == 1
    assert alerts.iloc[0]["rule_id"] == "R3"
    assert alerts.iloc[0]["attack_type"] == "role_enumeration"


def test_r3_ignores_plain_access_denied_and_slow_guesses():
    denied = [ev(i * 10, name="AssumeRole", err="AccessDenied") for i in range(10)]
    assert len(run_rules(mk(denied))) == 0
    slow = [ev(i * 2000, name="AssumeRole", err="MalformedPolicyDocumentException")
            for i in range(3)]                                              # 4000 s span
    assert len(run_rules(mk(slow))) == 0


# --------------------------------------------------- classification
def test_classification():
    guess = run_rules(mk([ev(i * 10) for i in range(25)]))
    assert guess.iloc[0]["attack_type"] == "password_guessing"
    spray = run_rules(mk([ev(i * 10, user=f"user{i}") for i in range(25)]))
    assert spray.iloc[0]["attack_type"] == "password_spraying"
    stuff = run_rules(mk([ev(i * 10, user=HIDDEN) for i in range(25)]))
    assert stuff.iloc[0]["attack_type"] == "credential_stuffing"


# --------------------------------------------------- severity
def test_severity_levels():
    medium = run_rules(mk([ev(i * 10) for i in range(25)]))
    assert medium.iloc[0]["severity"] == "MEDIUM"

    high_count = run_rules(mk([ev(i * 3) for i in range(100)]))
    assert high_count.iloc[0]["severity"] == "HIGH"

    admin = [ev(i * 10, user="admin") for i in range(25)]
    assert run_rules(mk(admin)).iloc[0]["severity"] == "HIGH"

    admin_hit = admin + [ev(300, user="admin", outcome="Success")]
    crit = run_rules(mk(admin_hit)).iloc[0]
    assert crit["severity"] == "CRITICAL"
    assert bool(crit["success_after"]) is True
    assert "URGENT" in crit["recommended_action"]


def test_success_from_another_ip_does_not_count():
    events = [ev(i * 10, user="admin") for i in range(25)]
    events.append(ev(300, ip="8.8.8.8", user="admin", outcome="Success"))
    a = run_rules(mk(events)).iloc[0]
    assert bool(a["success_after"]) is False
    assert a["severity"] == "HIGH"


def test_role_enumeration_success_raises_severity():
    events = [ev(i * 60, name="AssumeRole", err="MalformedPolicyDocumentException")
              for i in range(3)]
    plain = run_rules(mk(events)).iloc[0]
    assert plain["severity"] == "MEDIUM"
    events.append(ev(400, name="AssumeRole", outcome="Success"))
    assert run_rules(mk(events)).iloc[0]["severity"] == "HIGH"


def test_empty_input():
    assert len(run_rules(mk([ev(0, outcome="Success")]))) == 0


# --------------------------------------------------- metrics
def test_event_metrics():
    m = event_metrics([1, 1, 0, 0, 1], [1, 0, 1, 0, 1])
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (2, 1, 1, 1)
    assert m["precision"] == pytest.approx(0.6667, abs=1e-4)
    assert m["recall"] == pytest.approx(0.6667, abs=1e-4)
    assert m["false_positive_rate"] == 0.5


# --------------------------------------------------- on generated data
@pytest.fixture(scope="module")
def generated():
    gen = Generator(seed=1, days=5, start=datetime(2026, 9, 1))
    gen.run()
    df = pd.DataFrame([flatten(r, lab) for r, lab in gen.events])
    alerts = run_rules(df)
    flagged = set()
    for ids in alerts["event_ids"]:
        flagged.update(ids)
    return df, alerts, flagged


def _detected(df, flagged, attack_type):
    att = df[df["attack_type"] == attack_type]
    return att.groupby("attack_id")["event_id"].apply(lambda s: s.isin(flagged).any())


def test_loud_attacks_are_detected(generated):
    df, _, flagged = generated
    for kind in ("password_guessing", "credential_stuffing", "root_brute_force"):
        assert _detected(df, flagged, kind).all(), kind


def test_low_and_slow_evades_the_rules(generated):
    df, _, flagged = generated
    assert not df[df["attack_type"] == "low_and_slow"]["event_id"].isin(flagged).any()


def test_office_sso_glitch_is_a_false_alert(generated):
    df, alerts, _ = generated
    office = alerts[alerts["group"] == "203.0.113.10"]
    assert len(office) >= 1
    ids = set()
    for x in office["event_ids"]:
        ids.update(x)
    assert not df[df["event_id"].isin(ids)]["is_attack"].any()
