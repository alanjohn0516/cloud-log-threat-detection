# tests/test_generator.py
# Automatic checks for the log generator. Run from the project root with:
#   python -m pytest tests/test_generator.py -v
import json
from datetime import datetime

import pandas as pd

from cloud.generate_logs import Generator, ATTACK_PLAN


def build(out_dir, days=10, seed=7):
    gen = Generator(seed=seed, days=days, start=datetime(2026, 9, 1))
    gen.run()
    return gen.save(str(out_dir))


def test_files_are_created(tmp_path):
    build(tmp_path)
    assert (tmp_path / "cloudtrail_logs.json").exists()
    assert (tmp_path / "cloudtrail_labeled.csv").exists()


def test_records_look_like_cloudtrail(tmp_path):
    build(tmp_path)
    with open(tmp_path / "cloudtrail_logs.json") as f:
        records = json.load(f)["Records"]
    assert len(records) > 0
    for r in records[:300]:
        for key in ["eventTime", "eventSource", "eventName",
                    "sourceIPAddress", "userIdentity", "eventID"]:
            assert key in r
        assert r["eventName"] in ("ConsoleLogin", "AssumeRole")


def test_sorted_and_unique(tmp_path):
    df = build(tmp_path)
    assert df["event_time"].is_monotonic_increasing
    assert df["event_id"].is_unique


def test_all_attack_types_present(tmp_path):
    df = build(tmp_path)
    found = set(df[df["is_attack"]]["attack_type"].unique())
    assert found == set(ATTACK_PLAN.keys())
    n_attacks = df[df["is_attack"]]["attack_id"].nunique()
    assert n_attacks == sum(ATTACK_PLAN.values())


def test_labels_are_consistent(tmp_path):
    df = build(tmp_path)
    assert (df[df["is_attack"]]["attack_id"] != "").all()
    assert df[~df["is_attack"]]["attack_id"].fillna("").eq("").all()


def test_same_seed_gives_same_data(tmp_path):
    a = build(tmp_path / "a", seed=5)
    b = build(tmp_path / "b", seed=5)
    assert a.equals(b)


def test_sso_glitch_is_a_false_positive_trap(tmp_path):
    # 20+ failures from one IP in a short time, but labelled NORMAL
    df = build(tmp_path)
    glitch = df[(df["scenario"] == "office_sso_glitch") & (df["outcome"] == "Failure")]
    assert len(glitch) >= 20
    assert not glitch["is_attack"].any()


def test_low_and_slow_stays_under_ip_threshold(tmp_path):
    df = build(tmp_path)
    ls = df[df["attack_type"] == "low_and_slow"].copy()
    ls["t"] = pd.to_datetime(ls["event_time"])
    ls["one"] = 1
    for _, g in ls.groupby(["attack_id", "source_ip"]):
        counts = g.set_index("t").sort_index().rolling("5min")["one"].sum()
        assert counts.max() < 20
