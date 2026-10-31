# ml/experiment.py
# Helpers: build training data, run the rule baseline, score any detector.
from datetime import datetime

import numpy as np
import pandas as pd

from cloud.generate_logs import Generator, flatten
from ml.features import build_features
from security.metrics import event_metrics
from security.rules import run_rules

TRAIN_SEEDS = [1, 2, 3, 4, 5]


def make_synthetic_dataset(seed, days=30):
    gen = Generator(seed=seed, days=days, start=datetime(2026, 9, 1))
    gen.run()
    return pd.DataFrame([flatten(rec, lab) for rec, lab in gen.events])


def build_training_set(seeds=TRAIN_SEEDS, days=30):
    """Features are computed for each synthetic dataset separately,
    so time windows never mix events from different datasets."""
    parts = []
    for seed in seeds:
        feats = build_features(make_synthetic_dataset(seed, days))
        feats["dataset"] = seed
        parts.append(feats)
    return pd.concat(parts, ignore_index=True)


def rule_flags(df):
    """Events covered by an alert from the rule engine (Step 5)."""
    alerts = run_rules(df)
    flagged = set()
    for ids in alerts["event_ids"]:
        flagged.update(ids)
    return df["event_id"].isin(flagged).to_numpy()


def evaluate_flags(test, flags):
    """Score a detector: event-level metrics + attacks detected per type.
    An attack counts as detected if at least one of its events is flagged
    (the same definition used for the rules in Step 5)."""
    flags = np.asarray(flags, dtype=bool)
    t = test.copy()
    t["is_attack"] = t["is_attack"].astype(int)
    t["flagged"] = flags

    m = event_metrics(t["is_attack"] == 1, flags)
    attacks = t[t["is_attack"] == 1]
    per_attack = attacks.groupby(["attack_type", "attack_id"])["flagged"].any().reset_index()
    by_type = per_attack.groupby("attack_type")["flagged"].agg(detected="sum", total="count")
    m["attacks_detected"] = int(per_attack["flagged"].sum())
    m["attacks_total"] = int(len(per_attack))
    wrong = t[(t["is_attack"] == 0) & t["flagged"]]["scenario"].value_counts().to_dict()
    return m, by_type, wrong
