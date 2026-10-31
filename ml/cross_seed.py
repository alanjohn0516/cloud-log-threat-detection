# ml/cross_seed.py
# Robustness test: train once, then test on 10 NEW synthetic datasets
# (seeds never used for training) and report mean +- standard deviation.
# Run from the project root:  python -m ml.cross_seed
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from ml.experiment import (TRAIN_SEEDS, build_training_set, evaluate_flags,
                           make_synthetic_dataset, rule_flags)
from ml.features import FEATURES_FULL, FEATURES_NO_HISTORY, build_features
from ml.models import ALL_MODELS, fit_model, make_model, predict_flags
from security import pipeline

TEST_SEEDS = list(range(101, 111))
FEATURE_SETS = {"FULL": FEATURES_FULL, "NO_HISTORY": FEATURES_NO_HISTORY}


def make_row(feature_set, name, seed, m):
    return {"features": feature_set, "model": name, "seed": seed,
            "precision": m["precision"], "recall": m["recall"], "f1": m["f1"],
            "fpr": m["false_positive_rate"], "FP": m["fp"], "FN": m["fn"],
            "attacks_detected": m["attacks_detected"],
            "attacks_total": m["attacks_total"]}


def train_all():
    print(f"Training on synthetic datasets (seeds {TRAIN_SEEDS})...")
    train = build_training_set(TRAIN_SEEDS)
    train["is_attack"] = train["is_attack"].astype(int)
    y = train["is_attack"]
    pos_weight = float((y == 0).sum() / max((y == 1).sum(), 1))
    models = {}
    for set_name, cols in FEATURE_SETS.items():
        for name in ALL_MODELS:
            model = make_model(name, attack_rate=float(y.mean()),
                               scale_pos_weight=pos_weight)
            fit_model(name, model, train[cols], y)
            models[(set_name, name)] = (model, cols)
    return models


def run_seed(seed, models):
    raw = make_synthetic_dataset(seed)
    test = build_features(raw)
    test["is_attack"] = test["is_attack"].astype(int)
    rows = []

    m, _, _ = evaluate_flags(test, rule_flags(test))
    rows.append(make_row("n/a", "Rules (R1-R3)", seed, m))

    for (set_name, name), (model, cols) in models.items():
        flags = predict_flags(name, model, test[cols])
        m, _, _ = evaluate_flags(test, flags)
        rows.append(make_row(set_name, name, seed, m))

    # the integrated pipeline: Random Forest + incident grouping
    alerts, scored = pipeline.detect(raw, policy="ml",
                                     model_bundle=models[("FULL", "Random Forest")])
    scored["is_attack"] = scored["is_attack"].astype(int)
    m, _, _ = evaluate_flags(scored, scored["alerted"].to_numpy())
    rows.append(make_row("FULL", "Pipeline (RF + incidents)", seed, m))
    return rows, len(alerts)


def pm(series):
    return f"{series.mean():.3f} +- {series.std():.3f}"


def main():
    models = train_all()
    rows, alert_counts = [], []
    for seed in TEST_SEEDS:
        print(f"Testing on new dataset, seed {seed}...")
        seed_rows, n_alerts = run_seed(seed, models)
        rows += seed_rows
        alert_counts.append(n_alerts)

    res = pd.DataFrame(rows)
    os.makedirs("reports", exist_ok=True)
    res.to_csv("reports/cross_seed_results.csv", index=False)

    g = res.groupby(["features", "model"], sort=False)
    g[["precision", "recall", "f1", "FP", "attacks_detected"]].agg(
        ["mean", "std"]).to_csv("reports/cross_seed_summary.csv")

    table = pd.DataFrame({
        "precision": g["precision"].agg(pm),
        "recall": g["recall"].agg(pm),
        "f1": g["f1"].agg(pm),
        "FP/run": g["FP"].mean().round(1),
        "attacks/16": g["attacks_detected"].mean().round(1)})
    print(f"\nRESULTS ON {len(TEST_SEEDS)} UNSEEN DATASETS (mean +- std)")
    print(table.to_string())
    print(f"\nPipeline alerts per dataset: {alert_counts} "
          f"(each dataset contains 16 attacks)")

    f1 = g["f1"].agg(["mean", "std"]).reset_index()
    f1["label"] = f1["model"] + " (" + f1["features"] + ")"
    ax = f1.plot(x="label", y="mean", yerr="std", kind="bar", legend=False,
                 figsize=(12, 5), rot=35, capsize=3)
    plt.setp(ax.get_xticklabels(), ha="right")
    ax.set_ylim(0, 1.05)
    ax.set_xlabel("")
    ax.set_ylabel("F1-score")
    ax.set_title(f"F1 on {len(TEST_SEEDS)} unseen datasets (mean and std)")
    plt.tight_layout()
    plt.savefig("reports/cross_seed_f1.png", dpi=200)
    print("\nSaved reports/cross_seed_results.csv, cross_seed_summary.csv, cross_seed_f1.png")


if __name__ == "__main__":
    main()
