# ml/train.py
# Trains the ML models, tests them on the logs stored in the cloud database,
# and compares them with the rule engine.
# Run from the project root:  python -m ml.train
import os

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from cloud import database
from ml.experiment import TRAIN_SEEDS, build_training_set, evaluate_flags, rule_flags
from ml.features import FEATURES_FULL, FEATURES_NO_HISTORY, build_features
from ml.models import ALL_MODELS, fit_model, make_model, predict_flags

FEATURE_SETS = {"FULL": FEATURES_FULL, "NO_HISTORY": FEATURES_NO_HISTORY}


def prepare_data():
    print(f"Building training data from synthetic datasets (seeds {TRAIN_SEEDS})...")
    train = build_training_set(TRAIN_SEEDS)
    train["is_attack"] = train["is_attack"].astype(int)
    print(f"  training events: {len(train)}   attack share: {train['is_attack'].mean():.3f}")

    raw = database.load_events_df()
    if raw.empty or raw["is_attack"].isna().all():
        raise SystemExit("Database empty or unlabelled. Run: python -m cloud.load_logs --reset")
    test = build_features(raw)
    test["is_attack"] = test["is_attack"].astype(int)
    print(f"  test events (cloud database): {len(test)}   "
          f"attack share: {test['is_attack'].mean():.3f}")
    return train, test


def make_row(feature_set, model, m):
    return {"features": feature_set, "model": model,
            "precision": m["precision"], "recall": m["recall"], "f1": m["f1"],
            "fpr": m["false_positive_rate"], "FP": m["fp"], "FN": m["fn"],
            "attacks": f"{m['attacks_detected']}/{m['attacks_total']}"}


def main():
    train, test = prepare_data()
    y = train["is_attack"]
    pos_weight = float((y == 0).sum() / max((y == 1).sum(), 1))
    rows, by_type_all, wrong_all, importances = [], {}, {}, []

    m, by_type, wrong = evaluate_flags(test, rule_flags(test))
    rows.append(make_row("n/a", "Rules (R1-R3)", m))
    by_type_all["Rules (R1-R3)"], wrong_all["Rules (R1-R3)"] = by_type, wrong

    os.makedirs("ml/saved", exist_ok=True)
    for set_name, cols in FEATURE_SETS.items():
        for name in ALL_MODELS:
            print(f"Training {name} ({set_name})...")
            model = make_model(name, attack_rate=float(y.mean()),
                               scale_pos_weight=pos_weight)
            fit_model(name, model, train[cols], y)
            flags = predict_flags(name, model, test[cols])
            m, by_type, wrong = evaluate_flags(test, flags)
            rows.append(make_row(set_name, name, m))
            if set_name == "FULL":
                by_type_all[name], wrong_all[name] = by_type, wrong
                slug = name.lower().replace(" ", "_")
                joblib.dump({"name": name, "features": cols, "model": model},
                            f"ml/saved/{slug}.joblib")
                if hasattr(model, "feature_importances_"):
                    for feat, val in zip(cols, model.feature_importances_):
                        importances.append({"model": name, "feature": feat,
                                            "importance": float(val)})
    report(rows, by_type_all, wrong_all, importances, len(test))


def report(rows, by_type_all, wrong_all, importances, n_test):
    os.makedirs("reports", exist_ok=True)
    res = pd.DataFrame(rows)
    res.to_csv("reports/ml_results.csv", index=False)

    print(f"\nEVENT-LEVEL COMPARISON ({n_test} test events)")
    print("\nFULL feature set (with IP/user history):")
    full = res[res["features"].isin(["FULL", "n/a"])]
    print(full.drop(columns="features").to_string(index=False))
    print("\nNO_HISTORY ablation (history features removed):")
    print(res[res["features"] == "NO_HISTORY"].drop(columns="features").to_string(index=False))

    table = pd.DataFrame({
        name: bt.apply(lambda r: f"{int(r['detected'])}/{int(r['total'])}", axis=1)
        for name, bt in by_type_all.items()})
    table.to_csv("reports/ml_attack_level.csv")
    print("\nATTACK-LEVEL (attacks detected / launched), FULL features:")
    print(table.to_string())

    print("\nNORMAL ACTIVITY WRONGLY FLAGGED (events per scenario), FULL features:")
    for name, scenarios in wrong_all.items():
        print(f"  {name:20s} {scenarios if scenarios else 'none'}")

    if importances:
        imp = pd.DataFrame(importances).sort_values(
            ["model", "importance"], ascending=[True, False])
        imp.to_csv("reports/ml_feature_importance.csv", index=False)
        print("\nMOST IMPORTANT FEATURES:")
        for name, g in imp.groupby("model"):
            top = ", ".join(f"{r.feature} ({r.importance:.2f})" for r in g.head(5).itertuples())
            print(f"  {name}: {top}")

    ax = full.set_index("model")[["precision", "recall", "f1"]].plot(
        kind="bar", figsize=(10, 5), rot=20)
    ax.set_ylim(0, 1.05)
    ax.set_title("Rules vs machine learning (event level, FULL features)")
    plt.tight_layout()
    plt.savefig("reports/ml_comparison.png", dpi=200)
    print("\nSaved reports/ml_results.csv, ml_attack_level.csv, "
          "ml_feature_importance.csv, ml_comparison.png")
    print("Saved models in ml/saved/")


if __name__ == "__main__":
    main()
