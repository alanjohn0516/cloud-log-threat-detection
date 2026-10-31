# security/evaluate_rules.py
# Runs the rule engine on the database and measures its accuracy.
# Run from the project root:  python -m security.evaluate_rules
import json
import os

import pandas as pd

from cloud import database
from security.metrics import event_metrics
from security.rules import RULES, run_rules


def main():
    df = database.load_events_df()
    if df.empty:
        raise SystemExit("Database is empty. Run: python -m cloud.load_logs --reset")
    if df["is_attack"].isna().all():
        raise SystemExit("No ground-truth labels. Run: python -m cloud.load_logs --reset")

    print("RULES USED")
    for r in RULES:
        group = r.group_by or "account"
        print(f"  {r.rule_id}: >= {r.threshold} events in {r.window_seconds // 60} min "
              f"per {group}   [{r.source}]")

    alerts = run_rules(df)
    flagged_ids = set()
    for ids in alerts["event_ids"]:
        flagged_ids.update(ids)
    df["flagged"] = df["event_id"].isin(flagged_ids)

    # ---- 1) event-level metrics
    m = event_metrics(df["is_attack"] == 1, df["flagged"])
    print("\nEVENT-LEVEL RESULTS (every log line judged on its own)")
    print(f"  Precision:           {m['precision']:.3f}")
    print(f"  Recall:              {m['recall']:.3f}")
    print(f"  F1-score:            {m['f1']:.3f}")
    print(f"  False positive rate: {m['false_positive_rate']:.4f}")
    print(f"  TP={m['tp']}  FP={m['fp']}  FN={m['fn']}  TN={m['tn']}")

    # ---- 2) alert-level: is each alert a real attack?
    is_att = df.set_index("event_id")["is_attack"]
    scen = df.set_index("event_id")["scenario"]
    shares, scenarios = [], []
    for ids in alerts["event_ids"]:
        shares.append(float((is_att.reindex(ids) == 1).mean()))
        mode = scen.reindex(ids).dropna().mode()
        scenarios.append(mode.iloc[0] if len(mode) else "unknown")
    alerts["attack_share"] = shares
    alerts["scenario"] = scenarios
    alerts["true_alert"] = alerts["attack_share"] >= 0.5
    false_alerts = alerts[~alerts["true_alert"]]

    print("\nALERT-LEVEL RESULTS (is each alert a real attack?)")
    print(f"  Alerts raised: {len(alerts)}   "
          f"real: {int(alerts['true_alert'].sum())}   false: {len(false_alerts)}")
    if len(false_alerts):
        print("\n  FALSE ALERTS (normal behaviour wrongly flagged):")
        print(false_alerts[["alert_id", "rule_id", "group", "event_count",
                            "severity", "scenario"]].to_string(index=False))

    # ---- 3) attack-level: was each attack caught?
    att = df[df["is_attack"] == 1]
    per_attack = att.groupby(["attack_type", "attack_id"])["flagged"].any().reset_index()
    summary = per_attack.groupby("attack_type")["flagged"].agg(
        detected="sum", total="count")
    print("\nATTACK-LEVEL RESULTS (attacks detected / attacks launched)")
    print(summary.to_string())
    print(f"  Overall: {int(per_attack['flagged'].sum())} of {len(per_attack)} attacks detected")

    print("\nALERTS BY SEVERITY")
    print(alerts["severity"].value_counts().to_string())

    # ---- save results for the report and for Step 6
    os.makedirs("reports", exist_ok=True)
    result = {
        "event_level": m,
        "alerts_total": int(len(alerts)),
        "alerts_real": int(alerts["true_alert"].sum()),
        "alerts_false": int(len(false_alerts)),
        "attacks_detected": int(per_attack["flagged"].sum()),
        "attacks_total": int(len(per_attack)),
        "attack_level": {t: {"detected": int(r["detected"]), "total": int(r["total"])}
                         for t, r in summary.iterrows()},
    }
    with open("reports/rule_metrics.json", "w") as f:
        json.dump(result, f, indent=2)
    alerts.drop(columns=["event_ids"]).to_csv("reports/rule_alerts.csv", index=False)
    print("\nSaved reports/rule_metrics.json and reports/rule_alerts.csv")


if __name__ == "__main__":
    main()
