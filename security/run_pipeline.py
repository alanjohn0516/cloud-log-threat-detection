# security/run_pipeline.py
# Runs the integrated pipeline on the cloud database, compares the three
# policies, checks the attack classification and saves the alerts.
# Run from the project root:  python -m security.run_pipeline
import json
import os

import pandas as pd

from cloud import database
from ml.experiment import evaluate_flags
from security import alert_store, pipeline

TRUTH_TO_PRED = {"low_and_slow": "distributed_brute_force"}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}


def classification_check(alerts, scored):
    """Compare each alert's predicted attack type with the ground truth."""
    truth = scored.set_index("event_id")
    rows = []
    for a in alerts.itertuples():
        ev = truth.loc[a.event_ids]
        att = ev[ev["is_attack"] == 1]
        if len(att) / len(ev) < 0.5:
            true_type = "(false alert)"
        else:
            true_type = att["attack_type"].mode().iloc[0]
        expected = TRUTH_TO_PRED.get(true_type, true_type)
        rows.append({"alert_id": a.alert_id, "true_type": true_type,
                     "predicted": a.attack_type, "correct": expected == a.attack_type})
    return pd.DataFrame(rows)


def print_card(a):
    print("\nEXAMPLE ALERT (most severe)")
    print(f"  ID:          {a['alert_id']}")
    print(f"  Attack:      {a['attack_type']}")
    print(f"  Severity:    {a['severity']}")
    print(f"  Confidence:  {a['confidence']}%")
    print(f"  Source IPs:  {a['source_ips']}")
    print(f"  Targets:     {a['targets']}")
    print(f"  Events:      {a['event_count']} over {a['duration_s']} s "
          f"({a['failed_events']} failed)")
    print(f"  Sign-in after attack: {'YES' if a['success_after'] else 'no'}")
    print(f"  Detected by: {a['detected_by']}")
    print("  Recommended action:")
    for step in a["recommended_action"].split("; "):
        print(f"    -> {step}")


def main():
    events = database.load_events_df()
    if events.empty:
        raise SystemExit("Database is empty. Run: python -m cloud.load_logs --reset")
    labelled = bool(events["is_attack"].notna().all())
    model_bundle = pipeline.load_model()
    print(f"Loaded {len(events)} events from the cloud database")

    summary, wrongs, runs = [], {}, {}
    for policy in pipeline.POLICIES:
        alerts, scored = pipeline.detect(events, policy=policy, model_bundle=model_bundle)
        runs[policy] = (alerts, scored)
        row = {"policy": policy, "alerts": int(len(alerts))}
        if labelled:
            scored["is_attack"] = scored["is_attack"].astype(int)
            m, _, wrong = evaluate_flags(scored, scored["alerted"].to_numpy())
            row.update(precision=m["precision"], recall=m["recall"], f1=m["f1"],
                       FP=int(m["fp"]), FN=int(m["fn"]),
                       attacks=f"{m['attacks_detected']}/{m['attacks_total']}")
            wrongs[policy] = wrong
        summary.append(row)

    print("\nPOLICY COMPARISON (events judged after incident grouping)")
    print(pd.DataFrame(summary).to_string(index=False))
    if wrongs:
        print("\nNORMAL EVENTS WRONGLY ALERTED:")
        for policy, wrong in wrongs.items():
            print(f"  {policy:6s} {wrong if wrong else 'none'}")

    alerts, scored = runs["ml"]
    print(f"\nALERTS (policy = ml): {len(alerts)}")
    if alerts.empty:
        print("No alerts raised.")
        return
    print(alerts["severity"].value_counts().to_string())
    cols = ["alert_id", "attack_type", "severity", "confidence", "start_time",
            "event_count", "distinct_ips", "success_after", "detected_by"]
    print(alerts[cols].to_string(index=False))

    cls = None
    if labelled:
        cls = classification_check(alerts, scored)
        print("\nATTACK TYPE CLASSIFICATION (alerts by true attack type)")
        print(cls.groupby("true_type")["correct"].agg(alerts="count", correct="sum").to_string())

    top = alerts.assign(_o=alerts["severity"].map(SEVERITY_ORDER)) \
                .sort_values(["_o", "start_time"]).iloc[0]
    print_card(top)

    os.makedirs("reports", exist_ok=True)
    saved = alert_store.save_alerts(alerts)
    alerts.drop(columns=["event_ids"]).to_csv("reports/pipeline_alerts.csv", index=False)
    pd.DataFrame(summary).to_csv("reports/pipeline_policies.csv", index=False)
    with open("reports/pipeline_metrics.json", "w") as f:
        json.dump({"policies": summary,
                   "classification_correct": int(cls["correct"].sum()) if cls is not None else None,
                   "alerts": int(len(alerts))}, f, indent=2, default=str)
    print(f"\nSaved {saved} alerts to the database (table: alerts)")
    print("Saved reports/pipeline_alerts.csv, pipeline_policies.csv, pipeline_metrics.json")


if __name__ == "__main__":
    main()
