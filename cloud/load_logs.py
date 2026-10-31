# cloud/load_logs.py
# Loads the generated CloudTrail logs (plus ground-truth labels) into SQLite.
# Run from the project root:  python -m cloud.load_logs --reset
import argparse
import json
import os

import pandas as pd

from cloud import database


def read_labels(path):
    """Read the answer key (used only to measure detection accuracy later)."""
    if not os.path.exists(path):
        return {}
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    labels = {}
    for row in df.itertuples(index=False):
        labels[row.event_id] = {
            "is_attack": 1 if row.is_attack == "True" else 0,
            "attack_type": row.attack_type,
            "attack_id": row.attack_id,
            "scenario": row.scenario,
        }
    return labels


def main():
    parser = argparse.ArgumentParser(description="Load CloudTrail logs into SQLite")
    parser.add_argument("--json", default="data/cloudtrail_logs.json")
    parser.add_argument("--labels", default="data/cloudtrail_labeled.csv")
    parser.add_argument("--reset", action="store_true", help="empty the database first")
    args = parser.parse_args()

    if not os.path.exists(args.json):
        raise SystemExit(f"{args.json} not found. Run: python cloud/generate_logs.py")

    database.init_db()
    if args.reset:
        database.clear_events()
        print("Database emptied.")

    with open(args.json) as f:
        records = json.load(f)["Records"]
    labels = read_labels(args.labels)

    result = database.insert_records(records, labels=labels)
    stats = database.get_stats()

    print(f"Read {len(records)} records from {args.json}")
    print(f"Labels available: {len(labels)}")
    print(f"Result: {result}")
    print(f"\nDatabase file: {database.get_db_path()}")
    print(f"Total events:            {stats['total_events']}")
    print(f"By event type:           {stats['by_event_name']}")
    print(f"By outcome:              {stats['by_outcome']}")
    print(f"Unique source IPs:       {stats['unique_ips']}")
    print(f"Labelled attack events:  {stats['labelled_attack_events']}")
    print(f"Time range:              {stats['first_event']}  to  {stats['last_event']}")


if __name__ == "__main__":
    main()
