# security/alert_store.py
# Saves and loads alerts in the same SQLite database as the logs.
import json

import pandas as pd

from cloud import database

ALERT_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id           TEXT PRIMARY KEY,
    attack_type        TEXT,
    severity           TEXT,
    confidence         REAL,
    start_time         TEXT,
    end_time           TEXT,
    duration_s         INTEGER,
    event_count        INTEGER,
    failed_events      INTEGER,
    distinct_users     INTEGER,
    distinct_ips       INTEGER,
    source_ips         TEXT,
    targets            TEXT,
    success_after      INTEGER,
    detected_by        TEXT,
    rules_agree        REAL,
    recommended_action TEXT,
    status             TEXT DEFAULT 'open',
    event_ids          TEXT
);
"""

COLUMNS = ["alert_id", "attack_type", "severity", "confidence", "start_time",
           "end_time", "duration_s", "event_count", "failed_events",
           "distinct_users", "distinct_ips", "source_ips", "targets",
           "success_after", "detected_by", "rules_agree", "recommended_action",
           "status", "event_ids"]
STATUSES = ("open", "acknowledged", "resolved")


def _ensure(conn):
    conn.executescript(ALERT_SCHEMA)


def save_alerts(alerts, db_path=None):
    """Replace the stored alerts with a new set. Returns how many were saved."""
    rows = []
    for r in alerts.to_dict("records"):
        rows.append((
            r["alert_id"], r["attack_type"], r["severity"], float(r["confidence"]),
            r["start_time"], r["end_time"], int(r["duration_s"]), int(r["event_count"]),
            int(r["failed_events"]), int(r["distinct_users"]), int(r["distinct_ips"]),
            r["source_ips"], r["targets"], int(bool(r["success_after"])),
            r["detected_by"], float(r["rules_agree"]), r["recommended_action"],
            "open", json.dumps(list(r["event_ids"]))))
    placeholders = ",".join("?" * len(COLUMNS))
    with database.get_conn(db_path) as conn:
        _ensure(conn)
        conn.execute("DELETE FROM alerts")
        conn.executemany(
            f"INSERT INTO alerts ({', '.join(COLUMNS)}) VALUES ({placeholders})", rows)
    return len(rows)


def load_alerts(db_path=None):
    with database.get_conn(db_path) as conn:
        _ensure(conn)
        df = pd.read_sql_query(
            "SELECT * FROM alerts ORDER BY start_time, alert_id", conn)
    df["success_after"] = df["success_after"].astype(bool)
    return df


def set_status(alert_id, status, db_path=None):
    """open / acknowledged / resolved. Returns True if the alert exists."""
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    with database.get_conn(db_path) as conn:
        _ensure(conn)
        cur = conn.execute("UPDATE alerts SET status = ? WHERE alert_id = ?",
                           (status, alert_id))
        return cur.rowcount == 1
