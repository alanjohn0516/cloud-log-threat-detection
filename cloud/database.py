# cloud/database.py
# SQLite storage for CloudTrail events: create table, insert, query, stats.
import os
import sqlite3
from contextlib import contextmanager

import pandas as pd

DEFAULT_DB_PATH = "data/cloud_logs.db"
SUPPORTED_EVENTS = ("ConsoleLogin", "AssumeRole")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id    TEXT PRIMARY KEY,
    event_time  TEXT NOT NULL,
    event_name  TEXT NOT NULL,
    source_ip   TEXT,
    user_type   TEXT,
    user_name   TEXT,
    outcome     TEXT,
    error_code  TEXT,
    mfa_used    TEXT,
    user_agent  TEXT,
    role_arn    TEXT,
    is_attack   INTEGER,   -- ground truth, only for evaluation (NULL = unknown)
    attack_type TEXT,
    attack_id   TEXT,
    scenario    TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(event_time);
CREATE INDEX IF NOT EXISTS idx_events_ip   ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_name);
"""

INSERT_SQL = """
INSERT OR IGNORE INTO events
 (event_id, event_time, event_name, source_ip, user_type, user_name, outcome,
  error_code, mfa_used, user_agent, role_arn,
  is_attack, attack_type, attack_id, scenario)
VALUES
 (:event_id, :event_time, :event_name, :source_ip, :user_type, :user_name, :outcome,
  :error_code, :mfa_used, :user_agent, :role_arn,
  :is_attack, :attack_type, :attack_id, :scenario)
"""


def get_db_path():
    """Database file location. Can be changed with the CLOUD_DB_PATH variable."""
    return os.environ.get("CLOUD_DB_PATH", DEFAULT_DB_PATH)


@contextmanager
def get_conn(db_path=None):
    """Open the database (creating the file and table if needed), then close it."""
    path = db_path or get_db_path()
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path=None):
    with get_conn(db_path):
        pass


def clear_events(db_path=None):
    with get_conn(db_path) as conn:
        conn.execute("DELETE FROM events")


def parse_record(rec):
    """Turn one raw CloudTrail record into a flat row (dict).
    Raises ValueError if the record is unusable."""
    if not isinstance(rec, dict):
        raise ValueError("record is not an object")
    name = rec.get("eventName")
    if name not in SUPPORTED_EVENTS:
        raise ValueError(f"unsupported event: {name}")
    event_id, event_time = rec.get("eventID"), rec.get("eventTime")
    if not (isinstance(event_id, str) and event_id
            and isinstance(event_time, str) and event_time):
        raise ValueError("missing eventID or eventTime")

    ident = rec.get("userIdentity") or {}
    user_type = ident.get("type", "")
    user_name = ident.get("userName") or ("root" if user_type == "Root" else "")

    if name == "ConsoleLogin":
        outcome = (rec.get("responseElements") or {}).get("ConsoleLogin", "Unknown")
        mfa = (rec.get("additionalEventData") or {}).get("MFAUsed", "")
        role_arn = ""
    else:  # AssumeRole
        outcome = "Failure" if rec.get("errorCode") else "Success"
        mfa = ""
        role_arn = (rec.get("requestParameters") or {}).get("roleArn", "")

    return {
        "event_id": event_id,
        "event_time": event_time,
        "event_name": name,
        "source_ip": rec.get("sourceIPAddress", ""),
        "user_type": user_type,
        "user_name": user_name,
        "outcome": outcome,
        "error_code": rec.get("errorCode", ""),
        "mfa_used": mfa,
        "user_agent": rec.get("userAgent", ""),
        "role_arn": role_arn,
    }


def insert_records(records, labels=None, db_path=None):
    """Insert raw CloudTrail records. Duplicates (same eventID) are ignored.
    labels: optional dict  event_id -> {is_attack, attack_type, attack_id, scenario}"""
    labels = labels or {}
    result = {"received": len(records), "inserted": 0, "duplicates": 0, "skipped": 0}
    with get_conn(db_path) as conn:
        for rec in records:
            try:
                row = parse_record(rec)
            except (ValueError, AttributeError, TypeError):
                result["skipped"] += 1
                continue
            lab = labels.get(row["event_id"])
            row["is_attack"] = lab["is_attack"] if lab else None
            row["attack_type"] = lab["attack_type"] if lab else None
            row["attack_id"] = (lab["attack_id"] or None) if lab else None
            row["scenario"] = lab["scenario"] if lab else None
            cur = conn.execute(INSERT_SQL, row)
            if cur.rowcount == 1:
                result["inserted"] += 1
            else:
                result["duplicates"] += 1
    return result


def query_events(db_path=None, event_name=None, outcome=None, source_ip=None,
                 user_name=None, start=None, end=None, limit=100, offset=0):
    """Return events (oldest first) as a list of dicts, with optional filters."""
    clauses, params = [], []
    for column, value in [("event_name", event_name), ("outcome", outcome),
                          ("source_ip", source_ip), ("user_name", user_name)]:
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    if start is not None:
        clauses.append("event_time >= ?")
        params.append(start)
    if end is not None:
        clauses.append("event_time <= ?")
        params.append(end)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT * FROM events {where} ORDER BY event_time ASC LIMIT ? OFFSET ?"
    params += [limit, offset]
    with get_conn(db_path) as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def get_stats(db_path=None):
    with get_conn(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        by_event = {r[0]: r[1] for r in conn.execute(
            "SELECT event_name, COUNT(*) FROM events GROUP BY event_name")}
        by_outcome = {r[0]: r[1] for r in conn.execute(
            "SELECT outcome, COUNT(*) FROM events GROUP BY outcome")}
        ips = conn.execute("SELECT COUNT(DISTINCT source_ip) FROM events").fetchone()[0]
        attacks = conn.execute(
            "SELECT COUNT(*) FROM events WHERE is_attack = 1").fetchone()[0]
        first, last = conn.execute(
            "SELECT MIN(event_time), MAX(event_time) FROM events").fetchone()
    return {
        "total_events": total,
        "by_event_name": by_event,
        "by_outcome": by_outcome,
        "unique_ips": ips,
        "labelled_attack_events": attacks,
        "first_event": first,
        "last_event": last,
    }


def load_events_df(db_path=None):
    """All events as a pandas DataFrame (used by the rule engine and ML)."""
    with get_conn(db_path) as conn:
        return pd.read_sql_query("SELECT * FROM events ORDER BY event_time", conn)
