# dashboard/analyze.py
# "Analyze your logs" tab: upload CloudTrail files, run the detector, see alerts.
# Nothing uploaded is stored; results exist only for the current session.
import gzip
import io
import json
from datetime import datetime

import pandas as pd
import streamlit as st

from cloud import database
from cloud.generate_logs import Generator
from dashboard import ui
from security import pipeline

MAX_EVENTS = 100_000
MAX_BYTES = 150_000_000      # largest accepted file after unzipping
SHOW_COLUMNS = ["alert_id", "attack_type", "severity", "confidence", "start_time",
                "event_count", "distinct_ips", "targets", "detected_by"]
EVIDENCE_COLUMNS = ["event_time", "event_name", "source_ip", "user_name",
                    "outcome", "error_code"]


def _read_records(raw):
    """Bytes -> list of CloudTrail records. Accepts plain or gzip JSON, a
    {"Records": [...]} file, a plain list, or JSON Lines."""
    if raw[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as handle:
            raw = handle.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("file is too large after unzipping")
    text = raw.decode("utf-8-sig")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(data, dict):
        for key in ("Records", "Events"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    return data


def _unwrap(record):
    """The CloudTrail lookup API wraps each event as a JSON string."""
    if isinstance(record, dict) and isinstance(record.get("CloudTrailEvent"), str):
        return json.loads(record["CloudTrailEvent"])
    return record


def parse_uploads(files):
    """files: list of (name, bytes). Returns (events DataFrame, info dict).
    Raises ValueError if the upload has more than MAX_EVENTS usable events."""
    info = {"files": 0, "records": 0, "skipped": 0, "errors": []}
    rows, seen = [], set()
    for name, raw in files:
        try:
            records = _read_records(raw)
        except (ValueError, OSError, EOFError) as err:
            info["errors"].append(f"{name}: could not be read ({err})")
            continue
        if not isinstance(records, list):
            info["errors"].append(f"{name}: no list of records found")
            continue
        info["files"] += 1
        for record in records:
            info["records"] += 1
            try:
                row = database.parse_record(_unwrap(record))
            except (ValueError, TypeError, AttributeError, KeyError):
                info["skipped"] += 1      # other event type, or unreadable
                continue
            if row["event_id"] in seen:
                info["skipped"] += 1      # duplicate event
                continue
            seen.add(row["event_id"])
            rows.append(row)
            if len(rows) > MAX_EVENTS:
                raise ValueError(f"more than {MAX_EVENTS:,} usable events; "
                                 "please upload a smaller time range")
    return pd.DataFrame(rows), info


def analyze(events):
    """Run the integrated pipeline (ML + rules + cybersecurity engine)."""
    alerts, _ = pipeline.detect(events, policy="ml")
    alerts["status"] = "open"
    return alerts


def make_sample():
    """A synthetic CloudTrail file (10 days, includes attacks) to try the tab."""
    gen = Generator(seed=7, days=10, start=datetime(2026, 9, 1))
    gen.run()
    return json.dumps({"Records": [rec for rec, _ in gen.events]}).encode()


@st.cache_data(show_spinner=False)
def _sample_file():
    return make_sample()


@st.cache_data(show_spinner=False, max_entries=4)
def _analyze_cached(payload):
    events, info = parse_uploads(list(payload))
    alerts = analyze(events) if not events.empty else pd.DataFrame()
    return events, info, alerts


def render():
    ui.section("Analyze your own CloudTrail logs",
               "results are shown here and are not stored")
    st.info("Privacy: the online version runs on a public server. Do not upload real or "
            "sensitive CloudTrail logs there. To analyse real data, run this app on your "
            "own machine or your own server.")
    st.write("Upload one or more CloudTrail files (`.json` or `.json.gz`). The system reads "
             "sign-in (ConsoleLogin) and AssumeRole events, ignores everything else, and "
             "shows any brute force activity it finds. Use at least a few days of logs: "
             "the model learns who normally signs in from where, and a very short extract "
             "gives it little to learn from.")
    files = st.file_uploader("CloudTrail log files", type=["json", "gz"],
                             accept_multiple_files=True)
    st.download_button("⬇ Download a sample log file (10 days, includes attacks)",
                       _sample_file(), "sample_cloudtrail.json", "application/json",
                       key="dl_sample_logs")
    if not files:
        st.caption("No file uploaded yet. Download the sample above and upload it to try.")
        return

    payload = tuple((f.name, f.getvalue()) for f in files)
    try:
        with st.spinner("Analysing your logs..."):
            events, info, alerts = _analyze_cached(payload)
    except (ValueError, FileNotFoundError) as err:
        st.error(str(err))
        return

    for message in info["errors"]:
        st.warning(message)
    st.caption(f"{info['files']} file(s) read: {info['records']:,} records, "
               f"{len(events):,} used, {info['skipped']:,} skipped "
               "(other event types or duplicates).")
    if events.empty:
        st.error("No ConsoleLogin or AssumeRole events were found in the upload.")
        return

    failed = int((events["outcome"] == "Failure").sum())
    urgent = int(alerts["severity"].isin(["CRITICAL", "HIGH"]).sum()) if len(alerts) else 0
    k = st.columns(4)
    k[0].metric("Events analysed", f"{len(events):,}")
    k[1].metric("Failed events", f"{failed:,}")
    k[2].metric("Alerts", str(len(alerts)))
    k[3].metric("Critical + High", str(urgent))
    if alerts.empty:
        st.success("No brute force activity detected in this upload.")
        return

    ui.section("Alerts found", f"{len(alerts)} incident(s)")
    shown = alerts.drop(columns=["event_ids"])
    st.dataframe(shown[SHOW_COLUMNS], hide_index=True,
                 column_config={"confidence": st.column_config.ProgressColumn(
                     "ML confidence", min_value=0, max_value=100, format="%.1f")})
    st.download_button("Download these results as CSV", shown.to_csv(index=False),
                       "uploaded_logs_alerts.csv", "text/csv", key="dl_upload_alerts")

    ui.section("Inspect an alert")
    choice = st.selectbox("Alert from your upload", alerts["alert_id"].tolist(),
                          key="analyze_choice")
    a = alerts[alerts["alert_id"] == choice].iloc[0]
    st.markdown(ui.alert_detail(a), unsafe_allow_html=True)
    evidence = events[events["event_id"].isin(a["event_ids"])][EVIDENCE_COLUMNS]
    with st.expander(f"Evidence: {len(evidence)} log events"):
        st.dataframe(evidence, hide_index=True)
    st.caption("This is a screening aid. A person should confirm each alert before acting.")
