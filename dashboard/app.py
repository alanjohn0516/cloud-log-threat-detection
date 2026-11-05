# dashboard/app.py
# Upload-first security dashboard (Streamlit).
# Flow: sign in -> add a CloudTrail log file -> review the alerts for that file.
# Run from the project root:  streamlit run dashboard/app.py
import json
import os
import sys

try:
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
except NameError:
    ROOT = os.getcwd()
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pandas as pd
import streamlit as st

from cloud import database
from dashboard import analyze, auth, bootstrap, ui
from security import alert_store

st.set_page_config(page_title="Cloud Log Threat Detection", page_icon="🛡️", layout="wide")
ui.inject_css()
auth.require_login()
bootstrap.run_if_enabled()

SEVERITIES = ui.SEV_ORDER
ICON = {"CRITICAL": "🔴 CRITICAL", "HIGH": "🟠 HIGH", "MEDIUM": "🟡 MEDIUM"}
STATUSES = list(alert_store.STATUSES)
TABLE_COLUMNS = ["alert_id", "level", "attack_type", "confidence", "start_time",
                 "event_count", "distinct_ips", "targets", "success_after",
                 "detected_by", "status"]
FLOW = ["Log file", "Read events", "Features", "ML + rules",
        "Incidents", "Severity + response", "Dashboard"]
PRIVACY = ("Privacy: nothing you add is stored on the server, and results disappear when "
           "you close the page. The online version runs on a public server, so do not add "
           "real or sensitive CloudTrail logs there. To analyse real data, run this app "
           "on your own machine.")
db_path = database.get_db_path()


def has_stored():
    """True if the local database already holds logs and alerts."""
    try:
        return (database.get_stats(db_path)["total_events"] > 0
                and not alert_store.load_alerts(db_path).empty)
    except Exception:
        return False


def load_stored():
    events = database.load_events_df(db_path)
    alerts = alert_store.load_alerts(db_path).copy()
    alerts["event_ids"] = alerts["event_ids"].apply(json.loads)
    info = {"files": 1, "records": len(events), "skipped": 0, "errors": []}
    return "stored demo data", events, alerts, info


def open_dataset(name, events, alerts, info):
    st.session_state["dataset"] = {"name": name, "events": events,
                                   "alerts": alerts, "info": info}
    st.rerun()


def landing():
    ui.hero("🛡️ Cloud Log Threat Detection",
            "Add an AWS CloudTrail log file to see brute force attacks, how severe "
            "they are and what to do about them",
            ["Step 1: add a log file", "Step 2: review the dashboard"])
    ui.section("Step 1: add your CloudTrail log file", "JSON or gzipped JSON, several files allowed")
    st.info(PRIVACY)
    files = st.file_uploader("CloudTrail log files", type=["json", "gz"],
                             accept_multiple_files=True)
    if files:
        payload = tuple((f.name, f.getvalue()) for f in files)
        try:
            with st.spinner("Analysing your logs..."):
                events, info, alerts = analyze.run_upload(payload)
        except (ValueError, FileNotFoundError) as err:
            st.error(str(err))
            return
        for message in info["errors"]:
            st.warning(message)
        if events.empty:
            st.error("No ConsoleLogin or AssumeRole events were found in the file(s).")
            return
        name = files[0].name if len(files) == 1 else f"{len(files)} files"
        open_dataset(name, events, alerts, info)

    ui.section("No file at hand?")
    left, right = st.columns(2)
    with left:
        if st.button("Try it with a sample file"):
            with st.spinner("Creating and analysing a sample log..."):
                events, info, alerts = analyze.run_upload(
                    (("sample_cloudtrail.json", analyze.sample_bytes()),))
            open_dataset("sample file (10 days)", events, alerts, info)
        st.caption("A synthetic 10-day CloudTrail log that contains brute force attacks.")
        st.download_button("⬇ Download the sample file", analyze.sample_bytes(),
                           "sample_cloudtrail.json", "application/json", key="dl_sample")
    with right:
        if has_stored():
            if st.button("Open the stored demo data"):
                open_dataset(*load_stored())
            st.caption("The 30-day dataset already stored in this app's database.")


def overview_tab(events, failed, alerts, view):
    order = {s: i for i, s in enumerate(ui.SEV_ORDER)}
    attention = (alerts[alerts["status"] == "open"]
                 .assign(_o=lambda d: d["severity"].map(order))
                 .sort_values(["_o", "start_time"]).head(3))
    if not attention.empty:
        ui.section("Needs attention", "the most urgent open alerts")
        cols = st.columns(3)
        for col, (_, row) in zip(cols, attention.iterrows()):
            col.markdown(ui.alert_card(row), unsafe_allow_html=True)

    left, right = st.columns(2)
    with left:
        ui.section("Alerts by severity")
        if view.empty:
            st.caption("No alerts match the filters.")
        else:
            st.altair_chart(ui.severity_chart(view))
    with right:
        ui.section("Alerts by attack type")
        if view.empty:
            st.caption("No alerts match the filters.")
        else:
            st.altair_chart(ui.type_chart(view))

    span_days = (events["time"].max() - events["time"].min()).days
    freq, unit = ("1h", "hour") if span_days <= 14 else ("1D", "day")
    ui.section(f"Failed sign-ins and role calls per {unit}")
    if failed.empty:
        st.caption("No failed events.")
    else:
        st.altair_chart(ui.hourly_chart(failed, freq))

    ui.section("Alert timeline", "bubble size = number of events in the alert")
    if view.empty:
        st.caption("No alerts match the filters.")
    else:
        st.altair_chart(ui.timeline_chart(view))

    if not failed.empty:
        ui.section("Top source IPs by failed events")
        st.altair_chart(ui.ips_chart(failed))
        st.caption("A busy IP is not always an attacker: a shared office address can "
                   "also appear here because many normal users sit behind it.")


def alerts_tab(events, alerts, view):
    if view.empty:
        st.info("No alerts to show. Adjust the filters in the sidebar.")
        return
    ui.section("All alerts", f"{len(view)} shown")
    table = view.assign(level=view["severity"].map(ICON))[TABLE_COLUMNS]
    st.dataframe(
        table, hide_index=True,
        column_config={
            "alert_id": "Alert", "level": "Severity", "attack_type": "Attack",
            "confidence": st.column_config.ProgressColumn(
                "ML confidence", min_value=0, max_value=100, format="%.1f"),
            "start_time": "Start", "event_count": "Events", "distinct_ips": "IPs",
            "targets": "Targets",
            "success_after": st.column_config.CheckboxColumn("Sign-in after"),
            "detected_by": "Detected by", "status": "Status"})
    st.download_button("Download alerts as CSV", table.to_csv(index=False),
                       "alerts.csv", "text/csv", key="dl_alerts")

    ui.section("Inspect an alert")
    choice = st.selectbox("Alert", view["alert_id"].tolist(), label_visibility="collapsed")
    a = view[view["alert_id"] == choice].iloc[0]
    st.markdown(ui.alert_detail(a), unsafe_allow_html=True)
    if a["success_after"]:
        st.error("A successful sign-in followed this attack. "
                 "Treat the account as compromised.")

    new_status = st.radio("Status", STATUSES, index=STATUSES.index(a["status"]),
                          horizontal=True, key=f"status_{choice}_{a['status']}")
    if new_status != a["status"]:
        alerts.loc[alerts["alert_id"] == choice, "status"] = new_status
        st.rerun()

    evidence = events[events["event_id"].isin(a["event_ids"])][
        ["event_time", "event_name", "source_ip", "user_name", "outcome", "error_code"]]
    with st.expander(f"Evidence: {len(evidence)} log events"):
        st.dataframe(evidence, hide_index=True)
    st.caption("This is a screening aid. A person should confirm each alert before acting.")


def models_tab():
    ui.section("Rules vs machine learning")
    res_file = os.path.join(ROOT, "reports", "ml_results.csv")
    if os.path.exists(res_file):
        res = pd.read_csv(res_file)
        st.caption("Project results: scores on a stored synthetic dataset. The models were "
                   "trained on separate synthetic datasets. FULL = with IP/user history "
                   "features; NO_HISTORY = ablation without them.")
        st.dataframe(res, hide_index=True)
        full = res[res["features"].isin(["FULL", "n/a"])].set_index("model")[
            ["precision", "recall", "f1"]]
        st.bar_chart(full)
    else:
        st.info("Run  python -m ml.train  to create this comparison.")

    pol_file = os.path.join(ROOT, "reports", "pipeline_policies.csv")
    if os.path.exists(pol_file):
        ui.section("Detection policies in the integrated pipeline",
                   "rules only, ML only, or both")
        st.dataframe(pd.read_csv(pol_file), hide_index=True)

    img_file = os.path.join(ROOT, "reports", "ml_comparison.png")
    if os.path.exists(img_file):
        st.image(img_file)


def about_tab():
    ui.section("How the system works")
    st.markdown(ui.flow_html(FLOW), unsafe_allow_html=True)
    st.markdown(
        "**Roles:** the *cloud* module reads and stores logs, the *AI/ML* module "
        "scores every event, and the *cybersecurity* engine turns flagged events into "
        "incidents with an attack type, a severity and a recommended response.")
    ui.section("Severity levels")
    st.markdown(
        f"{ui.severity_badge('MEDIUM')} a detected attack with no sign of compromise<br>"
        f"{ui.severity_badge('HIGH')} 100+ failures, a privileged target, "
        "or a sign-in followed the attack<br>"
        f"{ui.severity_badge('CRITICAL')} a privileged account (root/admin) signed in "
        "after the attack", unsafe_allow_html=True)
    ui.section("Limitations")
    st.markdown("- The model was trained on synthetic logs, so scores on real CloudTrail "
                "data may be lower and false alarms more likely.\n"
                "- It learns who normally signs in from where using the file itself, so a "
                "very short extract gives it little to learn from.\n"
                "- Incidents that share a target within an hour can be merged into one alert.\n"
                "- It only recommends actions. A person must decide and act.")


def dashboard(ds):
    alerts = ds["alerts"]
    events = ds["events"].assign(time=pd.to_datetime(ds["events"]["event_time"], utc=True))
    failed = events[events["outcome"] == "Failure"]
    first, last = events["time"].min(), events["time"].max()
    ui.hero("🛡️ Cloud Log Threat Detection", f"Results for {ds['name']}",
            [f"{len(events):,} events", f"{len(alerts)} alerts",
             f"{first:%d %b %Y} to {last:%d %b %Y}"])
    for message in ds["info"]["errors"]:
        st.warning(message)

    with st.sidebar:
        st.markdown('<div class="brand">🛡️ ThreatWatch</div>'
                    '<div class="brand-sub">Cloud log threat detection</div>',
                    unsafe_allow_html=True)
        st.caption(f"Showing: {ds['name']}")
        if st.button("↩ Load another file"):
            st.session_state.pop("dataset", None)
            st.rerun()
        st.divider()
        sev_filter = st.multiselect("Severity", SEVERITIES, default=SEVERITIES)
        type_options = sorted(alerts["attack_type"].unique())
        type_filter = st.multiselect("Attack type", type_options, default=type_options)
        status_filter = st.multiselect("Alert status", STATUSES, default=STATUSES)
        st.caption("Alert status changes last for this session only.")

    view = alerts[alerts["severity"].isin(sev_filter)
                  & alerts["attack_type"].isin(type_filter)
                  & alerts["status"].isin(status_filter)].copy()

    k = st.columns(5)
    k[0].metric("Events analysed", f"{len(events):,}")
    k[1].metric("Failed events", f"{len(failed):,}")
    k[2].metric("Alerts", str(len(alerts)))
    k[3].metric("Critical + High",
                str(int(alerts["severity"].isin(["CRITICAL", "HIGH"]).sum())))
    k[4].metric("Open alerts", str(int((alerts["status"] == "open").sum())))
    if alerts.empty:
        st.success("No brute force activity was detected in this file.")

    st.write("")
    tab_over, tab_alerts, tab_models, tab_about = st.tabs(
        ["📊 Overview", "🚨 Alerts", "🧪 Model comparison", "ℹ️ About"])
    with tab_over:
        overview_tab(events, failed, alerts, view)
    with tab_alerts:
        alerts_tab(events, alerts, view)
    with tab_models:
        models_tab()
    with tab_about:
        about_tab()


dataset = st.session_state.get("dataset")
if dataset is None:
    landing()
else:
    dashboard(dataset)

st.markdown('<div class="footer">Cloud Log Threat Detection &middot; '
            'Brute force detection in AWS CloudTrail logs</div>', unsafe_allow_html=True)
