# dashboard/app.py
# Security dashboard (Streamlit): alerts, severity, timeline, evidence, response.
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
from dashboard import ui
from security import alert_store, pipeline

st.set_page_config(page_title="Cloud Log Threat Detection", page_icon="🛡️", layout="wide")
ui.inject_css()

SEVERITIES = ui.SEV_ORDER
ICON = {"CRITICAL": "🔴 CRITICAL", "HIGH": "🟠 HIGH", "MEDIUM": "🟡 MEDIUM"}
STATUSES = list(alert_store.STATUSES)
TABLE_COLUMNS = ["alert_id", "level", "attack_type", "confidence", "start_time",
                 "event_count", "distinct_ips", "targets", "success_after",
                 "detected_by", "status"]
FLOW = ["Cloud logs", "SQLite + FastAPI", "Features", "ML + rules",
        "Incidents", "Severity + response", "Dashboard"]


def db_stamp(path):
    return os.path.getmtime(path) if os.path.exists(path) else 0


@st.cache_data(ttl=60)
def load_events(path, stamp):
    return database.load_events_df(path)


def run_detection(events, path):
    """Run the integrated pipeline and store the alerts. Returns an error text or None."""
    try:
        with st.spinner("Analysing logs with the ML model and rule engine..."):
            alerts, _ = pipeline.detect(events, policy="ml")
            alert_store.save_alerts(alerts, path)
    except FileNotFoundError as err:
        return str(err)
    st.session_state["flash"] = f"Detection finished: {len(alerts)} alerts saved."
    return None


db_path = database.get_db_path()
events_raw = load_events(db_path, db_stamp(db_path))
alerts = alert_store.load_alerts(db_path)

if "flash" in st.session_state:
    st.success(st.session_state.pop("flash"))

ui.hero("🛡️ Cloud Log Threat Detection",
        "Brute force detection in AWS CloudTrail logs: machine learning, "
        "threshold rules and a cybersecurity response engine",
        ["AWS CloudTrail", "ML + rules", f"{len(events_raw):,} events"])

if events_raw.empty:
    st.warning("No logs found in the cloud database. Run: "
               "python cloud/generate_logs.py  and then  python -m cloud.load_logs --reset")
    st.stop()

events = events_raw.assign(time=pd.to_datetime(events_raw["event_time"], utc=True))
failed = events[events["outcome"] == "Failure"]

with st.sidebar:
    st.markdown('<div class="brand">🛡️ ThreatWatch</div>'
                '<div class="brand-sub">Cloud log threat detection</div>',
                unsafe_allow_html=True)
    sev_filter = st.multiselect("Severity", SEVERITIES, default=SEVERITIES)
    type_options = sorted(alerts["attack_type"].unique())
    type_filter = st.multiselect("Attack type", type_options, default=type_options)
    status_filter = st.multiselect("Alert status", STATUSES, default=STATUSES)
    st.divider()
    if st.button("▶ Run detection now"):
        error = run_detection(events_raw, db_path)
        if error:
            st.error(error)
        else:
            st.rerun()
    st.caption("Re-running detection replaces the stored alerts and resets their status.")
    st.caption(f"Database: {db_path}")

view = alerts[alerts["severity"].isin(sev_filter)
              & alerts["attack_type"].isin(type_filter)
              & alerts["status"].isin(status_filter)].copy()

k = st.columns(5)
k[0].metric("Events analysed", f"{len(events):,}")
k[1].metric("Failed events", f"{len(failed):,}")
k[2].metric("Alerts", str(len(alerts)))
k[3].metric("Critical + High", str(int(alerts["severity"].isin(["CRITICAL", "HIGH"]).sum())))
k[4].metric("Open alerts", str(int((alerts["status"] == "open").sum())))

if alerts.empty:
    st.info("No alerts yet. Click 'Run detection now' in the sidebar.")

st.write("")
tab_over, tab_alerts, tab_models, tab_about = st.tabs(
    ["📊 Overview", "🚨 Alerts", "🧪 Model comparison", "ℹ️ About"])

# ------------------------------------------------------------------ Overview
with tab_over:
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

    ui.section("Failed sign-ins and role calls per hour")
    if failed.empty:
        st.caption("No failed events.")
    else:
        st.altair_chart(ui.hourly_chart(failed))

    ui.section("Alert timeline", "bubble size = number of events in the alert")
    if view.empty:
        st.caption("No alerts match the filters.")
    else:
        st.altair_chart(ui.timeline_chart(view))

    if not failed.empty:
        ui.section("Top source IPs by failed events")
        st.altair_chart(ui.ips_chart(failed))
        st.caption("A busy IP is not always an attacker: your own office also appears here "
                   "because many normal users sit behind one shared address.")

# -------------------------------------------------------------------- Alerts
with tab_alerts:
    if view.empty:
        st.info("No alerts to show. Adjust the filters or run detection.")
    else:
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
                           "alerts.csv", "text/csv")

        ui.section("Inspect an alert")
        choice = st.selectbox("Alert", view["alert_id"].tolist(),
                              label_visibility="collapsed")
        a = view[view["alert_id"] == choice].iloc[0]
        st.markdown(ui.alert_detail(a), unsafe_allow_html=True)
        if a["success_after"]:
            st.error("A successful sign-in followed this attack. "
                     "Treat the account as compromised.")

        new_status = st.radio("Status", STATUSES, index=STATUSES.index(a["status"]),
                              horizontal=True, key=f"status_{choice}_{a['status']}")
        if new_status != a["status"]:
            alert_store.set_status(choice, new_status, db_path)
            st.rerun()

        ids = json.loads(a["event_ids"])
        evidence = events[events["event_id"].isin(ids)][
            ["event_time", "event_name", "source_ip", "user_name", "outcome", "error_code"]]
        with st.expander(f"Evidence: {len(evidence)} log events"):
            st.dataframe(evidence, hide_index=True)

# ------------------------------------------------------------ Model comparison
with tab_models:
    ui.section("Rules vs machine learning")
    res_file = os.path.join(ROOT, "reports", "ml_results.csv")
    if os.path.exists(res_file):
        res = pd.read_csv(res_file)
        st.caption("Scores on the logs stored in the cloud database. The models were "
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

# --------------------------------------------------------------------- About
with tab_about:
    ui.section("How the system works")
    st.markdown(ui.flow_html(FLOW), unsafe_allow_html=True)
    st.markdown(
        "**Roles:** the *cloud* module collects and stores logs, the *AI/ML* module "
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
    st.markdown("- All logs are synthetic and the models are trained and tested on the same "
                "generator (different random seeds), so the scores are an upper bound for "
                "real CloudTrail data.\n"
                "- Features based on IP/user history lean on the assumption that attackers "
                "use IP addresses never seen before.\n"
                "- Incidents that share a target within an hour can be merged into one alert.")

st.markdown('<div class="footer">Cloud Log Threat Detection &middot; '
            'Brute force detection in AWS CloudTrail logs</div>', unsafe_allow_html=True)
