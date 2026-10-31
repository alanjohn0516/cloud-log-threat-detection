# dashboard/ui.py
# Look and feel of the dashboard: CSS, badges, cards and charts.
import html

import altair as alt
import pandas as pd
import streamlit as st

SEV_COLORS = {"CRITICAL": "#DC2626", "HIGH": "#F97316", "MEDIUM": "#EAB308"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM"]
STATUS_COLORS = {"open": "#2563EB", "acknowledged": "#D97706", "resolved": "#16A34A"}
INDIGO = "#4F46E5"
TEAL = "#0EA5E9"

CSS = """
<style>
.stApp { background: #F6F7FB; }
.block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1280px; }
#MainMenu, footer { visibility: hidden; }
header[data-testid='stHeader'] { background: transparent; }
section[data-testid='stSidebar'] { background: #FFFFFF; border-right: 1px solid #E5E7EB; }

.hero { background: linear-gradient(135deg, #312E81 0%, #4F46E5 55%, #0EA5E9 100%);
  color: #fff; padding: 28px 32px; border-radius: 18px; margin-bottom: 20px;
  box-shadow: 0 10px 30px rgba(79,70,229,.25); }
.hero h1 { color: #fff; font-size: 2rem; margin: 0 0 6px 0; padding: 0;
  font-weight: 800; letter-spacing: -.5px; }
.hero p { color: rgba(255,255,255,.88); margin: 0 0 14px 0; font-size: 1.02rem; }
.chip { display: inline-block; background: rgba(255,255,255,.16);
  border: 1px solid rgba(255,255,255,.32); padding: 4px 12px; border-radius: 999px;
  font-size: .78rem; margin-right: 8px; }

.brand { font-size: 1.15rem; font-weight: 800; color: #111827; margin-bottom: 2px; }
.brand-sub { color: #6B7280; font-size: .8rem; margin-bottom: 10px; }

div[data-testid='stMetric'] { background: #fff; border: 1px solid #E5E7EB;
  border-left: 4px solid #4F46E5; border-radius: 14px; padding: 14px 18px;
  box-shadow: 0 1px 3px rgba(16,24,40,.06); }
div[data-testid='stMetricLabel'] p { color: #6B7280; font-size: .78rem;
  font-weight: 700; text-transform: uppercase; letter-spacing: .05em; }
div[data-testid='stMetricValue'] { color: #111827; font-weight: 800; }

div[data-baseweb='tab-list'] { gap: 6px; background: #fff; padding: 6px;
  border-radius: 14px; border: 1px solid #E5E7EB; width: fit-content; }
button[data-baseweb='tab'] { border-radius: 10px; padding: 8px 18px; height: auto; }
button[data-baseweb='tab'] p { font-weight: 600; color: #4B5563; }
button[data-baseweb='tab'][aria-selected='true'] { background: #4F46E5; }
button[data-baseweb='tab'][aria-selected='true'] p { color: #fff; }
div[data-baseweb='tab-highlight'], div[data-baseweb='tab-border'] { display: none; }

.stButton > button, .stDownloadButton > button { background: #4F46E5; color: #fff;
  border: none; border-radius: 10px; font-weight: 600; padding: .5rem 1.1rem; }
.stButton > button:hover, .stDownloadButton > button:hover { background: #4338CA; color: #fff; }

div[data-testid='stDataFrame'] { border: 1px solid #E5E7EB; border-radius: 12px; overflow: hidden; }
div[data-testid='stVegaLiteChart'], div[data-testid='stArrowVegaLiteChart'] {
  background: #fff; border: 1px solid #E5E7EB; border-radius: 14px; padding: 12px;
  box-shadow: 0 1px 3px rgba(16,24,40,.05); }

.badge { color: #fff; padding: 2px 10px; border-radius: 999px; font-size: .72rem;
  font-weight: 700; letter-spacing: .03em; margin-right: 4px; }
.flag { background: #FEE2E2; color: #B91C1C; padding: 2px 10px; border-radius: 999px;
  font-size: .72rem; font-weight: 700; }

.section { margin: 22px 0 8px 0; }
.section h3 { margin: 0; padding: 0; font-size: 1.1rem; color: #111827; }
.section span { color: #6B7280; font-size: .85rem; }

.acard { background: #fff; border: 1px solid #E5E7EB; border-left: 5px solid #6B7280;
  border-radius: 12px; padding: 12px 14px; box-shadow: 0 1px 3px rgba(16,24,40,.06); }
.acard-top { font-size: .85rem; color: #374151; margin-bottom: 6px; }
.acard-title { font-size: 1.05rem; font-weight: 700; color: #111827; }
.acard-meta { color: #6B7280; font-size: .8rem; margin-top: 4px; }

.detail { background: #fff; border: 1px solid #E5E7EB; border-top: 5px solid #6B7280;
  border-radius: 14px; padding: 18px 22px; box-shadow: 0 1px 4px rgba(16,24,40,.07);
  margin: 10px 0 14px 0; }
.detail-top { font-size: .9rem; color: #374151; }
.detail h2 { margin: 6px 0 4px 0; padding: 0; font-size: 1.5rem; color: #111827; }
.detail h4 { margin: 18px 0 8px 0; color: #111827; }
.detail .meta { color: #6B7280; font-size: .88rem; margin: 0 0 14px 0; }
.facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; }
.fact { background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 10px; padding: 8px 12px; }
.fact span { display: block; color: #6B7280; font-size: .7rem; text-transform: uppercase;
  letter-spacing: .05em; font-weight: 700; }
.fact b { font-size: 1.15rem; color: #111827; }
.steps { padding-left: 1.2rem; margin: 0; }
.step { margin: 6px 0; color: #1F2937; }
.step.urgent { color: #B91C1C; font-weight: 700; }

.flow { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 8px 0 16px 0; }
.flow-box { background: #fff; border: 1px solid #C7D2FE; color: #3730A3;
  padding: 8px 14px; border-radius: 10px; font-weight: 600; font-size: .88rem; }
.flow-arrow { color: #9CA3AF; font-weight: 700; }

.footer { text-align: center; color: #9CA3AF; font-size: .8rem; margin-top: 36px; }
</style>
"""


def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)


def esc(value):
    return html.escape(str(value))


def pretty(text):
    return str(text).replace("_", " ").title()


def badge(text, color):
    return f'<span class="badge" style="background:{color}">{esc(text)}</span>'


def severity_badge(severity):
    return badge(severity, SEV_COLORS.get(severity, "#6B7280"))


def status_badge(status):
    return badge(str(status).upper(), STATUS_COLORS.get(status, "#6B7280"))


def hero(title, subtitle, pills):
    chips = "".join(f'<span class="chip">{esc(p)}</span>' for p in pills)
    st.markdown(f'<div class="hero"><h1>{esc(title)}</h1><p>{esc(subtitle)}</p>'
                f'<div>{chips}</div></div>', unsafe_allow_html=True)


def section(title, caption=""):
    cap = f"<span>{esc(caption)}</span>" if caption else ""
    st.markdown(f'<div class="section"><h3>{esc(title)}</h3>{cap}</div>',
                unsafe_allow_html=True)


def flow_html(steps):
    parts = [f'<span class="flow-box">{esc(s)}</span>' for s in steps]
    return '<div class="flow">' + '<span class="flow-arrow">&rarr;</span>'.join(parts) + "</div>"


def alert_card(a):
    color = SEV_COLORS.get(a["severity"], "#6B7280")
    flag = '<span class="flag">sign-in followed</span>' if a["success_after"] else ""
    return (
        f'<div class="acard" style="border-left-color:{color}">'
        f'<div class="acard-top"><b>{esc(a["alert_id"])}</b> '
        f'{severity_badge(a["severity"])} {status_badge(a["status"])} {flag}</div>'
        f'<div class="acard-title">{esc(pretty(a["attack_type"]))}</div>'
        f'<div class="acard-meta">{esc(a["event_count"])} events &middot; '
        f'{esc(a["distinct_ips"])} IP(s) &middot; target: {esc(a["targets"])}<br>'
        f'{esc(a["start_time"])}</div></div>')


def steps_html(text):
    items = []
    for step in str(text).split("; "):
        css = "step urgent" if step.startswith("URGENT") else "step"
        items.append(f'<li class="{css}">{esc(step)}</li>')
    return '<ol class="steps">' + "".join(items) + "</ol>"


def facts_html(facts):
    cells = "".join(f'<div class="fact"><span>{esc(k)}</span><b>{esc(v)}</b></div>'
                    for k, v in facts)
    return f'<div class="facts">{cells}</div>'


def alert_detail(a):
    color = SEV_COLORS.get(a["severity"], "#6B7280")
    facts = [("ML confidence", f"{a['confidence']}%"), ("Events", a["event_count"]),
             ("Failed events", a["failed_events"]), ("Distinct IPs", a["distinct_ips"]),
             ("Distinct users", a["distinct_users"]), ("Duration", f"{a['duration_s']} s")]
    meta = (f'Source IPs: {esc(a["source_ips"])} &middot; Targets: {esc(a["targets"])}'
            f' &middot; {esc(a["start_time"])} to {esc(a["end_time"])}'
            f' &middot; Detected by: {esc(a["detected_by"])}')
    return (
        f'<div class="detail" style="border-top-color:{color}">'
        f'<div class="detail-top">{esc(a["alert_id"])} '
        f'{severity_badge(a["severity"])} {status_badge(a["status"])}</div>'
        f'<h2>{esc(pretty(a["attack_type"]))}</h2>'
        f'<p class="meta">{meta}</p>'
        f'{facts_html(facts)}'
        f'<h4>Recommended response</h4>{steps_html(a["recommended_action"])}'
        '</div>')


# ------------------------------------------------------------------- charts
def _sev_scale():
    return alt.Scale(domain=SEV_ORDER, range=[SEV_COLORS[s] for s in SEV_ORDER])


def severity_chart(view):
    d = (view["severity"].value_counts().reindex(SEV_ORDER, fill_value=0)
         .rename_axis("severity").reset_index(name="alerts"))
    return (alt.Chart(d)
            .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6)
            .encode(x=alt.X("severity:N", sort=SEV_ORDER, title=None,
                            axis=alt.Axis(labelAngle=0)),
                    y=alt.Y("alerts:Q", title=None, axis=alt.Axis(tickMinStep=1)),
                    color=alt.Color("severity:N", scale=_sev_scale(), legend=None),
                    tooltip=["severity", "alerts"])
            .properties(height=260))


def type_chart(view):
    d = view["attack_type"].value_counts().rename_axis("attack").reset_index(name="alerts")
    d["attack"] = d["attack"].map(pretty)
    return (alt.Chart(d)
            .mark_bar(cornerRadiusEnd=6, color=INDIGO)
            .encode(y=alt.Y("attack:N", sort="-x", title=None),
                    x=alt.X("alerts:Q", title=None, axis=alt.Axis(tickMinStep=1)),
                    tooltip=["attack", "alerts"])
            .properties(height=260))


def hourly_chart(failed):
    d = failed.set_index("time").resample("1h").size().reset_index()
    d.columns = ["time", "failed"]
    return (alt.Chart(d)
            .mark_area(opacity=0.28, color=INDIGO, line={"color": INDIGO})
            .encode(x=alt.X("time:T", title=None),
                    y=alt.Y("failed:Q", title="failed events"),
                    tooltip=["time:T", "failed:Q"])
            .properties(height=260))


def timeline_chart(view):
    d = pd.DataFrame({
        "start": pd.to_datetime(view["start_time"], utc=True).to_numpy(),
        "events": view["event_count"].to_numpy(),
        "severity": view["severity"].to_numpy(),
        "attack": view["attack_type"].map(pretty).to_numpy(),
        "alert": view["alert_id"].to_numpy()})
    return (alt.Chart(d)
            .mark_circle(opacity=0.85)
            .encode(x=alt.X("start:T", title=None),
                    y=alt.Y("events:Q", title="events in alert"),
                    size=alt.Size("events:Q", legend=None,
                                  scale=alt.Scale(range=[80, 900])),
                    color=alt.Color("severity:N", scale=_sev_scale(),
                                    legend=alt.Legend(orient="top", title=None)),
                    tooltip=["alert", "attack", "severity", "events", "start:T"])
            .properties(height=300))


def ips_chart(failed):
    d = (failed.groupby("source_ip").size().sort_values(ascending=False)
         .head(10).rename("failed").reset_index())
    return (alt.Chart(d)
            .mark_bar(cornerRadiusEnd=6, color=TEAL)
            .encode(y=alt.Y("source_ip:N", sort="-x", title=None),
                    x=alt.X("failed:Q", title="failed events"),
                    tooltip=["source_ip", "failed"])
            .properties(height=300))
