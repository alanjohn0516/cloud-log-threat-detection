# scripts/make_diagrams.py
# Draws the architecture diagram, detection flowchart and database diagram.
# Run from the project root:  python scripts/make_diagrams.py
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = "docs/figures"
INDIGO, TEAL, GREEN, ORANGE, RED, GREY = (
    "#4F46E5", "#0EA5E9", "#16A34A", "#F97316", "#DC2626", "#6B7280")


def box(ax, x, y, w, h, text, color, size=9, fill=True):
    patch = FancyBboxPatch((x - w / 2, y - h / 2), w, h,
                           boxstyle="round,pad=0.02,rounding_size=0.15",
                           fc=color if fill else "white", ec=color, lw=1.6)
    ax.add_patch(patch)
    ax.text(x, y, text, ha="center", va="center", fontsize=size,
            color="white" if fill else "#111827", fontweight="bold", wrap=True)


def arrow(ax, x1, y1, x2, y2, label=None):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>",
                                 mutation_scale=14, color="#374151", lw=1.4))
    if label:
        ax.text((x1 + x2) / 2 + 0.1, (y1 + y2) / 2, label, fontsize=7.5,
                color="#374151", va="center")


def canvas(w, h, title):
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, w)
    ax.set_ylim(0, h)
    ax.axis("off")
    ax.set_title(title, fontsize=13, fontweight="bold", pad=12)
    return fig, ax


def architecture():
    fig, ax = canvas(11, 8, "System architecture: cloud log threat detection")
    ax.text(5.5, 7.35, "CLOUD MODULE", fontsize=9, color=TEAL, fontweight="bold", ha="center")
    box(ax, 2.2, 6.6, 3.0, 0.8, "AWS CloudTrail logs\n(ConsoleLogin, AssumeRole)", TEAL)
    box(ax, 5.5, 6.6, 2.2, 0.8, "FastAPI\nPOST /logs", TEAL)
    box(ax, 8.6, 6.6, 3.0, 0.8, "SQLite log database\n(events table)", TEAL)
    arrow(ax, 3.7, 6.6, 4.4, 6.6)
    arrow(ax, 6.6, 6.6, 7.1, 6.6)

    ax.text(5.5, 5.45, "AI / ML MODULE", fontsize=9, color=INDIGO, fontweight="bold", ha="center")
    box(ax, 3.2, 4.7, 3.4, 0.8, "Feature engineering\n(per-IP and per-user windows)", INDIGO)
    box(ax, 7.6, 4.7, 3.4, 0.8, "Random Forest model\n+ threshold rules R1-R3", INDIGO)
    arrow(ax, 8.6, 6.2, 3.8, 5.1, "events")
    arrow(ax, 4.9, 4.7, 5.9, 4.7)

    ax.text(5.5, 3.55, "CYBERSECURITY MODULE", fontsize=9, color=ORANGE, fontweight="bold", ha="center")
    box(ax, 2.6, 2.8, 2.9, 0.8, "Incident grouping\n(same IP or user, 1 h)", ORANGE)
    box(ax, 5.5, 2.8, 2.5, 0.8, "Attack type +\nseverity", ORANGE)
    box(ax, 8.4, 2.8, 2.9, 0.8, "Recommended\nresponse", ORANGE)
    arrow(ax, 7.6, 4.3, 3.4, 3.2, "flagged events")
    arrow(ax, 4.05, 2.8, 4.25, 2.8)
    arrow(ax, 6.75, 2.8, 6.95, 2.8)

    box(ax, 3.5, 1.15, 3.2, 0.8, "Alerts table (SQLite)\nGET /alerts", GREEN)
    box(ax, 7.5, 1.15, 3.6, 0.8, "Security dashboard\n(Streamlit)", GREEN)
    arrow(ax, 7.4, 2.4, 4.3, 1.55)
    arrow(ax, 5.1, 1.15, 5.7, 1.15)
    fig.savefig(f"{OUT}/architecture.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def flowchart():
    fig, ax = canvas(8, 11, "Detection workflow")
    steps = [
        ("Log event arrives\n(ConsoleLogin or AssumeRole)", TEAL),
        ("Store in SQLite\n(duplicates ignored)", TEAL),
        ("Build features\n(failure counts, distinct users, IP history)", INDIGO),
        ("Random Forest scores the event\nand rules R1-R3 are checked", INDIGO),
    ]
    y = 10.0
    for i, (text, color) in enumerate(steps):
        box(ax, 4, y, 5.6, 0.85, text, color)
        if i:
            arrow(ax, 4, y + 1.2, 4, y + 0.43)
        y -= 1.3
    # decision diamond
    ax.add_patch(plt.Polygon([[4, 4.2], [5.7, 3.4], [4, 2.6], [2.3, 3.4]],
                             closed=True, fc="white", ec=ORANGE, lw=1.8))
    ax.text(4, 3.4, "Score above\nthreshold?", ha="center", va="center",
            fontsize=9, fontweight="bold")
    arrow(ax, 4, 5.9 - 0.45 + 0.45 - 0.0, 4, 4.2)
    box(ax, 7.2, 3.4, 1.9, 0.7, "Normal:\nno alert", GREEN, size=8)
    arrow(ax, 5.7, 3.4, 6.25, 3.4, "no")
    box(ax, 4, 1.7, 5.6, 0.85, "Group flagged events into incidents\n(same IP or user within 1 hour)", ORANGE)
    arrow(ax, 4, 2.6, 4, 2.13, "yes")
    box(ax, 4, 0.5, 5.6, 0.85, "Classify attack, set severity, add response\nsave alert, show on dashboard", RED)
    arrow(ax, 4, 1.27, 4, 0.93)
    fig.savefig(f"{OUT}/flowchart.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def severity_flow():
    fig, ax = canvas(10, 5.2, "Severity decision logic")
    box(ax, 2.0, 4.2, 3.2, 0.8, "Incident detected", INDIGO)
    ax.add_patch(plt.Polygon([[5.6, 4.7], [7.3, 4.2], [5.6, 3.7], [3.9, 4.2]],
                             closed=True, fc="white", ec=ORANGE, lw=1.8))
    ax.text(5.6, 4.2, "Sign-in after\nattack?", ha="center", va="center", fontsize=8.5, fontweight="bold")
    arrow(ax, 3.6, 4.2, 3.9, 4.2)
    ax.add_patch(plt.Polygon([[8.7, 4.7], [9.8, 4.2], [8.7, 3.7], [7.6, 4.2]],
                             closed=True, fc="white", ec=ORANGE, lw=1.8))
    ax.text(8.7, 4.2, "Admin or\nroot?", ha="center", va="center", fontsize=8, fontweight="bold")
    arrow(ax, 7.3, 4.2, 7.6, 4.2, "yes")
    box(ax, 8.7, 2.6, 2.4, 0.7, "CRITICAL", RED)
    arrow(ax, 8.7, 3.7, 8.7, 2.95, "yes")
    box(ax, 5.6, 2.0, 3.6, 0.7, "HIGH if 100+ failures,\nprivileged target or sign-in", ORANGE, size=8)
    arrow(ax, 5.6, 3.7, 5.6, 2.35, "no")
    arrow(ax, 8.2, 3.7, 6.5, 2.35, "no")
    box(ax, 2.0, 0.7, 3.2, 0.7, "MEDIUM otherwise", "#EAB308")
    arrow(ax, 4.3, 1.7, 2.9, 1.05, "no")
    fig.savefig(f"{OUT}/severity_flow.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def database_diagram():
    fig, ax = canvas(11, 6.5, "Database design (SQLite)")
    events = ["event_id  (primary key)", "event_time", "event_name", "source_ip",
              "user_type", "user_name", "outcome", "error_code", "mfa_used",
              "user_agent", "role_arn", "is_attack (ground truth)", "attack_type",
              "attack_id", "scenario"]
    alerts = ["alert_id  (primary key)", "attack_type", "severity", "confidence",
              "start_time", "end_time", "duration_s", "event_count",
              "failed_events", "distinct_users", "distinct_ips", "source_ips",
              "targets", "success_after", "detected_by", "rules_agree",
              "recommended_action", "status", "event_ids (JSON list)"]

    def table(x, title, fields, color):
        h = 0.32 * len(fields) + 0.6
        ax.add_patch(FancyBboxPatch((x, 5.6 - h), 4.0, h, boxstyle="round,pad=0.02",
                                    fc="white", ec=color, lw=2))
        ax.add_patch(FancyBboxPatch((x, 5.6 - 0.5), 4.0, 0.5, boxstyle="round,pad=0.02",
                                    fc=color, ec=color))
        ax.text(x + 2.0, 5.35, title, ha="center", va="center", color="white",
                fontweight="bold", fontsize=10)
        for i, f in enumerate(fields):
            ax.text(x + 0.2, 4.9 - i * 0.32, f, fontsize=8, va="center",
                    fontweight="bold" if "primary" in f else "normal")

    table(0.5, "events", events, TEAL)
    table(6.3, "alerts", alerts, INDIGO)
    ax.annotate("", xy=(6.3, 3.2), xytext=(4.5, 3.2),
                arrowprops=dict(arrowstyle="<|-|>", color=GREY, lw=1.5, ls="--"))
    ax.text(5.4, 3.4, "alerts.event_ids\nlist events.event_id", ha="center",
            fontsize=7.5, color=GREY)
    fig.savefig(f"{OUT}/database_design.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    architecture()
    flowchart()
    severity_flow()
    database_diagram()
    print("Saved architecture.png, flowchart.png, severity_flow.png, database_design.png in", OUT)
