# security/pipeline.py
# The integrated detection pipeline:
#   cloud database -> features -> ML model (+ rule engine) -> incidents
#   -> cybersecurity engine (attack type, severity, response) -> alerts
import os
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd

from ml.experiment import rule_flags
from ml.features import build_features
from security.rules import (HIDDEN, PRIVILEGED_USERS, RESPONSES,
                            SUCCESS_LOOKAHEAD, severity_of, to_seconds)

DEFAULT_MODEL = "ml/saved/random_forest.joblib"
POLICIES = ("rules", "ml", "union")
GAP_SECONDS = 3600          # flagged events within 1 hour of each other can be one incident
MIN_INCIDENT_EVENTS = 3     # smaller incidents are treated as noise
SKIP_USERS = {HIDDEN, "", "nan", "None"}   # usernames that must not link events together

RESPONSE_PLAYBOOK = dict(RESPONSES)
RESPONSE_PLAYBOOK["distributed_brute_force"] = [
    "Block all participating source IPs (or the whole range)",
    "Lock or rate-limit the targeted account",
    "Enforce MFA on the targeted account",
    "Notify the administrator"]

ALERT_COLUMNS = ["alert_id", "attack_type", "severity", "confidence", "start_time",
                 "end_time", "duration_s", "event_count", "failed_events",
                 "distinct_users", "distinct_ips", "source_ips", "targets",
                 "success_after", "detected_by", "rules_agree",
                 "recommended_action", "event_ids"]


def load_model(path=None):
    """Load a trained model saved by ml/train.py. Returns (model, feature_names)."""
    path = path or DEFAULT_MODEL
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found. Run: python -m ml.train")
    bundle = joblib.load(path)
    return bundle["model"], bundle["features"]


def group_incidents(flagged, gap=GAP_SECONDS):
    """Give every flagged event an incident number. Two events belong together
    when they share a source IP or a username and are at most `gap` seconds
    apart. `flagged` must be sorted by time and have columns t, source_ip, user_name."""
    n = len(flagged)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    t = flagged["t"].to_numpy()
    for col in ("source_ip", "user_name"):
        last = {}
        for i, key in enumerate(flagged[col].astype(str).to_numpy()):
            if col == "user_name" and key in SKIP_USERS:
                continue
            if key in last and t[i] - t[last[key]] <= gap:
                ra, rb = find(i), find(last[key])
                if ra != rb:
                    parent[rb] = ra
            last[key] = i
    return np.array([find(i) for i in range(n)])


def classify_incident(ep):
    """Cybersecurity decision: what kind of attack does this incident look like?"""
    fails = ep[ep["outcome"] == "Failure"]
    base = fails if len(fails) else ep
    if ((base["error_code"] == "MalformedPolicyDocumentException").any()
            or (base["event_name"] == "AssumeRole").mean() >= 0.5):
        return "role_enumeration"
    if (base["user_type"] == "Root").all():
        return "root_brute_force"
    if (base["user_name"] == HIDDEN).mean() >= 0.5:
        return "credential_stuffing"
    if base["user_name"].nunique() >= 5:
        return "password_spraying"
    if base["source_ip"].nunique() >= 3:
        return "distributed_brute_force"
    return "password_guessing"


def severity_for(attack_type, failed_count, privileged, success_after):
    """Step 5 severity logic, plus: a successful sign-in after an attack is at least HIGH."""
    level = severity_of(attack_type, failed_count, privileged, success_after)
    if success_after and level == "MEDIUM":
        level = "HIGH"
    return level


def recommend(attack_type, success_after):
    actions = list(RESPONSE_PLAYBOOK[attack_type])
    if success_after:
        actions.insert(0, "URGENT: a successful sign-in followed - revoke active "
                          "sessions and rotate credentials")
    return "; ".join(actions)


def _fmt(seconds):
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _short(values, limit=3):
    values = sorted(set(values))
    text = ", ".join(values[:limit])
    return text + (f" (+{len(values) - limit} more)" if len(values) > limit else "")


def _make_alert(ep, successes):
    start, end = float(ep["t"].min()), float(ep["t"].max())
    fails = ep[ep["outcome"] == "Failure"]
    base = fails if len(fails) else ep
    ips = set(ep["source_ip"])
    attack_type = classify_incident(ep)
    privileged = bool(PRIVILEGED_USERS & set(base["user_name"]))

    later = successes[successes["source_ip"].isin(ips)
                      & (successes["t"] >= start)
                      & (successes["t"] <= end + SUCCESS_LOOKAHEAD)]
    success_after = len(later) > 0

    ml_share = float(ep["ml_flag"].mean())
    rule_share = float(ep["rule_flag"].mean())
    if ml_share > 0 and rule_share > 0:
        detected_by = "ML + Rules"
    elif ml_share > 0:
        detected_by = "ML only"
    else:
        detected_by = "Rules only"

    return {
        "alert_id": None,
        "attack_type": attack_type,
        "severity": severity_for(attack_type, len(base), privileged, success_after),
        "confidence": round(100 * float(ep["ml_score"].mean()), 1),
        "start_time": _fmt(start),
        "end_time": _fmt(end),
        "duration_s": int(end - start),
        "event_count": int(len(ep)),
        "failed_events": int(len(fails)),
        "distinct_users": int(base["user_name"].nunique()),
        "distinct_ips": int(len(ips)),
        "source_ips": _short(ips),
        "targets": _short([u for u in base["user_name"] if u != HIDDEN])
                   or "(unknown usernames)",
        "success_after": bool(success_after),
        "detected_by": detected_by,
        "rules_agree": round(rule_share, 2),
        "recommended_action": recommend(attack_type, success_after),
        "event_ids": ep["event_id"].tolist(),
    }


def build_incidents(feats, gap=GAP_SECONDS, min_events=MIN_INCIDENT_EVENTS):
    """Turn flagged events into alerts (one alert per incident)."""
    flagged = (feats[feats["flagged"]].sort_values("t", kind="stable")
               .reset_index(drop=True))
    if flagged.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)
    flagged["incident"] = group_incidents(flagged, gap)
    successes = feats[feats["outcome"] == "Success"][["source_ip", "t"]]

    rows = []
    for _, ep in flagged.groupby("incident"):
        if len(ep) >= min_events:
            rows.append(_make_alert(ep, successes))
    if not rows:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    out = pd.DataFrame(rows).sort_values("start_time", kind="stable").reset_index(drop=True)
    out["alert_id"] = [f"ALERT-{i + 1:04d}" for i in range(len(out))]
    return out[ALERT_COLUMNS]


def detect(events_df, policy="ml", threshold=0.5, model_path=None,
           model_bundle=None, gap=GAP_SECONDS, min_events=MIN_INCIDENT_EVENTS):
    """Run the whole pipeline on a table of events.
    Returns (alerts, scored_events). scored_events has extra columns:
    ml_score, ml_flag, rule_flag, flagged, alerted."""
    if policy not in POLICIES:
        raise ValueError(f"policy must be one of {POLICIES}")
    model, cols = (model_bundle if model_bundle is not None
                   else load_model(model_path or DEFAULT_MODEL))

    feats = build_features(events_df)
    feats["t"] = to_seconds(feats["event_time"])
    feats["ml_score"] = model.predict_proba(feats[cols])[:, 1]
    feats["ml_flag"] = feats["ml_score"] >= threshold
    feats["rule_flag"] = rule_flags(feats)
    if policy == "ml":
        feats["flagged"] = feats["ml_flag"]
    elif policy == "rules":
        feats["flagged"] = feats["rule_flag"]
    else:
        feats["flagged"] = feats["ml_flag"] | feats["rule_flag"]

    alerts = build_incidents(feats, gap, min_events)
    in_alert = set()
    for ids in alerts["event_ids"]:
        in_alert.update(ids)
    feats["alerted"] = feats["event_id"].isin(in_alert)
    return alerts, feats
