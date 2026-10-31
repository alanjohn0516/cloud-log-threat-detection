# security/rules.py
# Cybersecurity rule engine: threshold rules (from the literature review),
# threat classification, severity levels and recommended responses.
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

import numpy as np
import pandas as pd

HIDDEN = "HIDDEN_DUE_TO_SECURITY_REASONS"   # CloudTrail hides unknown usernames
SUCCESS_LOOKAHEAD = 1800                    # seconds: look for a success after an attack
PRIVILEGED_USERS = {"root", "admin"}


# ------------------------------------------------------------------ rules
@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    source: str                              # where the rule comes from
    threshold: int                           # number of matching events
    window_seconds: int                      # ... inside this time window
    group_by: Optional[str]                  # column to group by (None = whole account)
    selector: Callable[[pd.DataFrame], pd.Series]   # which events count
    success_event: str                       # event type that means "the attacker got in"


def _failed_root_login(df):
    return ((df["event_name"] == "ConsoleLogin") & (df["outcome"] == "Failure")
            & (df["user_type"] == "Root"))


def _failed_console_login(df):
    return (df["event_name"] == "ConsoleLogin") & (df["outcome"] == "Failure")


def _malformed_assume_role(df):
    return ((df["event_name"] == "AssumeRole")
            & (df["error_code"] == "MalformedPolicyDocumentException"))


RULES = [
    Rule("R1", "Failed root console logins", "Elastic detection rule",
         10, 20 * 60, None, _failed_root_login, "ConsoleLogin"),
    Rule("R2", "Failed console logins from one IP", "Sigma / Splunk rule",
         20, 5 * 60, "source_ip", _failed_console_login, "ConsoleLogin"),
    Rule("R3", "AssumeRole role-name guessing", "Splunk Security Content",
         3, 60 * 60, "source_ip", _malformed_assume_role, "AssumeRole"),
]

RESPONSES = {
    "password_guessing": [
        "Temporarily lock or rate-limit the targeted account",
        "Block the source IP",
        "Notify the administrator",
        "Enforce MFA on the account"],
    "password_spraying": [
        "Block the source IP",
        "Reset passwords of targeted accounts that show a success",
        "Enforce MFA for all users",
        "Review the list of targeted accounts"],
    "credential_stuffing": [
        "Block the source IP",
        "Enforce MFA for all users",
        "Check whether leaked credentials are reused here",
        "Rate-limit failed sign-ins"],
    "role_enumeration": [
        "Block the source IP",
        "Rotate the credentials of the calling user",
        "Review IAM role trust policies",
        "Review other CloudTrail activity by this identity"],
    "root_brute_force": [
        "Notify the account owner immediately",
        "Block the source IP",
        "Enable MFA on the root account",
        "Review recent root activity"],
}

ALERT_COLUMNS = ["alert_id", "rule_id", "rule_name", "source", "group", "attack_type",
                 "severity", "start_time", "end_time", "duration_s", "event_count",
                 "distinct_users", "distinct_ips", "targets", "success_after",
                 "recommended_action", "event_ids"]


# --------------------------------------------------------- core algorithms
def to_seconds(series):
    """ISO time strings -> seconds since 1970 (independent of pandas time units)."""
    ts = pd.to_datetime(series, utc=True)
    return (ts - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()


def sliding_window_flags(times, threshold, window_seconds):
    """times: sorted array of seconds. Marks every event that belongs to a
    window of length `window_seconds` containing at least `threshold` events."""
    n = len(times)
    flagged = np.zeros(n, dtype=bool)
    i = 0
    for j in range(n):
        while times[j] - times[i] > window_seconds:
            i += 1
        if j - i + 1 >= threshold:
            flagged[i:j + 1] = True
    return flagged


def split_episodes(times, flagged, window_seconds):
    """Group flagged events into separate attack episodes (one alert each)."""
    idx = np.flatnonzero(flagged)
    if len(idx) == 0:
        return []
    episodes, current = [], [int(idx[0])]
    for k in idx[1:]:
        if times[k] - times[current[-1]] > window_seconds:
            episodes.append(current)
            current = [int(k)]
        else:
            current.append(int(k))
    episodes.append(current)
    return episodes


# ---------------------------------------------------- cybersecurity logic
def classify(rule, ep):
    """Decide what kind of attack an episode looks like."""
    if rule.rule_id == "R3":
        return "role_enumeration"
    if rule.rule_id == "R1" or (ep["user_type"] == "Root").all():
        return "root_brute_force"
    users = ep["user_name"]
    if (users == HIDDEN).mean() >= 0.5:
        return "credential_stuffing"
    if users.nunique() >= 5:
        return "password_spraying"
    return "password_guessing"


def severity_of(attack_type, count, privileged, success_after):
    if success_after and privileged:
        return "CRITICAL"
    if attack_type == "role_enumeration" and success_after:
        return "HIGH"
    if count >= 100 or privileged or attack_type == "root_brute_force":
        return "HIGH"
    return "MEDIUM"


def recommend(attack_type, success_after):
    actions = list(RESPONSES[attack_type])
    if success_after:
        actions.insert(0, "URGENT: a successful sign-in followed - revoke active "
                          "sessions and rotate credentials")
    return "; ".join(actions)


def _fmt(seconds):
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_alert(rule, key, ep, success_tables):
    start, end = float(ep["t"].min()), float(ep["t"].max())
    users, ips = set(ep["user_name"]), set(ep["source_ip"])
    attack_type = classify(rule, ep)
    privileged = bool(PRIVILEGED_USERS & users)

    succ = success_tables[rule.success_event]
    hit = succ[succ["source_ip"].isin(ips)
               & (succ["t"] >= start) & (succ["t"] <= end + SUCCESS_LOOKAHEAD)]
    success_after = len(hit) > 0

    return {
        "alert_id": None,
        "rule_id": rule.rule_id,
        "rule_name": rule.name,
        "source": rule.source,
        "group": str(key),
        "attack_type": attack_type,
        "severity": severity_of(attack_type, len(ep), privileged, success_after),
        "start_time": _fmt(start),
        "end_time": _fmt(end),
        "duration_s": int(end - start),
        "event_count": int(len(ep)),
        "distinct_users": int(len(users)),
        "distinct_ips": int(len(ips)),
        "targets": ", ".join(sorted(users)[:3]),
        "success_after": success_after,
        "recommended_action": recommend(attack_type, success_after),
        "event_ids": ep["event_id"].tolist(),
    }


def run_rules(df, rules=None):
    """Run every rule over the events and return a DataFrame of alerts."""
    rules = rules or RULES
    df = df.copy()
    df["t"] = to_seconds(df["event_time"])
    df = df.sort_values("t", kind="stable").reset_index(drop=True)

    success_tables = {
        name: df[(df["event_name"] == name) & (df["outcome"] == "Success")]
        for name in ("ConsoleLogin", "AssumeRole")
    }

    alerts = []
    for rule in rules:
        selected = df[rule.selector(df)]
        if selected.empty:
            continue
        if rule.group_by is None:
            groups = [("account", selected)]
        else:
            groups = list(selected.groupby(rule.group_by))
        for key, grp in groups:
            grp = grp.sort_values("t", kind="stable")
            times = grp["t"].to_numpy()
            flagged = sliding_window_flags(times, rule.threshold, rule.window_seconds)
            for ep_idx in split_episodes(times, flagged, rule.window_seconds):
                ep = grp.iloc[ep_idx]
                alerts.append(_make_alert(rule, key, ep, success_tables))

    if not alerts:
        return pd.DataFrame(columns=ALERT_COLUMNS)
    out = pd.DataFrame(alerts).sort_values("start_time").reset_index(drop=True)
    out["alert_id"] = [f"ALERT-{i + 1:04d}" for i in range(len(out))]
    return out[ALERT_COLUMNS]
