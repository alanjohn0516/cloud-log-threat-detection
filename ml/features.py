# ml/features.py
# Turns raw CloudTrail events into numeric features for machine learning.
# Rules for every feature:
#   * it looks only at the PAST (a trailing time window), never the future
#   * it never uses the attack labels
import numpy as np
import pandas as pd

HIDDEN = "HIDDEN_DUE_TO_SECURITY_REASONS"
MIN, HOUR, DAY = 60, 3600, 86400

FLAG_FEATURES = ["is_console_login", "is_failure", "is_root", "is_hidden_user",
                 "is_malformed", "is_access_denied"]
VOLUME_FEATURES = ["ip_login_fail_5m", "ip_login_fail_1h",
                   "ip_role_fail_5m", "ip_role_fail_1h", "ip_malformed_1h",
                   "ip_distinct_users_fail_5m", "ip_distinct_users_fail_1h",
                   "user_fail_1h", "user_fail_6h", "user_distinct_ips_fail_6h"]
HISTORY_FEATURES = ["ip_prior_success", "pair_prior_success", "baseline_age_days"]

FEATURES_FULL = FLAG_FEATURES + VOLUME_FEATURES + HISTORY_FEATURES
FEATURES_NO_HISTORY = FLAG_FEATURES + VOLUME_FEATURES


def _groups(keys):
    """Row numbers of each group, e.g. {'1.2.3.4': array([0, 5, 9]), ...}.
    Rows are already sorted by time, so every group is time-ordered too."""
    keys = np.asarray(keys).astype(str)
    return pd.Series(np.arange(len(keys))).groupby(keys, sort=False).indices


def trailing_count(t, groups, mask, window):
    """For every event: how many 'counted' events (mask=True) of the same group
    happened in the last `window` seconds (including this moment)."""
    out = np.zeros(len(t))
    for idx in groups.values():
        tg = t[idx]
        counted = tg[mask[idx]]
        out[idx] = (np.searchsorted(counted, tg, side="right")
                    - np.searchsorted(counted, tg - window, side="right"))
    return out


def trailing_distinct(t, groups, values, mask, window):
    """Like trailing_count, but counts DISTINCT values (e.g. different users)."""
    out = np.zeros(len(t))
    for idx in groups.values():
        tg, vg = t[idx], values[idx]
        pick = np.flatnonzero(mask[idx])
        ct, cv = tg[pick], vg[pick]
        seen, lo, hi = {}, 0, 0
        for k in range(len(idx)):
            while hi < len(ct) and ct[hi] <= tg[k]:          # add new events
                seen[cv[hi]] = seen.get(cv[hi], 0) + 1
                hi += 1
            while lo < hi and ct[lo] <= tg[k] - window:      # drop old events
                seen[cv[lo]] -= 1
                if seen[cv[lo]] == 0:
                    del seen[cv[lo]]
                lo += 1
            out[idx[k]] = len(seen)
    return out


def prior_count(groups, mask, n):
    """For every event: how many 'counted' events of its group came BEFORE it."""
    out = np.zeros(n)
    for idx in groups.values():
        m = mask[idx].astype(float)
        out[idx] = np.cumsum(m) - m
    return out


def build_features(df):
    """Return the events (sorted by time) with one extra column per feature."""
    d = df.sort_values("event_time", kind="stable").reset_index(drop=True)
    n = len(d)
    if n == 0:
        raise ValueError("no events")
    t = ((pd.to_datetime(d["event_time"], utc=True)
          - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds().to_numpy())
    users = d["user_name"].astype(str).to_numpy()
    ips = d["source_ip"].astype(str).to_numpy()
    pairs = (d["user_name"].astype(str) + "|" + d["source_ip"].astype(str)).to_numpy()
    errors = d["error_code"].fillna("").astype(str)

    login = (d["event_name"] == "ConsoleLogin").to_numpy()
    role = (d["event_name"] == "AssumeRole").to_numpy()
    fail = (d["outcome"] == "Failure").to_numpy()
    success = (d["outcome"] == "Success").to_numpy()
    malformed = (errors == "MalformedPolicyDocumentException").to_numpy()

    by_ip, by_user, by_pair = _groups(ips), _groups(users), _groups(pairs)

    f = pd.DataFrame(index=d.index)
    f["is_console_login"] = login.astype(int)
    f["is_failure"] = fail.astype(int)
    f["is_root"] = (d["user_type"] == "Root").astype(int)
    f["is_hidden_user"] = (d["user_name"] == HIDDEN).astype(int)
    f["is_malformed"] = malformed.astype(int)
    f["is_access_denied"] = (errors == "AccessDenied").astype(int)

    f["ip_login_fail_5m"] = trailing_count(t, by_ip, login & fail, 5 * MIN)
    f["ip_login_fail_1h"] = trailing_count(t, by_ip, login & fail, HOUR)
    f["ip_role_fail_5m"] = trailing_count(t, by_ip, role & fail, 5 * MIN)
    f["ip_role_fail_1h"] = trailing_count(t, by_ip, role & fail, HOUR)
    f["ip_malformed_1h"] = trailing_count(t, by_ip, malformed, HOUR)
    f["ip_distinct_users_fail_5m"] = trailing_distinct(t, by_ip, users, fail, 5 * MIN)
    f["ip_distinct_users_fail_1h"] = trailing_distinct(t, by_ip, users, fail, HOUR)
    f["user_fail_1h"] = trailing_count(t, by_user, fail, HOUR)
    f["user_fail_6h"] = trailing_count(t, by_user, fail, 6 * HOUR)
    f["user_distinct_ips_fail_6h"] = trailing_distinct(t, by_user, ips, fail, 6 * HOUR)

    f["ip_prior_success"] = prior_count(by_ip, success, n)
    f["pair_prior_success"] = prior_count(by_pair, success, n)
    f["baseline_age_days"] = np.minimum((t - t.min()) / DAY, 7.0)
    return pd.concat([d, f], axis=1)
