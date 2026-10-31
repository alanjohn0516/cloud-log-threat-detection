# cloud/generate_logs.py
# Generates synthetic AWS CloudTrail logs (ConsoleLogin + AssumeRole) with
# labelled brute force attacks mixed into normal activity.
#
# Run:  python cloud/generate_logs.py
# Output: data/cloudtrail_logs.json    (CloudTrail format, no labels)
#         data/cloudtrail_labeled.csv  (flat table with labels)

import argparse
import json
import os
import random
import uuid
from datetime import datetime, timedelta

import pandas as pd

# ---------------------------------------------------------------- constants
ACCOUNT_ID = "123456789012"
REGION = "us-east-1"
OFFICE_IP = "203.0.113.10"      # one shared public IP for the office (NAT)
BOT_IP = "198.51.100.7"         # CI/CD bot
BOT_UA = "aws-sdk-go/1.44.0"

NAMES = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
         "ivan", "judy", "karl", "laura", "mike", "nina", "oscar", "peggy",
         "quinn", "rita", "sam", "tina", "uma", "victor", "wendy", "xavier",
         "yara"]
NUM_USERS = 60                  # plus one extra user called "admin"

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
ATTACKER_UAS = ["python-requests/2.31.0", "curl/8.4.0", "Go-http-client/2.0"]

NORMAL_ROLES = ["DevRole", "ReadOnlyRole", "DataAnalystRole",
                "DeployRole", "AuditRole", "BackupRole"]

_WORDS = ["Admin", "Administrator", "PowerUser", "DevOps", "SuperAdmin",
          "Security", "Billing", "S3Admin", "EC2Admin", "Lambda", "Developer",
          "Owner", "Support", "Ops", "Prod", "Root", "Audit", "Backup",
          "Network", "Database"]
ENUM_ROLES = [w + s for w in _WORDS for s in ("Role", "Access")]  # 40 guesses

# How many of each attack to inject
ATTACK_PLAN = {
    "password_guessing": 3,
    "password_spraying": 3,
    "credential_stuffing": 3,
    "low_and_slow": 2,
    "role_enumeration": 3,
    "root_brute_force": 2,
}


# ------------------------------------------------- CloudTrail record builders
def new_id(rng):
    """Reproducible unique event ID."""
    return str(uuid.UUID(int=rng.getrandbits(128)))


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def iam_identity(name):
    return {
        "type": "IAMUser",
        "principalId": "AIDAEXAMPLE" + name.upper().replace("-", ""),
        "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/{name}",
        "accountId": ACCOUNT_ID,
        "userName": name,
    }


def console_login(rng, t, who, ip, ua, success, mfa="No"):
    """who = 'root', an IAM user name, or None (a username that does not exist).
    Real CloudTrail hides names of non-existent users, so we do the same."""
    if who == "root":
        identity = {"type": "Root", "principalId": ACCOUNT_ID,
                    "arn": f"arn:aws:iam::{ACCOUNT_ID}:root",
                    "accountId": ACCOUNT_ID}
    elif who is None:
        identity = {"type": "IAMUser",
                    "principalId": "HIDDEN_DUE_TO_SECURITY_REASONS",
                    "accountId": ACCOUNT_ID,
                    "userName": "HIDDEN_DUE_TO_SECURITY_REASONS"}
    else:
        identity = iam_identity(who)

    rec = {
        "eventVersion": "1.08",
        "userIdentity": identity,
        "eventTime": iso(t),
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": REGION,
        "sourceIPAddress": ip,
        "userAgent": ua,
        "requestParameters": None,
        "responseElements": {"ConsoleLogin": "Success" if success else "Failure"},
        "additionalEventData": {
            "LoginTo": f"https://console.aws.amazon.com/console/home?region={REGION}",
            "MobileVersion": "No",
            "MFAUsed": mfa,
        },
        "eventID": new_id(rng),
        "eventType": "AwsConsoleSignIn",
        "recipientAccountId": ACCOUNT_ID,
    }
    if not success:
        rec["errorMessage"] = "Failed authentication"
    return rec


def assume_role(rng, t, name, ip, ua, role, error=None):
    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/{role}"
    rec = {
        "eventVersion": "1.08",
        "userIdentity": iam_identity(name),
        "eventTime": iso(t),
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": REGION,
        "sourceIPAddress": ip,
        "userAgent": ua,
        "requestParameters": {"roleArn": role_arn,
                              "roleSessionName": f"{name}-session"},
        "responseElements": None if error else {"credentials": {"accessKeyId": "ASIAEXAMPLE"}},
        "eventID": new_id(rng),
        "eventType": "AwsApiCall",
        "recipientAccountId": ACCOUNT_ID,
    }
    if error == "AccessDenied":
        rec["errorCode"] = "AccessDenied"
        rec["errorMessage"] = (f"User: arn:aws:iam::{ACCOUNT_ID}:user/{name} is not "
                               f"authorized to perform: sts:AssumeRole on resource: {role_arn}")
    elif error == "MalformedPolicyDocumentException":
        rec["errorCode"] = "MalformedPolicyDocumentException"
        rec["errorMessage"] = "Syntax errors in policy."
    return rec


def flatten(rec, label):
    """Turn one CloudTrail record + its label into one flat table row."""
    ident = rec["userIdentity"]
    if rec["eventName"] == "ConsoleLogin":
        outcome = rec["responseElements"]["ConsoleLogin"]
        mfa = rec["additionalEventData"]["MFAUsed"]
        role_arn = ""
    else:
        outcome = "Failure" if "errorCode" in rec else "Success"
        mfa = ""
        role_arn = rec["requestParameters"]["roleArn"]
    return {
        "event_id": rec["eventID"],
        "event_time": rec["eventTime"],
        "event_name": rec["eventName"],
        "source_ip": rec["sourceIPAddress"],
        "user_type": ident["type"],
        "user_name": ident.get("userName", "root"),
        "outcome": outcome,
        "error_code": rec.get("errorCode", ""),
        "mfa_used": mfa,
        "user_agent": rec["userAgent"],
        "role_arn": role_arn,
        "is_attack": label["attack_type"] != "normal",
        "attack_type": label["attack_type"],
        "attack_id": label["attack_id"],
        "scenario": label["scenario"],
    }


# ------------------------------------------------------------- the generator
class Generator:
    def __init__(self, seed=42, days=30, start=None):
        self.rng = random.Random(seed)
        self.days = days
        self.start = start or datetime(2026, 9, 1)
        self.events = []        # list of (cloudtrail_record, label_dict)
        self.counters = {}
        self.users = self._make_users()

    # ---- small helpers
    def rand_ip(self):
        while True:
            a = self.rng.randint(11, 223)
            if a not in (100, 127, 169, 172, 192, 198, 203):
                break
        return f"{a}.{self.rng.randint(0, 255)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"

    def _make_users(self):
        names = NAMES + [f"user{i:02d}" for i in range(len(NAMES) + 1, NUM_USERS + 1)] + ["admin"]
        users = []
        for i, name in enumerate(names):
            users.append({
                "name": name,
                "ip": OFFICE_IP if i < 35 else self.rand_ip(),   # first 35 work in the office
                "ua": self.rng.choice(BROWSERS),
                "mfa": name != "admin" and self.rng.random() < 0.9,  # admin has no MFA
            })
        return users

    def random_start(self):
        usable = self.days * 24 * 3600 - 14 * 3600   # leave room for long attacks
        return self.start + timedelta(seconds=self.rng.randint(0, usable))

    def attacker_ua(self):
        return self.rng.choice(ATTACKER_UAS + BROWSERS)

    def next_id(self, kind):
        self.counters[kind] = self.counters.get(kind, 0) + 1
        return f"{kind}-{self.counters[kind]:02d}"

    def label(self, kind):
        return {"attack_type": kind, "scenario": kind, "attack_id": self.next_id(kind)}

    def emit(self, rec, attack_type="normal", scenario="routine", attack_id=""):
        self.events.append((rec, {"attack_type": attack_type,
                                  "scenario": scenario,
                                  "attack_id": attack_id}))

    def login(self, t, who, ip, ua, success, mfa="No", **label):
        self.emit(console_login(self.rng, t, who, ip, ua, success, mfa), **label)

    def role(self, t, name, ip, ua, role, error=None, **label):
        self.emit(assume_role(self.rng, t, name, ip, ua, role, error), **label)

    # ---- normal traffic
    def normal_traffic(self):
        rng = self.rng
        for day in range(self.days):
            date = self.start + timedelta(days=day)
            weekend = date.weekday() >= 5
            for u in self.users:
                if rng.random() > (0.15 if weekend else 0.85):
                    continue
                for _ in range(rng.randint(1, 2)):
                    t = date + timedelta(hours=rng.randint(8, 17),
                                         minutes=rng.randint(0, 59),
                                         seconds=rng.randint(0, 59))
                    if rng.random() < 0.04:                  # typo in password
                        for _ in range(rng.randint(1, 2)):
                            self.login(t, u["name"], u["ip"], u["ua"], False, scenario="typo")
                            t += timedelta(seconds=rng.randint(10, 40))
                    self.login(t, u["name"], u["ip"], u["ua"], True,
                               "Yes" if u["mfa"] else "No")
                    for _ in range(rng.randint(0, 3)):       # assume some roles
                        t += timedelta(minutes=rng.randint(1, 90))
                        error = "AccessDenied" if rng.random() < 0.05 else None
                        self.role(t, u["name"], u["ip"], u["ua"],
                                  rng.choice(NORMAL_ROLES), error,
                                  scenario="denied_role" if error else "routine")

    def bot_traffic(self):
        for day in range(self.days):
            for hour in range(24):
                t = self.start + timedelta(days=day, hours=hour,
                                           minutes=5, seconds=self.rng.randint(0, 30))
                self.role(t, "ci-bot", BOT_IP, BOT_UA, "DeployRole",
                          scenario="bot_routine")

    def root_activity(self):
        for _ in range(2):    # the owner sometimes uses root (with a typo first)
            t = self.random_start()
            self.login(t, "root", OFFICE_IP, BROWSERS[0], False, scenario="typo")
            self.login(t + timedelta(seconds=25), "root", OFFICE_IP, BROWSERS[0],
                       True, "Yes")

    # ---- hard normal cases (these trick simple rules)
    def benign_edge_cases(self):
        rng = self.rng

        # 1) Office SSO glitch: 12 office users fail twice within ~4 minutes
        base = self.start + timedelta(days=min(4, self.days - 1), hours=9)
        office_users = [u for u in self.users if u["ip"] == OFFICE_IP][:12]
        for u in office_users:
            t = base + timedelta(seconds=rng.randint(0, 200))
            for _ in range(2):
                self.login(t, u["name"], OFFICE_IP, u["ua"], False,
                           scenario="office_sso_glitch")
                t += timedelta(seconds=rng.randint(20, 50))
            self.login(t, u["name"], OFFICE_IP, u["ua"], True,
                       "Yes" if u["mfa"] else "No", scenario="office_sso_glitch")

        # 2) Forgotten password: 6 failures, then success (twice in the run)
        candidates = [u for u in self.users if u["name"] != "admin"]
        for _ in range(2):
            u = rng.choice(candidates)
            t = self.start + timedelta(days=rng.randint(0, self.days - 1),
                                       hours=rng.randint(8, 17),
                                       minutes=rng.randint(0, 59))
            for _ in range(6):
                self.login(t, u["name"], u["ip"], u["ua"], False,
                           scenario="forgot_password")
                t += timedelta(seconds=rng.randint(15, 30))
            self.login(t, u["name"], u["ip"], u["ua"], True,
                       "Yes" if u["mfa"] else "No", scenario="forgot_password")

        # 3) Misconfigured bot: 8 AccessDenied in 40 seconds
        t = self.start + timedelta(days=min(2, self.days - 1), hours=2)
        for _ in range(8):
            self.role(t, "ci-bot", BOT_IP, BOT_UA, "DeployRole", "AccessDenied",
                      scenario="misconfigured_bot")
            t += timedelta(seconds=5)

    # ---- attacks
    def attack_password_guessing(self):
        rng = self.rng
        lab = self.label("password_guessing")
        ip, ua = self.rand_ip(), self.attacker_ua()
        target = rng.choice(["admin", "admin", "alice", "bob", "carol"])
        n, duration = rng.randint(40, 150), rng.randint(120, 300)
        t = self.random_start()
        for _ in range(n):
            self.login(t, target, ip, ua, False, **lab)
            t += timedelta(seconds=max(1, round(duration / n * rng.uniform(0.5, 1.5))))
        if rng.random() < 0.5:                       # sometimes the attacker gets in
            self.login(t, target, ip, ua, True, **lab)

    def attack_password_spraying(self):
        rng = self.rng
        lab = self.label("password_spraying")
        ip, ua = self.rand_ip(), self.attacker_ua()
        targets = rng.sample([u["name"] for u in self.users], rng.randint(15, 25))
        rounds, duration = rng.randint(1, 3), rng.randint(900, 2400)
        total = len(targets) * rounds
        t = self.random_start()
        for _ in range(rounds):
            rng.shuffle(targets)
            for who in targets:
                self.login(t, who, ip, ua, False, **lab)
                t += timedelta(seconds=max(1, round(duration / total * rng.uniform(0.5, 1.5))))
        if rng.random() < 0.5:
            self.login(t, rng.choice(targets), ip, ua, True, **lab)

    def attack_credential_stuffing(self):
        rng = self.rng
        lab = self.label("credential_stuffing")
        ip, ua = self.rand_ip(), self.attacker_ua()
        names = [u["name"] for u in self.users]
        t = self.random_start()
        for _ in range(rng.randint(60, 150)):
            exists = rng.random() < 0.3              # most stolen usernames do not exist here
            who = rng.choice(names) if exists else None
            success = exists and rng.random() < 0.05
            self.login(t, who, ip, ua, success, **lab)
            t += timedelta(seconds=rng.randint(1, 3))

    def attack_low_and_slow(self):
        rng = self.rng
        lab = self.label("low_and_slow")
        ips = [self.rand_ip() for _ in range(rng.randint(8, 15))]
        ua = self.attacker_ua()
        target = rng.choice(["admin", "alice", "bob"])
        t0 = self.random_start()
        duration = rng.randint(6, 12) * 3600
        for _ in range(rng.randint(40, 80)):
            t = t0 + timedelta(seconds=rng.randint(0, duration))
            self.login(t, target, rng.choice(ips), ua, False, **lab)

    def attack_role_enumeration(self):
        rng = self.rng
        lab = self.label("role_enumeration")
        victim = rng.choice(self.users)["name"]      # stolen credentials
        ip, ua = self.rand_ip(), self.attacker_ua()
        n = rng.randint(10, 40)
        t = self.random_start()
        for role in rng.sample(ENUM_ROLES, min(n, len(ENUM_ROLES))):
            error = rng.choice(["AccessDenied", "MalformedPolicyDocumentException"])
            self.role(t, victim, ip, ua, role, error, **lab)
            t += timedelta(seconds=rng.randint(3, 20))
        if rng.random() < 0.5:                       # found a role that works
            self.role(t, victim, ip, ua, "OrganizationAccountAccessRole", None, **lab)

    def attack_root_brute_force(self):
        rng = self.rng
        lab = self.label("root_brute_force")
        ip, ua = self.rand_ip(), self.attacker_ua()
        n, duration = rng.randint(12, 40), rng.randint(600, 1080)
        t = self.random_start()
        for _ in range(n):
            self.login(t, "root", ip, ua, False, **lab)
            t += timedelta(seconds=max(1, round(duration / n * rng.uniform(0.5, 1.5))))

    # ---- run everything and save
    def run(self):
        self.normal_traffic()
        self.bot_traffic()
        self.root_activity()
        self.benign_edge_cases()
        for kind, count in ATTACK_PLAN.items():
            for _ in range(count):
                getattr(self, "attack_" + kind)()

    def save(self, outdir):
        os.makedirs(outdir, exist_ok=True)
        self.events.sort(key=lambda e: e[0]["eventTime"])
        records = [rec for rec, _ in self.events]
        with open(os.path.join(outdir, "cloudtrail_logs.json"), "w") as f:
            json.dump({"Records": records}, f, indent=2)
        df = pd.DataFrame([flatten(rec, lab) for rec, lab in self.events])
        df.to_csv(os.path.join(outdir, "cloudtrail_labeled.csv"), index=False)
        return df


# ------------------------------------------------------------------- main
def main():
    parser = argparse.ArgumentParser(description="Generate synthetic CloudTrail logs")
    parser.add_argument("--days", type=int, default=30, help="days of logs (min 3)")
    parser.add_argument("--seed", type=int, default=42, help="random seed")
    parser.add_argument("--start", default="2026-09-01", help="start date YYYY-MM-DD")
    parser.add_argument("--outdir", default="data", help="output folder")
    args = parser.parse_args()
    if args.days < 3:
        parser.error("--days must be at least 3")

    gen = Generator(seed=args.seed, days=args.days,
                    start=datetime.strptime(args.start, "%Y-%m-%d"))
    gen.run()
    df = gen.save(args.outdir)

    print(f"Saved {args.outdir}/cloudtrail_logs.json and {args.outdir}/cloudtrail_labeled.csv")
    print(f"\nTotal events: {len(df)}")
    print("\nBy event type:")
    print(df["event_name"].value_counts().to_string())
    print("\nBy outcome:")
    print(df["outcome"].value_counts().to_string())
    n_att = int(df["is_attack"].sum())
    print(f"\nAttack events: {n_att} ({n_att / len(df) * 100:.1f}%)")
    attacks = df[df["is_attack"]]
    print(attacks.groupby("attack_type").agg(
        events=("event_id", "count"), attacks=("attack_id", "nunique")).to_string())
    print("\nNormal-traffic scenarios:")
    print(df[~df["is_attack"]]["scenario"].value_counts().to_string())


if __name__ == "__main__":
    main()
