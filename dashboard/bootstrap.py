# dashboard/bootstrap.py
# First-start builder for cloud deployment. If AUTO_BOOTSTRAP=1 is set (as an
# environment variable or a Streamlit secret) and the app starts empty, it
#   1. generates synthetic CloudTrail logs and stores them in SQLite,
#   2. trains the Random Forest (the model file is not stored on GitHub),
#   3. runs the detection pipeline and saves the alerts.
# Without AUTO_BOOTSTRAP nothing happens, so local runs and tests are unchanged.
import os
from datetime import datetime

import joblib
import streamlit as st

from cloud import database
from cloud.generate_logs import Generator
from ml.experiment import build_training_set
from ml.features import FEATURES_FULL
from ml.models import fit_model, make_model
from security import alert_store, pipeline


def enabled():
    value = os.environ.get("AUTO_BOOTSTRAP")
    if not value:
        try:
            value = st.secrets.get("AUTO_BOOTSTRAP")
        except Exception:            # no secrets configured
            value = None
    return str(value or "").strip() == "1"


def _labels(events):
    return {rec["eventID"]: {"is_attack": int(lab["attack_type"] != "normal"),
                             "attack_type": lab["attack_type"],
                             "attack_id": lab["attack_id"],
                             "scenario": lab["scenario"]}
            for rec, lab in events}


def _train_model(seeds, days):
    train = build_training_set(list(seeds), days)
    train["is_attack"] = train["is_attack"].astype(int)
    y = train["is_attack"]
    model = make_model("Random Forest", attack_rate=float(y.mean()),
                       scale_pos_weight=float((y == 0).sum() / max((y == 1).sum(), 1)))
    fit_model("Random Forest", model, train[FEATURES_FULL], y)
    path = pipeline.DEFAULT_MODEL
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    joblib.dump({"name": "Random Forest", "features": FEATURES_FULL, "model": model}, path)


def ensure_ready(db_path=None, days=30, seed=42, train_seeds=(1, 2, 3), train_days=30):
    """Build whatever is missing. Safe to call again: it only fills gaps."""
    done = {"logs_created": False, "model_trained": False, "alerts_created": 0}
    database.init_db(db_path)

    if database.get_stats(db_path)["total_events"] == 0:
        gen = Generator(seed=seed, days=days, start=datetime(2026, 9, 1))
        gen.run()
        database.insert_records([rec for rec, _ in gen.events],
                                labels=_labels(gen.events), db_path=db_path)
        done["logs_created"] = True

    if not os.path.exists(pipeline.DEFAULT_MODEL):
        _train_model(train_seeds, train_days)
        done["model_trained"] = True

    if alert_store.load_alerts(db_path).empty:
        events = database.load_events_df(db_path)
        alerts, _ = pipeline.detect(events, policy="ml")
        done["alerts_created"] = alert_store.save_alerts(alerts, db_path)
    return done


@st.cache_resource(show_spinner=False)
def _run_once(db_path):
    return ensure_ready(db_path)


def run_if_enabled():
    """Called by the dashboard right after the login. Does the work once per server start."""
    if not enabled():
        return
    with st.spinner("First start: building demo logs and training the model "
                    "(about a minute)..."):
        _run_once(database.get_db_path())
