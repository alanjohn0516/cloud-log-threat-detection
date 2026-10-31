# ml/models.py
# The five machine learning models used in the comparison.
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

ALL_MODELS = ["Decision Tree", "Logistic Regression", "Random Forest",
              "XGBoost", "Isolation Forest"]
UNSUPERVISED = {"Isolation Forest"}   # learns "normal" without using labels


def make_model(name, attack_rate=0.1, scale_pos_weight=1.0):
    if name == "Decision Tree":
        return DecisionTreeClassifier(max_depth=8, min_samples_leaf=5,
                                      class_weight="balanced", random_state=42)
    if name == "Logistic Regression":
        return make_pipeline(
            FunctionTransformer(np.log1p),        # tame huge counts
            StandardScaler(),
            LogisticRegression(max_iter=2000, class_weight="balanced"))
    if name == "Random Forest":
        return RandomForestClassifier(n_estimators=150, max_depth=12,
                                      min_samples_leaf=2, class_weight="balanced",
                                      random_state=42, n_jobs=-1)
    if name == "XGBoost":
        return XGBClassifier(n_estimators=150, max_depth=4, learning_rate=0.1,
                             subsample=0.9, scale_pos_weight=scale_pos_weight,
                             eval_metric="logloss", random_state=42,
                             n_jobs=2, verbosity=0)
    if name == "Isolation Forest":
        rate = float(np.clip(attack_rate, 0.01, 0.5))
        return IsolationForest(n_estimators=200, contamination=rate,
                               random_state=42, n_jobs=-1)
    raise ValueError(f"unknown model: {name}")


def fit_model(name, model, X, y=None):
    if name in UNSUPERVISED:
        model.fit(X)          # no labels used
    else:
        model.fit(X, y)
    return model


def predict_flags(name, model, X):
    """True = the model says 'attack'."""
    pred = model.predict(X)
    return (pred == -1) if name in UNSUPERVISED else (pred == 1)
