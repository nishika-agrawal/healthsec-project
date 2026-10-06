"""
Loads the trained Random Forest risk model (if available) and exposes a
single predict_risk() function used by the rest of the application.

Falls back to the deterministic rule-based score (app.ml.dataset.
rule_based_risk_score) whenever the trained model file is missing,
corrupted, or scikit-learn/joblib aren't installed - so risk assessment
always produces a result rather than crashing, even on a machine where
training hasn't been run yet.
"""

import logging
from pathlib import Path
from typing import Optional

from app.ml.dataset import FEATURE_COLUMNS, risk_category_from_score, rule_based_risk_score

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).resolve().parent / "model" / "risk_model.joblib"

_cached_model = None
_model_load_attempted = False


def _load_model(model_path: Optional[Path] = None):
    """
    Cached model loader. Pass model_path explicitly (e.g. in tests) to
    bypass the cache and load from a specific location.
    """
    global _cached_model, _model_load_attempted

    path = model_path or MODEL_PATH

    if model_path is None:
        if _model_load_attempted:
            return _cached_model
        _model_load_attempted = True

    try:
        import joblib  # local import: the app must still run without scikit-learn/joblib installed

        if not path.exists():
            logger.warning("No trained risk model found at %s - using rule-based fallback.", path)
            return None

        model = joblib.load(path)
        if model_path is None:
            _cached_model = model
        return model
    except Exception as exc:  # noqa: BLE001 - any load failure should fall back, never crash
        logger.warning("Could not load trained risk model (%s) - using rule-based fallback.", exc)
        return None


def _features_to_vector(features: dict) -> list:
    row = []
    for column in FEATURE_COLUMNS:
        if column == "max_cvss_score_missing":
            row.append(int(features.get("max_cvss_score") is None))
        elif column == "max_cvss_score":
            value = features.get("max_cvss_score")
            row.append(float(value) if value is not None else 0.0)
        else:
            row.append(features.get(column, 0) or 0)
    return row


def _features_to_dataframe(features: dict):
    import pandas as pd  # local import: keeps pandas optional for the rule-based-only path

    return pd.DataFrame([_features_to_vector(features)], columns=FEATURE_COLUMNS)


def get_loaded_model(model_path: Optional[Path] = None):
    """
    Public accessor for the cached trained model (or None if unavailable).
    Used by app.xai.explainer so it can run SHAP against the exact same
    model instance that produced the prediction, without duplicating the
    loading/fallback logic here.
    """
    return _load_model(model_path)


def predict_risk(features: dict, model_path: Optional[Path] = None) -> dict:
    """
    features: a dict with (at least) the keys produced by
    app.security.features.compute_scan_features - critical_count,
    high_count, medium_count, low_count, max_cvss_score,
    vulnerable_dependency_count, container_vulnerability_count,
    failed_security_checks, fix_available_count, total_findings.

    Returns:
        {
            "risk_category": "Low" | "Medium" | "High",
            "predicted_probability": float | None,
                # The RANDOM FOREST's confidence (0-1) in its predicted
                # category. Only present when model_used == "random_forest" -
                # this is a genuine ML probability, not the risk_score below.
            "risk_score": float,
                # A 0-100 DETERMINISTIC, rule-based score (see
                # app.ml.dataset.rule_based_risk_score). Always available,
                # regardless of whether the ML model is. This is NOT a
                # probability and must not be interpreted as one.
            "model_used": "random_forest" | "rule_based_fallback",
        }
    """
    risk_score = rule_based_risk_score(features)

    model = _load_model(model_path)
    if model is None:
        return {
            "risk_category": risk_category_from_score(risk_score),
            "predicted_probability": None,
            "risk_score": risk_score,
            "model_used": "rule_based_fallback",
        }

    vector = _features_to_dataframe(features)
    predicted_category = model.predict(vector)[0]
    probabilities = model.predict_proba(vector)[0]
    class_index = list(model.classes_).index(predicted_category)
    predicted_probability = float(probabilities[class_index])

    return {
        "risk_category": predicted_category,
        "predicted_probability": predicted_probability,
        "risk_score": risk_score,
        "model_used": "random_forest",
    }
