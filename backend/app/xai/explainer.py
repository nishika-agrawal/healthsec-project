"""
Explains a risk prediction.

Two distinct, clearly-labeled methods are used depending on which
predictor produced the prediction (see app/ml/predictor.py):

- "shap_tree_explainer": when the trained Random Forest was used, SHAP's
  TreeExplainer computes each feature's exact contribution to the
  predicted class's probability for THIS SPECIFIC prediction. These are
  real, mathematically-derived values from the actual trained model -
  never invented or hand-assigned.

- "rule_based_breakdown": when the rule-based fallback was used instead
  (see app.ml.predictor - no trained model available), there is no
  model to run SHAP against. Instead, this decomposes the transparent
  scoring formula (app.ml.dataset.rule_based_risk_score) into its exact
  additive terms. This is a real breakdown of that specific formula, not
  a SHAP value, and is always labeled as such - it must never be
  presented as if it came from SHAP or any other ML explainability tool.
"""

from pathlib import Path
from typing import Optional

from app.ml.dataset import FEATURE_COLUMNS
from app.xai.labels import label_for

_cached_explainer = None
_explainer_load_attempted = False


def _load_shap_explainer(model):
    """Cached SHAP TreeExplainer for the given (already-loaded) model."""
    global _cached_explainer, _explainer_load_attempted

    if _explainer_load_attempted:
        return _cached_explainer

    _explainer_load_attempted = True
    try:
        import shap

        _cached_explainer = shap.TreeExplainer(model)
        return _cached_explainer
    except Exception:  # noqa: BLE001 - SHAP unavailable should degrade, not crash
        return None


def _features_to_dataframe(features: dict):
    import pandas as pd

    row = []
    for column in FEATURE_COLUMNS:
        if column == "max_cvss_score_missing":
            row.append(int(features.get("max_cvss_score") is None))
        elif column == "max_cvss_score":
            value = features.get("max_cvss_score")
            row.append(float(value) if value is not None else 0.0)
        else:
            row.append(features.get(column, 0) or 0)
    return pd.DataFrame([row], columns=FEATURE_COLUMNS)


def explain_with_shap(features: dict, model, predicted_category: str, top_n: int = 5) -> Optional[dict]:
    """
    Returns a contribution breakdown using real SHAP values for the
    predicted class, or None if SHAP/the model isn't usable (caller
    should fall back to explain_with_rule_breakdown in that case).
    """
    explainer = _load_shap_explainer(model)
    if explainer is None:
        return None

    try:
        row_df = _features_to_dataframe(features)
        shap_values = explainer.shap_values(row_df)  # shape: (1, n_features, n_classes)

        class_list = list(model.classes_)
        class_index = class_list.index(predicted_category)

        per_feature_shap = shap_values[0, :, class_index]
    except Exception:  # noqa: BLE001 - any SHAP computation failure falls back gracefully
        return None

    contributions = []
    for feature_name, shap_value in zip(FEATURE_COLUMNS, per_feature_shap):
        value = row_df.iloc[0][feature_name]
        direction = "increases" if shap_value > 0 else ("decreases" if shap_value < 0 else "no effect")
        contributions.append(
            {
                "feature": feature_name,
                "value": value.item() if hasattr(value, "item") else value,
                "contribution": float(shap_value),
                "direction": direction,
            }
        )

    contributions.sort(key=lambda c: abs(c["contribution"]), reverse=True)

    return {
        "method": "shap_tree_explainer",
        "contributions": contributions[:top_n],
        "all_contributions": contributions,
    }


def explain_with_rule_breakdown(features: dict, top_n: int = 5) -> dict:
    """
    Decomposes the deterministic rule_based_risk_score formula into its
    exact additive terms for this specific set of features. This is NOT
    a SHAP value - it's the literal terms of the formula in
    app.ml.dataset.rule_based_risk_score.
    """
    critical = features.get("critical_count", 0) or 0
    high = features.get("high_count", 0) or 0
    medium = features.get("medium_count", 0) or 0
    low = features.get("low_count", 0) or 0
    max_cvss = features.get("max_cvss_score") or 0
    failed_checks = features.get("failed_security_checks", 0) or 0
    fix_available = features.get("fix_available_count", 0) or 0

    terms = [
        ("critical_count", critical, critical * 25),
        ("high_count", high, high * 12),
        ("medium_count", medium, medium * 5),
        ("low_count", low, low * 1),
        ("max_cvss_score", max_cvss, max_cvss * 2),
        ("failed_security_checks", failed_checks, failed_checks * 8),
        ("fix_available_count", fix_available, fix_available * -1.5),
    ]

    contributions = [
        {
            "feature": feature_name,
            "value": value,
            "contribution": float(contribution),
            "direction": "increases" if contribution > 0 else ("decreases" if contribution < 0 else "no effect"),
        }
        for feature_name, value, contribution in terms
        if contribution != 0
    ]
    contributions.sort(key=lambda c: abs(c["contribution"]), reverse=True)

    return {
        "method": "rule_based_breakdown",
        "contributions": contributions[:top_n],
        "all_contributions": contributions,
    }


def _summarize(contributions: list, predicted_category: str, method: str) -> str:
    if not contributions:
        return (
            f"No security findings were present, so this build was classified as {predicted_category} risk."
        )

    top = contributions[:3]
    phrases = []
    for c in top:
        label = label_for(c["feature"])
        verb = "raised" if c["direction"] == "increases" else "lowered" if c["direction"] == "decreases" else "did not change"
        phrases.append(f"{label} ({c['value']}), which {verb} the assessed risk")

    if len(phrases) == 1:
        factor_text = phrases[0]
    elif len(phrases) == 2:
        factor_text = f"{phrases[0]} and {phrases[1]}"
    else:
        factor_text = f"{', '.join(phrases[:-1])}, and {phrases[-1]}"

    method_note = (
        "based on the trained model's learned patterns"
        if method == "shap_tree_explainer"
        else "based on the transparent scoring rule used when no trained model is available"
    )

    return f"This build was classified as {predicted_category} risk, primarily driven by {factor_text} ({method_note})."


def explain_prediction(features: dict, prediction: dict, top_n: int = 5, model=None) -> dict:
    """
    prediction: the dict returned by app.ml.predictor.predict_risk() -
    used to know which method produced the prediction (model_used) and
    the predicted category, so the explanation matches the prediction
    exactly rather than being computed independently and potentially
    disagreeing with it.
    """
    predicted_category = prediction["risk_category"]

    result = None
    if prediction.get("model_used") == "random_forest" and model is not None:
        result = explain_with_shap(features, model, predicted_category, top_n=top_n)

    if result is None:
        result = explain_with_rule_breakdown(features, top_n=top_n)

    result["predicted_category"] = predicted_category
    result["summary"] = _summarize(result["contributions"], predicted_category, result["method"])
    return result
