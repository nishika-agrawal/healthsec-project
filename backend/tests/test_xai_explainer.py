from app.ml.predictor import get_loaded_model, predict_risk
from app.xai.explainer import explain_prediction, explain_with_rule_breakdown, explain_with_shap

SEVERE_FINDINGS = {
    "critical_count": 2,
    "high_count": 1,
    "medium_count": 1,
    "low_count": 0,
    "max_cvss_score": 8.5,
    "vulnerable_dependency_count": 2,
    "container_vulnerability_count": 1,
    "failed_security_checks": 0,
    "fix_available_count": 1,
    "total_findings": 4,
}

NO_FINDINGS = {
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "max_cvss_score": None,
    "vulnerable_dependency_count": 0,
    "container_vulnerability_count": 0,
    "failed_security_checks": 0,
    "fix_available_count": 0,
    "total_findings": 0,
}


def test_explain_prediction_uses_shap_when_model_used():
    prediction = predict_risk(SEVERE_FINDINGS)
    assert prediction["model_used"] == "random_forest"
    model = get_loaded_model()

    explanation = explain_prediction(SEVERE_FINDINGS, prediction, model=model)

    assert explanation["method"] == "shap_tree_explainer"
    assert explanation["predicted_category"] == prediction["risk_category"]
    assert len(explanation["contributions"]) > 0
    for c in explanation["contributions"]:
        assert c["direction"] in ("increases", "decreases", "no effect")
    assert "summary" in explanation
    assert isinstance(explanation["summary"], str)
    assert len(explanation["summary"]) > 0


def test_explain_with_shap_contributions_are_sorted_by_magnitude():
    prediction = predict_risk(SEVERE_FINDINGS)
    model = get_loaded_model()
    result = explain_with_shap(SEVERE_FINDINGS, model, prediction["risk_category"], top_n=11)

    magnitudes = [abs(c["contribution"]) for c in result["all_contributions"]]
    assert magnitudes == sorted(magnitudes, reverse=True)


def test_explain_with_shap_returns_none_when_model_is_none():
    result = explain_with_shap(SEVERE_FINDINGS, model=None, predicted_category="High")
    assert result is None


def test_explain_prediction_falls_back_to_rule_breakdown_without_model():
    prediction = {
        "risk_category": "High",
        "predicted_probability": None,
        "risk_score": 80.0,
        "model_used": "rule_based_fallback",
    }
    explanation = explain_prediction(SEVERE_FINDINGS, prediction, model=None)

    assert explanation["method"] == "rule_based_breakdown"
    assert explanation["predicted_category"] == "High"
    assert len(explanation["contributions"]) > 0


def test_rule_breakdown_only_includes_nonzero_terms():
    result = explain_with_rule_breakdown(NO_FINDINGS)
    assert result["contributions"] == []
    assert result["all_contributions"] == []


def test_rule_breakdown_direction_matches_sign():
    features = {"critical_count": 1, "fix_available_count": 3}
    result = explain_with_rule_breakdown(features)

    critical_term = next(c for c in result["all_contributions"] if c["feature"] == "critical_count")
    assert critical_term["direction"] == "increases"

    fix_term = next(c for c in result["all_contributions"] if c["feature"] == "fix_available_count")
    assert fix_term["direction"] == "decreases"


def test_rule_breakdown_method_is_never_mislabeled_as_shap():
    result = explain_with_rule_breakdown(SEVERE_FINDINGS)
    assert result["method"] == "rule_based_breakdown"
    assert result["method"] != "shap_tree_explainer"
