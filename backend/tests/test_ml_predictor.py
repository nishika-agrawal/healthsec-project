from pathlib import Path

from app.ml.predictor import predict_risk

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

SEVERE_FINDINGS = {
    "critical_count": 3,
    "high_count": 2,
    "medium_count": 1,
    "low_count": 0,
    "max_cvss_score": 9.8,
    "vulnerable_dependency_count": 4,
    "container_vulnerability_count": 2,
    "failed_security_checks": 2,
    "fix_available_count": 1,
    "total_findings": 6,
}


def test_predict_risk_uses_trained_model_when_available():
    # This test relies on the real trained model produced by `python -m app.ml.train`.
    result = predict_risk(NO_FINDINGS)
    assert result["model_used"] == "random_forest"
    assert result["risk_category"] in ("Low", "Medium", "High")
    assert 0.0 <= result["predicted_probability"] <= 1.0
    assert 0.0 <= result["risk_score"] <= 100.0


def test_predict_risk_no_findings_is_low_risk_via_trained_model():
    result = predict_risk(NO_FINDINGS)
    assert result["risk_category"] == "Low"
    assert result["risk_score"] == 0.0


def test_predict_risk_severe_findings_score_higher_than_no_findings():
    no_findings_result = predict_risk(NO_FINDINGS)
    severe_result = predict_risk(SEVERE_FINDINGS)
    assert severe_result["risk_score"] > no_findings_result["risk_score"]


def test_predict_risk_falls_back_to_rule_based_when_model_missing(tmp_path):
    missing_model_path = tmp_path / "does-not-exist.joblib"
    result = predict_risk(SEVERE_FINDINGS, model_path=missing_model_path)

    assert result["model_used"] == "rule_based_fallback"
    assert result["predicted_probability"] is None
    assert result["risk_category"] in ("Low", "Medium", "High")
    # The fallback's risk_score must match the same deterministic rule
    # used everywhere else - it's the same function either way.
    from app.ml.dataset import rule_based_risk_score

    assert result["risk_score"] == rule_based_risk_score(SEVERE_FINDINGS)


def test_predict_risk_falls_back_when_model_file_is_corrupted(tmp_path):
    corrupted_model_path = tmp_path / "corrupted.joblib"
    corrupted_model_path.write_text("this is not a valid joblib file")

    result = predict_risk(NO_FINDINGS, model_path=corrupted_model_path)

    assert result["model_used"] == "rule_based_fallback"
    assert result["predicted_probability"] is None


def test_risk_score_and_probability_are_independent_concepts():
    """
    risk_score (0-100, deterministic) and predicted_probability (0-1, ML
    confidence) must never be conflated - this test checks they're
    reported as distinct fields with distinct ranges.
    """
    result = predict_risk(SEVERE_FINDINGS)
    assert result["risk_score"] > 1.0  # clearly not on a 0-1 scale
    assert 0.0 <= result["predicted_probability"] <= 1.0
    assert result["risk_score"] != result["predicted_probability"]
