from app.deployment.policy import decide_deployment, mandatory_checks_passed

ALL_OK = {"trivy": "ok", "dependency_check": "ok", "sonarqube": "ok"}


def test_mandatory_checks_passed_when_all_ok():
    passed, failed = mandatory_checks_passed(ALL_OK)
    assert passed is True
    assert failed == []


def test_mandatory_checks_failed_when_any_scanner_not_ok():
    status = {"trivy": "ok", "dependency_check": "missing", "sonarqube": "ok"}
    passed, failed = mandatory_checks_passed(status)
    assert passed is False
    assert failed == ["dependency_check"]


def test_mandatory_checks_treats_tool_unavailable_as_failure():
    status = {"trivy": "ok", "dependency_check": "ok", "sonarqube": "tool_unavailable"}
    passed, failed = mandatory_checks_passed(status)
    assert passed is False
    assert "sonarqube" in failed


def test_mandatory_checks_respects_custom_scanner_list():
    status = {"trivy": "missing", "dependency_check": "ok"}
    # trivy not required in this custom policy -> should pass
    passed, failed = mandatory_checks_passed(status, mandatory_scanners=["dependency_check"])
    assert passed is True
    assert failed == []


def test_low_risk_with_passing_checks_is_approved():
    result = decide_deployment("Low", ALL_OK)
    assert result["decision"] == "approved"
    assert result["mandatory_checks_passed"] is True


def test_medium_risk_requires_review():
    result = decide_deployment("Medium", ALL_OK)
    assert result["decision"] == "review_required"


def test_high_risk_is_blocked_even_with_passing_checks():
    result = decide_deployment("High", ALL_OK)
    assert result["decision"] == "blocked"


def test_low_risk_is_blocked_if_mandatory_checks_failed():
    """
    Core policy requirement: mandatory check failures block deployment
    REGARDLESS of how low the predicted risk is.
    """
    status = {"trivy": "ok", "dependency_check": "missing", "sonarqube": "ok"}
    result = decide_deployment("Low", status)
    assert result["decision"] == "blocked"
    assert result["mandatory_checks_passed"] is False
    assert "dependency_check" in result["failed_checks"]


def test_medium_risk_is_blocked_not_merely_review_if_mandatory_checks_failed():
    status = {"trivy": "invalid", "dependency_check": "ok", "sonarqube": "ok"}
    result = decide_deployment("Medium", status)
    assert result["decision"] == "blocked"


def test_invalid_risk_category_is_blocked_not_approved():
    """
    An invalid/unavailable prediction must never default to approval,
    even if every mandatory scanner passed.
    """
    result = decide_deployment("UnknownCategory", ALL_OK)
    assert result["decision"] == "blocked"
    assert "Invalid" in result["reason"]


def test_invalid_risk_category_blocked_even_with_failed_checks_too():
    status = {"trivy": "missing"}
    result = decide_deployment(None, status)
    assert result["decision"] == "blocked"


def test_decision_always_echoes_back_risk_category():
    result = decide_deployment("High", ALL_OK)
    assert result["risk_category"] == "High"


def test_all_scanners_missing_blocks_low_risk():
    status = {"trivy": "missing", "dependency_check": "missing", "sonarqube": "missing"}
    result = decide_deployment("Low", status)
    assert result["decision"] == "blocked"
    assert set(result["failed_checks"]) == {"trivy", "dependency_check", "sonarqube"}
