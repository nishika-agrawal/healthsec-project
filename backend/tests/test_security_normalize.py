from app.security.normalize import SeverityLevel, normalize_severity


def test_trivy_known_severities():
    assert normalize_severity("CRITICAL", "trivy") == SeverityLevel.CRITICAL
    assert normalize_severity("high", "trivy") == SeverityLevel.HIGH
    assert normalize_severity("Medium", "trivy") == SeverityLevel.MEDIUM
    assert normalize_severity("LOW", "trivy") == SeverityLevel.LOW


def test_dependency_check_uses_same_scale_as_trivy():
    assert normalize_severity("CRITICAL", "dependency_check") == SeverityLevel.CRITICAL
    assert normalize_severity("NEGLIGIBLE", "dependency_check") == SeverityLevel.LOW


def test_sonarqube_scale_is_mapped_onto_shared_scale():
    assert normalize_severity("BLOCKER", "sonarqube") == SeverityLevel.CRITICAL
    assert normalize_severity("CRITICAL", "sonarqube") == SeverityLevel.CRITICAL
    assert normalize_severity("MAJOR", "sonarqube") == SeverityLevel.HIGH
    assert normalize_severity("MINOR", "sonarqube") == SeverityLevel.MEDIUM
    assert normalize_severity("INFO", "sonarqube") == SeverityLevel.LOW


def test_unknown_or_missing_values_fall_back_to_unknown():
    assert normalize_severity("", "trivy") == SeverityLevel.UNKNOWN
    assert normalize_severity(None, "trivy") == SeverityLevel.UNKNOWN
    assert normalize_severity("SOMETHING_WEIRD", "sonarqube") == SeverityLevel.UNKNOWN
    assert normalize_severity("CRITICAL", "an_unregistered_source") == SeverityLevel.UNKNOWN
