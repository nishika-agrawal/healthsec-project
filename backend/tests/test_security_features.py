from app.security.features import compute_scan_features, compute_security_rating


def make_finding(**overrides):
    base = {
        "source": "trivy",
        "identifier": "CVE-0000",
        "normalized_severity": "LOW",
        "package_name": None,
        "cvss_score": None,
        "fix_available": False,
        "finding_class": None,
    }
    base.update(overrides)
    return base


def test_severity_counts():
    findings = [
        make_finding(normalized_severity="CRITICAL"),
        make_finding(normalized_severity="HIGH"),
        make_finding(normalized_severity="HIGH"),
        make_finding(normalized_severity="MEDIUM"),
        make_finding(normalized_severity="LOW"),
    ]
    features = compute_scan_features(findings, {"trivy": "ok", "dependency_check": "ok", "sonarqube": "ok"})

    assert features["critical_count"] == 1
    assert features["high_count"] == 2
    assert features["medium_count"] == 1
    assert features["low_count"] == 1
    assert features["total_findings"] == 5


def test_max_cvss_score_ignores_missing_scores():
    findings = [
        make_finding(cvss_score=None),
        make_finding(cvss_score=7.2),
        make_finding(cvss_score=9.8),
    ]
    features = compute_scan_features(findings, {"trivy": "ok"})
    assert features["max_cvss_score"] == 9.8


def test_max_cvss_score_is_none_when_no_scores_present():
    findings = [make_finding(cvss_score=None)]
    features = compute_scan_features(findings, {"trivy": "ok"})
    assert features["max_cvss_score"] is None


def test_vulnerable_dependency_count_counts_distinct_packages():
    findings = [
        make_finding(source="dependency_check", package_name="pkg-a"),
        make_finding(source="dependency_check", package_name="pkg-a"),  # same package, another CVE
        make_finding(source="dependency_check", package_name="pkg-b"),
        make_finding(source="trivy", finding_class="os-pkgs", package_name="debian-base-pkg"),
    ]
    features = compute_scan_features(findings, {"trivy": "ok", "dependency_check": "ok"})
    # Only pkg-a and pkg-b count (dependency_check); the os-pkgs finding does not.
    assert features["vulnerable_dependency_count"] == 2


def test_container_vulnerability_count_counts_only_trivy_os_pkgs():
    findings = [
        make_finding(source="trivy", finding_class="os-pkgs"),
        make_finding(source="trivy", finding_class="lang-pkgs"),
        make_finding(source="dependency_check", finding_class="dependency"),
    ]
    features = compute_scan_features(findings, {"trivy": "ok", "dependency_check": "ok"})
    assert features["container_vulnerability_count"] == 1


def test_fix_available_count():
    findings = [
        make_finding(fix_available=True),
        make_finding(fix_available=True),
        make_finding(fix_available=False),
    ]
    features = compute_scan_features(findings, {"trivy": "ok"})
    assert features["fix_available_count"] == 2


def test_failed_security_checks_counts_non_ok_scanners():
    findings = []
    statuses = {"trivy": "ok", "dependency_check": "missing", "sonarqube": "tool_unavailable"}
    features = compute_scan_features(findings, statuses)
    assert features["failed_security_checks"] == 2


def test_security_rating_follows_highest_severity_present():
    assert compute_security_rating(critical=1, high=0, medium=0, low=0) == "F"
    assert compute_security_rating(critical=0, high=1, medium=0, low=0) == "D"
    assert compute_security_rating(critical=0, high=0, medium=1, low=0) == "C"
    assert compute_security_rating(critical=0, high=0, medium=0, low=1) == "B"
    assert compute_security_rating(critical=0, high=0, medium=0, low=0) == "A"
