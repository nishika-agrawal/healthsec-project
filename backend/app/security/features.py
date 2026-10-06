"""
Computes structured security metrics ("features") from a deduplicated
list of findings. These are the values later stored in ScanFeatures and,
in Phase 6, fed into the Random Forest risk model.

security_rating here is a simple, transparent RULE (highest severity
present wins) - it is NOT a machine-learning prediction. Phase 6 adds a
separate, explicitly-labeled ML-based risk score; the two must never be
confused with each other.
"""

from typing import Optional


def compute_security_rating(critical: int, high: int, medium: int, low: int) -> str:
    """
    A quick-glance A-F label based on the highest severity present.
    This is a fixed rule, not a model output.
    """
    if critical > 0:
        return "F"
    if high > 0:
        return "D"
    if medium > 0:
        return "C"
    if low > 0:
        return "B"
    return "A"


def compute_scan_features(findings: list, scanner_statuses: "dict[str, str]") -> dict:
    """
    findings: deduplicated list of finding dicts (see parsers.py for the shape).
    scanner_statuses: e.g. {"trivy": "ok", "dependency_check": "ok", "sonarqube": "tool_unavailable"}
    """
    critical_count = sum(1 for f in findings if f["normalized_severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["normalized_severity"] == "HIGH")
    medium_count = sum(1 for f in findings if f["normalized_severity"] == "MEDIUM")
    low_count = sum(1 for f in findings if f["normalized_severity"] == "LOW")

    cvss_scores = [f["cvss_score"] for f in findings if f.get("cvss_score") is not None]
    max_cvss_score: Optional[float] = max(cvss_scores) if cvss_scores else None

    # "Vulnerable dependency" = a distinct package flagged by dependency
    # scanning (OWASP Dependency-Check, or Trivy's language-package results).
    vulnerable_dependency_count = len(
        {
            f["package_name"]
            for f in findings
            if f.get("package_name")
            and (f["source"] == "dependency_check" or (f["source"] == "trivy" and f.get("finding_class") == "lang-pkgs"))
        }
    )

    # "Container vulnerability" = OS-package findings from the Trivy image scan.
    container_vulnerability_count = sum(
        1 for f in findings if f["source"] == "trivy" and f.get("finding_class") == "os-pkgs"
    )

    fix_available_count = sum(1 for f in findings if f.get("fix_available"))

    # A scanner that didn't produce usable output counts as a failed check.
    failed_security_checks = sum(1 for status in scanner_statuses.values() if status != "ok")

    security_rating = compute_security_rating(critical_count, high_count, medium_count, low_count)

    return {
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "max_cvss_score": max_cvss_score,
        "vulnerable_dependency_count": vulnerable_dependency_count,
        "container_vulnerability_count": container_vulnerability_count,
        "security_rating": security_rating,
        "failed_security_checks": failed_security_checks,
        "fix_available_count": fix_available_count,
        "total_findings": len(findings),
    }
