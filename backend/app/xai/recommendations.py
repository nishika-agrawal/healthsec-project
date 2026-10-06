"""
Generates remediation recommendations directly from actual scan findings
(see app.security.parsers for the finding format).

Rules followed strictly:
- Every recommendation is linked back to the specific finding(s) that
  produced it (source, identifier, component) - nothing is invented.
- Critical and high-severity findings each get an individual, specific
  recommendation. Medium/low-severity findings are summarized by count
  rather than listed one-by-one, so the output stays focused on what
  matters most (per the project's Phase 7 requirement to prioritize
  critical/high findings).
- This module only produces TEXT recommendations for a developer to act
  on. It never modifies source code, dependency files, or Docker images
  itself - all remediation requires explicit developer action/approval.
"""

_PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def _recommend_for_finding(finding: dict) -> dict:
    source = finding.get("source")
    identifier = finding.get("identifier") or "(no identifier)"
    package_name = finding.get("package_name")
    component = finding.get("component")
    fixed_version = finding.get("fixed_version")
    installed_version = finding.get("installed_version")
    fix_available = bool(finding.get("fix_available"))

    if source == "trivy" and finding.get("finding_class") == "os-pkgs":
        category = "container_update"
        if fix_available:
            action = (
                f"Rebuild the Docker image to update {package_name} "
                f"from {installed_version or 'the current version'} to {fixed_version}, "
                f"which fixes {identifier}."
            )
        else:
            action = (
                f"No fixed version is currently published for {identifier} in {package_name}. "
                "Monitor the base image vendor for a security update."
            )

    elif source in ("trivy", "dependency_check"):
        category = "dependency_upgrade"
        if fix_available:
            action = (
                f"Upgrade {package_name} from {installed_version or 'the current version'} "
                f"to {fixed_version}, which fixes {identifier}."
            )
        else:
            action = (
                f"No fixed version is currently available for {identifier} in {package_name}. "
                "Track this dependency for a security release."
            )

    elif source == "sonarqube":
        category = "code_review"
        title = finding.get("title") or "see scanner details for this rule"
        action = f"Review and remediate the code issue {identifier} in {component or 'the affected file'}: {title}."

    else:
        category = "review"
        action = f"Review finding {identifier} in {component or package_name or 'the affected component'}."

    return {
        "priority": finding.get("normalized_severity", "UNKNOWN"),
        "category": category,
        "action": action,
        "linked_finding": {
            "source": source,
            "identifier": finding.get("identifier"),
            "component": component or package_name,
            "cvss_score": finding.get("cvss_score"),
        },
    }


def generate_recommendations(findings: list) -> dict:
    """
    Returns:
        {
            "recommendations": [ ... one per CRITICAL/HIGH finding, sorted CRITICAL first ... ],
            "summary": {
                "critical_count": int,
                "high_count": int,
                "medium_noted": int,   # not individually listed, only counted
                "low_noted": int,
                "unknown_noted": int,
            },
        }
    """
    recommendations = []
    summary = {"critical_count": 0, "high_count": 0, "medium_noted": 0, "low_noted": 0, "unknown_noted": 0}

    for finding in findings:
        severity = finding.get("normalized_severity", "UNKNOWN")

        if severity == "CRITICAL":
            summary["critical_count"] += 1
            recommendations.append(_recommend_for_finding(finding))
        elif severity == "HIGH":
            summary["high_count"] += 1
            recommendations.append(_recommend_for_finding(finding))
        elif severity == "MEDIUM":
            summary["medium_noted"] += 1
        elif severity == "LOW":
            summary["low_noted"] += 1
        else:
            summary["unknown_noted"] += 1

    recommendations.sort(key=lambda r: _PRIORITY_ORDER.get(r["priority"], 99))

    return {"recommendations": recommendations, "summary": summary}
