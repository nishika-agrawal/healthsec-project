"""
Plain-language labels for each model feature, used to turn technical
column names into sentences a non-specialist can read.
"""

FEATURE_LABELS = {
    "critical_count": "the number of critical-severity vulnerabilities",
    "high_count": "the number of high-severity vulnerabilities",
    "medium_count": "the number of medium-severity vulnerabilities",
    "low_count": "the number of low-severity vulnerabilities",
    "max_cvss_score": "the highest CVSS severity score found",
    "max_cvss_score_missing": "whether CVSS scoring data was missing",
    "vulnerable_dependency_count": "the number of vulnerable third-party dependencies",
    "container_vulnerability_count": "the number of vulnerabilities in the container base image",
    "failed_security_checks": "the number of security scanners that failed or were unavailable",
    "fix_available_count": "the number of findings that already have a fix available",
    "total_findings": "the total number of findings across all scanners",
}


def label_for(feature_name: str) -> str:
    return FEATURE_LABELS.get(feature_name, feature_name.replace("_", " "))
