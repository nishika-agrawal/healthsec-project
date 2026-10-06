"""
Normalizes each scanner's own severity vocabulary into one shared scale:
CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN.

- Trivy and OWASP Dependency-Check both already use CVSS-style severity
  words (CRITICAL/HIGH/MEDIUM/LOW), so they map almost directly.
- SonarQube uses its own severity scale (BLOCKER/CRITICAL/MAJOR/MINOR/INFO),
  which is mapped onto the same shared scale so all three sources can be
  compared and counted together.
"""

from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


_TRIVY_AND_DEPENDENCY_CHECK_MAP = {
    "CRITICAL": SeverityLevel.CRITICAL,
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "MODERATE": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
    "NEGLIGIBLE": SeverityLevel.LOW,
}

_SONARQUBE_MAP = {
    "BLOCKER": SeverityLevel.CRITICAL,
    "CRITICAL": SeverityLevel.CRITICAL,
    "MAJOR": SeverityLevel.HIGH,
    "MINOR": SeverityLevel.MEDIUM,
    "INFO": SeverityLevel.LOW,
}

_SOURCE_MAPS = {
    "trivy": _TRIVY_AND_DEPENDENCY_CHECK_MAP,
    "dependency_check": _TRIVY_AND_DEPENDENCY_CHECK_MAP,
    "sonarqube": _SONARQUBE_MAP,
}


def normalize_severity(raw_severity: str, source: str) -> SeverityLevel:
    """
    Maps a scanner's raw severity string to the shared SeverityLevel scale.
    Unknown or missing values map to SeverityLevel.UNKNOWN rather than
    raising an error, so a single unexpected value from a scanner never
    crashes the whole pipeline.
    """
    if not raw_severity:
        return SeverityLevel.UNKNOWN

    mapping = _SOURCE_MAPS.get(source, {})
    return mapping.get(raw_severity.strip().upper(), SeverityLevel.UNKNOWN)
