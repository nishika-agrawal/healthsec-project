"""
Parsers for each scanner's report format.

Every parser returns a ParseResult with:
- status: "ok" (parsed successfully, even if zero findings),
          "missing" (no report file/data was provided),
          "invalid" (file exists but isn't valid JSON / isn't the expected shape),
          "tool_unavailable" (the scanner itself reported it didn't run -
          currently only possible for SonarQube, via record_missing_sonar.py)
- findings: a list of dicts in the common format used across all sources:
    {
        "source": "trivy" | "dependency_check" | "sonarqube",
        "identifier": str | None,          # CVE ID or rule ID
        "raw_severity": str | None,
        "normalized_severity": str,        # SeverityLevel value
        "package_name": str | None,
        "installed_version": str | None,
        "fixed_version": str | None,
        "fix_available": bool,
        "title": str | None,
        "component": str | None,
        "cvss_score": float | None,
        "finding_class": str | None,
    }

Each scanner has two entry points:
- parse_<scanner>_report(path)  - reads and parses a report FILE (used by
  the Phase 5 CLI ingestion tool and the GitHub Actions pipeline output).
- parse_<scanner>_data(data)    - parses an already-loaded dict (used by
  the Phase 8 API, which receives report JSON directly in the request
  body - no temporary files needed).
Both ultimately run the same extraction logic.

A single malformed entry inside an otherwise valid report is skipped
rather than aborting the whole parse - see the try/except around each
per-item loop body.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app.security.normalize import normalize_severity


@dataclass
class ParseResult:
    source: str
    status: str  # "ok" | "missing" | "invalid" | "tool_unavailable"
    findings: list = field(default_factory=list)
    error: Optional[str] = None
    raw_meta: dict = field(default_factory=dict)


def _load_json(path: Path, source: str) -> "tuple[Optional[dict], Optional[ParseResult]]":
    """Shared file-loading logic. Returns (data, None) on success or (None, ParseResult) on failure."""
    if not path.exists():
        return None, ParseResult(source=source, status="missing", error=f"Report file not found: {path}")

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return None, ParseResult(source=source, status="invalid", error=f"Invalid JSON: {exc}")

    if not isinstance(data, dict):
        return None, ParseResult(source=source, status="invalid", error="Report root is not a JSON object")

    return data, None


def _extract_trivy_cvss(vuln: dict) -> Optional[float]:
    """Trivy nests CVSS scores per vendor (nvd, redhat, ghsa, ...) - take the highest V3 score found."""
    cvss_data = vuln.get("CVSS") or {}
    scores = []
    for vendor_data in cvss_data.values():
        if not isinstance(vendor_data, dict):
            continue
        score = vendor_data.get("V3Score")
        if isinstance(score, (int, float)):
            scores.append(float(score))
    return max(scores) if scores else None


def parse_trivy_data(data: dict) -> ParseResult:
    """Parses an already-loaded Trivy report dict (no file access)."""
    if not isinstance(data, dict):
        return ParseResult(source="trivy", status="invalid", error="Report root is not a JSON object")

    findings = []
    for result in data.get("Results", []) or []:
        target = result.get("Target")
        result_class = result.get("Class")
        for vuln in result.get("Vulnerabilities", []) or []:
            try:
                severity_raw = vuln.get("Severity", "")
                fixed_version = vuln.get("FixedVersion") or ""
                findings.append(
                    {
                        "source": "trivy",
                        "identifier": vuln.get("VulnerabilityID"),
                        "raw_severity": severity_raw,
                        "normalized_severity": normalize_severity(severity_raw, "trivy").value,
                        "package_name": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": fixed_version or None,
                        "fix_available": bool(fixed_version),
                        "title": vuln.get("Title") or vuln.get("VulnerabilityID"),
                        "component": target,
                        "cvss_score": _extract_trivy_cvss(vuln),
                        "finding_class": result_class,
                    }
                )
            except (TypeError, AttributeError):
                # Skip a single malformed entry rather than aborting the whole report.
                continue

    return ParseResult(
        source="trivy",
        status="ok",
        findings=findings,
        raw_meta={"artifact_name": data.get("ArtifactName")},
    )


def parse_trivy_report(path: Path) -> ParseResult:
    data, error_result = _load_json(path, "trivy")
    if error_result:
        return error_result
    return parse_trivy_data(data)


def parse_dependency_check_data(data: dict) -> ParseResult:
    """Parses an already-loaded OWASP Dependency-Check report dict (no file access)."""
    if not isinstance(data, dict):
        return ParseResult(source="dependency_check", status="invalid", error="Report root is not a JSON object")

    findings = []
    for dependency in data.get("dependencies", []) or []:
        file_name = dependency.get("fileName")
        file_path = dependency.get("filePath")
        for vuln in dependency.get("vulnerabilities", []) or []:
            try:
                severity_raw = vuln.get("severity", "")
                cvss_score = None
                cvssv3 = vuln.get("cvssv3") or {}
                if isinstance(cvssv3.get("baseScore"), (int, float)):
                    cvss_score = float(cvssv3["baseScore"])

                description = vuln.get("description") or vuln.get("name") or ""
                findings.append(
                    {
                        "source": "dependency_check",
                        "identifier": vuln.get("name"),
                        "raw_severity": severity_raw,
                        "normalized_severity": normalize_severity(severity_raw, "dependency_check").value,
                        "package_name": file_name,
                        "installed_version": None,
                        "fixed_version": None,
                        # OWASP Dependency-Check does not reliably report a fixed
                        # version, so fix availability isn't claimed here.
                        "fix_available": False,
                        "title": description[:300],
                        "component": file_path,
                        "cvss_score": cvss_score,
                        "finding_class": "dependency",
                    }
                )
            except (TypeError, AttributeError):
                continue

    return ParseResult(
        source="dependency_check",
        status="ok",
        findings=findings,
        raw_meta={"project_name": (data.get("projectInfo") or {}).get("name")},
    )


def parse_dependency_check_report(path: Path) -> ParseResult:
    data, error_result = _load_json(path, "dependency_check")
    if error_result:
        return error_result
    return parse_dependency_check_data(data)


def parse_sonarqube_data(data: dict) -> ParseResult:
    """
    Parses an already-loaded dict in the format produced by
    scripts/fetch_sonarqube_report.py (or scripts/record_missing_sonar.py) -
    not SonarQube's raw API response; those scripts already normalize the
    API output into this simpler shape.
    """
    if not isinstance(data, dict):
        return ParseResult(source="sonarqube", status="invalid", error="Report root is not a JSON object")

    if data.get("status") == "unavailable":
        return ParseResult(
            source="sonarqube",
            status="tool_unavailable",
            error=data.get("reason"),
            raw_meta={"quality_gate_status": data.get("quality_gate_status")},
        )

    findings = []
    for issue in data.get("issues", []) or []:
        try:
            severity_raw = issue.get("severity", "")
            findings.append(
                {
                    "source": "sonarqube",
                    "identifier": issue.get("rule"),
                    "raw_severity": severity_raw,
                    "normalized_severity": normalize_severity(severity_raw, "sonarqube").value,
                    "package_name": None,
                    "installed_version": None,
                    "fixed_version": None,
                    "fix_available": False,
                    "title": issue.get("message") or issue.get("rule"),
                    "component": issue.get("component"),
                    "cvss_score": None,
                    "finding_class": issue.get("type"),
                }
            )
        except (TypeError, AttributeError):
            continue

    return ParseResult(
        source="sonarqube",
        status="ok",
        findings=findings,
        raw_meta={
            "quality_gate_status": data.get("quality_gate_status"),
            "total_issues": data.get("total_issues"),
        },
    )


def parse_sonarqube_report(path: Path) -> ParseResult:
    data, error_result = _load_json(path, "sonarqube")
    if error_result:
        return error_result
    return parse_sonarqube_data(data)
