import json

from app.security.parsers import (
    parse_dependency_check_data,
    parse_dependency_check_report,
    parse_sonarqube_data,
    parse_sonarqube_report,
    parse_trivy_data,
    parse_trivy_report,
)


# ---------------------------------------------------------------------
# Shared behavior: missing / malformed files
# ---------------------------------------------------------------------


def test_trivy_missing_file_returns_missing_status(tmp_path):
    result = parse_trivy_report(tmp_path / "does-not-exist.json")
    assert result.status == "missing"
    assert result.findings == []


def test_trivy_malformed_json_returns_invalid_status(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not valid json")
    result = parse_trivy_report(path)
    assert result.status == "invalid"
    assert result.findings == []


def test_dependency_check_missing_file(tmp_path):
    result = parse_dependency_check_report(tmp_path / "missing.json")
    assert result.status == "missing"


def test_sonarqube_missing_file(tmp_path):
    result = parse_sonarqube_report(tmp_path / "missing.json")
    assert result.status == "missing"


# ---------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------


def test_parse_trivy_report_extracts_findings(tmp_path):
    report = {
        "ArtifactName": "test-image:latest",
        "Results": [
            {
                "Target": "test-image (debian 12)",
                "Class": "os-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "libfoo",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "Severity": "CRITICAL",
                        "Title": "Example vulnerability",
                        "CVSS": {"nvd": {"V3Score": 9.8}},
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0002",
                        "PkgName": "libbar",
                        "InstalledVersion": "2.0.0",
                        "FixedVersion": "",
                        "Severity": "LOW",
                        "Title": "No fix available example",
                    },
                ],
            }
        ],
    }
    path = tmp_path / "trivy-report.json"
    path.write_text(json.dumps(report))

    result = parse_trivy_report(path)

    assert result.status == "ok"
    assert len(result.findings) == 2

    critical_finding = next(f for f in result.findings if f["identifier"] == "CVE-2024-0001")
    assert critical_finding["normalized_severity"] == "CRITICAL"
    assert critical_finding["fix_available"] is True
    assert critical_finding["cvss_score"] == 9.8

    no_fix_finding = next(f for f in result.findings if f["identifier"] == "CVE-2024-0002")
    assert no_fix_finding["fix_available"] is False
    assert no_fix_finding["fixed_version"] is None


def test_parse_trivy_report_with_no_vulnerabilities_returns_empty_list(tmp_path):
    report = {"ArtifactName": "clean-image:latest", "Results": [{"Target": "clean-image", "Vulnerabilities": []}]}
    path = tmp_path / "trivy-clean.json"
    path.write_text(json.dumps(report))

    result = parse_trivy_report(path)

    assert result.status == "ok"
    assert result.findings == []


# ---------------------------------------------------------------------
# OWASP Dependency-Check
# ---------------------------------------------------------------------


def test_parse_dependency_check_report_extracts_findings(tmp_path):
    report = {
        "projectInfo": {"name": "test-project"},
        "dependencies": [
            {
                "fileName": "example-lib-1.0.0.tar.gz",
                "filePath": "backend/requirements.txt",
                "vulnerabilities": [
                    {
                        "name": "CVE-2024-9999",
                        "severity": "HIGH",
                        "cvssv3": {"baseScore": 7.5},
                        "description": "Example dependency vulnerability.",
                    }
                ],
            },
            {
                "fileName": "safe-lib-1.0.0.tar.gz",
                "filePath": "backend/requirements.txt",
                "vulnerabilities": [],
            },
        ],
    }
    path = tmp_path / "depcheck-report.json"
    path.write_text(json.dumps(report))

    result = parse_dependency_check_report(path)

    assert result.status == "ok"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["identifier"] == "CVE-2024-9999"
    assert finding["normalized_severity"] == "HIGH"
    assert finding["cvss_score"] == 7.5
    assert finding["package_name"] == "example-lib-1.0.0.tar.gz"


# ---------------------------------------------------------------------
# SonarQube (our own fetch_sonarqube_report.py output format)
# ---------------------------------------------------------------------


def test_parse_sonarqube_report_ok_status(tmp_path):
    report = {
        "scanner": "sonarqube",
        "status": "ok",
        "total_issues": 1,
        "issues": [
            {
                "rule": "python:S105",
                "severity": "MAJOR",
                "type": "VULNERABILITY",
                "component": "backend/app/config.py",
                "message": "Example issue.",
                "line": 10,
            }
        ],
        "quality_gate_status": "ERROR",
    }
    path = tmp_path / "sonar-ok.json"
    path.write_text(json.dumps(report))

    result = parse_sonarqube_report(path)

    assert result.status == "ok"
    assert len(result.findings) == 1
    assert result.findings[0]["normalized_severity"] == "HIGH"  # MAJOR -> HIGH
    assert result.raw_meta["quality_gate_status"] == "ERROR"


def test_parse_sonarqube_report_unavailable_status(tmp_path):
    report = {
        "scanner": "sonarqube",
        "status": "unavailable",
        "reason": "SONAR_TOKEN not configured.",
        "issues": [],
        "quality_gate_status": None,
    }
    path = tmp_path / "sonar-unavailable.json"
    path.write_text(json.dumps(report))

    result = parse_sonarqube_report(path)

    assert result.status == "tool_unavailable"
    assert result.findings == []
    assert "SONAR_TOKEN" in result.error


# ---------------------------------------------------------------------
# Data-based entry points (used by the Phase 8 API, no file access)
# ---------------------------------------------------------------------


def test_parse_trivy_data_matches_file_based_parsing():
    report = {
        "ArtifactName": "test-image:latest",
        "Results": [
            {
                "Target": "test-image",
                "Class": "os-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "libfoo",
                        "Severity": "HIGH",
                    }
                ],
            }
        ],
    }
    result = parse_trivy_data(report)
    assert result.status == "ok"
    assert len(result.findings) == 1
    assert result.findings[0]["identifier"] == "CVE-2024-0001"


def test_parse_trivy_data_rejects_non_dict_input():
    result = parse_trivy_data(["not", "a", "dict"])
    assert result.status == "invalid"


def test_parse_dependency_check_data_matches_file_based_parsing():
    report = {
        "dependencies": [
            {
                "fileName": "lib.jar",
                "vulnerabilities": [{"name": "CVE-2024-1", "severity": "MEDIUM"}],
            }
        ]
    }
    result = parse_dependency_check_data(report)
    assert result.status == "ok"
    assert len(result.findings) == 1


def test_parse_sonarqube_data_unavailable():
    report = {"status": "unavailable", "reason": "no token"}
    result = parse_sonarqube_data(report)
    assert result.status == "tool_unavailable"
