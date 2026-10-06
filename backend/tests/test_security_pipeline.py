from pathlib import Path

from app.security.pipeline import process_report_data, process_reports

# reports/samples/ lives at the project root: backend/tests -> backend -> project root
SAMPLES_DIR = Path(__file__).resolve().parents[2] / "reports" / "samples"


def test_pipeline_processes_the_real_sample_reports():
    processed = process_reports(
        trivy_path=SAMPLES_DIR / "sample-trivy-report.json",
        dependency_check_path=SAMPLES_DIR / "sample-dependency-check-report.json",
        sonarqube_path=SAMPLES_DIR / "sample-sonarqube-report.json",
    )

    # All three sample reports are valid, so all three scanners should be "ok".
    assert processed.scanner_statuses == {
        "trivy": "ok",
        "dependency_check": "ok",
        "sonarqube": "ok",
    }
    assert processed.duplicates_removed == 0
    assert processed.features["total_findings"] > 0
    assert processed.features["critical_count"] >= 1  # sample data includes a CRITICAL Trivy finding
    assert processed.features["security_rating"] == "F"  # highest severity present is CRITICAL

    # The sample SonarQube report has a failing quality gate, which should
    # be reflected as an additional failed security check.
    assert processed.features["failed_security_checks"] >= 1


def test_pipeline_handles_all_three_reports_missing(tmp_path):
    processed = process_reports(
        trivy_path=tmp_path / "no-trivy.json",
        dependency_check_path=tmp_path / "no-depcheck.json",
        sonarqube_path=tmp_path / "no-sonar.json",
    )

    assert processed.scanner_statuses == {
        "trivy": "missing",
        "dependency_check": "missing",
        "sonarqube": "missing",
    }
    assert processed.findings == []
    assert processed.features["total_findings"] == 0
    assert processed.features["security_rating"] == "A"
    # All three scanners failed to produce a usable report.
    assert processed.features["failed_security_checks"] == 3


def test_pipeline_handles_partial_availability(tmp_path):
    # Only Trivy's report exists; the other two are missing.
    trivy_report = tmp_path / "trivy-report.json"
    trivy_report.write_text(
        '{"ArtifactName": "test", "Results": [{"Target": "t", "Class": "os-pkgs", '
        '"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "pkg", '
        '"InstalledVersion": "1.0", "FixedVersion": "1.1", "Severity": "HIGH"}]}]}'
    )

    processed = process_reports(
        trivy_path=trivy_report,
        dependency_check_path=tmp_path / "missing-depcheck.json",
        sonarqube_path=tmp_path / "missing-sonar.json",
    )

    assert processed.scanner_statuses["trivy"] == "ok"
    assert processed.scanner_statuses["dependency_check"] == "missing"
    assert processed.scanner_statuses["sonarqube"] == "missing"
    assert processed.features["total_findings"] == 1
    assert processed.features["failed_security_checks"] == 2


# ---------------------------------------------------------------------
# process_report_data - used by the Phase 8 API (no file access)
# ---------------------------------------------------------------------


def test_process_report_data_all_missing():
    processed = process_report_data(trivy_data=None, dependency_check_data=None, sonarqube_data=None)

    assert processed.scanner_statuses == {
        "trivy": "missing",
        "dependency_check": "missing",
        "sonarqube": "missing",
    }
    assert processed.features["total_findings"] == 0
    assert processed.features["failed_security_checks"] == 3


def test_process_report_data_matches_file_based_pipeline_for_the_same_content():
    trivy_data = {
        "ArtifactName": "test",
        "Results": [
            {
                "Target": "t",
                "Class": "os-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-1",
                        "PkgName": "pkg",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.1",
                        "Severity": "HIGH",
                    }
                ],
            }
        ],
    }

    processed = process_report_data(
        trivy_data=trivy_data, dependency_check_data=None, sonarqube_data=None
    )

    assert processed.scanner_statuses["trivy"] == "ok"
    assert processed.features["total_findings"] == 1
    assert processed.features["high_count"] == 1
