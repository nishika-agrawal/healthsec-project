"""
Tests for app/deployment/gate_cli.py.

Run as real subprocesses (not direct function calls) since the script
calls sys.exit(), which would otherwise abort the test run.
"""

import json
import subprocess
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
SAMPLES_DIR = Path(__file__).resolve().parents[2] / "reports" / "samples"


def run_gate_cli(tmp_path, trivy_report, dependency_check_report, sonarqube_report, commit_sha="test-sha"):
    output_path = tmp_path / "deployment_decision.json"
    db_path = tmp_path / "gate_test.db"
    github_output_path = tmp_path / "github_output.txt"
    github_output_path.write_text("")

    env = {
        "PATH": "/usr/bin:/bin:" + str(Path(sys.executable).parent),
        "DATABASE_URL": f"sqlite:///{db_path}",
        "JWT_SECRET_KEY": "test-key",
        "GITHUB_OUTPUT": str(github_output_path),
    }

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.deployment.gate_cli",
            "--app-name",
            "gate-cli-test-app",
            "--commit-sha",
            commit_sha,
            "--trivy-report",
            str(trivy_report),
            "--dependency-check-report",
            str(dependency_check_report),
            "--sonarqube-report",
            str(sonarqube_report),
            "--output-path",
            str(output_path),
        ],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
    )

    decision_data = json.loads(output_path.read_text()) if output_path.exists() else None
    github_output = github_output_path.read_text()

    return result, decision_data, github_output


def test_gate_blocks_on_high_risk_sample_data(tmp_path):
    result, decision_data, github_output = run_gate_cli(
        tmp_path,
        SAMPLES_DIR / "sample-trivy-report.json",
        SAMPLES_DIR / "sample-dependency-check-report.json",
        SAMPLES_DIR / "sample-sonarqube-report.json",
    )

    assert result.returncode == 1
    assert decision_data["decision"] == "blocked"
    assert decision_data["risk_category"] == "High"
    assert "decision=blocked" in github_output


def test_gate_approves_clean_reports(tmp_path):
    trivy = tmp_path / "trivy.json"
    trivy.write_text(json.dumps({"ArtifactName": "clean", "Results": []}))
    depcheck = tmp_path / "depcheck.json"
    depcheck.write_text(json.dumps({"dependencies": []}))
    sonar = tmp_path / "sonar.json"
    sonar.write_text(
        json.dumps(
            {"scanner": "sonarqube", "status": "ok", "issues": [], "quality_gate_status": "OK", "total_issues": 0}
        )
    )

    result, decision_data, github_output = run_gate_cli(tmp_path, trivy, depcheck, sonar)

    assert result.returncode == 0
    assert decision_data["decision"] == "approved"
    assert decision_data["risk_category"] == "Low"
    assert "decision=approved" in github_output


def test_gate_blocks_when_reports_are_missing(tmp_path):
    result, decision_data, github_output = run_gate_cli(
        tmp_path,
        tmp_path / "missing-trivy.json",
        tmp_path / "missing-depcheck.json",
        tmp_path / "missing-sonar.json",
    )

    assert result.returncode == 1
    assert decision_data["decision"] == "blocked"
    assert decision_data["mandatory_checks_passed"] is False
    assert set(decision_data["failed_checks"]) == {"trivy", "dependency_check", "sonarqube"}


def test_gate_writes_decision_json_even_on_failure(tmp_path):
    result, decision_data, _ = run_gate_cli(
        tmp_path,
        tmp_path / "missing-trivy.json",
        tmp_path / "missing-depcheck.json",
        tmp_path / "missing-sonar.json",
    )
    # Even though the gate blocks (nonzero exit), the decision artifact
    # must still exist so it can be uploaded/inspected in CI.
    assert decision_data is not None
    assert "reason" in decision_data
