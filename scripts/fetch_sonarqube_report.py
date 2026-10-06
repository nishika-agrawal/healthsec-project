"""
Fetches static-analysis results from SonarQube (or SonarCloud) and saves
them as a single JSON report, so they can sit as a pipeline artifact
alongside the Trivy and OWASP Dependency-Check reports.

This runs AFTER the actual SonarQube scan step in the CI pipeline (the
scan step analyzes the code and uploads results to the SonarQube server;
this script pulls a summary back down).

Required environment variables:
  SONAR_HOST_URL     e.g. https://sonarcloud.io
  SONAR_TOKEN        authentication token
  SONAR_PROJECT_KEY  must match sonar.projectKey in sonar-project.properties

If the server can't be reached, or credentials are missing, this script
does NOT crash - it writes a report with "status": "unavailable" so
later phases can treat "SonarQube didn't run" as a known, visible state
instead of guessing or silently skipping it.
"""

import json
import os
import sys
from pathlib import Path

import requests

DEFAULT_OUTPUT_PATH = Path("reports/sonarqube/sonarqube-report.json")


def build_unavailable_report(reason: str) -> dict:
    return {
        "scanner": "sonarqube",
        "status": "unavailable",
        "reason": reason,
        "issues": [],
        "quality_gate_status": None,
    }


def fetch_report() -> dict:
    host = os.environ.get("SONAR_HOST_URL")
    token = os.environ.get("SONAR_TOKEN")
    project_key = os.environ.get("SONAR_PROJECT_KEY")

    if not host or not token or not project_key:
        return build_unavailable_report(
            "Missing SONAR_HOST_URL, SONAR_TOKEN, or SONAR_PROJECT_KEY environment variable."
        )

    auth = (token, "")

    try:
        issues_resp = requests.get(
            f"{host}/api/issues/search",
            params={"componentKeys": project_key, "resolved": "false"},
            auth=auth,
            timeout=30,
        )
        issues_resp.raise_for_status()
        issues_data = issues_resp.json()

        gate_resp = requests.get(
            f"{host}/api/qualitygates/project_status",
            params={"projectKey": project_key},
            auth=auth,
            timeout=30,
        )
        gate_resp.raise_for_status()
        gate_data = gate_resp.json()

    except requests.RequestException as exc:
        return build_unavailable_report(f"Could not reach SonarQube server: {exc}")

    issues = [
        {
            "rule": issue.get("rule"),
            "severity": issue.get("severity"),
            "type": issue.get("type"),
            "component": issue.get("component"),
            "message": issue.get("message"),
            "line": issue.get("line"),
        }
        for issue in issues_data.get("issues", [])
    ]

    return {
        "scanner": "sonarqube",
        "status": "ok",
        "project_key": project_key,
        "total_issues": issues_data.get("total", len(issues)),
        "issues": issues,
        "quality_gate_status": gate_data.get("projectStatus", {}).get("status"),
    }


def main(output_path: Path = DEFAULT_OUTPUT_PATH):
    report = fetch_report()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2))
    print(f"SonarQube report written to {output_path} (status: {report['status']})")
    return report


if __name__ == "__main__":
    main()
