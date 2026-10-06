"""
Tests for scripts/fetch_sonarqube_report.py.

Run with: pytest scripts/tests/test_fetch_sonarqube_report.py -v
(from the project root, so the "scripts" package can be found)
"""

import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts import fetch_sonarqube_report as fetcher


def test_missing_env_vars_returns_unavailable(monkeypatch):
    monkeypatch.delenv("SONAR_HOST_URL", raising=False)
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    monkeypatch.delenv("SONAR_PROJECT_KEY", raising=False)

    report = fetcher.fetch_report()

    assert report["status"] == "unavailable"
    assert "Missing" in report["reason"]
    assert report["issues"] == []


def test_network_failure_returns_unavailable_not_a_crash(monkeypatch):
    monkeypatch.setenv("SONAR_HOST_URL", "https://sonar.example.invalid")
    monkeypatch.setenv("SONAR_TOKEN", "fake-token")
    monkeypatch.setenv("SONAR_PROJECT_KEY", "healthsec-devsecops-framework")

    def raise_connection_error(*args, **kwargs):
        raise requests.ConnectionError("simulated network failure")

    monkeypatch.setattr(requests, "get", raise_connection_error)

    report = fetcher.fetch_report()

    assert report["status"] == "unavailable"
    assert "Could not reach SonarQube server" in report["reason"]


def test_successful_fetch_parses_issues_and_quality_gate(monkeypatch):
    monkeypatch.setenv("SONAR_HOST_URL", "https://sonar.example.invalid")
    monkeypatch.setenv("SONAR_TOKEN", "fake-token")
    monkeypatch.setenv("SONAR_PROJECT_KEY", "healthsec-devsecops-framework")

    class FakeResponse:
        def __init__(self, json_data):
            self._json_data = json_data

        def raise_for_status(self):
            pass

        def json(self):
            return self._json_data

    def fake_get(url, params=None, auth=None, timeout=None):
        if "issues/search" in url:
            return FakeResponse(
                {
                    "total": 1,
                    "issues": [
                        {
                            "rule": "python:S5445",
                            "severity": "CRITICAL",
                            "type": "VULNERABILITY",
                            "component": "backend/app/security.py",
                            "message": "Example illustrative finding for testing.",
                            "line": 12,
                        }
                    ],
                }
            )
        if "qualitygates/project_status" in url:
            return FakeResponse({"projectStatus": {"status": "ERROR"}})
        raise AssertionError(f"Unexpected URL called in test: {url}")

    monkeypatch.setattr(requests, "get", fake_get)

    report = fetcher.fetch_report()

    assert report["status"] == "ok"
    assert report["total_issues"] == 1
    assert report["quality_gate_status"] == "ERROR"
    assert report["issues"][0]["rule"] == "python:S5445"


def test_main_writes_report_file(tmp_path, monkeypatch):
    monkeypatch.delenv("SONAR_HOST_URL", raising=False)
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    monkeypatch.delenv("SONAR_PROJECT_KEY", raising=False)

    output_path = tmp_path / "sonarqube" / "sonarqube-report.json"
    report = fetcher.main(output_path)

    assert output_path.exists()
    assert report["status"] == "unavailable"
