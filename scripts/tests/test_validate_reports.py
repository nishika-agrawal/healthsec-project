"""
Tests for scripts/validate_reports.py.

Run with: pytest scripts/tests/test_validate_reports.py -v
(from the project root, so the "scripts" package can be found)
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.validate_reports import build_manifest, check_report


def write_report(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_check_report_missing_file(tmp_path):
    result = check_report(tmp_path / "does-not-exist.json")
    assert result["found"] is False
    assert result["valid_json"] is False
    assert "not found" in result["reason"]


def test_check_report_empty_file(tmp_path):
    report_path = tmp_path / "empty.json"
    write_report(report_path, "")
    result = check_report(report_path)
    assert result["found"] is True
    assert result["valid_json"] is False
    assert "empty" in result["reason"]


def test_check_report_invalid_json(tmp_path):
    report_path = tmp_path / "broken.json"
    write_report(report_path, "{not valid json")
    result = check_report(report_path)
    assert result["found"] is True
    assert result["valid_json"] is False
    assert "invalid JSON" in result["reason"]


def test_check_report_valid_json(tmp_path):
    report_path = tmp_path / "good.json"
    write_report(report_path, json.dumps({"hello": "world"}))
    result = check_report(report_path)
    assert result["found"] is True
    assert result["valid_json"] is True
    assert result["reason"] is None


def test_build_manifest_with_all_reports_present(tmp_path):
    write_report(tmp_path / "sonarqube" / "sonarqube-report.json", json.dumps({"a": 1}))
    write_report(tmp_path / "trivy" / "trivy-report.json", json.dumps({"b": 2}))
    write_report(
        tmp_path / "dependency-check" / "dependency-check-report.json",
        json.dumps({"c": 3}),
    )

    manifest = build_manifest(tmp_path)

    assert set(manifest.keys()) == {"sonarqube", "trivy", "dependency_check"}
    for scanner_result in manifest.values():
        assert scanner_result["found"] is True
        assert scanner_result["valid_json"] is True


def test_build_manifest_with_missing_reports(tmp_path):
    # No report files created at all.
    manifest = build_manifest(tmp_path)

    for scanner_result in manifest.values():
        assert scanner_result["found"] is False
        assert scanner_result["valid_json"] is False
