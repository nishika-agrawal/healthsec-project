"""
Orchestrates the full data-processing pipeline: parse all three scanner
reports (from files OR from already-loaded data), combine and deduplicate
their findings, and compute structured features - ready to be stored in
the database (see repository.py).
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app.security.dedupe import deduplicate_findings
from app.security.features import compute_scan_features
from app.security.parsers import (
    ParseResult,
    parse_dependency_check_data,
    parse_dependency_check_report,
    parse_sonarqube_data,
    parse_sonarqube_report,
    parse_trivy_data,
    parse_trivy_report,
)


@dataclass
class ProcessedScanResult:
    findings: list
    features: dict
    scanner_statuses: dict
    scanner_errors: dict
    duplicates_removed: int = 0
    raw_meta: dict = field(default_factory=dict)


def _combine_results(
    trivy_result: ParseResult,
    dependency_check_result: ParseResult,
    sonarqube_result: ParseResult,
) -> ProcessedScanResult:
    all_findings = (
        trivy_result.findings + dependency_check_result.findings + sonarqube_result.findings
    )
    deduped_findings, duplicates_removed = deduplicate_findings(all_findings)

    scanner_statuses = {
        "trivy": trivy_result.status,
        "dependency_check": dependency_check_result.status,
        "sonarqube": sonarqube_result.status,
    }
    scanner_errors = {
        "trivy": trivy_result.error,
        "dependency_check": dependency_check_result.error,
        "sonarqube": sonarqube_result.error,
    }

    features = compute_scan_features(deduped_findings, scanner_statuses)

    # A failing SonarQube Quality Gate is itself a failed security check,
    # separate from whether the SonarQube scan ran successfully at all.
    if sonarqube_result.raw_meta.get("quality_gate_status") == "ERROR":
        features["failed_security_checks"] += 1

    return ProcessedScanResult(
        findings=deduped_findings,
        features=features,
        scanner_statuses=scanner_statuses,
        scanner_errors=scanner_errors,
        duplicates_removed=duplicates_removed,
        raw_meta={
            "trivy": trivy_result.raw_meta,
            "dependency_check": dependency_check_result.raw_meta,
            "sonarqube": sonarqube_result.raw_meta,
        },
    )


def process_reports(
    trivy_path: Path,
    dependency_check_path: Path,
    sonarqube_path: Path,
) -> ProcessedScanResult:
    """Used by the Phase 5 CLI (app.security.ingest) - reads reports from files on disk."""
    trivy_result = parse_trivy_report(Path(trivy_path))
    dependency_check_result = parse_dependency_check_report(Path(dependency_check_path))
    sonarqube_result = parse_sonarqube_report(Path(sonarqube_path))
    return _combine_results(trivy_result, dependency_check_result, sonarqube_result)


def process_report_data(
    trivy_data: Optional[dict],
    dependency_check_data: Optional[dict],
    sonarqube_data: Optional[dict],
) -> ProcessedScanResult:
    """
    Used by the Phase 8 API (POST /scans) - accepts already-parsed report
    JSON directly from the request body. A None value for any report
    means that scanner's data wasn't submitted, and is recorded as
    "missing" - exactly like a missing file would be for process_reports.
    """
    trivy_result = (
        parse_trivy_data(trivy_data)
        if trivy_data is not None
        else ParseResult(source="trivy", status="missing", error="No Trivy report was submitted.")
    )
    dependency_check_result = (
        parse_dependency_check_data(dependency_check_data)
        if dependency_check_data is not None
        else ParseResult(
            source="dependency_check", status="missing", error="No Dependency-Check report was submitted."
        )
    )
    sonarqube_result = (
        parse_sonarqube_data(sonarqube_data)
        if sonarqube_data is not None
        else ParseResult(source="sonarqube", status="missing", error="No SonarQube report was submitted.")
    )

    return _combine_results(trivy_result, dependency_check_result, sonarqube_result)
