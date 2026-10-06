"""
Pydantic schemas for the security-scan REST API (Phase 8).

Kept in the security package since these describe the security-scan
domain's request/response shapes, the same way app/schemas.py describes
the patient-record domain's.
"""

from datetime import date, datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, field_validator


class ApplicationResponse(BaseModel):
    id: int
    app_uuid: str
    name: str
    repository_url: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanSubmissionRequest(BaseModel):
    """Body for POST /scans. Report fields are optional - a missing report
    is handled gracefully by the pipeline (recorded as scanner status
    "missing"), never silently treated as "no vulnerabilities"."""

    app_name: str
    repository_url: Optional[str] = None
    commit_sha: Optional[str] = None
    trivy_report: Optional[Dict[str, Any]] = None
    dependency_check_report: Optional[Dict[str, Any]] = None
    sonarqube_report: Optional[Dict[str, Any]] = None

    @field_validator("app_name")
    @classmethod
    def app_name_not_blank(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("app_name must not be blank")
        return value.strip()


class ScanSummaryResponse(BaseModel):
    id: int
    scan_uuid: str
    application_id: int
    commit_sha: Optional[str] = None
    triggered_at: datetime
    scanner_status: Optional[Dict[str, str]] = None
    scanner_errors: Optional[Dict[str, Optional[str]]] = None

    model_config = ConfigDict(from_attributes=True)


class ScanFeaturesResponse(BaseModel):
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    max_cvss_score: Optional[float] = None
    vulnerable_dependency_count: int
    container_vulnerability_count: int
    security_rating: Optional[str] = None
    failed_security_checks: int
    fix_available_count: int
    total_findings: int
    duplicates_removed: int
    computed_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanDetailResponse(BaseModel):
    scan: ScanSummaryResponse
    features: Optional[ScanFeaturesResponse] = None


class FindingResponse(BaseModel):
    id: int
    source: str
    identifier: Optional[str] = None
    raw_severity: Optional[str] = None
    normalized_severity: str
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    fix_available: bool
    title: Optional[str] = None
    component: Optional[str] = None
    cvss_score: Optional[float] = None
    finding_class: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ScanSubmissionResponse(BaseModel):
    """The full result of POST /scans: everything computed in one call."""

    scan: ScanSummaryResponse
    features: ScanFeaturesResponse
    findings: List[FindingResponse]
    prediction: Dict[str, Any]
    explanation: Dict[str, Any]
    recommendations: Dict[str, Any]
    deployment_decision: Dict[str, Any]
