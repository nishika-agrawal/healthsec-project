"""
Database models for the security-assessment side of the project.

These are deliberately separate from the patient-record models
(app/models.py) - they belong to a different part of the system
(security scanning, not the healthcare demo app) and are additive:
nothing about Phase 3's User/Patient tables changes here.

Schema overview:
    Application  1 --- many  Scan
    Scan         1 --- many  Finding
    Scan         1 --- one   ScanFeatures
"""

import uuid

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class Application(Base):
    """An application/repository that gets scanned (e.g. the healthcare demo app)."""

    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)
    app_uuid = Column(String(36), unique=True, nullable=False, default=generate_uuid, index=True)
    name = Column(String(200), unique=True, nullable=False)
    repository_url = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scans = relationship("Scan", back_populates="application", cascade="all, delete-orphan")


class Scan(Base):
    """One run of the security pipeline (one commit/build) for an application."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_uuid = Column(String(36), unique=True, nullable=False, default=generate_uuid, index=True)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    commit_sha = Column(String(64), nullable=True)
    triggered_at = Column(DateTime(timezone=True), server_default=func.now())

    # Per-scanner status (e.g. {"trivy": "ok", "sonarqube": "tool_unavailable"})
    # and any error messages, kept as JSON so partial/failed scans are visible
    # rather than silently dropped.
    scanner_status = Column(JSON, nullable=True)
    scanner_errors = Column(JSON, nullable=True)

    application = relationship("Application", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    features = relationship(
        "ScanFeatures", back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )


class Finding(Base):
    """A single normalized vulnerability/issue extracted from a scanner report."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    source = Column(String(50), nullable=False)  # "trivy" | "dependency_check" | "sonarqube"
    identifier = Column(String(200), nullable=True)  # CVE ID or rule ID
    raw_severity = Column(String(50), nullable=True)  # original value from the scanner
    normalized_severity = Column(String(20), nullable=False)  # CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
    package_name = Column(String(300), nullable=True)
    installed_version = Column(String(100), nullable=True)
    fixed_version = Column(String(100), nullable=True)
    fix_available = Column(Boolean, default=False)
    title = Column(Text, nullable=True)
    component = Column(String(500), nullable=True)  # file path or scan target
    cvss_score = Column(Float, nullable=True)
    finding_class = Column(String(100), nullable=True)  # e.g. os-pkgs, VULNERABILITY

    scan = relationship("Scan", back_populates="findings")


class ScanFeatures(Base):
    """Aggregated, structured features computed for one scan - the ML model's input."""

    __tablename__ = "scan_features"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), unique=True, nullable=False)

    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    max_cvss_score = Column(Float, nullable=True)
    vulnerable_dependency_count = Column(Integer, default=0)
    container_vulnerability_count = Column(Integer, default=0)
    security_rating = Column(String(2), nullable=True)  # simple rule-based A-F label
    failed_security_checks = Column(Integer, default=0)
    fix_available_count = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    duplicates_removed = Column(Integer, default=0)
    computed_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="features")
