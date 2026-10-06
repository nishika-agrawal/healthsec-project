"""
Database integration for the security-assessment tables: storing a
processed scan result, and retrieving applications/scans/findings/features
back out again.
"""

from typing import Optional

from sqlalchemy.orm import Session

from app.security import models as security_models
from app.security.pipeline import ProcessedScanResult


def get_or_create_application(
    db: Session, name: str, repository_url: Optional[str] = None
) -> security_models.Application:
    application = (
        db.query(security_models.Application)
        .filter(security_models.Application.name == name)
        .first()
    )
    if application:
        return application

    application = security_models.Application(name=name, repository_url=repository_url)
    db.add(application)
    db.commit()
    db.refresh(application)
    return application


def create_scan_with_results(
    db: Session,
    application: security_models.Application,
    commit_sha: Optional[str],
    processed: ProcessedScanResult,
) -> security_models.Scan:
    scan = security_models.Scan(
        application_id=application.id,
        commit_sha=commit_sha,
        scanner_status=processed.scanner_statuses,
        scanner_errors=processed.scanner_errors,
    )
    db.add(scan)
    db.flush()  # assigns scan.id without committing yet

    for finding_data in processed.findings:
        db.add(security_models.Finding(scan_id=scan.id, **finding_data))

    features_data = dict(processed.features)
    features_data["duplicates_removed"] = processed.duplicates_removed
    db.add(security_models.ScanFeatures(scan_id=scan.id, **features_data))

    db.commit()
    db.refresh(scan)
    return scan


def get_scan_by_uuid(db: Session, scan_uuid: str) -> Optional[security_models.Scan]:
    return db.query(security_models.Scan).filter(security_models.Scan.scan_uuid == scan_uuid).first()


def get_application_by_name(db: Session, name: str) -> Optional[security_models.Application]:
    return (
        db.query(security_models.Application)
        .filter(security_models.Application.name == name)
        .first()
    )


def list_applications(db: Session) -> list:
    return db.query(security_models.Application).order_by(security_models.Application.name).all()


def list_all_scans(db: Session, skip: int = 0, limit: int = 50) -> list:
    return (
        db.query(security_models.Scan)
        .order_by(security_models.Scan.triggered_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def list_scans_for_application(
    db: Session, application_id: int, limit: int = 50
) -> list:
    return (
        db.query(security_models.Scan)
        .filter(security_models.Scan.application_id == application_id)
        .order_by(security_models.Scan.triggered_at.desc())
        .limit(limit)
        .all()
    )


def get_latest_scan_for_application(
    db: Session, application_id: int
) -> Optional[security_models.Scan]:
    return (
        db.query(security_models.Scan)
        .filter(security_models.Scan.application_id == application_id)
        .order_by(security_models.Scan.triggered_at.desc())
        .first()
    )


def list_findings_for_scan(db: Session, scan_id: int) -> list:
    return (
        db.query(security_models.Finding)
        .filter(security_models.Finding.scan_id == scan_id)
        .all()
    )


def get_features_for_scan(db: Session, scan_id: int) -> Optional[security_models.ScanFeatures]:
    return (
        db.query(security_models.ScanFeatures)
        .filter(security_models.ScanFeatures.scan_id == scan_id)
        .first()
    )
