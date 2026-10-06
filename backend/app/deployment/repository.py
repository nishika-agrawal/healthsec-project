"""
Database integration for deployment decisions: save (create-or-update)
and retrieve a scan's deployment decision, and list decision history.
"""

from typing import Optional

from sqlalchemy.orm import Session

from app.deployment import models as deployment_models


def save_deployment_decision(
    db: Session, scan_id: int, decision: dict
) -> deployment_models.DeploymentRecord:
    existing = (
        db.query(deployment_models.DeploymentRecord)
        .filter(deployment_models.DeploymentRecord.scan_id == scan_id)
        .first()
    )

    if existing:
        existing.decision = decision["decision"]
        existing.reason = decision["reason"]
        existing.mandatory_checks_passed = decision["mandatory_checks_passed"]
        existing.failed_checks = decision["failed_checks"]
        existing.risk_category = decision["risk_category"]
        db.commit()
        db.refresh(existing)
        return existing

    record = deployment_models.DeploymentRecord(
        scan_id=scan_id,
        decision=decision["decision"],
        reason=decision["reason"],
        mandatory_checks_passed=decision["mandatory_checks_passed"],
        failed_checks=decision["failed_checks"],
        risk_category=decision["risk_category"],
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_deployment_decision_for_scan(
    db: Session, scan_id: int
) -> Optional[deployment_models.DeploymentRecord]:
    return (
        db.query(deployment_models.DeploymentRecord)
        .filter(deployment_models.DeploymentRecord.scan_id == scan_id)
        .first()
    )


def list_deployment_history(db: Session, skip: int = 0, limit: int = 50) -> list:
    return (
        db.query(deployment_models.DeploymentRecord)
        .order_by(deployment_models.DeploymentRecord.decided_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
