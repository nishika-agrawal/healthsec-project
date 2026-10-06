"""
Dashboard statistics API (Phase 8) - powers the "Overview" section of the
Phase 9 React dashboard. Stats are scoped to one application at a time,
since "total scans" / "latest risk" only make sense relative to a
specific application being tracked.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import models
from app.auth import get_current_user
from app.database import get_db
from app.deployment import repository as deployment_repository
from app.ml import repository as ml_repository
from app.security import repository as security_repository

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


class DashboardStatsResponse(BaseModel):
    application_name: str
    total_scans: int
    latest_scan_uuid: Optional[str] = None
    latest_scan_commit_sha: Optional[str] = None
    critical_count: Optional[int] = None
    high_count: Optional[int] = None
    latest_risk_category: Optional[str] = None
    latest_risk_score: Optional[float] = None
    latest_predicted_probability: Optional[float] = None
    latest_deployment_decision: Optional[str] = None


@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(
    application_name: str = Query(..., description="Name of the application to get stats for"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    application = security_repository.get_application_by_name(db, application_name)
    if not application:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")

    all_scans = security_repository.list_scans_for_application(db, application.id, limit=10_000)
    total_scans = len(all_scans)

    if total_scans == 0:
        return DashboardStatsResponse(application_name=application.name, total_scans=0)

    latest_scan = security_repository.get_latest_scan_for_application(db, application.id)
    features = security_repository.get_features_for_scan(db, latest_scan.id)
    prediction = ml_repository.get_prediction_for_scan(db, latest_scan.id)
    decision = deployment_repository.get_deployment_decision_for_scan(db, latest_scan.id)

    return DashboardStatsResponse(
        application_name=application.name,
        total_scans=total_scans,
        latest_scan_uuid=latest_scan.scan_uuid,
        latest_scan_commit_sha=latest_scan.commit_sha,
        critical_count=features.critical_count if features else None,
        high_count=features.high_count if features else None,
        latest_risk_category=prediction.risk_category if prediction else None,
        latest_risk_score=prediction.risk_score if prediction else None,
        latest_predicted_probability=prediction.predicted_probability if prediction else None,
        latest_deployment_decision=decision.decision if decision else None,
    )
