"""
Security-scan REST API (Phase 8).

Every endpoint requires authentication (the same JWT bearer scheme used
by /patients - see app.auth.get_current_user), and follows the same
structure as the Phase 3 patients router: a resource-oriented path,
Pydantic request/response models, and 404s for missing resources.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import models
from app.auth import get_current_user
from app.database import get_db
from app.deployment import repository as deployment_repository
from app.deployment.policy import decide_deployment
from app.deployment.schemas import DeploymentDecisionResponse, DeploymentHistoryItem
from app.ml import repository as ml_repository
from app.ml.predictor import get_loaded_model, predict_risk
from app.ml.schemas import PredictionResponse
from app.security import models as security_models
from app.security import repository as security_repository
from app.security.pipeline import process_report_data
from app.security.schemas import (
    ApplicationResponse,
    FindingResponse,
    ScanDetailResponse,
    ScanFeaturesResponse,
    ScanSubmissionRequest,
    ScanSubmissionResponse,
    ScanSummaryResponse,
)
from app.xai import repository as xai_repository
from app.xai.explainer import explain_prediction
from app.xai.recommendations import generate_recommendations
from app.xai.schemas import ExplanationResponse, RecommendationsResponse

router = APIRouter(tags=["Security Scans"])


# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------


def _get_scan_or_404(db: Session, scan_uuid: str):
    scan = security_repository.get_scan_by_uuid(db, scan_uuid)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


def _features_row_to_dict(features_row) -> dict:
    return {
        "critical_count": features_row.critical_count,
        "high_count": features_row.high_count,
        "medium_count": features_row.medium_count,
        "low_count": features_row.low_count,
        "max_cvss_score": features_row.max_cvss_score,
        "vulnerable_dependency_count": features_row.vulnerable_dependency_count,
        "container_vulnerability_count": features_row.container_vulnerability_count,
        "failed_security_checks": features_row.failed_security_checks,
        "fix_available_count": features_row.fix_available_count,
        "total_findings": features_row.total_findings,
    }


def _finding_rows_to_dicts(finding_rows: list) -> List[dict]:
    return [
        {
            "source": f.source,
            "identifier": f.identifier,
            "normalized_severity": f.normalized_severity,
            "package_name": f.package_name,
            "installed_version": f.installed_version,
            "fixed_version": f.fixed_version,
            "fix_available": f.fix_available,
            "title": f.title,
            "component": f.component,
            "cvss_score": f.cvss_score,
            "finding_class": f.finding_class,
        }
        for f in finding_rows
    ]


def _run_predict_explain_recommend_decide(
    db: Session, scan, features_dict: dict, findings: List[dict]
) -> dict:
    """
    The shared pipeline step used by both POST /scans (right after a new
    scan is created) and POST /scans/{scan_uuid}/predict (to re-run this
    step for an already-stored scan, e.g. after retraining the model).
    Runs prediction, explanation, recommendations, and the deployment
    decision, storing each result, and returns them all together.
    """
    prediction = predict_risk(features_dict)
    ml_repository.save_prediction(db, scan.id, prediction)

    model = get_loaded_model() if prediction["model_used"] == "random_forest" else None
    explanation = explain_prediction(features_dict, prediction, model=model)
    xai_repository.save_explanation(db, scan.id, explanation)

    recommendation_result = generate_recommendations(findings)
    xai_repository.save_recommendations(db, scan.id, recommendation_result)

    decision = decide_deployment(prediction["risk_category"], scan.scanner_status or {})
    deployment_repository.save_deployment_decision(db, scan.id, decision)

    return {
        "prediction": prediction,
        "explanation": explanation,
        "recommendations": recommendation_result,
        "deployment_decision": decision,
    }


# ---------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------


@router.get("/applications", response_model=List[ApplicationResponse])
def list_applications(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return security_repository.list_applications(db)


# ---------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------


@router.post("/scans", response_model=ScanSubmissionResponse, status_code=status.HTTP_201_CREATED)
def submit_scan(
    payload: ScanSubmissionRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Submits raw scanner report JSON (any of the three may be omitted - a
    missing report is recorded as that scanner's status being "missing",
    never silently treated as "no vulnerabilities"). Runs the full
    pipeline - parsing, feature extraction, risk prediction, explanation,
    recommendations, and the deployment decision - and stores everything.
    """
    application = security_repository.get_or_create_application(
        db, name=payload.app_name, repository_url=payload.repository_url
    )

    processed = process_report_data(
        trivy_data=payload.trivy_report,
        dependency_check_data=payload.dependency_check_report,
        sonarqube_data=payload.sonarqube_report,
    )

    scan = security_repository.create_scan_with_results(
        db, application, commit_sha=payload.commit_sha, processed=processed
    )

    results = _run_predict_explain_recommend_decide(db, scan, processed.features, processed.findings)

    features_row = security_repository.get_features_for_scan(db, scan.id)
    finding_rows = security_repository.list_findings_for_scan(db, scan.id)

    return ScanSubmissionResponse(
        scan=ScanSummaryResponse.model_validate(scan),
        features=ScanFeaturesResponse.model_validate(features_row),
        findings=[FindingResponse.model_validate(f) for f in finding_rows],
        prediction=results["prediction"],
        explanation=results["explanation"],
        recommendations=results["recommendations"],
        deployment_decision=results["deployment_decision"],
    )


@router.get("/scans", response_model=List[ScanSummaryResponse])
def list_scan_history(
    application_name: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if application_name:
        application = security_repository.get_application_by_name(db, application_name)
        if not application:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
        return security_repository.list_scans_for_application(db, application.id, limit=limit)

    return security_repository.list_all_scans(db, skip=skip, limit=limit)


@router.get("/scans/{scan_uuid}", response_model=ScanDetailResponse)
def get_scan_detail(
    scan_uuid: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = _get_scan_or_404(db, scan_uuid)
    features_row = security_repository.get_features_for_scan(db, scan.id)
    return ScanDetailResponse(
        scan=ScanSummaryResponse.model_validate(scan),
        features=ScanFeaturesResponse.model_validate(features_row) if features_row else None,
    )


@router.get("/scans/{scan_uuid}/findings", response_model=List[FindingResponse])
def get_scan_findings(
    scan_uuid: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = _get_scan_or_404(db, scan_uuid)
    return security_repository.list_findings_for_scan(db, scan.id)


@router.get("/scans/{scan_uuid}/prediction", response_model=PredictionResponse)
def get_scan_prediction(
    scan_uuid: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = _get_scan_or_404(db, scan_uuid)
    prediction = ml_repository.get_prediction_for_scan(db, scan.id)
    if not prediction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No prediction found for this scan yet. POST /scans/{scan_uuid}/predict to generate one.",
        )
    return prediction


@router.post("/scans/{scan_uuid}/predict", response_model=ScanSubmissionResponse)
def regenerate_scan_prediction(
    scan_uuid: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Re-runs prediction, explanation, recommendations, and the deployment
    decision for an already-stored scan - useful after retraining the
    model (Phase 6) without needing to resubmit the original reports.
    """
    scan = _get_scan_or_404(db, scan_uuid)
    features_row = security_repository.get_features_for_scan(db, scan.id)
    if not features_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No computed features found for this scan."
        )
    finding_rows = security_repository.list_findings_for_scan(db, scan.id)

    features_dict = _features_row_to_dict(features_row)
    findings = _finding_rows_to_dicts(finding_rows)

    results = _run_predict_explain_recommend_decide(db, scan, features_dict, findings)

    return ScanSubmissionResponse(
        scan=ScanSummaryResponse.model_validate(scan),
        features=ScanFeaturesResponse.model_validate(features_row),
        findings=[FindingResponse.model_validate(f) for f in finding_rows],
        prediction=results["prediction"],
        explanation=results["explanation"],
        recommendations=results["recommendations"],
        deployment_decision=results["deployment_decision"],
    )


@router.get("/scans/{scan_uuid}/explanation", response_model=ExplanationResponse)
def get_scan_explanation(
    scan_uuid: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = _get_scan_or_404(db, scan_uuid)
    explanation = xai_repository.get_explanation_for_scan(db, scan.id)
    if not explanation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No explanation found for this scan yet. POST /scans/{scan_uuid}/predict to generate one.",
        )
    return explanation


@router.get("/scans/{scan_uuid}/recommendations", response_model=RecommendationsResponse)
def get_scan_recommendations(
    scan_uuid: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = _get_scan_or_404(db, scan_uuid)
    recommendations = xai_repository.get_recommendations_for_scan(db, scan.id)
    if not recommendations:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No recommendations found for this scan yet. POST /scans/{scan_uuid}/predict to generate them.",
        )
    return recommendations


@router.get("/scans/{scan_uuid}/deployment-decision", response_model=DeploymentDecisionResponse)
def get_scan_deployment_decision(
    scan_uuid: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = _get_scan_or_404(db, scan_uuid)
    decision = deployment_repository.get_deployment_decision_for_scan(db, scan.id)
    if not decision:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No deployment decision found for this scan yet. POST /scans/{scan_uuid}/predict to generate one.",
        )
    return decision


# ---------------------------------------------------------------------
# Deployment history (across all scans)
# ---------------------------------------------------------------------


@router.get("/deployments", response_model=List[DeploymentHistoryItem])
def list_deployment_history(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Deployment decision history, enriched with which scan/application/
    commit each decision belongs to - needed for the dashboard's
    Deployment History section (application version, decision, reason).
    """
    records = deployment_repository.list_deployment_history(db, skip=skip, limit=limit)

    items = []
    for record in records:
        scan = db.query(security_models.Scan).filter(security_models.Scan.id == record.scan_id).first()
        application_name = None
        if scan:
            application = (
                db.query(security_models.Application)
                .filter(security_models.Application.id == scan.application_id)
                .first()
            )
            application_name = application.name if application else None

        items.append(
            DeploymentHistoryItem(
                decision=record.decision,
                reason=record.reason,
                mandatory_checks_passed=record.mandatory_checks_passed,
                failed_checks=record.failed_checks,
                risk_category=record.risk_category,
                decided_at=record.decided_at,
                scan_id=record.scan_id,
                scan_uuid=scan.scan_uuid if scan else None,
                application_name=application_name,
                commit_sha=scan.commit_sha if scan else None,
            )
        )

    return items
