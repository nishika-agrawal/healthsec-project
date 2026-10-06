from pathlib import Path

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.ml import repository as ml_repository
from app.ml.predictor import predict_risk
from app.security import repository as security_repository
from app.security.pipeline import process_reports

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "reports" / "samples"


def test_prediction_integrates_with_stored_scan_features():
    """
    End-to-end: process the sample reports (Phase 5), store the scan,
    load its features back out of the database, run risk prediction
    (Phase 6), and store + retrieve the prediction - all tied to the
    same scan.
    """
    with TestClient(app):
        db = SessionLocal()
        try:
            application = security_repository.get_or_create_application(
                db, name="ml-integration-test-app"
            )
            processed = process_reports(
                trivy_path=SAMPLES_DIR / "sample-trivy-report.json",
                dependency_check_path=SAMPLES_DIR / "sample-dependency-check-report.json",
                sonarqube_path=SAMPLES_DIR / "sample-sonarqube-report.json",
            )
            scan = security_repository.create_scan_with_results(
                db, application, commit_sha="ml-test-0001", processed=processed
            )

            features_row = security_repository.get_features_for_scan(db, scan.id)
            assert features_row is not None

            features_dict = {
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

            prediction = predict_risk(features_dict)
            # The sample data has 2 critical findings - this should not be "Low".
            assert prediction["risk_category"] in ("Medium", "High")

            saved = ml_repository.save_prediction(db, scan.id, prediction)
            assert saved.id is not None
            assert saved.risk_category == prediction["risk_category"]

            fetched = ml_repository.get_prediction_for_scan(db, scan.id)
            assert fetched is not None
            assert fetched.scan_id == scan.id
            assert fetched.risk_score == prediction["risk_score"]
        finally:
            db.close()


def test_saving_a_second_prediction_for_the_same_scan_updates_it_not_duplicates():
    with TestClient(app):
        db = SessionLocal()
        try:
            application = security_repository.get_or_create_application(
                db, name="ml-update-test-app"
            )
            processed = process_reports(
                trivy_path=SAMPLES_DIR / "sample-trivy-report.json",
                dependency_check_path=SAMPLES_DIR / "sample-dependency-check-report.json",
                sonarqube_path=SAMPLES_DIR / "sample-sonarqube-report.json",
            )
            scan = security_repository.create_scan_with_results(
                db, application, commit_sha="ml-test-0002", processed=processed
            )

            first_prediction = {
                "risk_category": "Low",
                "predicted_probability": 0.6,
                "risk_score": 10.0,
                "model_used": "random_forest",
            }
            ml_repository.save_prediction(db, scan.id, first_prediction)

            second_prediction = {
                "risk_category": "High",
                "predicted_probability": 0.9,
                "risk_score": 85.0,
                "model_used": "random_forest",
            }
            ml_repository.save_prediction(db, scan.id, second_prediction)

            fetched = ml_repository.get_prediction_for_scan(db, scan.id)
            assert fetched.risk_category == "High"
            assert fetched.risk_score == 85.0

            all_predictions = (
                db.query(type(fetched)).filter(type(fetched).scan_id == scan.id).all()
            )
            assert len(all_predictions) == 1  # updated in place, not duplicated
        finally:
            db.close()
