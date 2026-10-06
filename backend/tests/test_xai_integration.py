from pathlib import Path

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.ml.predictor import get_loaded_model, predict_risk
from app.security import repository as security_repository
from app.security.pipeline import process_reports
from app.xai import repository as xai_repository
from app.xai.explainer import explain_prediction
from app.xai.recommendations import generate_recommendations

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "reports" / "samples"


def test_full_explain_and_recommend_pipeline_against_stored_scan():
    with TestClient(app):
        db = SessionLocal()
        try:
            application = security_repository.get_or_create_application(
                db, name="xai-integration-test-app"
            )
            processed = process_reports(
                trivy_path=SAMPLES_DIR / "sample-trivy-report.json",
                dependency_check_path=SAMPLES_DIR / "sample-dependency-check-report.json",
                sonarqube_path=SAMPLES_DIR / "sample-sonarqube-report.json",
            )
            scan = security_repository.create_scan_with_results(
                db, application, commit_sha="xai-test-0001", processed=processed
            )

            features_row = security_repository.get_features_for_scan(db, scan.id)
            findings_rows = security_repository.list_findings_for_scan(db, scan.id)

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
            findings = [
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
                for f in findings_rows
            ]

            prediction = predict_risk(features_dict)
            model = get_loaded_model() if prediction["model_used"] == "random_forest" else None
            explanation = explain_prediction(features_dict, prediction, model=model)
            recommendation_result = generate_recommendations(findings)

            saved_explanation = xai_repository.save_explanation(db, scan.id, explanation)
            saved_recommendations = xai_repository.save_recommendations(db, scan.id, recommendation_result)

            # Explanation matches the prediction it was computed from.
            assert saved_explanation.predicted_category == prediction["risk_category"]
            assert saved_explanation.method in ("shap_tree_explainer", "rule_based_breakdown")
            assert len(saved_explanation.contributions) > 0
            assert len(saved_explanation.summary) > 0

            # The sample data has critical findings - expect at least one recommendation.
            assert saved_recommendations.critical_count >= 1
            assert len(saved_recommendations.recommendations) >= 1
            for rec in saved_recommendations.recommendations:
                assert rec["linked_finding"]["identifier"] is not None

            # Retrieval works.
            fetched_explanation = xai_repository.get_explanation_for_scan(db, scan.id)
            assert fetched_explanation.id == saved_explanation.id

            fetched_recommendations = xai_repository.get_recommendations_for_scan(db, scan.id)
            assert fetched_recommendations.id == saved_recommendations.id
        finally:
            db.close()


def test_saving_explanation_twice_updates_rather_than_duplicates():
    with TestClient(app):
        db = SessionLocal()
        try:
            application = security_repository.get_or_create_application(
                db, name="xai-update-test-app"
            )
            processed = process_reports(
                trivy_path=SAMPLES_DIR / "sample-trivy-report.json",
                dependency_check_path=SAMPLES_DIR / "sample-dependency-check-report.json",
                sonarqube_path=SAMPLES_DIR / "sample-sonarqube-report.json",
            )
            scan = security_repository.create_scan_with_results(
                db, application, commit_sha="xai-test-0002", processed=processed
            )

            first = {
                "method": "rule_based_breakdown",
                "predicted_category": "Low",
                "contributions": [],
                "summary": "first summary",
            }
            second = {
                "method": "shap_tree_explainer",
                "predicted_category": "High",
                "contributions": [{"feature": "critical_count", "value": 2, "contribution": 0.3, "direction": "increases"}],
                "summary": "second summary",
            }

            xai_repository.save_explanation(db, scan.id, first)
            xai_repository.save_explanation(db, scan.id, second)

            fetched = xai_repository.get_explanation_for_scan(db, scan.id)
            assert fetched.summary == "second summary"
            assert fetched.predicted_category == "High"

            from app.xai.models import Explanation

            all_rows = db.query(Explanation).filter(Explanation.scan_id == scan.id).all()
            assert len(all_rows) == 1
        finally:
            db.close()
