"""
Integrates Phase 5 (stored findings/features), Phase 6 (risk prediction),
and Phase 7 (explanation + recommendations) for one scan.

Usage (from the backend/ folder, with the virtualenv activated and
DATABASE_URL pointing at the database you stored a scan in via
app.security.ingest):

    python -m app.xai.explain_cli --scan-uuid <uuid-from-ingest-output>

This re-runs prediction (so the explanation always matches the latest
prediction) and then explains it and generates recommendations from the
scan's actual stored findings.
"""

import argparse

from app.database import Base, SessionLocal, engine
from app.ml import models as ml_models  # noqa: F401
from app.ml import repository as ml_repository
from app.ml.predictor import get_loaded_model, predict_risk
from app.security import models as security_models  # noqa: F401
from app.security import repository as security_repository
from app.xai import models as xai_models  # noqa: F401 - registers explanations/recommendation_sets tables
from app.xai import repository as xai_repository
from app.xai.explainer import explain_prediction
from app.xai.recommendations import generate_recommendations


def parse_args():
    parser = argparse.ArgumentParser(
        description="Explain a scan's risk prediction and generate recommendations."
    )
    parser.add_argument("--scan-uuid", required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        scan = security_repository.get_scan_by_uuid(db, args.scan_uuid)
        if not scan:
            print(f"No scan found with UUID {args.scan_uuid}. Run app.security.ingest first.")
            return

        features_row = security_repository.get_features_for_scan(db, scan.id)
        if not features_row:
            print(f"No computed features found for scan {args.scan_uuid}.")
            return

        findings_rows = security_repository.list_findings_for_scan(db, scan.id)
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
        ml_repository.save_prediction(db, scan.id, prediction)

        model = get_loaded_model() if prediction["model_used"] == "random_forest" else None
        explanation = explain_prediction(features_dict, prediction, model=model)
        xai_repository.save_explanation(db, scan.id, explanation)

        recommendation_result = generate_recommendations(findings)
        xai_repository.save_recommendations(db, scan.id, recommendation_result)

        scan_uuid = scan.scan_uuid
    finally:
        db.close()

    print(f"=== Explanation for scan {scan_uuid} ===")
    print(f"Predicted category: {prediction['risk_category']} (method: {explanation['method']})")
    print(explanation["summary"])
    print("\nTop contributing features:")
    for c in explanation["contributions"]:
        print(f"  - {c['feature']} = {c['value']}  ({c['direction']}, contribution={c['contribution']:.3f})")

    print(f"\n=== Recommendations ===")
    summary = recommendation_result["summary"]
    print(
        f"Critical: {summary['critical_count']}, High: {summary['high_count']} "
        f"(each listed below) | Medium noted: {summary['medium_noted']}, Low noted: {summary['low_noted']}"
    )
    for rec in recommendation_result["recommendations"]:
        print(f"  [{rec['priority']}] {rec['action']}")
        print(f"      -> linked finding: {rec['linked_finding']}")


if __name__ == "__main__":
    main()
