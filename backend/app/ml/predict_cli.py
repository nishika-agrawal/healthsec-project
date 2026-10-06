"""
Integrates Phase 5 (security data processing) with Phase 6 (ML risk
prediction): loads a stored scan's computed features from the database,
runs risk prediction, and stores the result back, tied to that scan.

Usage (from the backend/ folder, with the virtualenv activated and
DATABASE_URL pointing at the database you already stored a scan in via
app.security.ingest):

    python -m app.ml.predict_cli --scan-uuid <uuid-from-ingest-output>
"""

import argparse

from app.database import Base, SessionLocal, engine
from app.ml import models as ml_models  # noqa: F401 - registers the risk_predictions table
from app.ml import repository as ml_repository
from app.ml.predictor import predict_risk
from app.security import models as security_models  # noqa: F401 - registers scan/finding tables
from app.security import repository as security_repository


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run risk prediction for a scan already stored by app.security.ingest."
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

        scan_uuid = scan.scan_uuid
    finally:
        db.close()

    print(f"Risk prediction for scan {scan_uuid}:")
    print(f"  Risk category: {prediction['risk_category']}")
    print(f"  Risk score (0-100, deterministic rule): {prediction['risk_score']}")
    print(f"  Predicted probability (ML confidence, if applicable): {prediction['predicted_probability']}")
    print(f"  Model used: {prediction['model_used']}")


if __name__ == "__main__":
    main()
