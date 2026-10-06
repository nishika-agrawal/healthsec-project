"""
Command-line tool: parse the three scanner reports, process them, and
store the results in the database.

Example usage (from the backend/ folder, with the virtualenv activated
and DATABASE_URL pointing at a real database):

    python -m app.security.ingest \\
        --app-name healthsec-demo \\
        --commit-sha abc1234 \\
        --trivy-report ../reports/trivy/trivy-report.json \\
        --dependency-check-report ../reports/dependency-check/dependency-check-report.json \\
        --sonarqube-report ../reports/sonarqube/sonarqube-report.json

Any report path that doesn't exist is handled gracefully by the
processing pipeline (that scanner is recorded as "missing") rather than
crashing this script.

NOTE: This is a standalone tool for Phase 5. It is not yet wired into the
GitHub Actions pipeline or exposed as a FastAPI endpoint - that
integration is added in Phase 8, once the deployment decision engine
also needs this same data.
"""

import argparse
from pathlib import Path

from app.database import Base, SessionLocal, engine
from app.security import models as security_models  # noqa: F401 - registers tables on Base
from app.security import pipeline as security_pipeline
from app.security import repository


def parse_args():
    parser = argparse.ArgumentParser(
        description="Parse security scan reports and store the results in the database."
    )
    parser.add_argument("--app-name", required=True, help="Name of the application being scanned")
    parser.add_argument("--repository-url", default=None)
    parser.add_argument("--commit-sha", default=None)
    parser.add_argument("--trivy-report", default="../reports/trivy/trivy-report.json")
    parser.add_argument(
        "--dependency-check-report", default="../reports/dependency-check/dependency-check-report.json"
    )
    parser.add_argument("--sonarqube-report", default="../reports/sonarqube/sonarqube-report.json")
    return parser.parse_args()


def main():
    args = parse_args()

    # Creates the security tables if they don't already exist (harmless if they do).
    Base.metadata.create_all(bind=engine)

    processed = security_pipeline.process_reports(
        trivy_path=Path(args.trivy_report),
        dependency_check_path=Path(args.dependency_check_report),
        sonarqube_path=Path(args.sonarqube_report),
    )

    db = SessionLocal()
    try:
        application = repository.get_or_create_application(
            db, name=args.app_name, repository_url=args.repository_url
        )
        scan = repository.create_scan_with_results(
            db, application, commit_sha=args.commit_sha, processed=processed
        )
        # Capture the values we need to print BEFORE closing the session -
        # after close(), SQLAlchemy objects can no longer lazily reload
        # attributes and would raise DetachedInstanceError.
        application_name = application.name
        scan_uuid = scan.scan_uuid
    finally:
        db.close()

    print(f"Stored scan {scan_uuid} for application '{application_name}'")
    print("Scanner statuses:", processed.scanner_statuses)
    print("Features:", processed.features)
    print(f"Duplicate findings removed: {processed.duplicates_removed}")


if __name__ == "__main__":
    main()
