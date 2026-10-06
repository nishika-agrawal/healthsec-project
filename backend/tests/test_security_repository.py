from pathlib import Path

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.security import repository
from app.security.pipeline import process_reports

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "reports" / "samples"


def _process_sample_reports():
    return process_reports(
        trivy_path=SAMPLES_DIR / "sample-trivy-report.json",
        dependency_check_path=SAMPLES_DIR / "sample-dependency-check-report.json",
        sonarqube_path=SAMPLES_DIR / "sample-sonarqube-report.json",
    )


def test_store_and_retrieve_a_full_scan():
    # "with TestClient(app)" triggers the FastAPI lifespan, which creates
    # all tables (including the security ones) on the shared test database.
    with TestClient(app):
        db = SessionLocal()
        try:
            application = repository.get_or_create_application(
                db, name="healthsec-demo-app", repository_url="https://github.com/example/healthsec-demo"
            )
            assert application.id is not None
            assert application.app_uuid

            processed = _process_sample_reports()
            scan = repository.create_scan_with_results(
                db, application, commit_sha="abc1234", processed=processed
            )

            assert scan.id is not None
            assert scan.scan_uuid
            assert scan.application_id == application.id

            # Findings were actually persisted.
            findings = repository.list_findings_for_scan(db, scan.id)
            assert len(findings) == len(processed.findings)
            assert len(findings) > 0

            # Features were persisted and match what the pipeline computed.
            features = repository.get_features_for_scan(db, scan.id)
            assert features is not None
            assert features.critical_count == processed.features["critical_count"]
            assert features.total_findings == processed.features["total_findings"]
            assert features.security_rating == processed.features["security_rating"]

            # Retrieval helpers work.
            fetched_by_uuid = repository.get_scan_by_uuid(db, scan.scan_uuid)
            assert fetched_by_uuid.id == scan.id

            latest = repository.get_latest_scan_for_application(db, application.id)
            assert latest.id == scan.id

            scans_for_app = repository.list_scans_for_application(db, application.id)
            assert scan.id in [s.id for s in scans_for_app]
        finally:
            db.close()


def test_get_or_create_application_does_not_duplicate():
    with TestClient(app):
        db = SessionLocal()
        try:
            first = repository.get_or_create_application(db, name="repeat-app-test")
            second = repository.get_or_create_application(db, name="repeat-app-test")
            assert first.id == second.id
        finally:
            db.close()


def test_scan_records_scanner_status_and_errors_for_missing_reports(tmp_path):
    with TestClient(app):
        db = SessionLocal()
        try:
            application = repository.get_or_create_application(db, name="partial-scan-app-test")

            processed = process_reports(
                trivy_path=tmp_path / "missing-trivy.json",
                dependency_check_path=tmp_path / "missing-depcheck.json",
                sonarqube_path=tmp_path / "missing-sonar.json",
            )
            scan = repository.create_scan_with_results(
                db, application, commit_sha=None, processed=processed
            )

            assert scan.scanner_status == {
                "trivy": "missing",
                "dependency_check": "missing",
                "sonarqube": "missing",
            }
            features = repository.get_features_for_scan(db, scan.id)
            assert features.total_findings == 0
            assert features.failed_security_checks == 3
        finally:
            db.close()
