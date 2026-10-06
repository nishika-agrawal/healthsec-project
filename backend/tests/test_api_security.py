"""
Tests for the /scans, /applications, and /deployments API endpoints.

Uses real HTTP calls through FastAPI's TestClient against the same
throwaway SQLite database the rest of the backend test suite uses
(see tests/conftest.py).
"""

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

DEMO_USERNAME = "demo_doctor"
DEMO_PASSWORD = "ChangeMe123!"

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "reports" / "samples"


def get_auth_headers(client: TestClient) -> dict:
    response = client.post(
        "/auth/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD}
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _load_sample_reports() -> dict:
    import json

    return {
        "trivy_report": json.loads((SAMPLES_DIR / "sample-trivy-report.json").read_text()),
        "dependency_check_report": json.loads(
            (SAMPLES_DIR / "sample-dependency-check-report.json").read_text()
        ),
        "sonarqube_report": json.loads((SAMPLES_DIR / "sample-sonarqube-report.json").read_text()),
    }


# ---------------------------------------------------------------------
# Authentication enforcement
# ---------------------------------------------------------------------


def test_scans_endpoints_require_authentication():
    with TestClient(app) as client:
        assert client.get("/scans").status_code == 401
        assert client.post("/scans", json={"app_name": "x"}).status_code == 401
        assert client.get("/applications").status_code == 401
        assert client.get("/dashboard/stats?application_name=x").status_code == 401


# ---------------------------------------------------------------------
# Submission validation
# ---------------------------------------------------------------------


def test_submit_scan_rejects_blank_app_name():
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        response = client.post("/scans", json={"app_name": "   "}, headers=headers)
        assert response.status_code == 422


def test_submit_scan_with_no_reports_at_all_still_succeeds_with_missing_status():
    """
    Submitting a scan with every report omitted must not error, and must
    not be silently treated as "no vulnerabilities" - each scanner's
    status should be reported as "missing".
    """
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        response = client.post(
            "/scans", json={"app_name": "empty-scan-app-test"}, headers=headers
        )
        assert response.status_code == 201
        body = response.json()
        assert body["scan"]["scanner_status"] == {
            "trivy": "missing",
            "dependency_check": "missing",
            "sonarqube": "missing",
        }
        assert body["features"]["total_findings"] == 0
        # All checks failed -> deployment must be blocked regardless of risk.
        assert body["deployment_decision"]["decision"] == "blocked"
        assert body["deployment_decision"]["mandatory_checks_passed"] is False


# ---------------------------------------------------------------------
# Full submission -> retrieval flow with real sample data
# ---------------------------------------------------------------------


def test_full_submission_and_retrieval_flow():
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        payload = {
            "app_name": "api-test-app",
            "repository_url": "https://github.com/example/api-test-app",
            "commit_sha": "abc123",
            **_load_sample_reports(),
        }

        submit_response = client.post("/scans", json=payload, headers=headers)
        assert submit_response.status_code == 201
        body = submit_response.json()

        scan_uuid = body["scan"]["scan_uuid"]
        assert body["features"]["critical_count"] >= 1
        assert len(body["findings"]) > 0
        assert body["prediction"]["risk_category"] in ("Low", "Medium", "High")
        assert body["explanation"]["predicted_category"] == body["prediction"]["risk_category"]
        assert "recommendations" in body["recommendations"]
        assert body["deployment_decision"]["risk_category"] == body["prediction"]["risk_category"]

        # Application was created.
        apps_response = client.get("/applications", headers=headers)
        assert apps_response.status_code == 200
        assert any(a["name"] == "api-test-app" for a in apps_response.json())

        # Scan history includes it.
        history_response = client.get(
            "/scans", params={"application_name": "api-test-app"}, headers=headers
        )
        assert history_response.status_code == 200
        assert any(s["scan_uuid"] == scan_uuid for s in history_response.json())

        # Scan detail.
        detail_response = client.get(f"/scans/{scan_uuid}", headers=headers)
        assert detail_response.status_code == 200
        assert detail_response.json()["scan"]["scan_uuid"] == scan_uuid
        assert detail_response.json()["features"]["total_findings"] == body["features"]["total_findings"]

        # Findings.
        findings_response = client.get(f"/scans/{scan_uuid}/findings", headers=headers)
        assert findings_response.status_code == 200
        assert len(findings_response.json()) == len(body["findings"])

        # Prediction.
        prediction_response = client.get(f"/scans/{scan_uuid}/prediction", headers=headers)
        assert prediction_response.status_code == 200
        assert prediction_response.json()["risk_category"] == body["prediction"]["risk_category"]

        # Explanation.
        explanation_response = client.get(f"/scans/{scan_uuid}/explanation", headers=headers)
        assert explanation_response.status_code == 200
        assert len(explanation_response.json()["contributions"]) > 0

        # Recommendations.
        recommendations_response = client.get(f"/scans/{scan_uuid}/recommendations", headers=headers)
        assert recommendations_response.status_code == 200
        assert recommendations_response.json()["critical_count"] >= 1

        # Deployment decision.
        decision_response = client.get(f"/scans/{scan_uuid}/deployment-decision", headers=headers)
        assert decision_response.status_code == 200
        assert decision_response.json()["decision"] in ("approved", "review_required", "blocked")

        # Deployment history includes this scan.
        deployments_response = client.get("/deployments", headers=headers)
        assert deployments_response.status_code == 200
        matching = [d for d in deployments_response.json() if d["scan_id"] == body["scan"]["id"]]
        assert len(matching) == 1
        assert matching[0]["scan_uuid"] == scan_uuid
        assert matching[0]["application_name"] == "api-test-app"
        assert matching[0]["commit_sha"] == "abc123"

        # Dashboard stats reflect this scan.
        stats_response = client.get(
            "/dashboard/stats", params={"application_name": "api-test-app"}, headers=headers
        )
        assert stats_response.status_code == 200
        stats = stats_response.json()
        assert stats["total_scans"] == 1
        assert stats["latest_scan_uuid"] == scan_uuid
        assert stats["critical_count"] == body["features"]["critical_count"]
        assert stats["latest_risk_category"] == body["prediction"]["risk_category"]


def test_scan_not_found_returns_404_for_all_detail_endpoints():
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        fake_uuid = "00000000-0000-0000-0000-000000000000"

        assert client.get(f"/scans/{fake_uuid}", headers=headers).status_code == 404
        assert client.get(f"/scans/{fake_uuid}/findings", headers=headers).status_code == 404
        assert client.get(f"/scans/{fake_uuid}/prediction", headers=headers).status_code == 404
        assert client.get(f"/scans/{fake_uuid}/explanation", headers=headers).status_code == 404
        assert client.get(f"/scans/{fake_uuid}/recommendations", headers=headers).status_code == 404
        assert client.get(f"/scans/{fake_uuid}/deployment-decision", headers=headers).status_code == 404
        assert client.post(f"/scans/{fake_uuid}/predict", headers=headers).status_code == 404


def test_dashboard_stats_for_unknown_application_returns_404():
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        response = client.get(
            "/dashboard/stats", params={"application_name": "does-not-exist-app"}, headers=headers
        )
        assert response.status_code == 404


def test_dashboard_stats_for_application_with_zero_scans_is_safe():
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        # Create an application implicitly with a fully-empty scan, then
        # check a DIFFERENT never-scanned name returns 404 (covered above);
        # here we confirm the zero-scans branch doesn't error for an app
        # that exists but (hypothetically) has no scans - covered by
        # exercising get_or_create_application directly.
        from app.database import SessionLocal
        from app.security import repository as security_repository

        db = SessionLocal()
        try:
            security_repository.get_or_create_application(db, name="zero-scan-app-test")
        finally:
            db.close()

        response = client.get(
            "/dashboard/stats", params={"application_name": "zero-scan-app-test"}, headers=headers
        )
        assert response.status_code == 200
        body = response.json()
        assert body["total_scans"] == 0
        assert body["latest_scan_uuid"] is None
        assert body["critical_count"] is None


def test_regenerate_prediction_endpoint_updates_stored_results():
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        payload = {"app_name": "regen-test-app", **_load_sample_reports()}

        submit_response = client.post("/scans", json=payload, headers=headers)
        scan_uuid = submit_response.json()["scan"]["scan_uuid"]

        regen_response = client.post(f"/scans/{scan_uuid}/predict", headers=headers)
        assert regen_response.status_code == 200
        assert regen_response.json()["prediction"]["risk_category"] in ("Low", "Medium", "High")

        # The prediction is still retrievable afterward and consistent.
        prediction_response = client.get(f"/scans/{scan_uuid}/prediction", headers=headers)
        assert prediction_response.status_code == 200
        assert (
            prediction_response.json()["risk_category"]
            == regen_response.json()["prediction"]["risk_category"]
        )
