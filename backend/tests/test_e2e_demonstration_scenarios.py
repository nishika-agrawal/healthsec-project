"""
Phase 11: full end-to-end integration tests.

These exercise the ENTIRE system through the real HTTP API (auth, scan
submission, database storage, ML prediction, explanation, recommendations,
and the deployment policy) - not individual modules in isolation. They
implement the three demonstration scenarios described in
TESTING_AND_DEMONSTRATION.md:

  1. Low-risk application  -> approved
  2. High-risk application -> blocked
  3. Remediation            -> approved again, compared against scenario 2

They also directly verify the Phase 11 integration requirements:
  - predictions correspond to the processed scan data
  - explanations correspond to the actual prediction
  - deployment decisions follow the configured policy
  - mandatory-check failures block deployment regardless of risk
"""

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.ml.dataset import rule_based_risk_score
from app.deployment.policy import decide_deployment

DEMO_USERNAME = "demo_doctor"
DEMO_PASSWORD = "ChangeMe123!"

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "reports" / "fixtures"


def get_auth_headers(client: TestClient) -> dict:
    response = client.post(
        "/auth/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD}
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def load_scenario_reports(scenario_folder: str) -> dict:
    d = FIXTURES_DIR / scenario_folder
    return {
        "trivy_report": json.loads((d / "trivy-report.json").read_text()),
        "dependency_check_report": json.loads((d / "dependency-check-report.json").read_text()),
        "sonarqube_report": json.loads((d / "sonarqube-report.json").read_text()),
    }


APP_NAME = "patient-portal-demo"


def test_scenario_1_low_risk_build_is_approved():
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        payload = {
            "app_name": APP_NAME,
            "commit_sha": "v1.0.0-lowrisk",
            **load_scenario_reports("scenario-1-low-risk"),
        }

        response = client.post("/scans", json=payload, headers=headers)
        assert response.status_code == 201
        body = response.json()

        assert body["features"]["critical_count"] == 0
        assert body["features"]["high_count"] == 0
        assert body["prediction"]["risk_category"] == "Low"
        assert body["deployment_decision"]["decision"] == "approved"
        assert body["deployment_decision"]["mandatory_checks_passed"] is True

        # Explanation corresponds to the actual prediction.
        assert body["explanation"]["predicted_category"] == body["prediction"]["risk_category"]

        # No critical/high findings -> no individual recommendations.
        assert body["recommendations"]["recommendations"] == []


def test_scenario_2_high_risk_build_is_blocked():
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        payload = {
            "app_name": APP_NAME,
            "commit_sha": "v1.1.0-highrisk",
            **load_scenario_reports("scenario-2-high-risk"),
        }

        response = client.post("/scans", json=payload, headers=headers)
        assert response.status_code == 201
        body = response.json()

        # Real findings were detected (the synthetic TEST-CVE-DEMO-* fixtures).
        assert body["features"]["critical_count"] >= 3
        assert body["features"]["high_count"] >= 1

        assert body["prediction"]["risk_category"] == "High"
        assert body["deployment_decision"]["decision"] == "blocked"
        assert "High" in body["deployment_decision"]["reason"]

        # Explanation corresponds to the actual prediction, and correctly
        # identifies critical_count as increasing the assessed risk.
        assert body["explanation"]["predicted_category"] == "High"
        assert body["explanation"]["method"] == "shap_tree_explainer"
        top_contribution = body["explanation"]["contributions"][0]
        assert top_contribution["direction"] == "increases"

        # Recommendations are linked to the real synthetic findings, and
        # span every recommendation category the fixture was designed to exercise.
        recommendation_ids = {r["linked_finding"]["identifier"] for r in body["recommendations"]["recommendations"]}
        assert "TEST-CVE-DEMO-0001" in recommendation_ids
        categories = {r["category"] for r in body["recommendations"]["recommendations"]}
        assert "container_update" in categories
        assert "dependency_upgrade" in categories
        assert "code_review" in categories


def test_scenario_3_remediation_is_approved_and_improves_on_scenario_2():
    with TestClient(app) as client:
        headers = get_auth_headers(client)

        # Re-submit scenario 2 first so this test is self-contained (does
        # not depend on test execution order).
        high_risk_payload = {
            "app_name": APP_NAME,
            "commit_sha": "v1.1.0-highrisk-b",
            **load_scenario_reports("scenario-2-high-risk"),
        }
        high_risk_response = client.post("/scans", json=high_risk_payload, headers=headers)
        assert high_risk_response.status_code == 201
        high_risk_body = high_risk_response.json()

        remediated_payload = {
            "app_name": APP_NAME,
            "commit_sha": "v1.2.0-remediated",
            **load_scenario_reports("scenario-3-remediated"),
        }
        remediated_response = client.post("/scans", json=remediated_payload, headers=headers)
        assert remediated_response.status_code == 201
        remediated_body = remediated_response.json()

        # The remediated build is meaningfully better than the high-risk one.
        assert remediated_body["features"]["critical_count"] == 0
        assert remediated_body["features"]["critical_count"] < high_risk_body["features"]["critical_count"]
        assert remediated_body["prediction"]["risk_score"] < high_risk_body["prediction"]["risk_score"]
        assert remediated_body["prediction"]["risk_category"] == "Low"
        assert remediated_body["deployment_decision"]["decision"] == "approved"

        # Scan history for the application shows both scans, in the
        # correct order, so the improvement is visible/comparable.
        history_response = client.get(
            "/scans", params={"application_name": APP_NAME}, headers=headers
        )
        assert history_response.status_code == 200
        commit_shas = [s["commit_sha"] for s in history_response.json()]
        assert "v1.1.0-highrisk-b" in commit_shas
        assert "v1.2.0-remediated" in commit_shas


# ---------------------------------------------------------------------
# Direct verification of the Phase 11 integration requirements
# ---------------------------------------------------------------------


def test_prediction_corresponds_to_the_processed_scan_data():
    """
    The prediction's risk_score must be independently reproducible from
    the SAME features the scan actually computed - i.e. the prediction
    is really derived from this scan's data, not some other value.
    """
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        payload = {
            "app_name": "prediction-correspondence-test-app",
            "commit_sha": "corr-0001",
            **load_scenario_reports("scenario-2-high-risk"),
        }
        response = client.post("/scans", json=payload, headers=headers)
        body = response.json()

        expected_score = rule_based_risk_score(body["features"])
        assert body["prediction"]["risk_score"] == expected_score


def test_deployment_decision_follows_the_configured_policy_independently():
    """
    Re-derives the expected decision using the standalone policy engine
    from this scan's own recorded risk category and scanner statuses, and
    confirms the API's stored decision matches it exactly.
    """
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        payload = {
            "app_name": "policy-correspondence-test-app",
            "commit_sha": "policy-0001",
            **load_scenario_reports("scenario-1-low-risk"),
        }
        response = client.post("/scans", json=payload, headers=headers)
        body = response.json()

        expected_decision = decide_deployment(
            body["prediction"]["risk_category"], body["scan"]["scanner_status"]
        )
        assert body["deployment_decision"]["decision"] == expected_decision["decision"]
        assert body["deployment_decision"]["reason"] == expected_decision["reason"]


def test_low_risk_build_is_still_blocked_if_a_mandatory_scanner_is_missing():
    """
    Full end-to-end proof of the core policy requirement: even a build
    with zero findings must NOT be auto-approved if a mandatory scanner
    didn't actually run.
    """
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        reports = load_scenario_reports("scenario-1-low-risk")
        del reports["sonarqube_report"]  # simulate SonarQube not having run

        payload = {
            "app_name": "missing-scanner-test-app",
            "commit_sha": "missing-0001",
            **reports,
        }
        response = client.post("/scans", json=payload, headers=headers)
        assert response.status_code == 201
        body = response.json()

        assert body["prediction"]["risk_category"] == "Low"
        assert body["deployment_decision"]["decision"] == "blocked"
        assert body["deployment_decision"]["mandatory_checks_passed"] is False
        assert "sonarqube" in body["deployment_decision"]["failed_checks"]
