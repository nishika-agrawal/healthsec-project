"""
Tests for authentication and patient record CRUD endpoints.

Run with:  pytest tests/ -v
"""

from fastapi.testclient import TestClient

from app.main import app

DEMO_USERNAME = "demo_doctor"
DEMO_PASSWORD = "ChangeMe123!"

SAMPLE_PATIENT = {
    "first_name": "Jane",
    "last_name": "Doe",
    "date_of_birth": "1990-05-01",
    "gender": "female",
    "contact_number": "555-0100",
    "email": "jane.doe@example.com",
    "address": "123 Synthetic Street",
    "medical_notes": "No known allergies (synthetic test data).",
}


def get_auth_headers(client: TestClient) -> dict:
    response = client.post(
        "/auth/login",
        data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_login_with_correct_credentials_succeeds():
    with TestClient(app) as client:
        response = client.post(
            "/auth/login",
            data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["token_type"] == "bearer"
        assert body["access_token"]


def test_login_with_wrong_password_fails():
    with TestClient(app) as client:
        response = client.post(
            "/auth/login",
            data={"username": DEMO_USERNAME, "password": "wrong-password"},
        )
        assert response.status_code == 401


def test_patients_endpoint_requires_authentication():
    with TestClient(app) as client:
        response = client.get("/patients")
        assert response.status_code == 401


def test_full_patient_crud_flow():
    with TestClient(app) as client:
        headers = get_auth_headers(client)

        # Create
        create_response = client.post("/patients", json=SAMPLE_PATIENT, headers=headers)
        assert create_response.status_code == 201
        created_patient = create_response.json()
        patient_id = created_patient["id"]
        assert created_patient["first_name"] == "Jane"

        # List - the new patient should appear
        list_response = client.get("/patients", headers=headers)
        assert list_response.status_code == 200
        assert any(p["id"] == patient_id for p in list_response.json())

        # Retrieve single record
        get_response = client.get(f"/patients/{patient_id}", headers=headers)
        assert get_response.status_code == 200
        assert get_response.json()["last_name"] == "Doe"

        # Update
        updated_data = dict(SAMPLE_PATIENT)
        updated_data["medical_notes"] = "Updated synthetic note for testing."
        update_response = client.put(
            f"/patients/{patient_id}", json=updated_data, headers=headers
        )
        assert update_response.status_code == 200
        assert update_response.json()["medical_notes"] == "Updated synthetic note for testing."

        # Delete
        delete_response = client.delete(f"/patients/{patient_id}", headers=headers)
        assert delete_response.status_code == 204

        # Confirm it's gone
        get_after_delete = client.get(f"/patients/{patient_id}", headers=headers)
        assert get_after_delete.status_code == 404


def test_get_nonexistent_patient_returns_404():
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        response = client.get("/patients/999999", headers=headers)
        assert response.status_code == 404


def test_create_patient_with_blank_name_is_rejected():
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        invalid_patient = dict(SAMPLE_PATIENT)
        invalid_patient["first_name"] = "   "
        response = client.post("/patients", json=invalid_patient, headers=headers)
        assert response.status_code == 422


def test_create_patient_with_invalid_email_is_rejected():
    with TestClient(app) as client:
        headers = get_auth_headers(client)
        invalid_patient = dict(SAMPLE_PATIENT)
        invalid_patient["email"] = "not-a-valid-email"
        response = client.post("/patients", json=invalid_patient, headers=headers)
        assert response.status_code == 422
