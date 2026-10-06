"""
Placeholder liveness tests from Phase 2.

Using "with TestClient(app) as client" ensures FastAPI's startup/shutdown
lifespan events run (table creation, demo user seeding) exactly as they
would when the real server starts.
"""

from fastapi.testclient import TestClient

from app.main import app


def test_root_endpoint():
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "message" in response.json()


def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
