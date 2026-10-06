"""
Pytest configuration.

These environment variables must be set BEFORE app modules are imported,
so the app connects to a throwaway SQLite file instead of requiring a
running PostgreSQL server just to run the test suite.
"""

import os

os.environ["DATABASE_URL"] = "sqlite:///./test_healthsec.db"
os.environ["JWT_SECRET_KEY"] = "test-only-secret-key"
os.environ["DEMO_USERNAME"] = "demo_doctor"
os.environ["DEMO_PASSWORD"] = "ChangeMe123!"

import pytest  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_database():
    yield
    test_db_file = "test_healthsec.db"
    if os.path.exists(test_db_file):
        os.remove(test_db_file)
