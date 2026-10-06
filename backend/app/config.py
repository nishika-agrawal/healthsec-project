"""
Application configuration.

All settings are read from environment variables (loaded from a .env file
during local development). Nothing sensitive is hardcoded here.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # General
    APP_NAME: str = "Healthcare DevSecOps Risk Assessment Backend"
    APP_ENV: str = "development"

    # Database
    DATABASE_URL: str = "postgresql://healthsec_user:healthsec_pass@localhost:5432/healthsec_db"

    # Security
    SECRET_KEY: str = "change-this-secret-key-in-your-env-file"

    # JWT authentication
    JWT_SECRET_KEY: str = "change-this-jwt-secret-key-in-your-env-file"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Demo user seeded automatically on startup (Phase 3 only).
    # Change these in your .env file - do not use these defaults in production.
    DEMO_USERNAME: str = "demo_doctor"
    DEMO_PASSWORD: str = "ChangeMe123!"

    # CORS - comma separated list of allowed frontend origins
    CORS_ORIGINS: str = "http://localhost:5173"

    # Phase 8: Deployment decision policy - comma-separated list of scanners
    # that MUST report status "ok" for a build to be eligible for automatic
    # approval. Any scanner not in this list is informational only.
    DEPLOYMENT_MANDATORY_SCANNERS: str = "trivy,dependency_check,sonarqube"

    class Config:
        env_file = ".env"

    @property
    def cors_origin_list(self):
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def mandatory_scanners_list(self):
        return [s.strip() for s in self.DEPLOYMENT_MANDATORY_SCANNERS.split(",") if s.strip()]


settings = Settings()
