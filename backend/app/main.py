"""
FastAPI application entry point.

On startup this:
1. Creates all database tables if they don't already exist.
2. Seeds a single demo user (from DEMO_USERNAME / DEMO_PASSWORD env vars)
   so the app is immediately usable without a manual registration step.

Real security-scan, ML, and dashboard endpoints are added in later phases.
"""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import models
from app.security import models as security_models  # noqa: F401 - registers scan/finding tables on Base
from app.ml import models as ml_models  # noqa: F401 - registers risk_predictions table on Base
from app.xai import models as xai_models  # noqa: F401 - registers explanations/recommendation_sets tables
from app.deployment import models as deployment_models  # noqa: F401 - registers deployment_decisions table
from app.config import settings
from app.database import Base, SessionLocal, engine, get_db
from app.routers import auth as auth_router
from app.routers import patients as patients_router
from app.routers import security as security_router
from app.routers import dashboard as dashboard_router
from app.auth_security import hash_password


def seed_demo_user() -> None:
    """Creates the demo login user if it does not already exist."""
    db = SessionLocal()
    try:
        existing_user = (
            db.query(models.User).filter(models.User.username == settings.DEMO_USERNAME).first()
        )
        if not existing_user:
            demo_user = models.User(
                username=settings.DEMO_USERNAME,
                hashed_password=hash_password(settings.DEMO_PASSWORD),
            )
            db.add(demo_user)
            db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    Base.metadata.create_all(bind=engine)
    seed_demo_user()
    yield
    # Shutdown (nothing to clean up yet)


app = FastAPI(
    title=settings.APP_NAME,
    description="Backend API for the Intelligent DevSecOps Risk Assessment Framework",
    version="0.2.0",
    lifespan=lifespan,
)

# Allow the React frontend (running on a different port) to call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(patients_router.router)
app.include_router(security_router.router)
app.include_router(dashboard_router.router)


@app.get("/")
def read_root():
    """Basic placeholder root endpoint."""
    return {
        "message": "Healthcare DevSecOps Risk Assessment API is running",
        "environment": settings.APP_ENV,
    }


@app.get("/health")
def health_check():
    """
    Simple liveness check. Does not touch the database.
    Used by Docker/CI to confirm the API process is up.
    """
    return {"status": "ok"}


@app.get("/health/db")
def health_check_db(db: Session = Depends(get_db)):
    """
    Confirms the API can actually reach and query the database.
    Returns status 'ok' if the database responds, 'error' otherwise.
    """
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected"}
    except Exception as exc:  # noqa: BLE001 - simple placeholder handler
        return {"status": "error", "database": "unreachable", "detail": str(exc)}
