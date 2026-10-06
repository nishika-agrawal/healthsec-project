"""
Database connection setup.

This creates a SQLAlchemy engine and session factory pointed at the
database defined by DATABASE_URL (PostgreSQL for normal use). SQLite is
also supported so the automated test suite can run without requiring a
running PostgreSQL server.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import settings

# SQLite needs this extra flag when used with FastAPI's TestClient because
# requests may be handled on a different thread than the one that created
# the connection. PostgreSQL does not need this.
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    FastAPI dependency that provides a database session per request
    and closes it afterward, even if an error occurs.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
