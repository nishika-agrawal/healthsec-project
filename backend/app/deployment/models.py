"""
Database model for storing the deployment decision computed for a scan -
one row per scan, so deployment history (Phase 9's dashboard) can be
reconstructed directly from the database.
"""

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.sql import func

from app.database import Base


class DeploymentRecord(Base):
    __tablename__ = "deployment_decisions"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), unique=True, nullable=False)

    decision = Column(String(20), nullable=False)  # approved | review_required | blocked
    reason = Column(Text, nullable=False)
    mandatory_checks_passed = Column(Boolean, nullable=False)
    failed_checks = Column(JSON, nullable=True)  # list of scanner names, if any failed
    risk_category = Column(String(10), nullable=True)

    decided_at = Column(DateTime(timezone=True), server_default=func.now())
