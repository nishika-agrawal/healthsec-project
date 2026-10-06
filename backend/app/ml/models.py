"""
Database model for storing the risk prediction computed for a scan.

Kept in its own module (rather than inside app/security/models.py) since
this belongs to the ML part of the system, not the security-scan data
processing part - Phase 5's tables stay unchanged. The link back to a
scan is by foreign key only (no ORM relationship declared on Scan) to
avoid a circular import between app.security.models and app.ml.models.
"""

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.sql import func

from app.database import Base


class RiskPrediction(Base):
    __tablename__ = "risk_predictions"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), unique=True, nullable=False)

    risk_category = Column(String(10), nullable=False)  # Low | Medium | High
    predicted_probability = Column(Float, nullable=True)  # ML confidence; None for rule-based fallback
    risk_score = Column(Float, nullable=False)  # 0-100 deterministic rule-based score
    model_used = Column(String(30), nullable=False)  # random_forest | rule_based_fallback
    model_version = Column(String(50), nullable=True)

    predicted_at = Column(DateTime(timezone=True), server_default=func.now())
