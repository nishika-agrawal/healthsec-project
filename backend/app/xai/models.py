"""
Database models for Phase 7: one Explanation and one RecommendationSet
per scan. Kept in their own module for the same reason as app/ml/models.py -
avoids a circular import with app/security/models.py, and keeps each
phase's tables clearly separated.
"""

from sqlalchemy import JSON, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.sql import func

from app.database import Base


class Explanation(Base):
    __tablename__ = "explanations"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), unique=True, nullable=False)

    method = Column(String(30), nullable=False)  # shap_tree_explainer | rule_based_breakdown
    predicted_category = Column(String(10), nullable=False)
    contributions = Column(JSON, nullable=False)  # list of {feature, value, contribution, direction}
    summary = Column(Text, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class RecommendationSet(Base):
    __tablename__ = "recommendation_sets"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), unique=True, nullable=False)

    recommendations = Column(JSON, nullable=False)  # list of recommendation dicts
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_noted = Column(Integer, default=0)
    low_noted = Column(Integer, default=0)
    unknown_noted = Column(Integer, default=0)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
