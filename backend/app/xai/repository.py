"""
Database integration for Phase 7: save/retrieve an explanation and a
recommendation set for a scan (create-or-update, same pattern as
app.ml.repository.save_prediction).
"""

from typing import Optional

from sqlalchemy.orm import Session

from app.xai import models as xai_models


def save_explanation(db: Session, scan_id: int, explanation: dict) -> xai_models.Explanation:
    existing = (
        db.query(xai_models.Explanation).filter(xai_models.Explanation.scan_id == scan_id).first()
    )

    if existing:
        existing.method = explanation["method"]
        existing.predicted_category = explanation["predicted_category"]
        existing.contributions = explanation["contributions"]
        existing.summary = explanation["summary"]
        db.commit()
        db.refresh(existing)
        return existing

    record = xai_models.Explanation(
        scan_id=scan_id,
        method=explanation["method"],
        predicted_category=explanation["predicted_category"],
        contributions=explanation["contributions"],
        summary=explanation["summary"],
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_explanation_for_scan(db: Session, scan_id: int) -> Optional[xai_models.Explanation]:
    return db.query(xai_models.Explanation).filter(xai_models.Explanation.scan_id == scan_id).first()


def save_recommendations(db: Session, scan_id: int, recommendation_result: dict) -> xai_models.RecommendationSet:
    existing = (
        db.query(xai_models.RecommendationSet)
        .filter(xai_models.RecommendationSet.scan_id == scan_id)
        .first()
    )

    summary = recommendation_result["summary"]

    if existing:
        existing.recommendations = recommendation_result["recommendations"]
        existing.critical_count = summary["critical_count"]
        existing.high_count = summary["high_count"]
        existing.medium_noted = summary["medium_noted"]
        existing.low_noted = summary["low_noted"]
        existing.unknown_noted = summary["unknown_noted"]
        db.commit()
        db.refresh(existing)
        return existing

    record = xai_models.RecommendationSet(
        scan_id=scan_id,
        recommendations=recommendation_result["recommendations"],
        critical_count=summary["critical_count"],
        high_count=summary["high_count"],
        medium_noted=summary["medium_noted"],
        low_noted=summary["low_noted"],
        unknown_noted=summary["unknown_noted"],
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_recommendations_for_scan(db: Session, scan_id: int) -> Optional[xai_models.RecommendationSet]:
    return (
        db.query(xai_models.RecommendationSet)
        .filter(xai_models.RecommendationSet.scan_id == scan_id)
        .first()
    )
