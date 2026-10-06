"""
Database integration for risk predictions: save a prediction for a scan
(creating or updating), and retrieve it back.
"""

from typing import Optional

from sqlalchemy.orm import Session

from app.ml import models as ml_models


def save_prediction(
    db: Session, scan_id: int, prediction: dict, model_version: Optional[str] = None
) -> ml_models.RiskPrediction:
    existing = (
        db.query(ml_models.RiskPrediction)
        .filter(ml_models.RiskPrediction.scan_id == scan_id)
        .first()
    )

    if existing:
        existing.risk_category = prediction["risk_category"]
        existing.predicted_probability = prediction["predicted_probability"]
        existing.risk_score = prediction["risk_score"]
        existing.model_used = prediction["model_used"]
        existing.model_version = model_version
        db.commit()
        db.refresh(existing)
        return existing

    record = ml_models.RiskPrediction(
        scan_id=scan_id,
        risk_category=prediction["risk_category"],
        predicted_probability=prediction["predicted_probability"],
        risk_score=prediction["risk_score"],
        model_used=prediction["model_used"],
        model_version=model_version,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_prediction_for_scan(db: Session, scan_id: int) -> Optional[ml_models.RiskPrediction]:
    return (
        db.query(ml_models.RiskPrediction)
        .filter(ml_models.RiskPrediction.scan_id == scan_id)
        .first()
    )
