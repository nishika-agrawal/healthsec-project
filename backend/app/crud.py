"""
Database CRUD (Create, Read, Update, Delete) helper functions for patients.
Kept separate from the route handlers so the logic is easy to unit test
and reuse.
"""

from typing import List, Optional

from sqlalchemy.orm import Session

from app import models, schemas


def get_patients(db: Session, skip: int = 0, limit: int = 100) -> List[models.Patient]:
    return (
        db.query(models.Patient)
        .order_by(models.Patient.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_patient(db: Session, patient_id: int) -> Optional[models.Patient]:
    return db.query(models.Patient).filter(models.Patient.id == patient_id).first()


def create_patient(db: Session, patient: schemas.PatientCreate) -> models.Patient:
    db_patient = models.Patient(**patient.model_dump())
    db.add(db_patient)
    db.commit()
    db.refresh(db_patient)
    return db_patient


def update_patient(
    db: Session, patient_id: int, patient: schemas.PatientUpdate
) -> Optional[models.Patient]:
    db_patient = get_patient(db, patient_id)
    if not db_patient:
        return None
    for field, value in patient.model_dump().items():
        setattr(db_patient, field, value)
    db.commit()
    db.refresh(db_patient)
    return db_patient


def delete_patient(db: Session, patient_id: int) -> Optional[models.Patient]:
    db_patient = get_patient(db, patient_id)
    if not db_patient:
        return None
    db.delete(db_patient)
    db.commit()
    return db_patient
