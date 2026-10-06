"""
Pydantic schemas used to validate incoming requests and shape outgoing
responses. Keeping these separate from the SQLAlchemy models (models.py)
means the API's public contract is explicit and controlled.
"""

from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, ConfigDict, field_validator


class PatientBase(BaseModel):
    first_name: str
    last_name: str
    date_of_birth: date
    gender: Optional[str] = None
    contact_number: Optional[str] = None
    email: Optional[EmailStr] = None
    address: Optional[str] = None
    medical_notes: Optional[str] = None

    @field_validator("first_name", "last_name")
    @classmethod
    def name_must_not_be_blank(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must not be blank")
        return value.strip()

    @field_validator("contact_number")
    @classmethod
    def contact_number_length(cls, value: Optional[str]) -> Optional[str]:
        if value and len(value) > 30:
            raise ValueError("contact_number must be 30 characters or fewer")
        return value


class PatientCreate(PatientBase):
    """Fields required to create a new patient record."""
    pass


class PatientUpdate(PatientBase):
    """Fields required to update an existing patient record."""
    pass


class PatientResponse(PatientBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
