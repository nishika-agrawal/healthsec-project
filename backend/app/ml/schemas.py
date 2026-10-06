from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class PredictionResponse(BaseModel):
    risk_category: str
    predicted_probability: Optional[float] = None
    risk_score: float
    model_used: str
    model_version: Optional[str] = None
    predicted_at: datetime

    model_config = ConfigDict(from_attributes=True, protected_namespaces=())
