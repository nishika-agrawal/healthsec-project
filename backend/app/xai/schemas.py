from datetime import datetime
from typing import Any, Dict, List

from pydantic import BaseModel, ConfigDict


class ContributionItem(BaseModel):
    feature: str
    value: Any
    contribution: float
    direction: str


class ExplanationResponse(BaseModel):
    method: str
    predicted_category: str
    contributions: List[ContributionItem]
    summary: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RecommendationItem(BaseModel):
    priority: str
    category: str
    action: str
    linked_finding: Dict[str, Any]


class RecommendationsResponse(BaseModel):
    recommendations: List[RecommendationItem]
    critical_count: int
    high_count: int
    medium_noted: int
    low_noted: int
    unknown_noted: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
