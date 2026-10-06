from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class DeploymentDecisionResponse(BaseModel):
    decision: str
    reason: str
    mandatory_checks_passed: bool
    failed_checks: Optional[List[str]] = None
    risk_category: Optional[str] = None
    decided_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DeploymentHistoryItem(DeploymentDecisionResponse):
    scan_id: int
    scan_uuid: Optional[str] = None
    application_name: Optional[str] = None
    commit_sha: Optional[str] = None
