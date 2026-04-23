from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ScanWorkflowEvent(BaseModel):
    scan_id: str
    type: str
    message: str
    timestamp: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)
