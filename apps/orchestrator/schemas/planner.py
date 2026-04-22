from typing import Any, Literal

from pydantic import BaseModel, Field


class PlannerSelection(BaseModel):
    selected_contracts: list[str] = Field(default_factory=list)
    skipped_contracts: list[str] = Field(default_factory=list)
    reasoning_summary: str
    confidence: Literal["low", "medium", "high"]


class AdvancedContractFinding(BaseModel):
    tool_name: str
    type: str
    category: str
    title: str
    severity: str
    confidence: str
    evidence: str
    details: dict[str, Any] = Field(default_factory=dict)


class AdvancedContractExecutionResult(BaseModel):
    contract: str
    status: Literal["completed", "failed", "timed_out", "skipped"]
    findings: list[AdvancedContractFinding] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
