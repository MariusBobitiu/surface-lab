from typing import Any, Literal

from pydantic import BaseModel, Field


class PlannerSelection(BaseModel):
    selected_contracts: list[str] = Field(default_factory=list)
    skipped_contracts: list[str] = Field(default_factory=list)
    reasoning_summary: str
    confidence: Literal["low", "medium", "high"]
    source: Literal["llm", "deterministic"] = "llm"


class VulnerabilityResearchQuery(BaseModel):
    product: str
    version: str | None = None
    query_keywords: list[str] = Field(default_factory=list)
    rationale: str = ""


class VulnerabilityResearchPlan(BaseModel):
    queries: list[VulnerabilityResearchQuery] = Field(default_factory=list)
    reasoning_summary: str
    confidence: Literal["low", "medium", "high"]


class VulnerabilityResearchResult(BaseModel):
    product: str
    version: str | None = None
    query_keywords: list[str] = Field(default_factory=list)
    cpe_matches: list[dict[str, Any]] = Field(default_factory=list)
    cve_matches: list[dict[str, Any]] = Field(default_factory=list)


class AdvancedExecutionPlan(BaseModel):
    confidence: Literal["low", "medium", "high"]
    raw_selected_contracts: list[str] = Field(default_factory=list)
    executed_contracts: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


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
