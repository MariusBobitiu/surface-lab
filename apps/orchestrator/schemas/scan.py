from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str


class ScanResponse(BaseModel):
    scan_id: str
    status: str


class ScanStepResponse(BaseModel):
    id: str
    tool_name: str
    status: str
    duration_ms: int
    raw_metadata: dict[str, Any]
    created_at: datetime


class FindingResponse(BaseModel):
    id: str
    tool_name: str
    type: str
    category: str
    title: str
    summary: str | None = None
    severity: str
    confidence: str
    evidence: str
    evidence_refs: list[str] = Field(default_factory=list)
    details: dict[str, Any]
    created_at: datetime


class SignalResponse(BaseModel):
    id: str
    tool_name: str
    key: str
    value: Any
    confidence: str
    source: str
    evidence_refs: list[str] = Field(default_factory=list)
    created_at: datetime


class EvidenceResponse(BaseModel):
    id: str
    tool_name: str
    kind: str
    target: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class ScanSummaryResponse(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class ScanDetailsResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    error_message: str | None
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    summary: ScanSummaryResponse
    steps: list[ScanStepResponse]
    findings: list[FindingResponse]
    signals: list[SignalResponse] = Field(default_factory=list)
    evidence: list[EvidenceResponse] = Field(default_factory=list)


class ReportSummaryResponse(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class ReportTopIssueResponse(BaseModel):
    tool_name: str
    title: str
    severity: str
    confidence: str
    evidence: str
    category: str
    details: dict[str, Any]


class ReportCategoryResponse(BaseModel):
    name: str
    slug: str
    count: int
    highest_severity: str
    findings: list[ReportTopIssueResponse]


class ScanReportResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    score: int
    summary: ReportSummaryResponse
    top_issues: list[ReportTopIssueResponse]
    categories: list[ReportCategoryResponse]
    created_at: datetime
    completed_at: datetime | None


class EnrichedFindingResponse(BaseModel):
    id: str
    tool_name: str
    type: str
    category: str
    title: str
    summary: str | None = None
    severity: str
    confidence: str
    evidence: str
    evidence_refs: list[str] = Field(default_factory=list)
    details: dict[str, Any]
    created_at: datetime
    owasp_category: str | None
    wstg_reference: str | None
    remediation_summary: str | None
    source_references: list[str]
    cve_matches: list[dict[str, Any]]
    cpe_matches: list[dict[str, Any]]


class EnrichedReportCategoryResponse(BaseModel):
    name: str
    slug: str
    count: int
    highest_severity: str
    findings: list[EnrichedFindingResponse]


class EnrichedReportResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    score: int
    summary: ReportSummaryResponse
    top_issues: list[EnrichedFindingResponse]
    categories: list[EnrichedReportCategoryResponse]
    created_at: datetime
    completed_at: datetime | None
    executive_summary: str | None = None
    quick_wins: list[str] = Field(default_factory=list)
