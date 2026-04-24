from typing import Any
from typing_extensions import NotRequired, TypedDict

from schemas.planner import (
    AdvancedContractExecutionResult,
    AdvancedExecutionPlan,
    PlannerSelection,
    VulnerabilityResearchPlan,
    VulnerabilityResearchResult,
)
from schemas.scan import EnrichedFindingResponse, EnrichedReportResponse, FindingResponse, ScanReportResponse, ScanStepResponse, SignalResponse
from services.baseline_context import BaselineContext


class EnrichedReportGraphState(TypedDict):
    scan_id: str
    target: NotRequired[str]
    scan: NotRequired[dict[str, Any]]
    baseline_result: NotRequired[dict[str, Any]]
    baseline_context: NotRequired[BaselineContext]
    steps: NotRequired[list[ScanStepResponse]]
    baseline_findings: NotRequired[list[FindingResponse]]
    baseline_signals: NotRequired[list[SignalResponse]]
    findings: NotRequired[list[FindingResponse]]
    selected_contracts: NotRequired[list[str]]
    executed_contracts: NotRequired[list[str]]
    failed_contracts: NotRequired[list[str]]
    retryable_contracts: NotRequired[list[str]]
    retry_counts: NotRequired[dict[str, int]]
    replan_count: NotRequired[int]
    merged_findings: NotRequired[list[FindingResponse]]
    result_quality: NotRequired[str]
    execution_notes: NotRequired[list[str]]
    report: NotRequired[ScanReportResponse]
    enriched_findings: NotRequired[list[EnrichedFindingResponse]]
    planner_result: NotRequired[PlannerSelection]
    vulnerability_research_plan: NotRequired[VulnerabilityResearchPlan]
    vulnerability_research_results: NotRequired[list[VulnerabilityResearchResult]]
    advanced_execution_plan: NotRequired[AdvancedExecutionPlan]
    advanced_results: NotRequired[list[AdvancedContractExecutionResult]]
    summary_output: NotRequired[dict[str, Any]]
    final_report: NotRequired[EnrichedReportResponse]
    nvd_enabled: bool
    ollama_enabled: bool
