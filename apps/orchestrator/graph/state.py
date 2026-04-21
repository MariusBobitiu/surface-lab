from typing import Any
from typing_extensions import NotRequired, TypedDict

from schemas.scan import EnrichedFindingResponse, EnrichedReportResponse, FindingResponse, ScanReportResponse, ScanStepResponse


class EnrichedReportGraphState(TypedDict):
    scan_id: str
    scan: NotRequired[dict[str, Any]]
    steps: NotRequired[list[ScanStepResponse]]
    findings: NotRequired[list[FindingResponse]]
    report: NotRequired[ScanReportResponse]
    enriched_findings: NotRequired[list[EnrichedFindingResponse]]
    final_report: NotRequired[EnrichedReportResponse]
    nvd_enabled: bool
    ollama_enabled: bool
