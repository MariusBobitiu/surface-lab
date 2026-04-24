from schemas.scan import (
    EnrichedFindingResponse,
    EnrichedReportCategoryResponse,
    EnrichedReportResponse,
    FindingResponse,
    ReportCategoryResponse,
    ReportCheckCategoryResponse,
    ReportCheckResponse,
    ReportSummaryResponse,
    ReportTopIssueResponse,
    ScanReportResponse,
    ScanSummaryResponse,
    ScanStepResponse,
)
from schemas.planner import VulnerabilityResearchPlan, VulnerabilityResearchResult
from services.baseline_context import build_baseline_context, BaselineContext
from services.enrichment import enrich_findings
from services.llm import generate_vulnerability_control_matrix
from services.scans import build_summary, fetch_evidence, fetch_findings, fetch_scan, fetch_scan_steps, fetch_signals
from db.postgres import get_db_connection


CATEGORY_MAP = {
    "http_headers": ("http-headers", "HTTP Headers"),
    "public_files": ("public-exposure", "Public Exposure"),
    "sensitive_file_exposure": ("sensitive-file-exposure", "Sensitive File Exposure"),
    "fingerprint_server": ("technology-fingerprint", "Technology Fingerprint"),
    "fingerprint_framework": ("technology-fingerprint", "Technology Fingerprint"),
    "fingerprint_edge": ("technology-fingerprint", "Technology Fingerprint"),
    "fingerprint_generator": ("technology-fingerprint", "Technology Fingerprint"),
    "wordpress_fingerprint": ("wordpress-stack", "WordPress Stack"),
    "wordpress_surface": ("wordpress-stack", "WordPress Stack"),
    "wordpress_exposure": ("wordpress-stack", "WordPress Stack"),
    "wordpress_vulnerability": ("wordpress-stack", "WordPress Stack"),
    "nextjs_fingerprint": ("nextjs-stack", "Next.js Stack"),
    "nextjs_surface": ("nextjs-stack", "Next.js Stack"),
    "nextjs_exposure": ("nextjs-stack", "Next.js Stack"),
    "nextjs_vulnerability": ("nextjs-stack", "Next.js Stack"),
}

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

CONFIDENCE_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
}


def get_scan_report(scan_id: str) -> ScanReportResponse:
    with get_db_connection() as connection:
        scan = fetch_scan(connection, scan_id)
        if scan is None:
            raise LookupError("Scan not found")

        steps = fetch_scan_steps(connection, scan_id)
        findings = fetch_findings(connection, scan_id)
        signals = fetch_signals(connection, scan_id)
        evidence = fetch_evidence(connection, scan_id)
    scan = {
        **scan,
        "canonical_target": build_baseline_context(scan, steps, findings, signals, evidence).canonical_url,
    }

    return build_scan_report(scan, findings)


def get_enriched_scan_report(scan_id: str) -> EnrichedReportResponse:
    with get_db_connection() as connection:
        scan = fetch_scan(connection, scan_id)
        if scan is None:
            raise LookupError("Scan not found")

        steps = fetch_scan_steps(connection, scan_id)
        findings = fetch_findings(connection, scan_id)
        signals = fetch_signals(connection, scan_id)
        evidence = fetch_evidence(connection, scan_id)
    baseline_context = build_baseline_context(scan, steps, findings, signals, evidence)
    scan = {
        **scan,
        "canonical_target": baseline_context.canonical_url,
    }

    enriched_findings = enrich_findings(findings)
    return build_enriched_report(scan, findings, enriched_findings, steps=steps, baseline_context=baseline_context)


def build_scan_report(scan: dict, findings: list[FindingResponse]) -> ScanReportResponse:
    summary = build_summary(findings)

    return ScanReportResponse(
        scan_id=str(scan["id"]),
        target=scan.get("canonical_target") or scan["target"],
        status=scan["status"],
        score=_build_score(summary),
        summary=ReportSummaryResponse(**summary.model_dump()),
        top_issues=_build_top_issues(findings),
        categories=_build_categories(findings),
        created_at=scan["created_at"],
        completed_at=scan["completed_at"],
    )


def build_enriched_report(
    scan: dict,
    findings: list[FindingResponse],
    enriched_findings: list[EnrichedFindingResponse],
    steps: list[ScanStepResponse] | None = None,
    executed_contracts: list[str] | None = None,
    vulnerability_research_plan: VulnerabilityResearchPlan | None = None,
    vulnerability_research_results: list[VulnerabilityResearchResult] | None = None,
    baseline_context: BaselineContext | None = None,
) -> EnrichedReportResponse:
    summary = build_summary(findings)
    
    # Build the basic report first
    report = EnrichedReportResponse(
        scan_id=str(scan["id"]),
        target=scan.get("canonical_target") or scan["target"],
        status=scan["status"],
        score=_build_score(summary),
        summary=ReportSummaryResponse(**summary.model_dump()),
        top_issues=_build_enriched_top_issues(enriched_findings),
        categories=_build_enriched_categories(enriched_findings),
        created_at=scan["created_at"],
        completed_at=scan["completed_at"],
    )
    
    # Use LLM to generate a smart vulnerability control matrix
    detected_stack = _detect_stack(baseline_context) if baseline_context else "generic"
    check_categories = generate_vulnerability_control_matrix(
        report=report,
        detected_stack=detected_stack,
        executed_contracts=executed_contracts or [],
    )
    
    return report.model_copy(update={"check_categories": check_categories})


def _detect_stack(baseline_context: BaselineContext) -> str:
    """Detect the primary stack from baseline signals."""
    if baseline_context.signal_is_true("framework.wordpress"):
        return "WordPress"
    if baseline_context.signal_is_true("framework.nextjs"):
        return "Next.js"
    if baseline_context.signal_is_true("framework.react"):
        return "React"
    if baseline_context.signal_is_true("framework.angular"):
        return "Angular"
    if baseline_context.signal_is_true("framework.vue"):
        return "Vue.js"
    if baseline_context.signal_is_true("framework.django"):
        return "Django"
    if baseline_context.signal_is_true("framework.dotnet"):
        return "ASP.NET Core"
    return "Generic Web Application"


def _build_top_issues(findings: list[FindingResponse]) -> list[ReportTopIssueResponse]:
    sorted_findings = sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity.lower(), len(SEVERITY_ORDER)),
            CONFIDENCE_ORDER.get(finding.confidence.lower(), len(CONFIDENCE_ORDER)),
            finding.title.lower(),
        ),
    )

    return [_to_report_issue(finding) for finding in sorted_findings[:5]]


def _build_enriched_top_issues(findings: list[EnrichedFindingResponse]) -> list[EnrichedFindingResponse]:
    sorted_findings = sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity.lower(), len(SEVERITY_ORDER)),
            CONFIDENCE_ORDER.get(finding.confidence.lower(), len(CONFIDENCE_ORDER)),
            finding.title.lower(),
        ),
    )
    return sorted_findings[:5]


def _build_categories(findings: list[FindingResponse]) -> list[ReportCategoryResponse]:
    grouped: dict[str, dict] = {}

    for finding in findings:
        slug, name = CATEGORY_MAP.get(finding.category, ("other", "Other"))
        group = grouped.setdefault(
            slug,
            {
                "name": name,
                "findings": [],
            },
        )
        group["findings"].append(finding)

    categories: list[ReportCategoryResponse] = []
    for slug, group in grouped.items():
        group_findings = sorted(
            group["findings"],
            key=lambda finding: (
                SEVERITY_ORDER.get(finding.severity.lower(), len(SEVERITY_ORDER)),
                CONFIDENCE_ORDER.get(finding.confidence.lower(), len(CONFIDENCE_ORDER)),
                finding.title.lower(),
            ),
        )

        categories.append(
            ReportCategoryResponse(
                name=group["name"],
                slug=slug,
                count=len(group_findings),
                highest_severity=_highest_severity(group_findings),
                findings=[_to_report_issue(finding) for finding in group_findings],
            )
        )

    categories.sort(
        key=lambda category: (
            SEVERITY_ORDER.get(category.highest_severity, len(SEVERITY_ORDER)),
            category.name.lower(),
        )
    )
    return categories


def _build_enriched_categories(findings: list[EnrichedFindingResponse]) -> list[EnrichedReportCategoryResponse]:
    grouped: dict[str, dict] = {}

    for finding in findings:
        slug, name = CATEGORY_MAP.get(finding.category, ("other", "Other"))
        group = grouped.setdefault(
            slug,
            {
                "name": name,
                "findings": [],
            },
        )
        group["findings"].append(finding)

    categories: list[EnrichedReportCategoryResponse] = []
    for slug, group in grouped.items():
        group_findings = sorted(
            group["findings"],
            key=lambda finding: (
                SEVERITY_ORDER.get(finding.severity.lower(), len(SEVERITY_ORDER)),
                CONFIDENCE_ORDER.get(finding.confidence.lower(), len(CONFIDENCE_ORDER)),
                finding.title.lower(),
            ),
        )

        categories.append(
            EnrichedReportCategoryResponse(
                name=group["name"],
                slug=slug,
                count=len(group_findings),
                highest_severity=_highest_severity(group_findings),
                findings=group_findings,
            )
        )

    categories.sort(
        key=lambda category: (
            SEVERITY_ORDER.get(category.highest_severity, len(SEVERITY_ORDER)),
            category.name.lower(),
        )
    )
    return categories


def _highest_severity(findings: list[FindingResponse | EnrichedFindingResponse]) -> str:
    if not findings:
        return "info"

    return min(
        findings,
        key=lambda finding: SEVERITY_ORDER.get(finding.severity.lower(), len(SEVERITY_ORDER)),
    ).severity.lower()


def _build_score(summary: ScanSummaryResponse) -> int:
    score = 100
    score -= summary.critical * 20
    score -= summary.high * 12
    score -= summary.medium * 6
    score -= summary.low * 2
    return max(score, 0)


def _to_report_issue(finding: FindingResponse) -> ReportTopIssueResponse:
    _, category_name = CATEGORY_MAP.get(finding.category, ("other", "Other"))

    return ReportTopIssueResponse(
        tool_name=finding.tool_name,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        evidence=finding.evidence,
        category=category_name,
        details=finding.details,
    )
