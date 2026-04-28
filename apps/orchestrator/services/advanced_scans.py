import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime, timezone

import grpc

from grpc_clients.nextjs_stack_client import is_nextjs_stack_enabled, run_nextjs_stack
from grpc_clients.laravel_stack_client import is_laravel_stack_enabled, run_laravel_stack
from grpc_clients.php_stack_client import is_php_stack_enabled, run_php_stack
from grpc_clients.shopify_stack_client import is_shopify_stack_enabled, run_shopify_stack
from grpc_clients.wp_stack_client import is_wp_stack_enabled, run_wordpress_stack
from schemas.planner import (
    AdvancedContractExecutionResult,
    AdvancedContractFinding,
    AdvancedExecutionPlan,
    PlannerSelection,
    VulnerabilityResearchResult,
)
from schemas.scan import FindingResponse
from services.baseline_context import BaselineContext
from services.contracts import (
    CONTRACT_ALIAS_GROUPS,
    AdvancedScanContract,
    get_advanced_scan_contract,
    list_advanced_scan_contracts,
)
from services.event_bus import publish_scan_event


logger = logging.getLogger(__name__)


class PartialAdvancedScanError(Exception):
    def __init__(
        self,
        message: str,
        findings: list[AdvancedContractFinding] | None = None,
        metadata: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.findings = findings or []
        self.metadata = metadata or {}


def execute_advanced_scan_plan(
    planner_result: PlannerSelection | AdvancedExecutionPlan,
    baseline_context: BaselineContext,
    vulnerability_research: list[VulnerabilityResearchResult] | None = None,
    scan: dict | None = None,
    scan_id: str | None = None,
) -> list[AdvancedContractExecutionResult]:
    execution_plan = (
        planner_result if isinstance(planner_result, AdvancedExecutionPlan) else build_advanced_execution_plan(planner_result)
    )
    results: list[AdvancedContractExecutionResult] = []

    for contract_name in execution_plan.executed_contracts:
        contract = get_advanced_scan_contract(contract_name)
        if contract is None:
            logger.warning("Skipping unknown advanced scan contract at execution time: %s", contract_name)
            results.append(
                AdvancedContractExecutionResult(
                    contract=contract_name,
                    status="skipped",
                    metadata={"reason": "unknown_contract"},
                    error="Unknown contract name was rejected before execution.",
                )
            )
            continue

        if scan_id is not None:
            publish_scan_event(
                scan_id,
                "contract.started",
                "Advanced contract execution started.",
                {
                    "contract": contract.name,
                    "service": contract.service,
                },
            )

        result = _execute_contract_with_timeout(contract, baseline_context, vulnerability_research or [], scan)
        results.append(result)

        if scan_id is not None:
            event_type = "contract.completed" if result.status == "completed" else "contract.failed"
            publish_scan_event(
                scan_id,
                event_type,
                "Advanced contract execution finished.",
                {
                    "contract": contract.name,
                    "status": result.status,
                    "finding_count": len(result.findings),
                    "error": result.error,
                },
            )

    return results


def build_advanced_execution_plan(planner_result: PlannerSelection) -> AdvancedExecutionPlan:
    raw_selected_contracts = _dedupe_preserving_order(planner_result.selected_contracts)
    raw_selected_contracts = _suppress_alias_duplicates(raw_selected_contracts)
    is_deterministic_plan = planner_result.source == "deterministic"
    if "php.v1.verify_stack" in raw_selected_contracts and (
        "wordpress.v1.run_stack" in raw_selected_contracts or "laravel.v1.verify_stack" in raw_selected_contracts
    ):
        raw_selected_contracts = [name for name in raw_selected_contracts if name != "php.v1.verify_stack"]
    executed_contracts = list(raw_selected_contracts)
    notes: list[str] = []
    generic_contract = "generic_http.v1.run_stack" if get_advanced_scan_contract("generic_http.v1.run_stack") else None
    specialist_contracts = [contract_name for contract_name in raw_selected_contracts if contract_name != generic_contract]

    if planner_result.confidence == "medium":
        if specialist_contracts and generic_contract and generic_contract not in executed_contracts:
            executed_contracts.append(generic_contract)
            notes.append(
                "Planner confidence was medium, so the orchestrator added generic_http.v1.run_stack for broader coverage."
            )
    elif planner_result.confidence == "low":
        if is_deterministic_plan:
            if specialist_contracts and generic_contract and generic_contract not in executed_contracts:
                executed_contracts.append(generic_contract)
                notes.append(
                    "Deterministic planner output runs selected specialists plus generic_http.v1.run_stack because no LLM confidence score was available."
                )
            elif not executed_contracts and generic_contract is not None:
                executed_contracts = [generic_contract]
                notes.append(
                    "Deterministic planner output had no specialist matches, so the orchestrator ran generic_http.v1.run_stack only."
                )
        elif generic_contract is not None:
            executed_contracts = [generic_contract]
            if specialist_contracts or generic_contract not in raw_selected_contracts:
                notes.append(
                    "Planner confidence was low, so the orchestrator suppressed speculative specialist execution and ran generic_http.v1.run_stack only."
                )
        else:
            executed_contracts = []
            if raw_selected_contracts:
                notes.append(
                    "Planner confidence was low, so the orchestrator suppressed speculative specialist execution and ran no advanced contracts."
                )

    return AdvancedExecutionPlan(
        confidence=planner_result.confidence,
        raw_selected_contracts=raw_selected_contracts,
        executed_contracts=_dedupe_preserving_order(executed_contracts),
        notes=notes,
    )


def merge_advanced_findings(
    findings: list[FindingResponse],
    advanced_results: list[AdvancedContractExecutionResult],
    scan: dict | None = None,
) -> list[FindingResponse]:
    merged_findings = list(findings)
    seen = {_finding_signature(finding) for finding in findings}
    created_at = _resolve_advanced_created_at(scan)

    for result in advanced_results:
        for index, finding in enumerate(result.findings, start=1):
            merged_finding = FindingResponse(
                id=f"advanced-{result.contract}-{index}",
                tool_name=finding.tool_name,
                type=finding.type,
                category=finding.category,
                title=finding.title,
                summary=getattr(finding, "summary", None),
                severity=finding.severity,
                confidence=finding.confidence,
                evidence=finding.evidence,
                evidence_refs=getattr(finding, "evidence_refs", []),
                details={
                    **finding.details,
                    "advanced_contract": result.contract,
                    "advanced_status": result.status,
                },
                created_at=created_at,
            )
            signature = _finding_signature(merged_finding)
            if signature in seen:
                continue

            seen.add(signature)
            merged_findings.append(merged_finding)

    return merged_findings


def analyze_baseline_findings(baseline_context: BaselineContext) -> dict:
    contract_matches: dict[str, list[str]] = {}

    for contract in list_advanced_scan_contracts():
        if contract.name == "generic_http.v1.run_stack":
            continue
        if _is_secondary_alias_name(contract.name):
            continue

        matched_signals = _match_trigger_signals(contract, baseline_context)
        if matched_signals:
            contract_matches[contract.name] = matched_signals

    best_signal_count = max((len(signals) for signals in contract_matches.values()), default=0)
    ambiguous_evidence = len(contract_matches) != 1 or best_signal_count < 2

    return {
        "ambiguous_evidence": ambiguous_evidence,
        "contract_signal_matches": contract_matches,
        "fingerprint_findings": sum(
            1 for finding in baseline_context.findings if finding.category.lower().startswith("fingerprint_")
        ),
        "signal_count": len(baseline_context.signal_map),
        "canonical_url": baseline_context.canonical_url,
        "redirected": baseline_context.redirected,
    }


def evaluate_advanced_contract_results(
    advanced_results: list[AdvancedContractExecutionResult],
    executed_contracts: list[str],
    retry_counts: dict[str, int] | None = None,
) -> dict:
    retry_counts = retry_counts or {}
    failed_contracts: list[str] = []
    retryable_contracts: list[str] = []
    notes: list[str] = []
    total_findings = 0
    significant_findings = 0
    specialist_success = False
    generic_contract = "generic_http.v1.run_stack"
    only_generic_executed = bool(executed_contracts) and set(executed_contracts) == {generic_contract}

    for result in advanced_results:
        total_findings += len(result.findings)
        significant_findings += sum(
            1 for finding in result.findings if finding.severity.lower() in {"critical", "high", "medium"}
        )

        if result.contract != generic_contract and result.status == "completed" and result.findings:
            specialist_success = True

        if result.status not in {"failed", "timed_out"}:
            continue

        failed_contracts.append(result.contract)
        contract = get_advanced_scan_contract(result.contract)
        if contract is None:
            notes.append(f"Contract {result.contract} failed but was not retryable because it is not in the registry.")
            continue

        attempts = retry_counts.get(result.contract, 0)
        if contract.retryable and attempts < contract.max_retries:
            retryable_contracts.append(result.contract)
            notes.append(f"Contract {result.contract} failed and is eligible for retry attempt {attempts + 1}.")
        else:
            notes.append(f"Contract {result.contract} failed and is not eligible for further retries.")

    if significant_findings > 0 or specialist_success:
        result_quality = "sufficient"
    elif total_findings > 0:
        result_quality = "partial"
    elif only_generic_executed and advanced_results:
        result_quality = "weak"
    elif advanced_results and any(result.status == "completed" for result in advanced_results):
        result_quality = "partial"
    else:
        result_quality = "weak"

    if not executed_contracts:
        notes.append("No advanced contracts were executed for this graph run.")

    return {
        "failed_contracts": _dedupe_preserving_order(failed_contracts),
        "retryable_contracts": _dedupe_preserving_order(retryable_contracts),
        "result_quality": result_quality,
        "notes": notes,
    }


def replace_advanced_results(
    existing_results: list[AdvancedContractExecutionResult],
    new_results: list[AdvancedContractExecutionResult],
) -> list[AdvancedContractExecutionResult]:
    ordered_results: list[AdvancedContractExecutionResult] = []
    result_map = {result.contract: result for result in existing_results}

    for result in new_results:
        result_map[result.contract] = result

    seen: set[str] = set()
    for result in existing_results + new_results:
        if result.contract in seen:
            continue

        seen.add(result.contract)
        ordered_results.append(result_map[result.contract])

    return ordered_results


def _execute_contract_with_timeout(
    contract: AdvancedScanContract,
    baseline_context: BaselineContext,
    vulnerability_research: list[VulnerabilityResearchResult],
    scan: dict | None,
) -> AdvancedContractExecutionResult:
    started_at = time.monotonic()

    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_dispatch_contract, contract, baseline_context, vulnerability_research, scan)

    try:
        result = future.result(timeout=contract.timeout_seconds)
    except TimeoutError:
        logger.warning("Advanced scan contract timed out: %s", contract.name)
        future.cancel()
        return AdvancedContractExecutionResult(
            contract=contract.name,
            status="timed_out",
            metadata={
                "service": contract.service,
                "timeout_seconds": contract.timeout_seconds,
                "duration_ms": int((time.monotonic() - started_at) * 1000),
            },
            error=f"Contract timed out after {contract.timeout_seconds} seconds.",
        )
    except PartialAdvancedScanError as exc:
        logger.warning("Advanced scan contract failed with partial results: %s", contract.name)
        findings_payload = exc.findings if contract.allow_partial_results else []
        metadata = {
            "service": contract.service,
            "timeout_seconds": contract.timeout_seconds,
            "duration_ms": int((time.monotonic() - started_at) * 1000),
            **exc.metadata,
        }
        return AdvancedContractExecutionResult(
            contract=contract.name,
            status="failed",
            findings=findings_payload,
            metadata=metadata,
            error=str(exc),
        )
    except Exception as exc:
        logger.exception("Advanced scan contract failed: %s", contract.name)
        return AdvancedContractExecutionResult(
            contract=contract.name,
            status="failed",
            metadata={
                "service": contract.service,
                "timeout_seconds": contract.timeout_seconds,
                "duration_ms": int((time.monotonic() - started_at) * 1000),
            },
            error=str(exc),
        )
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    return result.model_copy(
        update={
            "metadata": {
                "service": contract.service,
                "timeout_seconds": contract.timeout_seconds,
                "duration_ms": int((time.monotonic() - started_at) * 1000),
                **result.metadata,
            }
        }
    )


def _dispatch_contract(
    contract: AdvancedScanContract,
    baseline_context: BaselineContext,
    vulnerability_research: list[VulnerabilityResearchResult],
    scan: dict | None,
) -> AdvancedContractExecutionResult:
    handlers = {
        "wordpress.v1.run_stack": _run_wordpress_contract,
        "wordpress.v1.verify_stack": _run_wordpress_contract,
        "nextjs.v1.run_stack": _run_nextjs_contract,
        "nextjs.v1.verify_stack": _run_nextjs_contract,
        "laravel.v1.verify_stack": _run_laravel_contract,
        "php.v1.verify_stack": _run_php_contract,
        "shopify.v1.verify_stack": _run_shopify_contract,
        "frontend_frameworks.v1.run_stack": _run_generic_http_contract,
        "backend_frameworks.v1.run_stack": _run_generic_http_contract,
        "data_services.v1.run_stack": _run_generic_http_contract,
        "deployment_platforms.v1.run_stack": _run_generic_http_contract,
        "generic_http.v1.run_stack": _run_generic_http_contract,
    }

    handler = handlers.get(contract.name)
    if handler is None:
        raise RuntimeError(f"No handler registered for contract {contract.name}")

    return handler(contract, baseline_context, vulnerability_research, scan)


def _run_wordpress_contract(
    contract: AdvancedScanContract,
    baseline_context: BaselineContext,
    vulnerability_research: list[VulnerabilityResearchResult],
    scan: dict | None,
) -> AdvancedContractExecutionResult:
    matched_signals = _match_trigger_signals(contract, baseline_context)
    target = _resolve_execution_target(scan, baseline_context)

    if target and is_wp_stack_enabled():
        try:
            response = run_wordpress_stack(
                target,
                metadata={
                    "matched_signals": matched_signals,
                    "baseline_signals": baseline_context.planner_signal_summary(),
                    "baseline_findings": baseline_context.planner_finding_summary(limit=12),
                    "wordpress_version": baseline_context.signal_value("framework.wordpress.version"),
                    "technology_summary": baseline_context.signal_value("technology.summary", {}),
                    "vulnerability_research": [item.model_dump() for item in vulnerability_research],
                    "baseline_finding_count": len(baseline_context.findings),
                    "canonical_target": baseline_context.canonical_url,
                    "redirected": baseline_context.redirected,
                },
            )
        except grpc.RpcError as exc:
            logger.warning("wp-stack gRPC call failed for %s: %s", target, exc)
            return AdvancedContractExecutionResult(
                contract=contract.name,
                status="failed",
                metadata={
                    "service_status": "grpc_error",
                    "matched_signals": matched_signals,
                    "target": target,
                    "grpc_status": exc.code().name if exc.code() else None,
                },
                error=exc.details() or str(exc),
            )
        except RuntimeError as exc:
            logger.warning("wp-stack execution unavailable for %s: %s", target, exc)
        else:
            return AdvancedContractExecutionResult(
                contract=contract.name,
                status=_normalize_contract_status(response.get("status")),
                findings=[
                    AdvancedContractFinding(
                        tool_name=response.get("tool") or contract.name,
                        type=item.get("type", "informational"),
                        category=item.get("category", "wordpress_fingerprint"),
                        title=item.get("title", "WordPress stack finding"),
                        severity=item.get("severity", "info"),
                        confidence=item.get("confidence", "medium"),
                        evidence=item.get("evidence", ""),
                        details=item.get("details") or {},
                    )
                    for item in response.get("findings", [])
                ],
                metadata={
                    "service_status": "grpc",
                    "matched_signals": matched_signals,
                    "target": target,
                    **(response.get("metadata") or {}),
                },
                error=response.get("error") or None,
            )

    stub_findings = [
        AdvancedContractFinding(
            tool_name="advanced_wordpress_stub",
            type="fingerprint",
            category="fingerprint_framework",
            title="WordPress specialist scan path selected",
            severity="info",
            confidence="medium",
            evidence="Baseline findings contained WordPress-aligned signals that triggered the specialist contract.",
            details={
                "matched_signals": matched_signals,
                "target": target,
                "stub": True,
            },
        )
    ]

    return AdvancedContractExecutionResult(
        contract=contract.name,
        status="completed",
        findings=stub_findings,
        metadata={
            "service_status": "stub_fallback",
            "matched_signals": matched_signals,
            "target": target,
        },
    )


def _run_nextjs_contract(
    contract: AdvancedScanContract,
    baseline_context: BaselineContext,
    vulnerability_research: list[VulnerabilityResearchResult],
    scan: dict | None,
) -> AdvancedContractExecutionResult:
    matched_signals = _match_trigger_signals(contract, baseline_context)
    target = _resolve_execution_target(scan, baseline_context)

    if target and is_nextjs_stack_enabled():
        try:
            logger.info(
                "Executing specialist contract name=%s service=%s target=%s",
                contract.name,
                contract.service,
                target,
            )
            response = run_nextjs_stack(
                target,
                metadata={
                    "matched_signals": matched_signals,
                    "baseline_signals": baseline_context.planner_signal_summary(),
                    "baseline_findings": baseline_context.planner_finding_summary(limit=12),
                    "next_version": baseline_context.signal_value("framework.nextjs.version"),
                    "vulnerability_research": [item.model_dump() for item in vulnerability_research],
                    "baseline_finding_count": len(baseline_context.findings),
                    "canonical_target": baseline_context.canonical_url,
                    "redirected": baseline_context.redirected,
                },
            )
            logger.info("Received response from nextjs-stack for target %s: status=%s finding_count=%d", target, response.get("status"), len(response.get("findings", [])))
        except grpc.RpcError as exc:
            logger.warning("nextjs-stack gRPC call failed for %s: %s", target, exc)
            return AdvancedContractExecutionResult(
                contract=contract.name,
                status="failed",
                metadata={
                    "service_status": "grpc_error",
                    "matched_signals": matched_signals,
                    "target": target,
                    "grpc_status": exc.code().name if exc.code() else None,
                },
                error=exc.details() or str(exc),
            )
        except RuntimeError as exc:
            logger.warning("nextjs-stack execution unavailable for %s: %s", target, exc)
        else:
            logger.info(
                "Specialist contract %s completed with status %s and %d findings",
                contract.name,
                response.get("status"),
                len(response.get("findings", [])),
            )
            return AdvancedContractExecutionResult(
                contract=contract.name,
                status=_normalize_contract_status(response.get("status")),
                findings=[
                    AdvancedContractFinding(
                        tool_name=response.get("tool") or contract.name,
                        type=item.get("type", "informational"),
                        category=item.get("category", "nextjs_fingerprint"),
                        title=item.get("title", "Next.js stack finding"),
                        severity=item.get("severity", "info"),
                        confidence=item.get("confidence", "medium"),
                        evidence=item.get("evidence", ""),
                        details=item.get("details") or {},
                    )
                    for item in response.get("findings", [])
                ],
                metadata={
                    "service_status": "grpc",
                    "matched_signals": matched_signals,
                    "target": target,
                    **(response.get("metadata") or {}),
                },
                error=response.get("error") or None,
            )

    return AdvancedContractExecutionResult(
        contract=contract.name,
        status="completed",
        findings=[
            AdvancedContractFinding(
                tool_name="advanced_nextjs_stub",
                type="fingerprint",
                category="nextjs_fingerprint",
                title="Next.js specialist scan path selected",
                severity="info",
                confidence="medium",
                evidence="Baseline findings contained Next.js-aligned signals that triggered the specialist contract.",
                details={
                    "matched_signals": matched_signals,
                    "target": target,
                    "stub": True,
                },
            )
        ],
        metadata={
            "service_status": "stub_fallback",
            "matched_signals": matched_signals,
            "target": target,
            "canonical_target": baseline_context.canonical_url,
        },
    )


def _run_generic_http_contract(
    contract: AdvancedScanContract,
    baseline_context: BaselineContext,
    vulnerability_research: list[VulnerabilityResearchResult],
    scan: dict | None,
) -> AdvancedContractExecutionResult:
    matched_signals = _match_trigger_signals(contract, baseline_context)
    return AdvancedContractExecutionResult(
        contract=contract.name,
        status="completed",
        findings=[],
        metadata={
            "service_status": "stubbed",
            "matched_signals": matched_signals,
            "baseline_finding_count": len(baseline_context.findings),
            "baseline_signal_count": len(baseline_context.signal_map),
            "technology_summary": baseline_context.signal_value("technology.summary", {}),
            "baseline_signals": baseline_context.planner_signal_summary(),
            "baseline_findings": baseline_context.planner_finding_summary(limit=12),
            "vulnerability_research": [item.model_dump() for item in vulnerability_research],
            "target": _resolve_execution_target(scan, baseline_context),
            "canonical_target": baseline_context.canonical_url,
        },
    )


def _run_laravel_contract(
    contract: AdvancedScanContract,
    baseline_context: BaselineContext,
    vulnerability_research: list[VulnerabilityResearchResult],
    scan: dict | None,
) -> AdvancedContractExecutionResult:
    return _run_grpc_specialist_contract(
        contract=contract,
        baseline_context=baseline_context,
        vulnerability_research=vulnerability_research,
        scan=scan,
        enabled_check=is_laravel_stack_enabled,
        runner=run_laravel_stack,
        default_category="laravel_exposure",
        default_title="Laravel stack finding",
        stack_metadata={
            "technology_summary": baseline_context.signal_value("technology.summary", {}),
            "laravel_version": baseline_context.signal_value("framework.laravel.version"),
        },
        stub_tool_name="advanced_laravel_stub",
        stub_title="Laravel specialist scan path selected",
        stub_evidence="Baseline signals selected Laravel verification checks.",
    )


def _run_php_contract(
    contract: AdvancedScanContract,
    baseline_context: BaselineContext,
    vulnerability_research: list[VulnerabilityResearchResult],
    scan: dict | None,
) -> AdvancedContractExecutionResult:
    return _run_grpc_specialist_contract(
        contract=contract,
        baseline_context=baseline_context,
        vulnerability_research=vulnerability_research,
        scan=scan,
        enabled_check=is_php_stack_enabled,
        runner=run_php_stack,
        default_category="php_exposure",
        default_title="PHP stack finding",
        stack_metadata={
            "technology_summary": baseline_context.signal_value("technology.summary", {}),
            "php_version": baseline_context.signal_value("language.php.version"),
        },
        stub_tool_name="advanced_php_stub",
        stub_title="PHP specialist scan path selected",
        stub_evidence="Baseline signals selected PHP verification checks.",
    )


def _run_shopify_contract(
    contract: AdvancedScanContract,
    baseline_context: BaselineContext,
    vulnerability_research: list[VulnerabilityResearchResult],
    scan: dict | None,
) -> AdvancedContractExecutionResult:
    return _run_grpc_specialist_contract(
        contract=contract,
        baseline_context=baseline_context,
        vulnerability_research=vulnerability_research,
        scan=scan,
        enabled_check=is_shopify_stack_enabled,
        runner=run_shopify_stack,
        default_category="shopify_posture",
        default_title="Shopify stack finding",
        stack_metadata={
            "technology_summary": baseline_context.signal_value("technology.summary", {}),
            "shopify_domain": baseline_context.signal_value("platform.shopify.domain"),
        },
        stub_tool_name="advanced_shopify_stub",
        stub_title="Shopify specialist scan path selected",
        stub_evidence="Baseline signals selected Shopify storefront verification checks.",
    )


def _run_grpc_specialist_contract(
    contract: AdvancedScanContract,
    baseline_context: BaselineContext,
    vulnerability_research: list[VulnerabilityResearchResult],
    scan: dict | None,
    enabled_check,
    runner,
    default_category: str,
    default_title: str,
    stack_metadata: dict,
    stub_tool_name: str,
    stub_title: str,
    stub_evidence: str,
) -> AdvancedContractExecutionResult:
    matched_signals = _match_trigger_signals(contract, baseline_context)
    target = _resolve_execution_target(scan, baseline_context)

    if target and enabled_check():
        try:
            response = runner(
                target,
                metadata={
                    "matched_signals": matched_signals,
                    "baseline_signals": baseline_context.planner_signal_summary(),
                    "baseline_findings": baseline_context.planner_finding_summary(limit=12),
                    "vulnerability_research": [item.model_dump() for item in vulnerability_research],
                    "baseline_finding_count": len(baseline_context.findings),
                    "canonical_target": baseline_context.canonical_url,
                    "redirected": baseline_context.redirected,
                    **stack_metadata,
                },
            )
        except grpc.RpcError as exc:
            logger.warning("%s gRPC call failed for %s: %s", contract.name, target, exc)
            return AdvancedContractExecutionResult(
                contract=contract.name,
                status="failed",
                metadata={
                    "service_status": "grpc_error",
                    "matched_signals": matched_signals,
                    "target": target,
                    "grpc_status": exc.code().name if exc.code() else None,
                },
                error=exc.details() or str(exc),
            )
        except RuntimeError as exc:
            logger.warning("%s execution unavailable for %s: %s", contract.name, target, exc)
        else:
            return AdvancedContractExecutionResult(
                contract=contract.name,
                status=_normalize_contract_status(response.get("status")),
                findings=[
                    AdvancedContractFinding(
                        tool_name=response.get("tool") or contract.name,
                        type=item.get("type", "informational"),
                        category=item.get("category", default_category),
                        title=item.get("title", default_title),
                        severity=item.get("severity", "info"),
                        confidence=item.get("confidence", "medium"),
                        evidence=item.get("evidence", ""),
                        details=item.get("details") or {},
                    )
                    for item in response.get("findings", [])
                ],
                metadata={
                    "service_status": "grpc",
                    "matched_signals": matched_signals,
                    "target": target,
                    **(response.get("metadata") or {}),
                },
                error=response.get("error") or None,
            )

    return AdvancedContractExecutionResult(
        contract=contract.name,
        status="completed",
        findings=[
            AdvancedContractFinding(
                tool_name=stub_tool_name,
                type="fingerprint",
                category=default_category,
                title=stub_title,
                severity="info",
                confidence="medium",
                evidence=stub_evidence,
                details={
                    "matched_signals": matched_signals,
                    "target": target,
                    "stub": True,
                },
            )
        ],
        metadata={
            "service_status": "stub_fallback",
            "matched_signals": matched_signals,
            "target": target,
            "canonical_target": baseline_context.canonical_url,
        },
    )


def _match_trigger_signals(
    contract: AdvancedScanContract,
    baseline_context: BaselineContext,
) -> list[str]:
    haystack_parts: list[str] = []
    active_signal_keys = {key.lower() for key, signal in baseline_context.signal_map.items() if signal.value is True}

    matched = [signal for signal in contract.signal_triggers if signal.lower() in active_signal_keys]

    for finding in baseline_context.findings:
        haystack_parts.extend(
            [
                finding.title,
                finding.summary or "",
                finding.category,
                finding.evidence,
                finding.tool_name,
                str(finding.details),
            ]
        )

    haystack = " ".join(haystack_parts).lower()

    for term in contract.legacy_trigger_terms:
        if term.lower() in haystack and term not in matched:
            matched.append(term)

    return matched


def _resolve_execution_target(scan: dict | None, baseline_context: BaselineContext) -> str | None:
    if baseline_context.canonical_url:
        return baseline_context.canonical_url
    if scan is None:
        return None
    return scan.get("canonical_target") or scan.get("target")


def _normalize_contract_status(status: str | None) -> str:
    if status in {"completed", "failed", "timed_out", "skipped"}:
        return status

    return "completed"


def _dedupe_preserving_order(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()

    for value in values:
        if value in seen:
            continue

        seen.add(value)
        deduped.append(value)

    return deduped


def _suppress_alias_duplicates(contract_names: list[str]) -> list[str]:
    if not contract_names:
        return contract_names

    deduped = list(contract_names)
    for alias_group in CONTRACT_ALIAS_GROUPS:
        selected = [name for name in deduped if name in alias_group]
        if len(selected) <= 1:
            continue

        keep = selected[0]
        deduped = [name for name in deduped if name not in alias_group or name == keep]

    return deduped


def _is_secondary_alias_name(contract_name: str) -> bool:
    for alias_group in CONTRACT_ALIAS_GROUPS:
        if contract_name in alias_group and contract_name != alias_group[0]:
            return True
    return False


def _resolve_advanced_created_at(scan: dict | None) -> datetime:
    if scan is not None:
        completed_at = scan.get("completed_at")
        if completed_at is not None:
            return completed_at

        created_at = scan.get("created_at")
        if created_at is not None:
            return created_at

    return datetime.now(timezone.utc)


def _finding_signature(finding: FindingResponse) -> tuple[str, str, str, str]:
    return (
        finding.tool_name,
        finding.type,
        finding.title,
        finding.evidence,
    )


def create_execution_plan(
    confidence: str,
    raw_selected_contracts: list[str],
    executed_contracts: list[str],
    notes: list[str] | None = None,
) -> AdvancedExecutionPlan:
    return AdvancedExecutionPlan(
        confidence=confidence,
        raw_selected_contracts=_dedupe_preserving_order(raw_selected_contracts),
        executed_contracts=_dedupe_preserving_order(executed_contracts),
        notes=notes or [],
    )
