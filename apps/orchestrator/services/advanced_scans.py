import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError

from schemas.planner import AdvancedContractExecutionResult, AdvancedContractFinding, PlannerSelection
from schemas.scan import FindingResponse
from services.contracts import AdvancedScanContract, get_advanced_scan_contract


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
    planner_result: PlannerSelection,
    findings: list[FindingResponse],
    scan: dict | None = None,
) -> list[AdvancedContractExecutionResult]:
    results: list[AdvancedContractExecutionResult] = []

    for contract_name in planner_result.selected_contracts:
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

        results.append(_execute_contract_with_timeout(contract, findings, scan))

    return results


def _execute_contract_with_timeout(
    contract: AdvancedScanContract,
    findings: list[FindingResponse],
    scan: dict | None,
) -> AdvancedContractExecutionResult:
    started_at = time.monotonic()

    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_dispatch_contract, contract, findings, scan)

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
    findings: list[FindingResponse],
    scan: dict | None,
) -> AdvancedContractExecutionResult:
    handlers = {
        "wordpress.v1.run_stack": _run_wordpress_contract,
        "nextjs.v1.run_stack": _run_nextjs_contract,
        "generic_http.v1.run_stack": _run_generic_http_contract,
    }

    handler = handlers.get(contract.name)
    if handler is None:
        raise RuntimeError(f"No handler registered for contract {contract.name}")

    return handler(contract, findings, scan)


def _run_wordpress_contract(
    contract: AdvancedScanContract,
    findings: list[FindingResponse],
    scan: dict | None,
) -> AdvancedContractExecutionResult:
    matched_signals = _match_trigger_signals(contract, findings)
    target = scan.get("target") if scan else None

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
            "service_status": "stubbed",
            "matched_signals": matched_signals,
            "target": target,
        },
    )


def _run_nextjs_contract(
    contract: AdvancedScanContract,
    findings: list[FindingResponse],
    scan: dict | None,
) -> AdvancedContractExecutionResult:
    return AdvancedContractExecutionResult(
        contract=contract.name,
        status="completed",
        findings=[],
        metadata={
            "service_status": "stubbed",
            "matched_signals": _match_trigger_signals(contract, findings),
            "target": scan.get("target") if scan else None,
        },
    )


def _run_generic_http_contract(
    contract: AdvancedScanContract,
    findings: list[FindingResponse],
    scan: dict | None,
) -> AdvancedContractExecutionResult:
    return AdvancedContractExecutionResult(
        contract=contract.name,
        status="completed",
        findings=[],
        metadata={
            "service_status": "stubbed",
            "baseline_finding_count": len(findings),
            "target": scan.get("target") if scan else None,
        },
    )


def _match_trigger_signals(contract: AdvancedScanContract, findings: list[FindingResponse]) -> list[str]:
    haystack_parts: list[str] = []

    for finding in findings:
        haystack_parts.extend(
            [
                finding.title,
                finding.category,
                finding.evidence,
                finding.tool_name,
                str(finding.details),
            ]
        )

    haystack = " ".join(haystack_parts).lower()

    return [signal for signal in contract.trigger_signals if signal.lower() in haystack]
