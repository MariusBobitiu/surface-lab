import json
import logging

import httpx

from config.settings import OLLAMA_BASE_URL, OLLAMA_ENABLED, OLLAMA_MODEL, OLLAMA_TIMEOUT_SECONDS
from schemas.planner import AdvancedContractExecutionResult, PlannerSelection
from services.baseline_context import BaselineContext
from services.contracts import AdvancedScanContract
from services.llm import OLLAMA_GENERATE_PATH, _normalize_ollama_base_url


logger = logging.getLogger(__name__)


def plan_advanced_scans(
    baseline_context: BaselineContext,
    contracts: list[AdvancedScanContract],
    previous_planner_result: PlannerSelection | None = None,
    failed_contracts: list[str] | None = None,
    advanced_results: list[AdvancedContractExecutionResult] | None = None,
) -> PlannerSelection:
    fallback = _build_fallback_plan(baseline_context)
    if not OLLAMA_ENABLED:
        return fallback

    prompt = _build_prompt(baseline_context, contracts, previous_planner_result, failed_contracts or [], advanced_results or [])
    base_url = _normalize_ollama_base_url(OLLAMA_BASE_URL)

    try:
        with httpx.Client(base_url=base_url, timeout=OLLAMA_TIMEOUT_SECONDS) as client:
            response = client.post(
                OLLAMA_GENERATE_PATH,
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                },
            )
            response.raise_for_status()
            body = response.json()
    except httpx.HTTPError as exc:
        logger.warning("Advanced scan planner request failed for %s%s: %s", base_url, OLLAMA_GENERATE_PATH, exc)
        return fallback
    except ValueError as exc:
        logger.warning("Advanced scan planner response parsing failed: %s", exc)
        return fallback

    raw_response = body.get("response", "")
    try:
        parsed = json.loads(raw_response)
    except json.JSONDecodeError as exc:
        logger.warning("Advanced scan planner returned invalid JSON: %s", exc)
        return fallback

    parsed = _normalize_raw_plan_payload(parsed)

    try:
        plan = PlannerSelection.model_validate(parsed)
    except Exception as exc:
        logger.warning("Advanced scan planner schema validation failed: %s", exc)
        return fallback

    if not _is_valid_plan(plan, contracts):
        return fallback

    return _normalize_plan(plan)


def _build_prompt(
    baseline_context: BaselineContext,
    contracts: list[AdvancedScanContract],
    previous_planner_result: PlannerSelection | None,
    failed_contracts: list[str],
    advanced_results: list[AdvancedContractExecutionResult],
) -> str:
    available_contracts = [
        {
            "name": contract.name,
            "description": contract.description,
            "tags": list(contract.tags),
            "signal_triggers": list(contract.signal_triggers),
        }
        for contract in contracts
    ]

    compact_findings = baseline_context.planner_finding_summary()
    compact_signals = baseline_context.planner_signal_summary()
    compact_evidence = baseline_context.planner_evidence_summary()

    replan_context = ""
    if previous_planner_result is not None or failed_contracts or advanced_results:
        replan_payload = {
            "previous_planner_result": previous_planner_result.model_dump() if previous_planner_result is not None else None,
            "failed_contracts": failed_contracts,
            "advanced_results": [
                {
                    "contract": result.contract,
                    "status": result.status,
                    "findings_count": len(result.findings),
                    "error": result.error,
                    "metadata": _compact_details(result.metadata),
                }
                for result in advanced_results
            ],
        }
        replan_context = f"""

Re-plan context:
{json.dumps(replan_payload, indent=2)}
"""

    return f"""You are selecting advanced stack-specific scan contracts for a security orchestrator.

Choose only from the provided contracts.
Do not invent contract names.
If the stack evidence is weak or ambiguous, prefer `generic_http.v1.run_stack` or no specialist contracts.
Return JSON only with exactly these fields:
- selected_contracts
- skipped_contracts
- reasoning_summary
- confidence

`confidence` must be one of exactly: "low", "medium", "high".
Do not return numbers like 0.9.

Available contracts:
{json.dumps(available_contracts, indent=2)}

Baseline target context:
{json.dumps({
    "target_input": baseline_context.target_input,
    "canonical_url": baseline_context.canonical_url,
    "redirected": baseline_context.redirected,
}, indent=2)}

Baseline signals:
{json.dumps(compact_signals, indent=2)}

Baseline findings:
{json.dumps(compact_findings, indent=2)}

Selected baseline evidence:
{json.dumps(compact_evidence, indent=2)}
{replan_context}
"""


def _compact_details(details: dict) -> dict:
    compact: dict = {}

    for key, value in list(details.items())[:5]:
        if isinstance(value, (str, int, float, bool)) or value is None:
            compact[key] = value
            continue

        compact[key] = str(value)[:120]

    return compact


def _normalize_raw_plan_payload(parsed: object) -> dict:
    if not isinstance(parsed, dict):
        return {}

    normalized = dict(parsed)
    normalized["confidence"] = _normalize_confidence_value(parsed.get("confidence"))
    return normalized


def _normalize_confidence_value(value: object) -> str:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"low", "medium", "high"}:
            return normalized

        if normalized in {"0", "0.0", "1", "1.0"}:
            try:
                return _normalize_confidence_value(float(normalized))
            except ValueError:
                return "low"

    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric >= 0.8:
            return "high"
        if numeric >= 0.45:
            return "medium"
        return "low"

    return "low"


def _is_valid_plan(plan: PlannerSelection, contracts: list[AdvancedScanContract]) -> bool:
    allowed_names = {contract.name for contract in contracts}
    selected_names = set(plan.selected_contracts)
    skipped_names = set(plan.skipped_contracts)

    if not selected_names.issubset(allowed_names):
        logger.warning("Advanced scan planner selected unknown contracts: %s", sorted(selected_names - allowed_names))
        return False

    if not skipped_names.issubset(allowed_names):
        logger.warning("Advanced scan planner skipped unknown contracts: %s", sorted(skipped_names - allowed_names))
        return False

    return True


def _normalize_plan(plan: PlannerSelection) -> PlannerSelection:
    selected_contracts = _dedupe_preserving_order(plan.selected_contracts)
    selected_set = set(selected_contracts)
    skipped_contracts = [
        contract_name
        for contract_name in _dedupe_preserving_order(plan.skipped_contracts)
        if contract_name not in selected_set
    ]

    reasoning_summary = " ".join(plan.reasoning_summary.split()).strip()
    if not reasoning_summary:
        reasoning_summary = "Planner returned no usable reasoning summary."

    return PlannerSelection(
        selected_contracts=selected_contracts,
        skipped_contracts=skipped_contracts,
        reasoning_summary=reasoning_summary,
        confidence=plan.confidence,
    )


def _build_fallback_plan(baseline_context: BaselineContext) -> PlannerSelection:
    selected_contracts: list[str] = []
    has_routing_signal = any(
        baseline_context.signal_is_true(key)
        for key in (
            "framework.wordpress",
            "framework.nextjs",
            "assets.next_static",
            "assets.js_bundle",
            "surface.api",
            "surface.login",
            "surface.admin",
        )
    )

    if baseline_context.signal_is_true("framework.wordpress"):
        selected_contracts.append("wordpress.v1.run_stack")
    if baseline_context.signal_is_true("framework.nextjs") or baseline_context.signal_is_true("assets.next_static"):
        selected_contracts.append("nextjs.v1.run_stack")
    if has_routing_signal:
        selected_contracts.append("generic_http.v1.run_stack")

    skipped_contracts = [
        "wordpress.v1.run_stack",
        "nextjs.v1.run_stack",
        "generic_http.v1.run_stack",
    ]
    selected_deduped = _dedupe_preserving_order(selected_contracts)
    skipped_contracts = [name for name in skipped_contracts if name not in set(selected_deduped)]

    return PlannerSelection(
        selected_contracts=selected_deduped,
        skipped_contracts=skipped_contracts,
        reasoning_summary="Using deterministic fallback planner output because the LLM plan was unavailable or invalid.",
        confidence="low",
    )


def _dedupe_preserving_order(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()

    for value in values:
        if value in seen:
            continue

        seen.add(value)
        deduped.append(value)

    return deduped
