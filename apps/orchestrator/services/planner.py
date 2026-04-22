import json
import logging

import httpx

from config.settings import OLLAMA_BASE_URL, OLLAMA_ENABLED, OLLAMA_MODEL, OLLAMA_TIMEOUT_SECONDS
from schemas.planner import PlannerSelection
from schemas.scan import FindingResponse
from services.contracts import AdvancedScanContract
from services.llm import OLLAMA_GENERATE_PATH, _normalize_ollama_base_url


logger = logging.getLogger(__name__)


def plan_advanced_scans(
    findings: list[FindingResponse],
    contracts: list[AdvancedScanContract],
) -> PlannerSelection:
    fallback = _build_fallback_plan(findings)
    if not OLLAMA_ENABLED:
        return fallback

    prompt = _build_prompt(findings, contracts)
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

    try:
        plan = PlannerSelection.model_validate(parsed)
    except Exception as exc:
        logger.warning("Advanced scan planner schema validation failed: %s", exc)
        return fallback

    if not _is_valid_plan(plan, contracts):
        return fallback

    return _normalize_plan(plan)


def _build_prompt(findings: list[FindingResponse], contracts: list[AdvancedScanContract]) -> str:
    available_contracts = [
        {
            "name": contract.name,
            "description": contract.description,
            "tags": list(contract.tags),
            "trigger_signals": list(contract.trigger_signals),
        }
        for contract in contracts
    ]

    compact_findings = [
        {
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "tool_name": finding.tool_name,
            "evidence": finding.evidence[:180],
            "details": _compact_details(finding.details),
        }
        for finding in findings[:10]
    ]

    return f"""You are selecting advanced stack-specific scan contracts for a security orchestrator.

Choose only from the provided contracts.
Do not invent contract names.
If the stack evidence is weak or ambiguous, prefer `generic_http.v1.run_stack` or no specialist contracts.
Return JSON only with exactly these fields:
- selected_contracts
- skipped_contracts
- reasoning_summary
- confidence

Available contracts:
{json.dumps(available_contracts, indent=2)}

Baseline findings:
{json.dumps(compact_findings, indent=2)}
"""


def _compact_details(details: dict) -> dict:
    compact: dict = {}

    for key, value in list(details.items())[:5]:
        if isinstance(value, (str, int, float, bool)) or value is None:
            compact[key] = value
            continue

        compact[key] = str(value)[:120]

    return compact


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


def _build_fallback_plan(findings: list[FindingResponse]) -> PlannerSelection:
    select_generic_http = bool(findings)
    selected_contracts = ["generic_http.v1.run_stack"] if select_generic_http else []
    skipped_contracts = [
        "wordpress.v1.run_stack",
        "nextjs.v1.run_stack",
    ]
    if not select_generic_http:
        skipped_contracts.append("generic_http.v1.run_stack")

    return PlannerSelection(
        selected_contracts=selected_contracts,
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
