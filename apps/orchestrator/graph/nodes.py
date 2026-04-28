import logging
from typing import Literal

from db.postgres import get_db_connection
from graph.state import EnrichedReportGraphState
from schemas.planner import AdvancedExecutionPlan
from services.advanced_scans import (
    analyze_baseline_findings,
    build_advanced_execution_plan,
    create_execution_plan,
    evaluate_advanced_contract_results,
    execute_advanced_scan_plan,
    merge_advanced_findings,
    replace_advanced_results,
)
from services.baseline_context import build_baseline_context
from services.contracts import get_advanced_scan_contract, list_advanced_scan_contracts
from services.enrichment import enrich_findings
from services.event_bus import publish_scan_event
from services.llm import summarize_enriched_report
from services.planner import plan_advanced_scans
from services.reports import build_enriched_report, build_scan_report
from services.scans import fetch_evidence, fetch_findings, fetch_scan, fetch_scan_steps, fetch_signals
from services.vulnerability_research import execute_vulnerability_research, plan_vulnerability_research


logger = logging.getLogger(__name__)


def run_baseline_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: run_baseline_node")
    _publish_event(state, "baseline.started", "Baseline results loading started.")

    with get_db_connection() as connection:
        scan = fetch_scan(connection, state["scan_id"])
        if scan is None:
            raise LookupError("Scan not found")

        steps = fetch_scan_steps(connection, state["scan_id"])
        findings = fetch_findings(connection, state["scan_id"])
        signals = fetch_signals(connection, state["scan_id"])
        evidence = fetch_evidence(connection, state["scan_id"])

    baseline_context = build_baseline_context(scan, steps, findings, signals, evidence)
    scan_payload = {
        **scan,
        "canonical_target": baseline_context.canonical_url,
        "redirected": baseline_context.redirected,
    }

    payload = {
        "scan": scan_payload,
        "target": baseline_context.canonical_url,
        "baseline_result": scan_payload,
        "baseline_context": baseline_context,
        "steps": steps,
        "baseline_findings": findings,
        "baseline_signals": signals,
        "findings": findings,
        "merged_findings": findings,
        "advanced_results": [],
        "selected_contracts": [],
        "executed_contracts": [],
        "failed_contracts": [],
        "retryable_contracts": [],
        "retry_counts": {},
        "replan_count": 0,
        "execution_notes": [],
    }
    _publish_event(
        state,
        "baseline.completed",
        "Baseline results loading completed.",
        {
            "status": scan["status"],
            "finding_count": len(findings),
            "canonical_target": baseline_context.canonical_url,
        },
    )
    return payload


def analyze_baseline_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: analyze_baseline_node")

    baseline_analysis = analyze_baseline_findings(state["baseline_context"])
    baseline_result = {
        **state["baseline_result"],
        "analysis": baseline_analysis,
    }
    notes = list(state.get("execution_notes", []))
    if baseline_analysis["ambiguous_evidence"]:
        notes.append("Baseline evidence was classified as ambiguous before planner execution.")
    else:
        notes.append("Baseline evidence was classified as sufficiently strong for an initial planning pass.")

    return {
        "baseline_result": baseline_result,
        "execution_notes": notes,
    }


def plan_vulnerability_research_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: plan_vulnerability_research_node")
    _publish_event(state, "vuln.research.planning.started", "Planning vulnerability research targets.")

    plan = plan_vulnerability_research(state["baseline_context"])
    notes = list(state.get("execution_notes", []))
    notes.append(
        f"Vulnerability research planner selected {len(plan.queries)} query targets with confidence={plan.confidence}."
    )

    _publish_event(
        state,
        "vuln.research.planning.completed",
        "Vulnerability research target planning completed.",
        {
            "confidence": plan.confidence,
            "query_count": len(plan.queries),
        },
    )

    return {
        "vulnerability_research_plan": plan,
        "execution_notes": notes,
    }


def execute_vulnerability_research_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: execute_vulnerability_research_node")
    _publish_event(state, "vuln.research.started", "Running vulnerability research lookups.")

    plan = state.get("vulnerability_research_plan")
    notes = list(state.get("execution_notes", []))

    if plan is None:
        notes.append("Vulnerability research skipped because no research plan was available.")
        return {
            "vulnerability_research_results": [],
            "execution_notes": notes,
        }

    results = execute_vulnerability_research(plan, state.get("nvd_enabled", False))
    total_cves = sum(len(item.cve_matches) for item in results)
    notes.append(
        f"Vulnerability research executed {len(results)} lookups and returned {total_cves} CVE matches."
    )

    _publish_event(
        state,
        "vuln.research.completed",
        "Vulnerability research lookups completed.",
        {
            "query_count": len(results),
            "cve_match_count": total_cves,
        },
    )

    return {
        "vulnerability_research_results": results,
        "execution_notes": notes,
    }


def plan_contracts_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: plan_contracts_node")
    _publish_event(state, "planner.started", "Planner execution started.")

    planner_result = plan_advanced_scans(
        baseline_context=state["baseline_context"],
        contracts=list_advanced_scan_contracts(),
        vulnerability_research=[result.model_dump() for result in state.get("vulnerability_research_results", [])],
    )
    notes = list(state.get("execution_notes", []))
    notes.append(f"Planner selected {planner_result.selected_contracts or []} with confidence={planner_result.confidence}.")

    _publish_event(
        state,
        "planner.completed",
        "Planner execution completed.",
        {
            "confidence": planner_result.confidence,
            "selected_contracts": planner_result.selected_contracts,
        },
    )
    _publish_event(
        state,
        "contracts.selected",
        "Contracts were selected for advanced execution.",
        {
            "confidence": planner_result.confidence,
            "selected_contracts": planner_result.selected_contracts,
        },
    )

    return {
        "planner_result": planner_result,
        "selected_contracts": planner_result.selected_contracts,
        "execution_notes": notes,
    }


def route_after_plan(state: EnrichedReportGraphState) -> Literal[
    "execute_selected_contracts_node",
    "execute_generic_only_node",
]:
    planner_result = state["planner_result"]

    if planner_result.source == "deterministic" and planner_result.selected_contracts:
        return "execute_selected_contracts_node"

    if planner_result.confidence == "low":
        return "execute_generic_only_node"

    return "execute_selected_contracts_node"


def execute_selected_contracts_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: execute_selected_contracts_node")

    execution_plan = build_advanced_execution_plan(state["planner_result"])
    _publish_event(
        state,
        "contracts.selected",
        "Executing selected advanced contracts.",
        {
            "executed_contracts": execution_plan.executed_contracts,
            "confidence": execution_plan.confidence,
        },
    )
    advanced_results = execute_advanced_scan_plan(
        planner_result=execution_plan,
        baseline_context=state["baseline_context"],
        vulnerability_research=state.get("vulnerability_research_results", []),
        scan=state["scan"],
        scan_id=state["scan_id"],
    )
    notes = list(state.get("execution_notes", [])) + execution_plan.notes
    notes.append(f"Executed contracts: {execution_plan.executed_contracts}.")

    return {
        "advanced_execution_plan": execution_plan,
        "advanced_results": advanced_results,
        "executed_contracts": execution_plan.executed_contracts,
        "execution_notes": notes,
    }


def execute_generic_only_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: execute_generic_only_node")

    generic_contract = get_advanced_scan_contract("generic_http.v1.run_stack")
    notes = list(state.get("execution_notes", []))
    if generic_contract is None:
        notes.append("Generic fallback contract was unavailable, so no advanced contracts were executed.")
        return {
            "advanced_execution_plan": create_execution_plan(
                confidence=state["planner_result"].confidence,
                raw_selected_contracts=state["planner_result"].selected_contracts,
                executed_contracts=[],
                notes=[],
            ),
            "advanced_results": [],
            "executed_contracts": [],
            "execution_notes": notes,
        }

    execution_plan = create_execution_plan(
        confidence=state["planner_result"].confidence,
        raw_selected_contracts=state["planner_result"].selected_contracts,
        executed_contracts=[generic_contract.name],
        notes=[
            "Planner confidence was low, so the graph routed to generic_http.v1.run_stack only.",
        ],
    )
    _publish_event(
        state,
        "contracts.selected",
        "Executing generic fallback contract only.",
        {
            "executed_contracts": execution_plan.executed_contracts,
            "confidence": execution_plan.confidence,
        },
    )
    advanced_results = execute_advanced_scan_plan(
        planner_result=execution_plan,
        baseline_context=state["baseline_context"],
        vulnerability_research=state.get("vulnerability_research_results", []),
        scan=state["scan"],
        scan_id=state["scan_id"],
    )
    notes.extend(execution_plan.notes)
    notes.append(f"Executed contracts: {execution_plan.executed_contracts}.")

    return {
        "advanced_execution_plan": execution_plan,
        "advanced_results": advanced_results,
        "executed_contracts": execution_plan.executed_contracts,
        "execution_notes": notes,
    }


def evaluate_contract_results_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: evaluate_contract_results_node")

    evaluation = evaluate_advanced_contract_results(
        advanced_results=state.get("advanced_results", []),
        executed_contracts=state.get("executed_contracts", []),
        retry_counts=state.get("retry_counts", {}),
    )
    notes = list(state.get("execution_notes", [])) + evaluation["notes"]
    notes.append(f"Result quality evaluated as {evaluation['result_quality']}.")

    return {
        "failed_contracts": evaluation["failed_contracts"],
        "retryable_contracts": evaluation["retryable_contracts"],
        "result_quality": evaluation["result_quality"],
        "execution_notes": notes,
    }


def route_after_evaluation(state: EnrichedReportGraphState) -> Literal[
    "retry_failed_contracts_node",
    "replan_contracts_node",
    "merge_results_node",
]:
    if state.get("retryable_contracts"):
        return "retry_failed_contracts_node"

    if _should_replan(state):
        return "replan_contracts_node"

    return "merge_results_node"


def retry_failed_contracts_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: retry_failed_contracts_node")

    retryable_contracts = state.get("retryable_contracts", [])
    retry_counts = dict(state.get("retry_counts", {}))
    notes = list(state.get("execution_notes", []))

    if not retryable_contracts:
        return {
            "execution_notes": notes,
        }

    retry_plan = AdvancedExecutionPlan(
        confidence=state["planner_result"].confidence,
        raw_selected_contracts=state["selected_contracts"],
        executed_contracts=retryable_contracts,
        notes=[],
    )
    _publish_event(
        state,
        "retry.started",
        "Retrying failed advanced contracts.",
        {
            "contracts": retryable_contracts,
        },
    )
    retry_results = execute_advanced_scan_plan(
        planner_result=retry_plan,
        baseline_context=state["baseline_context"],
        vulnerability_research=state.get("vulnerability_research_results", []),
        scan=state["scan"],
        scan_id=state["scan_id"],
    )

    for contract_name in retryable_contracts:
        retry_counts[contract_name] = retry_counts.get(contract_name, 0) + 1

    notes.append(f"Retried contracts: {retryable_contracts}.")
    _publish_event(
        state,
        "retry.completed",
        "Retry execution completed.",
        {
            "contracts": retryable_contracts,
        },
    )

    return {
        "advanced_results": replace_advanced_results(state.get("advanced_results", []), retry_results),
        "retry_counts": retry_counts,
        "retryable_contracts": [],
        "execution_notes": notes,
    }


def replan_contracts_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: replan_contracts_node")
    _publish_event(
        state,
        "replan.started",
        "Re-planning advanced contracts after weak results.",
        {
            "failed_contracts": state.get("failed_contracts", []),
            "result_quality": state.get("result_quality"),
        },
    )

    planner_result = plan_advanced_scans(
        baseline_context=state["baseline_context"],
        contracts=list_advanced_scan_contracts(),
        vulnerability_research=[result.model_dump() for result in state.get("vulnerability_research_results", [])],
        previous_planner_result=state["planner_result"],
        failed_contracts=state.get("failed_contracts", []),
        advanced_results=state.get("advanced_results", []),
    )
    notes = list(state.get("execution_notes", []))
    notes.append(
        f"Ran a single re-plan pass after weak results; planner returned {planner_result.selected_contracts or []} with confidence={planner_result.confidence}."
    )
    _publish_event(
        state,
        "replan.completed",
        "Re-planning completed.",
        {
            "confidence": planner_result.confidence,
            "selected_contracts": planner_result.selected_contracts,
        },
    )

    return {
        "planner_result": planner_result,
        "selected_contracts": planner_result.selected_contracts,
        "replan_count": state.get("replan_count", 0) + 1,
        "failed_contracts": [],
        "retryable_contracts": [],
        "execution_notes": notes,
    }


def merge_results_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: merge_results_node")
    _publish_event(state, "merge.started", "Merging workflow findings into the final report set.")

    merged_findings = merge_advanced_findings(
        findings=state["baseline_findings"],
        advanced_results=state.get("advanced_results", []),
        scan=state["scan"],
    )
    report = build_scan_report(state["scan"], merged_findings)
    enriched_findings = enrich_findings(merged_findings)
    final_report = build_enriched_report(
        state["scan"],
        merged_findings,
        enriched_findings,
        steps=state.get("steps", []),
        executed_contracts=state.get("executed_contracts", []),
        vulnerability_research_plan=state.get("vulnerability_research_plan"),
        vulnerability_research_results=state.get("vulnerability_research_results", []),
        baseline_context=state.get("baseline_context"),
    )

    _publish_event(
        state,
        "merge.completed",
        "Merged findings are ready for reporting.",
        {
            "merged_finding_count": len(merged_findings),
            "result_quality": state.get("result_quality"),
        },
    )

    return {
        "merged_findings": merged_findings,
        "findings": merged_findings,
        "report": report,
        "enriched_findings": enriched_findings,
        "final_report": final_report,
    }


def route_after_merge(state: EnrichedReportGraphState) -> Literal["summarize_report_node", "complete_node"]:
    if state["ollama_enabled"] and state.get("result_quality") != "weak":
        return "summarize_report_node"

    return "complete_node"


def summarize_report_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: summarize_report_node")
    _publish_event(
        state,
        "summary.started",
        "Summary generation started.",
        {
            "result_quality": state.get("result_quality"),
        },
    )

    summary = summarize_enriched_report(state["final_report"])
    final_report = state["final_report"].model_copy(
        update={
            "executive_summary": summary["executive_summary"],
            "quick_wins": summary["quick_wins"],
        }
    )
    _publish_event(
        state,
        "summary.completed",
        "Summary generation completed.",
        {
            "has_executive_summary": final_report.executive_summary is not None,
            "quick_wins_count": len(final_report.quick_wins),
        },
    )

    return {
        "summary_output": summary,
        "final_report": final_report,
    }


def complete_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: complete_node")

    summary_output = state.get(
        "summary_output",
        {
            "executive_summary": state["final_report"].executive_summary,
            "quick_wins": state["final_report"].quick_wins,
        },
    )
    notes = list(state.get("execution_notes", []))
    notes.append(f"Workflow completed with result_quality={state.get('result_quality', 'unknown')}.")
    _publish_event(
        state,
        "scan.completed",
        "Scan workflow completed.",
        {
            "status": "completed",
            "result_quality": state.get("result_quality"),
            "executed_contracts": state.get("executed_contracts", []),
        },
    )

    return {
        "summary_output": summary_output,
        "execution_notes": notes,
    }


def _should_replan(state: EnrichedReportGraphState) -> bool:
    baseline_analysis = state["baseline_result"].get("analysis", {})
    ambiguous_evidence = bool(baseline_analysis.get("ambiguous_evidence"))
    return (
        state.get("result_quality") == "weak"
        and ambiguous_evidence
        and state.get("replan_count", 0) < 1
    )


def _publish_event(
    state: EnrichedReportGraphState,
    event_type: str,
    message: str,
    metadata: dict | None = None,
) -> None:
    publish_scan_event(state["scan_id"], event_type, message, metadata)
