import logging
from typing import Literal

from db.postgres import get_db_connection
from graph.state import EnrichedReportGraphState
from services.advanced_scans import execute_advanced_scan_plan
from services.contracts import list_advanced_scan_contracts
from services.enrichment import enrich_findings
from services.llm import summarize_enriched_report
from services.planner import plan_advanced_scans
from services.reports import build_enriched_report, build_scan_report
from services.scans import fetch_findings, fetch_scan, fetch_scan_steps


logger = logging.getLogger(__name__)


def load_scan_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: load_scan_node")

    with get_db_connection() as connection:
        scan = fetch_scan(connection, state["scan_id"])
        if scan is None:
            raise LookupError("Scan not found")

        steps = fetch_scan_steps(connection, state["scan_id"])
        findings = fetch_findings(connection, state["scan_id"])

    return {
        "scan": scan,
        "steps": steps,
        "findings": findings,
    }


def plan_advanced_scans_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: plan_advanced_scans_node")

    planner_result = plan_advanced_scans(
        findings=state["findings"],
        contracts=list_advanced_scan_contracts(),
    )
    return {"planner_result": planner_result}


def execute_advanced_scans_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: execute_advanced_scans_node")

    advanced_results = execute_advanced_scan_plan(
        planner_result=state["planner_result"],
        findings=state["findings"],
        scan=state["scan"],
    )
    return {"advanced_results": advanced_results}


def build_report_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: build_report_node")

    report = build_scan_report(state["scan"], state["findings"])
    return {"report": report}


def enrich_findings_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: enrich_findings_node")

    enriched_findings = enrich_findings(state["findings"])
    return {"enriched_findings": enriched_findings}


def route_after_enrichment(state: EnrichedReportGraphState) -> Literal["maybe_attach_nvd_node", "finalize_report_node"]:
    if state["nvd_enabled"] and _has_relevant_nvd_findings(state):
        return "maybe_attach_nvd_node"

    return "finalize_report_node"


def maybe_attach_nvd_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: maybe_attach_nvd_node")
    return {"enriched_findings": state["enriched_findings"]}


def finalize_report_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: finalize_report_node")

    final_report = build_enriched_report(
        state["scan"],
        state["findings"],
        state["enriched_findings"],
    )
    return {"final_report": final_report}


def route_after_finalize(state: EnrichedReportGraphState) -> Literal["summarize", "end"]:
    if state["ollama_enabled"]:
        return "summarize"

    return "end"


def summarize_report_node(state: EnrichedReportGraphState) -> dict:
    logger.info("LangGraph node: summarize_report_node")

    summary = summarize_enriched_report(state["final_report"])
    final_report = state["final_report"].model_copy(
        update={
            "executive_summary": summary["executive_summary"],
            "quick_wins": summary["quick_wins"],
        }
    )
    return {"final_report": final_report}


def _has_relevant_nvd_findings(state: EnrichedReportGraphState) -> bool:
    for finding in state["findings"]:
        if finding.category.lower().startswith("fingerprint_"):
            return True

    return False
