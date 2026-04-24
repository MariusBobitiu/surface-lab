import logging
import time
from collections.abc import Callable
from functools import wraps

from langgraph.graph import END, START, StateGraph

from config.settings import NVD_ENABLED, OLLAMA_ENABLED
from graph.nodes import (
    analyze_baseline_node,
    complete_node,
    evaluate_contract_results_node,
    execute_generic_only_node,
    execute_selected_contracts_node,
    merge_results_node,
    plan_contracts_node,
    replan_contracts_node,
    retry_failed_contracts_node,
    route_after_evaluation,
    route_after_merge,
    route_after_plan,
    run_baseline_node,
    summarize_report_node,
)
from graph.state import EnrichedReportGraphState


logger = logging.getLogger(__name__)


def _logged_node(name: str, node: Callable[[EnrichedReportGraphState], dict]) -> Callable[[EnrichedReportGraphState], dict]:
    @wraps(node)
    def wrapper(state: EnrichedReportGraphState) -> dict:
        scan_id = state.get("scan_id")
        started_at = time.monotonic()
        logger.info("workflow node started scan_id=%s node=%s", scan_id, name)
        try:
            result = node(state)
        except Exception:
            logger.exception(
                "workflow node failed scan_id=%s node=%s duration_ms=%d",
                scan_id,
                name,
                int((time.monotonic() - started_at) * 1000),
            )
            raise

        logger.info(
            "workflow node completed scan_id=%s node=%s duration_ms=%d output_keys=%s",
            scan_id,
            name,
            int((time.monotonic() - started_at) * 1000),
            sorted(result.keys()),
        )
        return result

    return wrapper


def build_enriched_report_graph():
    builder = StateGraph(EnrichedReportGraphState)
    builder.add_node("run_baseline_node", _logged_node("run_baseline_node", run_baseline_node))
    builder.add_node("analyze_baseline_node", _logged_node("analyze_baseline_node", analyze_baseline_node))
    builder.add_node("plan_contracts_node", _logged_node("plan_contracts_node", plan_contracts_node))
    builder.add_node("execute_selected_contracts_node", _logged_node("execute_selected_contracts_node", execute_selected_contracts_node))
    builder.add_node("execute_generic_only_node", _logged_node("execute_generic_only_node", execute_generic_only_node))
    builder.add_node("evaluate_contract_results_node", _logged_node("evaluate_contract_results_node", evaluate_contract_results_node))
    builder.add_node("retry_failed_contracts_node", _logged_node("retry_failed_contracts_node", retry_failed_contracts_node))
    builder.add_node("replan_contracts_node", _logged_node("replan_contracts_node", replan_contracts_node))
    builder.add_node("merge_results_node", _logged_node("merge_results_node", merge_results_node))
    builder.add_node("summarize_report_node", _logged_node("summarize_report_node", summarize_report_node))
    builder.add_node("complete_node", _logged_node("complete_node", complete_node))

    builder.add_edge(START, "run_baseline_node")
    builder.add_edge("run_baseline_node", "analyze_baseline_node")
    builder.add_edge("analyze_baseline_node", "plan_contracts_node")
    builder.add_conditional_edges(
        "plan_contracts_node",
        route_after_plan,
        {
            "execute_selected_contracts_node": "execute_selected_contracts_node",
            "execute_generic_only_node": "execute_generic_only_node",
        },
    )
    builder.add_edge("execute_selected_contracts_node", "evaluate_contract_results_node")
    builder.add_edge("execute_generic_only_node", "evaluate_contract_results_node")
    builder.add_conditional_edges(
        "evaluate_contract_results_node",
        route_after_evaluation,
        {
            "retry_failed_contracts_node": "retry_failed_contracts_node",
            "replan_contracts_node": "replan_contracts_node",
            "merge_results_node": "merge_results_node",
        },
    )
    builder.add_edge("retry_failed_contracts_node", "evaluate_contract_results_node")
    builder.add_conditional_edges(
        "replan_contracts_node",
        route_after_plan,
        {
            "execute_selected_contracts_node": "execute_selected_contracts_node",
            "execute_generic_only_node": "execute_generic_only_node",
        },
    )
    builder.add_conditional_edges(
        "merge_results_node",
        route_after_merge,
        {
            "summarize_report_node": "summarize_report_node",
            "complete_node": "complete_node",
        },
    )
    builder.add_edge("summarize_report_node", "complete_node")
    builder.add_edge("complete_node", END)

    return builder.compile()


_ENRICHED_REPORT_GRAPH = build_enriched_report_graph()


def run_enriched_report_workflow(scan_id: str) -> dict:
    logger.info("workflow started scan_id=%s", scan_id)
    started_at = time.monotonic()
    try:
        result = _ENRICHED_REPORT_GRAPH.invoke(
            {
                "scan_id": scan_id,
                "nvd_enabled": NVD_ENABLED,
                "ollama_enabled": OLLAMA_ENABLED,
            }
        )
    except Exception:
        logger.exception("workflow failed scan_id=%s duration_ms=%d", scan_id, int((time.monotonic() - started_at) * 1000))
        raise

    logger.info("workflow completed scan_id=%s duration_ms=%d", scan_id, int((time.monotonic() - started_at) * 1000))
    return result


def run_enriched_report_graph(scan_id: str):
    result = run_enriched_report_workflow(scan_id)
    return result["final_report"]
