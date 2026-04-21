from langgraph.graph import END, START, StateGraph

from config.settings import NVD_ENABLED, OLLAMA_ENABLED
from graph.nodes import (
    build_report_node,
    enrich_findings_node,
    finalize_report_node,
    load_scan_node,
    maybe_attach_nvd_node,
    route_after_enrichment,
    route_after_finalize,
    summarize_report_node,
)
from graph.state import EnrichedReportGraphState


def build_enriched_report_graph():
    builder = StateGraph(EnrichedReportGraphState)
    builder.add_node("load_scan_node", load_scan_node)
    builder.add_node("build_report_node", build_report_node)
    builder.add_node("enrich_findings_node", enrich_findings_node)
    builder.add_node("maybe_attach_nvd_node", maybe_attach_nvd_node)
    builder.add_node("finalize_report_node", finalize_report_node)
    builder.add_node("summarize_report_node", summarize_report_node)

    builder.add_edge(START, "load_scan_node")
    builder.add_edge("load_scan_node", "build_report_node")
    builder.add_edge("build_report_node", "enrich_findings_node")
    builder.add_conditional_edges("enrich_findings_node", route_after_enrichment)
    builder.add_edge("maybe_attach_nvd_node", "finalize_report_node")
    builder.add_conditional_edges(
        "finalize_report_node",
        route_after_finalize,
        {
            "summarize": "summarize_report_node",
            "end": END,
        },
    )
    builder.add_edge("summarize_report_node", END)

    return builder.compile()


_ENRICHED_REPORT_GRAPH = build_enriched_report_graph()


def run_enriched_report_graph(scan_id: str):
    result = _ENRICHED_REPORT_GRAPH.invoke(
        {
            "scan_id": scan_id,
            "nvd_enabled": NVD_ENABLED,
            "ollama_enabled": OLLAMA_ENABLED,
        }
    )
    return result["final_report"]
