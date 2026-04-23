import os
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

os.environ.setdefault("SCANNER_SERVICE_TOKEN", "scanner-token")
os.environ.setdefault("ORCHESTRATOR_API_KEY", "dev-orchestrator-api-key")

from graph.nodes import route_after_evaluation, route_after_merge, route_after_plan
from graph.workflow import run_enriched_report_workflow
from schemas.planner import PlannerSelection
from schemas.scan import FindingResponse, SignalResponse
from services.event_bus import cleanup_scan_stream, subscribe
from services.workflow_runner import run_or_wait_scan_workflow


class WorkflowRoutingTests(unittest.TestCase):
    def test_route_after_plan_high_confidence_executes_selected_contracts(self) -> None:
        state = {
            "planner_result": PlannerSelection(
                selected_contracts=["wordpress.v1.run_stack"],
                skipped_contracts=[],
                reasoning_summary="Strong signal.",
                confidence="high",
            )
        }

        self.assertEqual(route_after_plan(state), "execute_selected_contracts_node")

    def test_route_after_plan_low_confidence_executes_generic_only(self) -> None:
        state = {
            "planner_result": PlannerSelection(
                selected_contracts=["wordpress.v1.run_stack"],
                skipped_contracts=[],
                reasoning_summary="Weak signal.",
                confidence="low",
            )
        }

        self.assertEqual(route_after_plan(state), "execute_generic_only_node")

    def test_route_after_evaluation_retries_before_replanning(self) -> None:
        state = {
            "retryable_contracts": ["wordpress.v1.run_stack"],
            "result_quality": "weak",
            "baseline_result": {"analysis": {"ambiguous_evidence": True}},
            "replan_count": 0,
        }

        self.assertEqual(route_after_evaluation(state), "retry_failed_contracts_node")

    def test_route_after_evaluation_replans_once_for_weak_ambiguous_results(self) -> None:
        state = {
            "retryable_contracts": [],
            "result_quality": "weak",
            "baseline_result": {"analysis": {"ambiguous_evidence": True}},
            "replan_count": 0,
        }

        self.assertEqual(route_after_evaluation(state), "replan_contracts_node")

    def test_route_after_merge_skips_summary_for_weak_results(self) -> None:
        state = {
            "ollama_enabled": True,
            "result_quality": "weak",
        }

        self.assertEqual(route_after_merge(state), "complete_node")

    def test_workflow_publishes_key_events(self) -> None:
        scan_id = "scan-workflow-events"
        created_at = datetime.now(timezone.utc)
        finding = FindingResponse(
            id="f-1",
            tool_name="fingerprint",
            type="fingerprint",
            category="fingerprint_generator",
            title="WordPress generator detected",
            severity="info",
            confidence="high",
            evidence="generator: WordPress",
            details={"generator": "WordPress"},
            created_at=created_at,
        )
        signal = SignalResponse(
            id="s-1",
            tool_name="fingerprint/v1",
            key="framework.wordpress",
            value=True,
            confidence="high",
            source="fingerprint.html",
            created_at=created_at,
        )

        connection_context = MagicMock()
        connection_context.__enter__.return_value = object()
        connection_context.__exit__.return_value = False

        with (
            patch("graph.nodes.get_db_connection", return_value=connection_context),
            patch(
                "graph.nodes.fetch_scan",
                return_value={
                    "id": scan_id,
                    "target": "https://example.com",
                    "status": "completed",
                    "created_at": created_at,
                    "completed_at": created_at,
                },
            ),
            patch("graph.nodes.fetch_scan_steps", return_value=[]),
            patch("graph.nodes.fetch_findings", return_value=[finding]),
            patch("graph.nodes.fetch_signals", return_value=[signal]),
            patch("graph.nodes.fetch_evidence", return_value=[]),
            patch(
                "graph.nodes.plan_advanced_scans",
                return_value=PlannerSelection(
                    selected_contracts=["wordpress.v1.run_stack"],
                    skipped_contracts=[],
                    reasoning_summary="WordPress evidence found.",
                    confidence="high",
                ),
            ),
        ):
            run_enriched_report_workflow(scan_id)

        _, backlog = subscribe(scan_id)
        event_types = [event.type for event in backlog]

        self.assertIn("baseline.started", event_types)
        self.assertIn("planner.completed", event_types)
        self.assertIn("contract.started", event_types)
        self.assertIn("merge.completed", event_types)
        self.assertIn("scan.completed", event_types)

        cleanup_scan_stream(scan_id)

    def test_workflow_runner_closes_stream_on_completion(self) -> None:
        scan_id = "scan-runner-close"

        with patch("services.workflow_runner.run_enriched_report_workflow", return_value={"final_report": {"scan_id": scan_id}}):
            run_or_wait_scan_workflow(scan_id)

        subscriber_queue, backlog = subscribe(scan_id)
        self.assertIn("scan.started", [event.type for event in backlog])
        sentinel = subscriber_queue.get(timeout=1)
        self.assertFalse(hasattr(sentinel, "model_dump"))

        cleanup_scan_stream(scan_id)


if __name__ == "__main__":
    unittest.main()
