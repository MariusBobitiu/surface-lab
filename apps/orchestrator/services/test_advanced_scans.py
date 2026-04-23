import os
import unittest

os.environ.setdefault("SCANNER_SERVICE_TOKEN", "scanner-token")
os.environ.setdefault("ORCHESTRATOR_API_KEY", "dev-orchestrator-api-key")

from schemas.planner import AdvancedExecutionPlan, PlannerSelection
from schemas.scan import FindingResponse, SignalResponse
from services.baseline_context import build_baseline_context
from services.advanced_scans import (
    analyze_baseline_findings,
    build_advanced_execution_plan,
    evaluate_advanced_contract_results,
    execute_advanced_scan_plan,
)


class AdvancedScanExecutionTests(unittest.TestCase):
    def test_high_confidence_runs_specialist_contract(self) -> None:
        planner_result = PlannerSelection(
            selected_contracts=["wordpress.v1.run_stack"],
            skipped_contracts=["nextjs.v1.run_stack", "generic_http.v1.run_stack"],
            reasoning_summary="WordPress evidence is present.",
            confidence="high",
        )

        execution_plan = build_advanced_execution_plan(planner_result)

        self.assertEqual(execution_plan.executed_contracts, ["wordpress.v1.run_stack"])
        self.assertEqual(execution_plan.notes, [])

    def test_medium_confidence_adds_generic_fallback(self) -> None:
        planner_result = PlannerSelection(
            selected_contracts=["wordpress.v1.run_stack"],
            skipped_contracts=["generic_http.v1.run_stack"],
            reasoning_summary="WordPress evidence is plausible.",
            confidence="medium",
        )

        execution_plan = build_advanced_execution_plan(planner_result)

        self.assertEqual(
            execution_plan.executed_contracts,
            ["wordpress.v1.run_stack", "generic_http.v1.run_stack"],
        )
        self.assertEqual(len(execution_plan.notes), 1)

    def test_low_confidence_suppresses_speculative_specialist_execution(self) -> None:
        planner_result = PlannerSelection(
            selected_contracts=["wordpress.v1.run_stack"],
            skipped_contracts=[],
            reasoning_summary="Weak signal.",
            confidence="low",
        )

        execution_plan = build_advanced_execution_plan(planner_result)

        self.assertEqual(execution_plan.executed_contracts, ["generic_http.v1.run_stack"])
        self.assertEqual(len(execution_plan.notes), 1)

    def test_executes_wordpress_stub_contract(self) -> None:
        execution_plan = AdvancedExecutionPlan(
            confidence="high",
            raw_selected_contracts=["wordpress.v1.run_stack"],
            executed_contracts=["wordpress.v1.run_stack"],
            notes=[],
        )
        findings = [
            FindingResponse(
                id="f-1",
                tool_name="fingerprint",
                type="fingerprint",
                category="fingerprint_generator",
                title="WordPress generator detected",
                severity="info",
                confidence="high",
                evidence="generator: WordPress 6.x",
                details={"generator": "WordPress"},
                created_at="2026-04-22T10:00:00Z",
            )
        ]
        baseline_context = build_baseline_context(
            scan={"id": "scan-1", "target": "https://raw.example.com"},
            steps=[],
            findings=findings,
            signals=[
                SignalResponse(
                    id="s1",
                    tool_name="fingerprint/v1",
                    key="framework.wordpress",
                    value=True,
                    confidence="high",
                    source="fingerprint.html",
                    created_at="2026-04-22T10:00:00Z",
                ),
                SignalResponse(
                    id="s2",
                    tool_name="targeting/v1",
                    key="transport.canonical_url",
                    value="https://example.com",
                    confidence="high",
                    source="targeting.redirect_chain",
                    created_at="2026-04-22T10:00:00Z",
                ),
            ],
            evidence=[],
        )

        results = execute_advanced_scan_plan(
            planner_result=execution_plan,
            baseline_context=baseline_context,
            scan={"target": "https://raw.example.com", "canonical_target": "https://example.com"},
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].contract, "wordpress.v1.run_stack")
        self.assertEqual(results[0].status, "completed")
        self.assertEqual(results[0].findings[0].tool_name, "advanced_wordpress_stub")
        self.assertEqual(results[0].metadata["target"], "https://example.com")

    def test_failed_wordpress_contract_is_retryable_once(self) -> None:
        evaluation = evaluate_advanced_contract_results(
            advanced_results=[
                execute_advanced_scan_plan(
                    planner_result=AdvancedExecutionPlan(
                        confidence="high",
                        raw_selected_contracts=["wordpress.v1.run_stack"],
                        executed_contracts=["wordpress.v1.run_stack"],
                        notes=[],
                    ),
                    baseline_context=build_baseline_context(
                        scan={"id": "scan-1", "target": "https://example.com"},
                        steps=[],
                        findings=[],
                        signals=[],
                        evidence=[],
                    ),
                    scan={},
                )[0].model_copy(update={"status": "failed", "findings": [], "error": "boom"})
            ],
            executed_contracts=["wordpress.v1.run_stack"],
            retry_counts={},
        )

        self.assertEqual(evaluation["retryable_contracts"], ["wordpress.v1.run_stack"])
        self.assertEqual(evaluation["result_quality"], "weak")

    def test_analyze_baseline_prefers_structured_signal_matches(self) -> None:
        baseline_context = build_baseline_context(
            scan={"id": "scan-1", "target": "https://example.com"},
            steps=[],
            findings=[],
            signals=[
                SignalResponse(
                    id="s1",
                    tool_name="fingerprint/v1",
                    key="framework.nextjs",
                    value=True,
                    confidence="high",
                    source="fingerprint.combined",
                    created_at="2026-04-22T10:00:00Z",
                ),
                SignalResponse(
                    id="s2",
                    tool_name="fingerprint/v1",
                    key="assets.next_static",
                    value=True,
                    confidence="high",
                    source="fingerprint.html",
                    created_at="2026-04-22T10:00:00Z",
                ),
            ],
            evidence=[],
        )

        analysis = analyze_baseline_findings(baseline_context)

        self.assertFalse(analysis["ambiguous_evidence"])
        self.assertEqual(analysis["contract_signal_matches"]["nextjs.v1.run_stack"], ["framework.nextjs", "assets.next_static"])


if __name__ == "__main__":
    unittest.main()
