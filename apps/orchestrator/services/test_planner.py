import os
import unittest
from unittest.mock import patch

os.environ.setdefault("SCANNER_SERVICE_TOKEN", "scanner-token")
os.environ.setdefault("ORCHESTRATOR_API_KEY", "dev-orchestrator-api-key")

from schemas.scan import FindingResponse, SignalResponse
from services.baseline_context import build_baseline_context
from services.contracts import list_advanced_scan_contracts
from services.planner import plan_advanced_scans


class AdvancedPlannerTests(unittest.TestCase):
    def test_falls_back_to_generic_http_when_llm_disabled(self) -> None:
        findings = [
            FindingResponse(
                id="f-1",
                tool_name="fingerprint",
                type="fingerprint",
                category="fingerprint_framework",
                title="WordPress generator detected",
                severity="info",
                confidence="high",
                evidence="generator: WordPress",
                details={"generator": "WordPress"},
                created_at="2026-04-22T10:00:00Z",
            )
        ]
        signals = [
            SignalResponse(
                id="s-1",
                tool_name="fingerprint/v1",
                key="framework.wordpress",
                value=True,
                confidence="high",
                source="fingerprint.html",
                created_at="2026-04-22T10:00:00Z",
            )
        ]

        baseline_context = build_baseline_context(
            scan={"id": "scan-1", "target": "example.com"},
            steps=[],
            findings=findings,
            signals=signals,
            evidence=[],
        )

        with patch("services.planner.OLLAMA_ENABLED", False):
            result = plan_advanced_scans(baseline_context, list_advanced_scan_contracts())

        self.assertEqual(result.selected_contracts, ["wordpress.v1.run_stack", "generic_http.v1.run_stack"])
        self.assertEqual(result.confidence, "low")

    def test_rejects_unknown_contracts_from_llm_output(self) -> None:
        findings: list[FindingResponse] = []

        with patch("services.planner.OLLAMA_ENABLED", True), patch("services.planner.httpx.Client") as client_class:
            client = client_class.return_value.__enter__.return_value
            client.post.return_value.json.return_value = {
                "response": (
                    '{"selected_contracts":["invented.v1.run_stack"],'
                    '"skipped_contracts":["wordpress.v1.run_stack"],'
                    '"reasoning_summary":"bad",'
                    '"confidence":"high"}'
                )
            }
            client.post.return_value.raise_for_status.return_value = None

            baseline_context = build_baseline_context(
                scan={"id": "scan-1", "target": "example.com"},
                steps=[],
                findings=findings,
                signals=[],
                evidence=[],
            )

            result = plan_advanced_scans(baseline_context, list_advanced_scan_contracts())

        self.assertEqual(result.selected_contracts, [])
        self.assertIn("generic_http.v1.run_stack", result.skipped_contracts)

    def test_accepts_numeric_confidence_from_llm_and_normalizes_it(self) -> None:
        baseline_context = build_baseline_context(
            scan={"id": "scan-1", "target": "https://example.com"},
            steps=[],
            findings=[],
            signals=[
                SignalResponse(
                    id="s-1",
                    tool_name="fingerprint/v1",
                    key="framework.wordpress",
                    value=True,
                    confidence="high",
                    source="fingerprint.html",
                    created_at="2026-04-22T10:00:00Z",
                )
            ],
            evidence=[],
        )

        with patch("services.planner.OLLAMA_ENABLED", True), patch("services.planner.httpx.Client") as client_class:
            client = client_class.return_value.__enter__.return_value
            client.post.return_value.json.return_value = {
                "response": (
                    '{"selected_contracts":["wordpress.v1.run_stack"],'
                    '"skipped_contracts":["generic_http.v1.run_stack"],'
                    '"reasoning_summary":"Strong structured signal match.",'
                    '"confidence":0.9}'
                )
            }
            client.post.return_value.raise_for_status.return_value = None

            result = plan_advanced_scans(baseline_context, list_advanced_scan_contracts())

        self.assertEqual(result.selected_contracts, ["wordpress.v1.run_stack"])
        self.assertEqual(result.confidence, "high")

    def test_posture_only_baseline_does_not_trigger_advanced_contracts(self) -> None:
        findings = [
            FindingResponse(
                id="f-1",
                tool_name="headers/v1",
                type="missing-csp",
                category="http_headers",
                title="Content-Security-Policy is missing",
                severity="high",
                confidence="high",
                evidence="The main response is missing the Content-Security-Policy security header.",
                details={},
                created_at="2026-04-22T10:00:00Z",
            )
        ]
        signals = [
            SignalResponse(
                id="s-1",
                tool_name="headers/v1",
                key="security.csp.present",
                value=False,
                confidence="high",
                source="headers.response",
                created_at="2026-04-22T10:00:00Z",
            )
        ]
        baseline_context = build_baseline_context(
            scan={"id": "scan-1", "target": "https://example.com"},
            steps=[],
            findings=findings,
            signals=signals,
            evidence=[],
        )

        with patch("services.planner.OLLAMA_ENABLED", False):
            result = plan_advanced_scans(baseline_context, list_advanced_scan_contracts())

        self.assertEqual(result.selected_contracts, [])
        self.assertIn("generic_http.v1.run_stack", result.skipped_contracts)


if __name__ == "__main__":
    unittest.main()
