import os
import unittest
from unittest.mock import patch

os.environ.setdefault("SCANNER_SERVICE_TOKEN", "scanner-token")

from schemas.scan import FindingResponse
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

        with patch("services.planner.OLLAMA_ENABLED", False):
            result = plan_advanced_scans(findings, list_advanced_scan_contracts())

        self.assertEqual(result.selected_contracts, ["generic_http.v1.run_stack"])
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

            result = plan_advanced_scans(findings, list_advanced_scan_contracts())

        self.assertEqual(result.selected_contracts, [])
        self.assertIn("generic_http.v1.run_stack", result.skipped_contracts)


if __name__ == "__main__":
    unittest.main()
