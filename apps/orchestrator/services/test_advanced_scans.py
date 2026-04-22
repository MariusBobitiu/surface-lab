import os
import unittest

os.environ.setdefault("SCANNER_SERVICE_TOKEN", "scanner-token")

from schemas.planner import PlannerSelection
from schemas.scan import FindingResponse
from services.advanced_scans import execute_advanced_scan_plan


class AdvancedScanExecutionTests(unittest.TestCase):
    def test_executes_wordpress_stub_contract(self) -> None:
        planner_result = PlannerSelection(
            selected_contracts=["wordpress.v1.run_stack"],
            skipped_contracts=["nextjs.v1.run_stack", "generic_http.v1.run_stack"],
            reasoning_summary="WordPress evidence is present.",
            confidence="high",
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

        results = execute_advanced_scan_plan(
            planner_result=planner_result,
            findings=findings,
            scan={"target": "https://example.com"},
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].contract, "wordpress.v1.run_stack")
        self.assertEqual(results[0].status, "completed")
        self.assertEqual(results[0].findings[0].tool_name, "advanced_wordpress_stub")


if __name__ == "__main__":
    unittest.main()
