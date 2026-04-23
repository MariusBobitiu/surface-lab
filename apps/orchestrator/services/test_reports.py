import os
import unittest
from datetime import datetime, timezone

os.environ.setdefault("SCANNER_SERVICE_TOKEN", "scanner-token")

from schemas.planner import AdvancedContractExecutionResult, AdvancedContractFinding
from schemas.scan import FindingResponse
from services.advanced_scans import merge_advanced_findings
from services.enrichment import enrich_findings
from services.reports import build_enriched_report, build_scan_report


class ReportMergingTests(unittest.TestCase):
    def test_advanced_wordpress_findings_are_merged_into_report(self) -> None:
        created_at = datetime.now(timezone.utc)
        scan = {
            "id": "scan-1",
            "target": "https://example.com",
            "status": "completed",
            "created_at": created_at,
            "completed_at": created_at,
        }
        baseline_findings = [
            FindingResponse(
                id="f-1",
                tool_name="headers",
                type="misconfiguration",
                category="http_headers",
                title="Missing CSP",
                severity="low",
                confidence="high",
                evidence="Content-Security-Policy header missing",
                details={},
                created_at=created_at,
            )
        ]
        advanced_results = [
            AdvancedContractExecutionResult(
                contract="wordpress.v1.run_stack",
                status="completed",
                findings=[
                    AdvancedContractFinding(
                        tool_name="wordpress.v1.run_stack",
                        type="surface",
                        category="wordpress_surface",
                        title="WordPress XML-RPC endpoint appears enabled",
                        severity="medium",
                        confidence="high",
                        evidence="/xmlrpc.php returned HTTP 405",
                        details={"path": "/xmlrpc.php", "status": 405},
                    )
                ],
                metadata={},
            )
        ]

        merged_findings = merge_advanced_findings(baseline_findings, advanced_results, scan)
        report = build_scan_report(scan, merged_findings)
        enriched_report = build_enriched_report(scan, merged_findings, enrich_findings(merged_findings))

        self.assertEqual(report.summary.total, 2)
        self.assertEqual(report.summary.medium, 1)
        self.assertEqual(report.top_issues[0].title, "WordPress XML-RPC endpoint appears enabled")
        self.assertEqual(report.categories[0].name, "WordPress Stack")
        self.assertEqual(enriched_report.categories[0].name, "WordPress Stack")


if __name__ == "__main__":
    unittest.main()
