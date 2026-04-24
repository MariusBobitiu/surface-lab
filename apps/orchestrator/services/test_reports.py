import os
import unittest
from datetime import datetime, timezone

os.environ.setdefault("SCANNER_SERVICE_TOKEN", "scanner-token")
os.environ.setdefault("ORCHESTRATOR_API_KEY", "test-orchestrator-token")

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
            "canonical_target": "https://www.example.com",
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
        self.assertEqual(report.target, "https://www.example.com")
        self.assertEqual(report.top_issues[0].title, "WordPress XML-RPC endpoint appears enabled")
        self.assertEqual(report.categories[0].name, "WordPress Stack")
        self.assertEqual(enriched_report.categories[0].name, "WordPress Stack")

    def test_advanced_nextjs_findings_are_mapped_into_report(self) -> None:
        created_at = datetime.now(timezone.utc)
        scan = {
            "id": "scan-2",
            "target": "https://example.com",
            "canonical_target": "https://example.com",
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
                severity="high",
                confidence="high",
                evidence="Content-Security-Policy header missing",
                details={},
                created_at=created_at,
            )
        ]
        advanced_results = [
            AdvancedContractExecutionResult(
                contract="nextjs.v1.run_stack",
                status="completed",
                findings=[
                    AdvancedContractFinding(
                        tool_name="nextjs.v1.run_stack",
                        type="source_map_reference",
                        category="nextjs_exposure",
                        title="Next.js chunk references a source map",
                        severity="low",
                        confidence="medium",
                        evidence="Chunk /_next/static/app.js referenced source map app.js.map",
                        details={"url": "/_next/static/app.js", "source_map_hint": "app.js.map"},
                    )
                ],
                metadata={},
            )
        ]

        merged_findings = merge_advanced_findings(baseline_findings, advanced_results, scan)
        report = build_scan_report(scan, merged_findings)
        enriched_report = build_enriched_report(scan, merged_findings, enrich_findings(merged_findings))

        category_names = [category.name for category in report.categories]
        self.assertIn("Next.js Stack", category_names)
        nextjs_category = next(category for category in enriched_report.categories if category.name == "Next.js Stack")
        self.assertEqual(nextjs_category.findings[0].title, "Next.js chunk references a source map")
        self.assertIn("source maps", nextjs_category.findings[0].remediation_summary)


if __name__ == "__main__":
    unittest.main()
