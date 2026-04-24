import os
import unittest
from datetime import datetime, timezone

os.environ.setdefault("SCANNER_SERVICE_TOKEN", "scanner-token")
os.environ.setdefault("ORCHESTRATOR_API_KEY", "dev-orchestrator-api-key")

from schemas.scan import EvidenceResponse, FindingResponse, ScanStepResponse, SignalResponse
from services.baseline_context import build_baseline_context


class BaselineContextTests(unittest.TestCase):
    def test_prefers_structured_signals_and_canonical_url(self) -> None:
        created_at = datetime.now(timezone.utc)
        scan = {"id": "scan-1", "target": "example.com"}
        context = build_baseline_context(
            scan=scan,
            steps=[],
            findings=[],
            signals=[
                SignalResponse(
                    id="s1",
                    tool_name="targeting/v1",
                    key="transport.canonical_url",
                    value="https://www.example.com",
                    confidence="high",
                    source="targeting.redirect_chain",
                    created_at=created_at,
                ),
                SignalResponse(
                    id="s2",
                    tool_name="targeting/v1",
                    key="transport.redirected",
                    value=True,
                    confidence="high",
                    source="targeting.redirect_chain",
                    created_at=created_at,
                ),
            ],
            evidence=[],
        )

        self.assertEqual(context.canonical_url, "https://www.example.com")
        self.assertTrue(context.redirected)
        self.assertEqual(context.signal_value("transport.canonical_url"), "https://www.example.com")

    def test_legacy_scans_can_derive_signals_from_findings_and_steps(self) -> None:
        created_at = datetime.now(timezone.utc)
        scan = {"id": "scan-1", "target": "example.com"}
        context = build_baseline_context(
            scan=scan,
            steps=[
                ScanStepResponse(
                    id="step-1",
                    tool_name="fingerprint/v1",
                    status="success",
                    duration_ms=10,
                    raw_metadata={"metadata": {"final_url": "https://example.com"}},
                    created_at=created_at,
                )
            ],
            findings=[
                FindingResponse(
                    id="f1",
                    tool_name="fingerprint/v1",
                    type="legacy",
                    category="fingerprint_framework",
                    title="WordPress generator detected",
                    severity="info",
                    confidence="high",
                    evidence="generator: WordPress",
                    details={},
                    created_at=created_at,
                )
            ],
            signals=[],
            evidence=[],
        )

        self.assertTrue(context.signal_is_true("framework.wordpress"))
        self.assertEqual(context.canonical_url, "https://example.com")

    def test_prefers_redirect_chain_evidence_when_signal_missing(self) -> None:
        created_at = datetime.now(timezone.utc)
        scan = {"id": "scan-1", "target": "example.com"}
        context = build_baseline_context(
            scan=scan,
            steps=[],
            findings=[],
            signals=[],
            evidence=[
                EvidenceResponse(
                    id="e1",
                    tool_name="targeting/v1",
                    kind="redirect_chain",
                    target="https://example.com",
                    data={"final_url": "https://www.example.com"},
                    created_at=created_at,
                )
            ],
        )

        self.assertEqual(context.canonical_url, "https://www.example.com")

    def test_routing_signals_include_tooling(self) -> None:
        created_at = datetime.now(timezone.utc)
        scan = {"id": "scan-1", "target": "example.com"}
        context = build_baseline_context(
            scan=scan,
            steps=[],
            findings=[],
            signals=[
                SignalResponse(
                    id="s1",
                    tool_name="fingerprint/v1",
                    key="tooling.supabase",
                    value=True,
                    confidence="medium",
                    source="fingerprint.html",
                    created_at=created_at,
                )
            ],
            evidence=[],
        )

        self.assertIn("tooling.supabase", context.routing_signals)
        self.assertEqual(context.planner_signal_summary()[0]["key"], "tooling.supabase")


if __name__ == "__main__":
    unittest.main()
