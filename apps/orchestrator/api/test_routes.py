import os
import unittest
from unittest.mock import patch

os.environ.setdefault("SCANNER_SERVICE_TOKEN", "scanner-token")
os.environ.setdefault("ORCHESTRATOR_API_KEY", "dev-orchestrator-api-key")

from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.routes import create_scan
from main import create_app
from schemas.scan import ScanRequest
from services.event_bus import cleanup_scan_stream, close_scan_stream, ensure_scan_stream, publish_scan_event


class CreateScanRouteTests(unittest.TestCase):
    def test_rejects_unsafe_target_before_scanner_call(self) -> None:
        with patch("api.routes.run_baseline_scan") as run_baseline_scan:
            with self.assertRaises(HTTPException) as context:
                create_scan(ScanRequest(target="http://127.0.0.1"))

        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(context.exception.detail, "Private or local addresses cannot be scanned")
        run_baseline_scan.assert_not_called()

    def test_stream_events_endpoint_returns_sse_payload(self) -> None:
        scan_id = "scan-events"
        ensure_scan_stream(scan_id)
        publish_scan_event(scan_id, "planner.completed", "Planner execution completed.", {"confidence": "high"})
        close_scan_stream(scan_id, cleanup_delay_seconds=30)

        client = TestClient(create_app(), base_url="http://localhost")
        response = client.get(f"/scans/{scan_id}/events", headers={"x-api-key": "dev-orchestrator-api-key"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"].split(";")[0], "text/event-stream")
        self.assertIn("data: ", response.text)
        self.assertIn('"type": "planner.completed"', response.text)

        cleanup_scan_stream(scan_id)
