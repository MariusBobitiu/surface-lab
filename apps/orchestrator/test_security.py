import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

os.environ.setdefault("SCANNER_SERVICE_TOKEN", "scanner-token")
os.environ.setdefault("ORCHESTRATOR_API_KEY", "test-api-key")

from fastapi.testclient import TestClient

from config import settings
from main import create_app


def _scan_details_payload() -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "scan_id": "scan-123",
        "target": "https://example.com",
        "status": "completed",
        "error_message": None,
        "created_at": now,
        "updated_at": now,
        "started_at": now,
        "completed_at": now,
        "summary": {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
        "steps": [],
        "findings": [],
    }


class OrchestratorSecurityTests(unittest.TestCase):
    def _build_client(self, **overrides: object) -> TestClient:
        patchers = [
            patch.object(settings, "ORCHESTRATOR_API_KEY", overrides.get("api_key", "test-api-key")),
            patch.object(settings, "ORCHESTRATOR_REQUIRE_API_KEY", overrides.get("require_api_key", True)),
            patch.object(settings, "ORCHESTRATOR_RATE_LIMIT_ENABLED", overrides.get("rate_limit_enabled", True)),
            patch.object(settings, "ORCHESTRATOR_RATE_LIMIT_RPM", overrides.get("rate_limit_rpm", 60)),
            patch.object(settings, "ORCHESTRATOR_RATE_LIMIT_BURST", overrides.get("rate_limit_burst", 20)),
            patch.object(
                settings,
                "ORCHESTRATOR_ALLOWED_ORIGINS",
                overrides.get("allowed_origins", ["http://localhost:3000"]),
            ),
            patch.object(
                settings,
                "ORCHESTRATOR_TRUSTED_HOSTS",
                overrides.get("trusted_hosts", ["localhost", "127.0.0.1"]),
            ),
            patch.object(
                settings,
                "ORCHESTRATOR_SECURITY_HEADERS_ENABLED",
                overrides.get("security_headers_enabled", True),
            ),
            patch.object(settings, "ORCHESTRATOR_BODY_LIMIT_BYTES", overrides.get("body_limit_bytes", 1048576)),
        ]

        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        return TestClient(create_app(), base_url=overrides.get("base_url", "http://localhost"))

    def test_missing_api_key_is_rejected(self) -> None:
        client = self._build_client(rate_limit_enabled=False)

        response = client.get("/scans/scan-123")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Unauthorized"})

    def test_invalid_api_key_is_rejected(self) -> None:
        client = self._build_client(rate_limit_enabled=False)

        response = client.get("/scans/scan-123", headers={"x-api-key": "wrong"})

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Unauthorized"})

    def test_valid_api_key_allows_request(self) -> None:
        client = self._build_client(rate_limit_enabled=False)

        with patch("api.routes.get_scan_details", return_value=_scan_details_payload()):
            response = client.get("/scans/scan-123", headers={"x-api-key": "test-api-key"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["scan_id"], "scan-123")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["referrer-policy"], "no-referrer")
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_rate_limited_request_returns_429(self) -> None:
        client = self._build_client(rate_limit_enabled=True, rate_limit_rpm=60, rate_limit_burst=1)

        with patch("api.routes.get_scan_details", return_value=_scan_details_payload()):
            first = client.get("/scans/scan-123", headers={"x-api-key": "test-api-key"})
            second = client.get("/scans/scan-123", headers={"x-api-key": "test-api-key"})

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)
        self.assertEqual(second.json(), {"detail": "Too Many Requests"})

    def test_invalid_host_is_rejected(self) -> None:
        client = self._build_client(rate_limit_enabled=False, base_url="http://evil.internal")

        response = client.get("/scans/scan-123", headers={"x-api-key": "test-api-key"})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"detail": "Invalid host header"})

    def test_cors_preflight_is_allowed_without_api_key(self) -> None:
        client = self._build_client(rate_limit_enabled=False)

        response = client.options(
            "/scans",
            headers={
                "origin": "http://localhost:3000",
                "access-control-request-method": "POST",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["access-control-allow-origin"], "http://localhost:3000")

    def test_oversized_body_is_rejected(self) -> None:
        client = self._build_client(rate_limit_enabled=False, body_limit_bytes=16)

        response = client.post(
            "/scans",
            headers={"x-api-key": "test-api-key"},
            json={"target": "https://example.com"},
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json(), {"detail": "Request body too large"})
