import os
import unittest
from unittest.mock import patch

os.environ.setdefault("SCANNER_SERVICE_TOKEN", "scanner-token")

from fastapi import HTTPException

from api.routes import create_scan
from schemas.scan import ScanRequest


class CreateScanRouteTests(unittest.TestCase):
    def test_rejects_unsafe_target_before_scanner_call(self) -> None:
        with patch("api.routes.run_baseline_scan") as run_baseline_scan:
            with self.assertRaises(HTTPException) as context:
                create_scan(ScanRequest(target="http://127.0.0.1"))

        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(context.exception.detail, "Private or local addresses cannot be scanned")
        run_baseline_scan.assert_not_called()
