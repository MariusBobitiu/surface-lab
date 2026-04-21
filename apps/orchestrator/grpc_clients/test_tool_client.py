import os
import unittest

os.environ.setdefault("SCANNER_SERVICE_TOKEN", "scanner-token")

from grpc_clients.tool_client import _build_auth_metadata


class BuildAuthMetadataTests(unittest.TestCase):
    def test_builds_bearer_metadata_by_default(self) -> None:
        self.assertEqual(
            _build_auth_metadata("scanner-token", "bearer"),
            (("authorization", "Bearer scanner-token"),),
        )

    def test_builds_x_service_token_metadata(self) -> None:
        self.assertEqual(
            _build_auth_metadata("scanner-token", "x-service-token"),
            (("x-service-token", "scanner-token"),),
        )


if __name__ == "__main__":
    unittest.main()
