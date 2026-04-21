import os
import unittest

os.environ.setdefault("SCANNER_SERVICE_TOKEN", "scanner-token")

from grpc_clients.tool_client import _build_auth_metadata, _build_channel_options


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

    def test_builds_empty_channel_options_without_server_name(self) -> None:
        self.assertEqual(_build_channel_options(""), ())

    def test_builds_server_name_override_option(self) -> None:
        self.assertEqual(
            _build_channel_options("scanner.local"),
            (("grpc.ssl_target_name_override", "scanner.local"),),
        )


if __name__ == "__main__":
    unittest.main()
