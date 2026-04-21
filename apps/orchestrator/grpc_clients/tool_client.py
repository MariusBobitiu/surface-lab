import logging
from pathlib import Path

import grpc

from config.settings import (
    SCANNER_GRPC_ADDRESS,
    SCANNER_GRPC_AUTH_MODE,
    SCANNER_GRPC_TLS_CA_FILE,
    SCANNER_GRPC_TLS_ENABLED,
    SCANNER_GRPC_TLS_SERVER_NAME,
    SCANNER_SERVICE_TOKEN,
)
from grpc_clients.v1 import tool_pb2, tool_pb2_grpc

logger = logging.getLogger(__name__)


def _build_auth_metadata(token: str, auth_mode: str) -> tuple[tuple[str, str], ...]:
    if auth_mode == "x-service-token":
        return (("x-service-token", token),)

    return (("authorization", f"Bearer {token}"),)


class ScannerClient:
    def __init__(
        self,
        address: str,
        service_token: str,
        auth_mode: str,
        tls_enabled: bool,
        tls_ca_file: str,
        tls_server_name: str,
    ) -> None:
        self._address = address
        self._metadata = _build_auth_metadata(service_token, auth_mode)
        self._auth_mode = auth_mode
        self._tls_enabled = tls_enabled
        self._channel_credentials = _load_channel_credentials(tls_enabled, tls_ca_file)
        self._channel_options = _build_channel_options(tls_server_name)

        logger.info(
            "scanner gRPC client initialized address=%s auth_mode=%s tls_enabled=%s",
            address,
            auth_mode,
            tls_enabled,
        )

    def _invoke(self, method_name: str, request: object) -> object:
        with self._create_channel() as channel:
            client = tool_pb2_grpc.ToolServiceStub(channel)
            method = getattr(client, method_name)

            try:
                return method(request, metadata=self._metadata)
            except grpc.RpcError as exc:
                if exc.code() == grpc.StatusCode.UNAUTHENTICATED:
                    logger.error("scanner authentication failed method=%s auth_mode=%s", method_name, self._auth_mode)
                raise

    def _create_channel(self) -> grpc.Channel:
        if self._tls_enabled:
            logger.info("scanner gRPC client using TLS address=%s", self._address)
            return grpc.secure_channel(
                self._address,
                self._channel_credentials,
                options=self._channel_options,
            )

        logger.info("scanner gRPC client using insecure channel address=%s", self._address)
        return grpc.insecure_channel(self._address)

    def run_baseline_scan(self, target: str) -> dict[str, str]:
        response = self._invoke("RunBaselineScan", tool_pb2.BaselineScanRequest(target=target))
        return {
            "scan_id": response.scan_id,
            "status": response.status,
        }


def _load_channel_credentials(tls_enabled: bool, tls_ca_file: str) -> grpc.ChannelCredentials | None:
    if not tls_enabled:
        return None

    root_certificates = Path(tls_ca_file).read_bytes()
    return grpc.ssl_channel_credentials(root_certificates=root_certificates)


def _build_channel_options(server_name: str) -> tuple[tuple[str, str], ...]:
    if not server_name:
        return ()

    return (("grpc.ssl_target_name_override", server_name),)


scanner_client = ScannerClient(
    address=SCANNER_GRPC_ADDRESS,
    service_token=SCANNER_SERVICE_TOKEN,
    auth_mode=SCANNER_GRPC_AUTH_MODE,
    tls_enabled=SCANNER_GRPC_TLS_ENABLED,
    tls_ca_file=SCANNER_GRPC_TLS_CA_FILE,
    tls_server_name=SCANNER_GRPC_TLS_SERVER_NAME,
)


def run_baseline_scan(target: str) -> dict[str, str]:
    return scanner_client.run_baseline_scan(target)
