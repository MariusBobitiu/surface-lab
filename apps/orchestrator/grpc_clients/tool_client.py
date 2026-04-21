import logging

import grpc

from config.settings import SCANNER_GRPC_ADDRESS, SCANNER_GRPC_AUTH_MODE, SCANNER_SERVICE_TOKEN
from grpc_clients.v1 import tool_pb2, tool_pb2_grpc

logger = logging.getLogger(__name__)


def _build_auth_metadata(token: str, auth_mode: str) -> tuple[tuple[str, str], ...]:
    if auth_mode == "x-service-token":
        return (("x-service-token", token),)

    return (("authorization", f"Bearer {token}"),)


class ScannerClient:
    def __init__(self, address: str, service_token: str, auth_mode: str) -> None:
        self._address = address
        self._metadata = _build_auth_metadata(service_token, auth_mode)
        self._auth_mode = auth_mode

        logger.info("scanner gRPC client initialized address=%s auth_mode=%s", address, auth_mode)

    def _invoke(self, method_name: str, request: object) -> object:
        with grpc.insecure_channel(self._address) as channel:
            client = tool_pb2_grpc.ToolServiceStub(channel)
            method = getattr(client, method_name)

            try:
                return method(request, metadata=self._metadata)
            except grpc.RpcError as exc:
                if exc.code() == grpc.StatusCode.UNAUTHENTICATED:
                    logger.error("scanner authentication failed method=%s auth_mode=%s", method_name, self._auth_mode)
                raise

    def run_baseline_scan(self, target: str) -> dict[str, str]:
        response = self._invoke("RunBaselineScan", tool_pb2.BaselineScanRequest(target=target))
        return {
            "scan_id": response.scan_id,
            "status": response.status,
        }


scanner_client = ScannerClient(
    address=SCANNER_GRPC_ADDRESS,
    service_token=SCANNER_SERVICE_TOKEN,
    auth_mode=SCANNER_GRPC_AUTH_MODE,
)


def run_baseline_scan(target: str) -> dict[str, str]:
    return scanner_client.run_baseline_scan(target)
