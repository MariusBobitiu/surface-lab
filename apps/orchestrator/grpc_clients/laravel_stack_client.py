import logging
from pathlib import Path

import grpc
from google.protobuf import json_format, struct_pb2

from config.settings import (
    LARAVEL_STACK_ENABLED,
    LARAVEL_STACK_GRPC_ADDRESS,
    LARAVEL_STACK_GRPC_AUTH_MODE,
    LARAVEL_STACK_GRPC_TLS_CA_FILE,
    LARAVEL_STACK_GRPC_TLS_ENABLED,
    LARAVEL_STACK_GRPC_TLS_SERVER_NAME,
    LARAVEL_STACK_SERVICE_TOKEN,
)
from grpc_clients.v1 import laravel_stack_pb2, laravel_stack_pb2_grpc


logger = logging.getLogger(__name__)


def _build_auth_metadata(token: str, auth_mode: str) -> tuple[tuple[str, str], ...]:
    if auth_mode == "x-service-token":
        return (("x-service-token", token),)

    return (("authorization", f"Bearer {token}"),)


class LaravelStackClient:
    def __init__(
        self,
        enabled: bool,
        address: str,
        service_token: str,
        auth_mode: str,
        tls_enabled: bool,
        tls_ca_file: str,
        tls_server_name: str,
    ) -> None:
        self._enabled = enabled
        self._address = address
        self._metadata = _build_auth_metadata(service_token, auth_mode) if service_token else ()
        self._auth_mode = auth_mode
        self._tls_enabled = tls_enabled
        self._channel_credentials = _load_channel_credentials(tls_enabled, tls_ca_file)
        self._channel_options = _build_channel_options(tls_server_name)

        logger.info(
            "laravel-stack gRPC client initialized enabled=%s address=%s auth_mode=%s tls_enabled=%s",
            enabled,
            address,
            auth_mode,
            tls_enabled,
        )

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _invoke(self, method_name: str, request: object) -> object:
        if not self._enabled:
            raise RuntimeError("laravel-stack gRPC client is disabled")

        if not self._metadata:
            raise RuntimeError("laravel-stack service token is not configured")

        with self._create_channel() as channel:
            client = laravel_stack_pb2_grpc.LaravelStackServiceStub(channel)
            method = getattr(client, method_name)

            try:
                return method(request, metadata=self._metadata)
            except grpc.RpcError as exc:
                if exc.code() == grpc.StatusCode.UNAUTHENTICATED:
                    logger.error("laravel-stack authentication failed method=%s auth_mode=%s", method_name, self._auth_mode)
                raise

    def _create_channel(self) -> grpc.Channel:
        if self._tls_enabled:
            logger.info("laravel-stack gRPC client using TLS address=%s", self._address)
            return grpc.secure_channel(
                self._address,
                self._channel_credentials,
                options=self._channel_options,
            )

        logger.info("laravel-stack gRPC client using insecure channel address=%s", self._address)
        return grpc.insecure_channel(self._address)

    def run_stack(self, target: str, metadata: dict | None = None) -> dict:
        request_metadata = struct_pb2.Struct()
        if metadata:
            request_metadata.update(metadata)

        response = self._invoke(
            "RunStack",
            laravel_stack_pb2.RunStackRequest(
                target=target,
                metadata=request_metadata,
            ),
        )

        return {
            "tool": response.tool,
            "target": response.target,
            "status": response.status,
            "duration_ms": response.duration_ms,
            "findings": [
                {
                    "type": finding.type,
                    "category": finding.category,
                    "title": finding.title,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "evidence": finding.evidence,
                    "details": json_format.MessageToDict(finding.details),
                }
                for finding in response.findings
            ],
            "metadata": json_format.MessageToDict(response.metadata),
            "error": response.error,
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


laravel_stack_client = LaravelStackClient(
    enabled=LARAVEL_STACK_ENABLED,
    address=LARAVEL_STACK_GRPC_ADDRESS,
    service_token=LARAVEL_STACK_SERVICE_TOKEN,
    auth_mode=LARAVEL_STACK_GRPC_AUTH_MODE,
    tls_enabled=LARAVEL_STACK_GRPC_TLS_ENABLED,
    tls_ca_file=LARAVEL_STACK_GRPC_TLS_CA_FILE,
    tls_server_name=LARAVEL_STACK_GRPC_TLS_SERVER_NAME,
)


def is_laravel_stack_enabled() -> bool:
    return laravel_stack_client.enabled


def run_laravel_stack(target: str, metadata: dict | None = None) -> dict:
    return laravel_stack_client.run_stack(target, metadata)
