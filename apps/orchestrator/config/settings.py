import os
from pathlib import Path


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default

    try:
        return float(value)
    except ValueError:
        return default


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default

    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc


def _get_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _get_required_str(name: str) -> str:
    value = _get_str(name)
    if not value:
        raise RuntimeError(f"{name} is required")

    return value


def _get_csv(name: str, default: list[str]) -> list[str]:
    value = os.getenv(name)
    if value is None:
        return default

    return [entry.strip() for entry in value.split(",") if entry.strip()]


def _get_scanner_auth_mode() -> str:
    mode = _get_str("SCANNER_GRPC_AUTH_MODE", "bearer").lower()
    if mode not in {"bearer", "x-service-token"}:
        raise RuntimeError("SCANNER_GRPC_AUTH_MODE must be one of: bearer, x-service-token")

    return mode


def _get_scanner_tls_settings() -> tuple[bool, str, str]:
    enabled = _get_bool("SCANNER_GRPC_TLS_ENABLED", False)
    ca_file = _get_str("SCANNER_GRPC_TLS_CA_FILE")
    server_name = _get_str("SCANNER_GRPC_TLS_SERVER_NAME")

    if enabled and not ca_file:
        raise RuntimeError("SCANNER_GRPC_TLS_CA_FILE is required when SCANNER_GRPC_TLS_ENABLED=true")

    if ca_file:
        ca_path = Path(ca_file)
        if not ca_path.exists():
            raise RuntimeError(f"SCANNER_GRPC_TLS_CA_FILE does not exist: {ca_file}")

    return enabled, ca_file, server_name


def _get_orchestrator_api_key() -> str:
    required = _get_bool("ORCHESTRATOR_REQUIRE_API_KEY", True)
    api_key = _get_str("ORCHESTRATOR_API_KEY")

    if required and not api_key:
        raise RuntimeError("ORCHESTRATOR_API_KEY is required when ORCHESTRATOR_REQUIRE_API_KEY=true")

    return api_key


def _get_allowed_origins() -> list[str]:
    origins = _get_csv(
        "ORCHESTRATOR_ALLOWED_ORIGINS",
        [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ],
    )
    if "*" in origins:
        raise RuntimeError("ORCHESTRATOR_ALLOWED_ORIGINS must not include '*'")

    return origins


def _get_trusted_hosts() -> list[str]:
    return _get_csv(
        "ORCHESTRATOR_TRUSTED_HOSTS",
        ["localhost", "127.0.0.1", "[::1]"],
    )


SCANNER_GRPC_ADDRESS = _get_str("SCANNER_GRPC_ADDRESS", "localhost:50051")
SCANNER_SERVICE_TOKEN = _get_required_str("SCANNER_SERVICE_TOKEN")
SCANNER_GRPC_AUTH_MODE = _get_scanner_auth_mode()
SCANNER_GRPC_TLS_ENABLED, SCANNER_GRPC_TLS_CA_FILE, SCANNER_GRPC_TLS_SERVER_NAME = _get_scanner_tls_settings()
DATABASE_URL = os.getenv("DATABASE_URL", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NVD_ENABLED = _get_bool("NVD_ENABLED", bool(NVD_API_KEY))
NVD_MIN_INTERVAL_SECONDS = _get_float("NVD_MIN_INTERVAL_SECONDS", 6.0)
NVD_TIMEOUT_SECONDS = _get_float("NVD_TIMEOUT_SECONDS", 10.0)
REDIS_URL = os.getenv("REDIS_URL", "").strip()
REDIS_ENABLED = _get_bool("REDIS_ENABLED", bool(REDIS_URL))
NVD_CACHE_TTL_SECONDS = int(_get_float("NVD_CACHE_TTL_SECONDS", 86400))
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").strip()
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma3").strip()
OLLAMA_TIMEOUT_SECONDS = _get_float("OLLAMA_TIMEOUT_SECONDS", 30.0)
OLLAMA_ENABLED = _get_bool("OLLAMA_ENABLED", False)
ORCHESTRATOR_REQUIRE_API_KEY = _get_bool("ORCHESTRATOR_REQUIRE_API_KEY", True)
ORCHESTRATOR_API_KEY = _get_orchestrator_api_key()
ORCHESTRATOR_RATE_LIMIT_ENABLED = _get_bool("ORCHESTRATOR_RATE_LIMIT_ENABLED", True)
ORCHESTRATOR_RATE_LIMIT_RPM = _get_int("ORCHESTRATOR_RATE_LIMIT_RPM", 60)
ORCHESTRATOR_RATE_LIMIT_BURST = _get_int("ORCHESTRATOR_RATE_LIMIT_BURST", 20)
ORCHESTRATOR_ALLOWED_ORIGINS = _get_allowed_origins()
ORCHESTRATOR_TRUSTED_HOSTS = _get_trusted_hosts()
ORCHESTRATOR_SECURITY_HEADERS_ENABLED = _get_bool("ORCHESTRATOR_SECURITY_HEADERS_ENABLED", True)
ORCHESTRATOR_BODY_LIMIT_BYTES = _get_int("ORCHESTRATOR_BODY_LIMIT_BYTES", 1048576)
