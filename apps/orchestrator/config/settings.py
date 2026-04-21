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


def _get_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _get_required_str(name: str) -> str:
    value = _get_str(name)
    if not value:
        raise RuntimeError(f"{name} is required")

    return value


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
