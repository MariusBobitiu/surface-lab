import logging
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi


def load_env_file() -> None:
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return

    for line in env_path.read_text().splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#") or "=" not in entry:
            continue

        key, value = entry.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


load_env_file()
logging.basicConfig(level=logging.INFO, format="%(levelname)s:     %(message)s")

from config import settings
from api.routes import router as scans_router
from middleware import (
    ApiKeyMiddleware,
    BodySizeLimitMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    TrustedHostValidationMiddleware,
)

EXEMPT_API_KEY_PATHS = {
    "/health",
    "/healthz",
    "/livez",
    "/readyz",
    "/docs",
    "/redoc",
    "/openapi.json",
}


def _configure_openapi_api_key(app: FastAPI) -> None:
    def custom_openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema

        openapi_schema = get_openapi(
            title=app.title,
            version="1.0.0",
            description="SurfaceLab Orchestrator API",
            routes=app.routes,
        )
        components = openapi_schema.setdefault("components", {})
        security_schemes = components.setdefault("securitySchemes", {})
        security_schemes["ApiKeyAuth"] = {
            "type": "apiKey",
            "in": "header",
            "name": "x-api-key",
            "description": "Shared internal API key for orchestrator access.",
        }
        openapi_schema["security"] = [{"ApiKeyAuth": []}]
        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = custom_openapi


def create_app() -> FastAPI:
    app = FastAPI(title="SurfaceLab Orchestrator")
    app.include_router(scans_router)
    _configure_openapi_api_key(app)

    app.add_middleware(
        BodySizeLimitMiddleware,
        max_body_bytes=settings.ORCHESTRATOR_BODY_LIMIT_BYTES,
    )
    app.add_middleware(
        ApiKeyMiddleware,
        api_key=settings.ORCHESTRATOR_API_KEY,
        require_api_key=settings.ORCHESTRATOR_REQUIRE_API_KEY,
        exempt_paths=EXEMPT_API_KEY_PATHS,
    )
    if settings.ORCHESTRATOR_RATE_LIMIT_ENABLED:
        app.add_middleware(
            RateLimitMiddleware,
            requests_per_minute=settings.ORCHESTRATOR_RATE_LIMIT_RPM,
            burst=settings.ORCHESTRATOR_RATE_LIMIT_BURST,
        )
    app.add_middleware(
        TrustedHostValidationMiddleware,
        allowed_hosts=settings.ORCHESTRATOR_TRUSTED_HOSTS,
    )
    if settings.ORCHESTRATOR_SECURITY_HEADERS_ENABLED:
        app.add_middleware(SecurityHeadersMiddleware)
    if settings.ORCHESTRATOR_ALLOWED_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.ORCHESTRATOR_ALLOWED_ORIGINS,
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["content-type", "x-api-key"],
        )

    return app


app = create_app()
