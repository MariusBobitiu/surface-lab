import logging
import os
import time
from pathlib import Path

import psycopg
from fastapi import FastAPI, Request
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
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    force=True,
)
logger = logging.getLogger(__name__)

from config import settings
from api.routes import router as scans_router
from services.cache import _get_redis_client
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

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        started_at = time.monotonic()
        logger.info("HTTP request started method=%s path=%s", request.method, request.url.path)
        try:
            response = await call_next(request)
        except Exception:
            logger.exception(
                "HTTP request failed method=%s path=%s duration_ms=%d",
                request.method,
                request.url.path,
                int((time.monotonic() - started_at) * 1000),
            )
            raise

        logger.info(
            "HTTP request completed method=%s path=%s status_code=%s duration_ms=%d",
            request.method,
            request.url.path,
            response.status_code,
            int((time.monotonic() - started_at) * 1000),
        )
        return response

    @app.get("/health")
    @app.get("/healthz")
    def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/livez")
    def liveness() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/readyz")
    def readiness() -> dict[str, object]:
        checks: dict[str, str] = {"api": "ok"}

        try:
            if settings.DATABASE_URL:
                with psycopg.connect(settings.DATABASE_URL) as connection:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT 1")
        except psycopg.Error:
            logger.exception("readiness database check failed")
            return {"status": "error", "checks": {**checks, "database": "error"}}

        checks["database"] = "ok"

        if settings.REDIS_ENABLED and settings.REDIS_URL:
            client = _get_redis_client()
            if client is None:
                return {"status": "error", "checks": {**checks, "redis": "error"}}
            checks["redis"] = "ok"

        return {"status": "ok", "checks": checks}

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
