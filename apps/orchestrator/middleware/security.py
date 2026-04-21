import fnmatch
import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response


logger = logging.getLogger("orchestrator.security")


class TrustedHostValidationMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, allowed_hosts: list[str]) -> None:
        super().__init__(app)
        self.allowed_hosts = allowed_hosts

    async def dispatch(self, request: Request, call_next) -> Response:
        host = request.headers.get("host", "").split(":", 1)[0].strip().lower()
        if host and _is_allowed_host(host, self.allowed_hosts):
            return await call_next(request)

        logger.warning("Rejected request with invalid host header", extra={"host": host or "<missing>"})
        return JSONResponse(status_code=400, content={"detail": "Invalid host header"})


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")

        forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
        if request.url.scheme == "https" or forwarded_proto == "https":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, max_body_bytes: int) -> None:
        super().__init__(app)
        if max_body_bytes < 0:
            raise RuntimeError("ORCHESTRATOR_BODY_LIMIT_BYTES must be greater than or equal to 0")
        self.max_body_bytes = max_body_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        if self.max_body_bytes == 0 or request.method not in {"POST", "PUT", "PATCH"}:
            return await call_next(request)

        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.max_body_bytes:
                    return JSONResponse(status_code=413, content={"detail": "Request body too large"})
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header"})

        body = await request.body()
        if len(body) > self.max_body_bytes:
            return JSONResponse(status_code=413, content={"detail": "Request body too large"})

        return await call_next(request)


def _is_allowed_host(host: str, allowed_hosts: list[str]) -> bool:
    return any(fnmatch.fnmatch(host, pattern.lower()) for pattern in allowed_hosts)
