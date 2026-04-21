import logging
import secrets
from collections.abc import Iterable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response


logger = logging.getLogger("orchestrator.security")


class ApiKeyMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        api_key: str,
        require_api_key: bool,
        exempt_paths: Iterable[str] = (),
    ) -> None:
        super().__init__(app)
        self.api_key = api_key
        self.require_api_key = require_api_key
        self.exempt_paths = set(exempt_paths)

    async def dispatch(self, request: Request, call_next) -> Response:
        if not self.require_api_key or request.method == "OPTIONS" or request.url.path in self.exempt_paths:
            return await call_next(request)

        supplied_key = request.headers.get("x-api-key", "")
        if not supplied_key:
            logger.warning("Rejected request with missing API key", extra={"path": request.url.path})
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        if not secrets.compare_digest(supplied_key, self.api_key):
            logger.warning("Rejected request with invalid API key", extra={"path": request.url.path})
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        return await call_next(request)
