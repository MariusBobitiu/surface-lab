import logging
import threading
import time

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response


logger = logging.getLogger("orchestrator.security")


class _TokenBucket:
    def __init__(self, capacity: int, refill_rate_per_second: float) -> None:
        self.capacity = float(capacity)
        self.refill_rate_per_second = refill_rate_per_second
        self.tokens = float(capacity)
        self.updated_at = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.updated_at
        self.updated_at = now
        self.tokens = min(self.capacity, self.tokens + (elapsed * self.refill_rate_per_second))
        if self.tokens < cost:
            return False

        self.tokens -= cost
        return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, requests_per_minute: int, burst: int) -> None:
        super().__init__(app)
        if requests_per_minute <= 0:
            raise RuntimeError("ORCHESTRATOR_RATE_LIMIT_RPM must be greater than 0")
        if burst <= 0:
            raise RuntimeError("ORCHESTRATOR_RATE_LIMIT_BURST must be greater than 0")

        self.requests_per_minute = requests_per_minute
        self.burst = burst
        self.refill_rate_per_second = requests_per_minute / 60.0
        self.buckets: dict[str, _TokenBucket] = {}
        self.lock = threading.Lock()

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method == "OPTIONS":
            return await call_next(request)

        client_ip = _get_client_ip(request)
        with self.lock:
            bucket = self.buckets.get(client_ip)
            if bucket is None:
                bucket = _TokenBucket(capacity=self.burst, refill_rate_per_second=self.refill_rate_per_second)
                self.buckets[client_ip] = bucket
            allowed = bucket.allow()

        if not allowed:
            logger.warning("Rate limited request", extra={"path": request.url.path, "client_ip": client_ip})
            return JSONResponse(status_code=429, content={"detail": "Too Many Requests"})

        return await call_next(request)


def _get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    if request.client and request.client.host:
        return request.client.host

    return "unknown"
