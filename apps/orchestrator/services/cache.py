import json
import logging
from typing import Any

import redis
from redis import Redis
from redis.exceptions import RedisError

from config.settings import REDIS_ENABLED, REDIS_URL


logger = logging.getLogger(__name__)

_redis_client: Redis | None = None
_redis_error_logged = False


def get(key: str) -> dict[str, Any] | None:
    client = _get_redis_client()
    if client is None:
        return None

    try:
        value = client.get(key)
    except RedisError as exc:
        _log_redis_error_once("Redis cache get failed: %s", exc)
        return None

    if value is None:
        return None

    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        _log_redis_error_once("Redis cache decode failed: %s", exc)
        return None


def set(key: str, value: dict[str, Any], ttl: int) -> None:
    client = _get_redis_client()
    if client is None:
        return

    try:
        payload = json.dumps(value)
        client.set(key, payload, ex=ttl)
    except (TypeError, RedisError) as exc:
        _log_redis_error_once("Redis cache set failed: %s", exc)


def _get_redis_client() -> Redis | None:
    global _redis_client

    if not REDIS_ENABLED or not REDIS_URL:
        return None

    if _redis_client is not None:
        return _redis_client

    try:
        _redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        _redis_client.ping()
        return _redis_client
    except RedisError as exc:
        _log_redis_error_once("Redis unavailable, continuing without cache: %s", exc)
        _redis_client = None
        return None


def _log_redis_error_once(message: str, exc: Exception) -> None:
    global _redis_error_logged

    if _redis_error_logged:
        return

    logger.warning(message, exc)
    _redis_error_logged = True
