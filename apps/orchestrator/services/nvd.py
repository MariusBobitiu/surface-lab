import logging
import time
from threading import Lock
from typing import Any

import httpx

from config.settings import (
    NVD_CACHE_TTL_SECONDS,
    NVD_API_KEY,
    NVD_ENABLED,
    NVD_MIN_INTERVAL_SECONDS,
    NVD_TIMEOUT_SECONDS,
)
from services import cache


logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json"
MAX_CPE_RESULTS = 5
MAX_CVE_RESULTS = 10

_CACHE: dict[tuple[str, str], dict[str, Any]] = {}
_REQUEST_LOCK = Lock()
_LAST_REQUEST_STARTED_AT = 0.0


def search_cpes(keyword_search: str) -> list[dict[str, Any]]:
    keyword = _normalize_query(keyword_search)
    if not keyword or not NVD_ENABLED:
        return []

    return _cached_lookup("nvd:cpe", keyword, lambda: _fetch_cpes(keyword))


def search_cves_by_cpe(cpe_name: str) -> list[dict[str, Any]]:
    normalized_cpe = _normalize_query(cpe_name)
    if not normalized_cpe or not NVD_ENABLED:
        return []

    return _cached_lookup(
        "nvd:cve:cpe",
        normalized_cpe,
        lambda: _fetch_cves_by_cpe(normalized_cpe),
    )


def search_cves_by_keyword(keyword: str) -> list[dict[str, Any]]:
    normalized_keyword = _normalize_query(keyword)
    if not normalized_keyword or not NVD_ENABLED:
        return []

    return _cached_lookup(
        "nvd:cve:keyword",
        normalized_keyword,
        lambda: _fetch_cves_by_keyword(normalized_keyword),
    )


def search_cves(product: str, version: str | None = None) -> list[dict[str, Any]]:
    if not product or not version:
        return []

    cpe_matches = search_cpes(product)
    matching_cpe = _find_versioned_cpe_match(cpe_matches, version)
    if matching_cpe is None:
        return []

    return search_cves_by_cpe(matching_cpe["cpe_name"])


def _cached_lookup(
    query_type: str,
    query_value: str,
    fetcher,
) -> list[dict[str, Any]]:
    redis_key = _build_cache_key(query_type, query_value)
    redis_cached = cache.get(redis_key)
    if redis_cached is not None:
        logger.info("NVD cache hit: %s", redis_key)
        return _decode_cached_payload(redis_cached)

    logger.info("NVD cache miss: %s", redis_key)

    cache_key = (query_type, query_value)
    now = time.time()
    cached = _CACHE.get(cache_key)

    if cached and now - cached["timestamp"] < NVD_CACHE_TTL_SECONDS:
        return cached["payload"]

    payload = fetcher()
    _CACHE[cache_key] = {
        "timestamp": now,
        "payload": payload,
    }
    cache.set(redis_key, {"payload": payload}, NVD_CACHE_TTL_SECONDS)
    logger.info("NVD cache store: %s", redis_key)
    return payload


def _fetch_cpes(keyword: str) -> list[dict[str, Any]]:
    payload = _request_json(
        "/cpes/2.0",
        {
            "keywordSearch": keyword,
            "resultsPerPage": MAX_CPE_RESULTS,
        },
    )
    if payload is None:
        return []

    products = payload.get("products", [])
    return [_normalize_cpe_result(item) for item in products[:MAX_CPE_RESULTS]]


def _fetch_cves_by_cpe(cpe_name: str) -> list[dict[str, Any]]:
    payload = _request_json(
        "/cves/2.0",
        {
            "cpeName": cpe_name,
            "isVulnerable": "",
            "resultsPerPage": MAX_CVE_RESULTS,
        },
    )
    if payload is None:
        return []

    vulnerabilities = payload.get("vulnerabilities", [])
    return [_normalize_cve_result(item, cpe_name) for item in vulnerabilities[:MAX_CVE_RESULTS]]


def _fetch_cves_by_keyword(keyword: str) -> list[dict[str, Any]]:
    params: dict[str, Any] = {
        "keywordSearch": keyword,
        "resultsPerPage": MAX_CVE_RESULTS,
    }
    if " " in keyword:
        params["keywordExactMatch"] = ""

    payload = _request_json("/cves/2.0", params)
    if payload is None:
        return []

    vulnerabilities = payload.get("vulnerabilities", [])
    return [_normalize_cve_result(item, None) for item in vulnerabilities[:MAX_CVE_RESULTS]]


def _request_json(path: str, params: dict[str, Any]) -> dict[str, Any] | None:
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    with _REQUEST_LOCK:
        _sleep_if_needed()
        global _LAST_REQUEST_STARTED_AT
        _LAST_REQUEST_STARTED_AT = time.monotonic()

        try:
            with httpx.Client(base_url=NVD_BASE_URL, timeout=NVD_TIMEOUT_SECONDS, headers=headers) as client:
                response = client.get(path, params=params)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as exc:
            logger.warning("NVD request failed for %s: %s", path, exc)
            return None
        except ValueError as exc:
            logger.warning("NVD response parsing failed for %s: %s", path, exc)
            return None


def _sleep_if_needed() -> None:
    elapsed = time.monotonic() - _LAST_REQUEST_STARTED_AT
    if elapsed < NVD_MIN_INTERVAL_SECONDS:
        time.sleep(NVD_MIN_INTERVAL_SECONDS - elapsed)


def _normalize_cpe_result(item: dict[str, Any]) -> dict[str, Any]:
    cpe = item.get("cpe", {})
    titles = cpe.get("titles", [])
    title = ""
    if titles:
        title = titles[0].get("title", "")

    return {
        "cpe_name": cpe.get("cpeName", ""),
        "title": title,
        "cpe_name_id": cpe.get("cpeNameId", ""),
        "deprecated": cpe.get("deprecated", False),
    }


def _normalize_cve_result(item: dict[str, Any], cpe_name: str | None) -> dict[str, Any]:
    cve = item.get("cve", {})
    description = _extract_description(cve.get("descriptions", []))
    score, severity = _extract_cvss(cve.get("metrics", {}))

    return {
        "cve_id": cve.get("id", ""),
        "source_identifier": cve.get("sourceIdentifier", ""),
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "cvss_score": score,
        "cvss_severity": severity,
        "description": description,
        "cpe_name": cpe_name,
    }


def _extract_description(descriptions: list[dict[str, Any]]) -> str:
    for description in descriptions:
        if description.get("lang") == "en":
            value = description.get("value", "")
            return value[:240]

    if descriptions:
        return str(descriptions[0].get("value", ""))[:240]

    return ""


def _extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    metric_keys = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

    for key in metric_keys:
        values = metrics.get(key, [])
        if not values:
            continue

        metric = values[0]
        cvss_data = metric.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
        return score, severity

    return None, None


def _find_versioned_cpe_match(cpe_matches: list[dict[str, Any]], version: str) -> dict[str, Any] | None:
    normalized_version = version.strip().lower()
    if not normalized_version:
        return None

    for cpe_match in cpe_matches:
        cpe_name = str(cpe_match.get("cpe_name", "")).lower()
        title = str(cpe_match.get("title", "")).lower()
        if normalized_version in cpe_name or normalized_version in title:
            return cpe_match

    return None


def _normalize_query(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _build_cache_key(prefix: str, value: str) -> str:
    return f"{prefix}:{value}"


def _decode_cached_payload(cached: dict[str, Any]) -> list[dict[str, Any]]:
    payload = cached.get("payload")
    if isinstance(payload, list):
        return payload

    return []
