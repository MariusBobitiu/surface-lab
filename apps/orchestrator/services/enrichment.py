import logging
import re

from schemas.scan import EnrichedFindingResponse, FindingResponse
from services.nvd import search_cpes, search_cves_by_cpe, search_cves_by_keyword


logger = logging.getLogger(__name__)

MAX_CPE_MATCHES_WITH_VERSION = 3
MAX_CPE_MATCHES_WITHOUT_VERSION = 1

PRODUCT_ALIASES = {
    "next.js": "nextjs",
    "next js": "nextjs",
}

PRODUCT_DENY_SUBSTRINGS = {
    "cloudflare": {"scrape"},
    "nextjs": {"starter", "boilerplate", "plugin", "theme"},
}


def enrich_findings(findings: list[FindingResponse]) -> list[EnrichedFindingResponse]:
    return [_enrich_finding(finding) for finding in findings]


def _enrich_finding(finding: FindingResponse) -> EnrichedFindingResponse:
    owasp_category = _map_owasp_category(finding)
    wstg_reference = _map_wstg_reference(finding)
    remediation_summary = _build_remediation_summary(finding)
    cve_matches, cpe_matches = _lookup_nvd_matches(finding)
    source_references = _build_source_references(owasp_category, wstg_reference, cve_matches, cpe_matches)

    return EnrichedFindingResponse(
        id=finding.id,
        tool_name=finding.tool_name,
        type=finding.type,
        category=finding.category,
        title=finding.title,
        summary=finding.summary,
        severity=finding.severity,
        confidence=finding.confidence,
        evidence=finding.evidence,
        evidence_refs=finding.evidence_refs,
        details=finding.details,
        created_at=finding.created_at,
        owasp_category=owasp_category,
        wstg_reference=wstg_reference,
        remediation_summary=remediation_summary,
        source_references=source_references,
        cve_matches=cve_matches,
        cpe_matches=cpe_matches,
    )


def _map_owasp_category(finding: FindingResponse) -> str | None:
    title = finding.title.lower()
    category = finding.category.lower()
    finding_type = finding.type.lower()

    if category == "wordpress_exposure":
        return "A05:2025 - Security Misconfiguration"

    if category == "wordpress_surface":
        return "A05:2025 - Security Misconfiguration"

    if category in {"nextjs_surface", "nextjs_exposure"}:
        return "A05:2025 - Security Misconfiguration"

    if category == "nextjs_vulnerability":
        return "A03:2025 - Software Supply Chain Failures"

    if category in {"http_headers", "public_files", "sensitive_file_exposure"}:
        return "A05:2025 - Security Misconfiguration"

    if "tls" in category or "certificate" in title or "https" in title:
        return "A05:2025 - Security Misconfiguration"

    if "outdated" in title or "version" in title or "component" in finding_type:
        return "A03:2025 - Software Supply Chain Failures"

    return None


def _map_wstg_reference(finding: FindingResponse) -> str | None:
    category = finding.category.lower()
    title = finding.title.lower()

    if category == "wordpress_fingerprint":
        return "Information Gathering"

    if category in {"wordpress_surface", "wordpress_exposure"}:
        return "Configuration and Deployment Management Testing"

    if category == "nextjs_fingerprint":
        return "Information Gathering"

    if category in {"nextjs_surface", "nextjs_exposure"}:
        return "Configuration and Deployment Management Testing"

    if category == "nextjs_vulnerability":
        return "Configuration and Deployment Management Testing"

    if category == "http_headers" or "tls" in category or "certificate" in title or "https" in title:
        return "Configuration and Deployment Management Testing"

    if category in {"public_files", "sensitive_file_exposure"}:
        return "Configuration and Deployment Management Testing"

    if category.startswith("fingerprint_"):
        return "Information Gathering"

    return None


def _build_remediation_summary(finding: FindingResponse) -> str | None:
    title = finding.title.lower()
    evidence = finding.evidence.lower()
    category = finding.category.lower()

    if category == "wordpress_exposure" and "readme" in title:
        return "Remove public access to the WordPress readme file to reduce unnecessary product disclosure."

    if category == "wordpress_surface" and "xml-rpc" in title:
        return "Disable XML-RPC if it is not required, or restrict access to trusted clients only."

    if category == "wordpress_surface" and "login" in title:
        return "Restrict access to the WordPress login surface with network controls, MFA, and rate limiting."

    if category == "nextjs_exposure" and "source map" in title:
        return "Disable production browser source maps or restrict access to generated map files if they are not intended for public debugging."

    if category == "nextjs_surface" and "data endpoint" in title:
        return "Review the exposed Next.js data route and ensure it does not return sensitive page props or internal state."

    if category == "nextjs_fingerprint":
        return "Avoid exposing unnecessary framework and build metadata where it is not needed for normal client operation."

    if category == "nextjs_vulnerability":
        return "Upgrade Next.js to a patched release for the matched advisory, then rebuild and redeploy the application."

    if "strict-transport-security" in title or "hsts" in title:
        return "Add a Strict-Transport-Security header and verify it is applied consistently on HTTPS responses."

    if "content-security-policy" in title or "csp" in title:
        return "Define a restrictive Content-Security-Policy and validate it against the application's required resources."

    if ".env" in title or ".env" in evidence:
        return "Remove public access to the exposed environment file and rotate any secrets that may have been disclosed."

    if "redirect" in title and "https" in title:
        return "Enforce HTTP to HTTPS redirection at the edge or application layer."

    if "certificate" in title and "expir" in title:
        return "Renew the TLS certificate before expiry and confirm the full certificate chain is served correctly."

    if category == "public_files":
        return "Remove public access to unnecessary files and restrict web exposure to intended assets only."

    if category == "sensitive_file_exposure":
        return "Block access to sensitive artifacts, remove exposed files from the web root, and rotate any exposed credentials."

    if category == "http_headers":
        return "Add the missing security headers and verify they are present on all relevant responses."

    return None


def _build_source_references(
    owasp_category: str | None,
    wstg_reference: str | None,
    cve_matches: list[dict],
    cpe_matches: list[dict],
) -> list[str]:
    references: list[str] = []

    if owasp_category is not None:
        references.append("OWASP Top 10 2025")

    if wstg_reference is not None:
        references.append("OWASP WSTG")

    if cve_matches or cpe_matches:
        references.append("NVD")

    return references


def _lookup_nvd_matches(finding: FindingResponse) -> tuple[list[dict], list[dict]]:
    if not _should_lookup_nvd(finding):
        logger.info("NVD lookup skipped: weak evidence for finding '%s'", finding.title)
        return [], []

    product = _extract_product(finding)
    version = _extract_version(finding)

    if not product:
        logger.info("NVD lookup skipped: no product signal for finding '%s'", finding.title)
        return [], []

    normalized_product = _normalize_log_value(product)
    normalized_version = _normalize_log_value(version) if version else "none"
    logger.info("NVD lookup started: product=%s version=%s", normalized_product, normalized_version)

    raw_cpe_matches = search_cpes(product)
    filtered_cpe_matches = _filter_cpe_matches(raw_cpe_matches, product, version)
    cpe_matches = _strip_internal_match_fields(filtered_cpe_matches)
    cve_matches: list[dict] = []

    if _has_strong_version_signal(version):
        matching_cpe = _find_matching_cpe(filtered_cpe_matches, version)
        if matching_cpe is not None:
            logger.info("NVD CVE lookup by CPE: %s", matching_cpe["cpe_name"])
            cve_matches = search_cves_by_cpe(matching_cpe["cpe_name"])
        elif _is_safe_keyword_fallback(finding, product, version):
            logger.info("NVD CVE lookup by keyword: %s %s", normalized_product, normalized_version)
            cve_matches = search_cves_by_keyword(f"{product} {version}")
        else:
            logger.info("NVD CVE lookup skipped: insufficient match confidence for '%s'", finding.title)
    else:
        logger.info("NVD CVE lookup skipped: no strong version signal for '%s'", finding.title)

    return cve_matches, cpe_matches


def _should_lookup_nvd(finding: FindingResponse) -> bool:
    category = finding.category.lower()
    if not category.startswith("fingerprint_"):
        return False

    if finding.severity.lower() == "info" and finding.confidence.lower() == "low":
        return False

    product = _extract_product(finding)
    return _has_strong_product_signal(product)


def _has_strong_product_signal(product: str | None) -> bool:
    if product is None:
        return False

    normalized_product = product.strip().lower()
    if not normalized_product:
        return False

    weak_products = {"unknown", "generic", "server", "framework", "edge", "generator"}
    return normalized_product not in weak_products


def _has_strong_version_signal(version: str | None) -> bool:
    if version is None:
        return False

    normalized_version = version.strip().lower()
    if not normalized_version:
        return False

    weak_versions = {"unknown", "latest", "current"}
    return any(character.isdigit() for character in normalized_version) and normalized_version not in weak_versions


def _find_matching_cpe(cpe_matches: list[dict], version: str | None) -> dict | None:
    if not _has_strong_version_signal(version):
        return None

    normalized_version = version.strip().lower()
    for cpe_match in cpe_matches:
        cpe_name = str(cpe_match.get("cpe_name", "")).lower()
        title = str(cpe_match.get("title", "")).lower()
        if cpe_match.get("_match_quality") not in {"exact", "probable"}:
            continue
        if normalized_version in cpe_name or normalized_version in title:
            return cpe_match

    return None


def _is_safe_keyword_fallback(finding: FindingResponse, product: str, version: str | None) -> bool:
    if not _has_strong_product_signal(product) or not _has_strong_version_signal(version):
        return False

    return finding.category.lower() in {"fingerprint_framework", "fingerprint_server"}


def _extract_product(finding: FindingResponse) -> str | None:
    for key in ("product", "server", "framework", "technology", "generator", "name"):
        value = finding.details.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    return None


def _extract_version(finding: FindingResponse) -> str | None:
    for key in ("version", "detected_version"):
        value = finding.details.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    return None


def _normalize_log_value(value: str | None) -> str:
    if value is None:
        return ""

    return " ".join(value.strip().lower().split())


def _filter_cpe_matches(raw_cpe_matches: list[dict], product: str, version: str | None) -> list[dict]:
    normalized_product = _normalize_product_name(product)
    if not normalized_product:
        return []

    accepted_matches: list[dict] = []

    for cpe_match in raw_cpe_matches:
        quality = _classify_cpe_match(cpe_match, normalized_product, version)
        cpe_name = cpe_match.get("cpe_name", "")

        if quality == "weak":
            logger.info("NVD CPE candidate rejected: weak match for %s", cpe_name)
            continue

        logger.info("NVD CPE candidate accepted: %s match for %s", quality, cpe_name)
        accepted_matches.append(
            {
                **cpe_match,
                "_match_quality": quality,
            }
        )

    if _has_strong_version_signal(version):
        strong_matches = [match for match in accepted_matches if match["_match_quality"] in {"exact", "probable"}]
        return strong_matches[:MAX_CPE_MATCHES_WITH_VERSION]

    exact_matches = [match for match in accepted_matches if match["_match_quality"] == "exact"]
    return exact_matches[:MAX_CPE_MATCHES_WITHOUT_VERSION]


def _classify_cpe_match(cpe_match: dict, normalized_product: str, version: str | None) -> str:
    cpe_name = str(cpe_match.get("cpe_name", ""))
    title = str(cpe_match.get("title", ""))
    _, candidate_product, candidate_version = _parse_cpe_name(cpe_name)
    normalized_candidate_product = _normalize_product_name(candidate_product)
    normalized_title = _normalize_product_name(title)

    if not normalized_candidate_product and not normalized_title:
        return "weak"

    if _contains_denied_variant(normalized_product, normalized_candidate_product, normalized_title):
        return "weak"

    product_exact = normalized_candidate_product == normalized_product
    title_exact = normalized_product and normalized_product in _split_normalized_terms(normalized_title)

    if _has_strong_version_signal(version):
        normalized_version = version.strip().lower()
        version_match = normalized_version == candidate_version.lower() or normalized_version in cpe_name.lower() or normalized_version in title.lower()
        if product_exact and version_match:
            return "exact"
        if product_exact and candidate_version:
            return "probable"
        return "weak"

    if product_exact and _is_product_level_cpe(candidate_version):
        return "exact"

    if product_exact and title_exact and not candidate_version:
        return "probable"

    return "weak"


def _contains_denied_variant(normalized_product: str, normalized_candidate_product: str, normalized_title: str) -> bool:
    deny_terms = PRODUCT_DENY_SUBSTRINGS.get(normalized_product, set())
    searchable = f"{normalized_candidate_product} {normalized_title}"
    return any(term in searchable for term in deny_terms)


def _parse_cpe_name(cpe_name: str) -> tuple[str, str, str]:
    parts = cpe_name.split(":")
    if len(parts) < 6:
        return "", "", ""

    vendor = parts[3]
    product = parts[4]
    version = parts[5]
    return vendor, product, version


def _normalize_product_name(value: str | None) -> str:
    if value is None:
        return ""

    normalized = value.strip().lower()
    normalized = PRODUCT_ALIASES.get(normalized, normalized)
    normalized = normalized.replace(".", "").replace("-", "").replace("_", "").replace("/", " ")
    normalized = re.sub(r"[^a-z0-9\s]", "", normalized)
    normalized = "".join(normalized.split())
    return PRODUCT_ALIASES.get(normalized, normalized)


def _split_normalized_terms(value: str) -> set[str]:
    if not value:
        return set()

    spaced = re.sub(r"[^a-z0-9]+", " ", value.lower())
    raw_terms = {term for term in spaced.split() if term}
    normalized_terms = {_normalize_product_name(term) for term in raw_terms}
    return {term for term in normalized_terms if term}


def _is_product_level_cpe(candidate_version: str) -> bool:
    normalized_version = candidate_version.strip().lower()
    return normalized_version in {"*", "-", "na", ""}


def _strip_internal_match_fields(cpe_matches: list[dict]) -> list[dict]:
    cleaned_matches: list[dict] = []
    for match in cpe_matches:
        cleaned_match = dict(match)
        cleaned_match.pop("_match_quality", None)
        cleaned_matches.append(cleaned_match)

    return cleaned_matches
