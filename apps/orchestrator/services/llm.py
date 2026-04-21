import json
import logging

import httpx

from config.settings import OLLAMA_BASE_URL, OLLAMA_ENABLED, OLLAMA_MODEL, OLLAMA_TIMEOUT_SECONDS
from schemas.scan import EnrichedReportResponse


logger = logging.getLogger(__name__)
OLLAMA_GENERATE_PATH = "/api/generate"


def summarize_enriched_report(report: EnrichedReportResponse) -> dict:
    if not OLLAMA_ENABLED:
        return {"executive_summary": None, "quick_wins": []}

    payload = _build_report_payload(report)
    prompt = _build_prompt(payload)
    base_url = _normalize_ollama_base_url(OLLAMA_BASE_URL)

    try:
        with httpx.Client(base_url=base_url, timeout=OLLAMA_TIMEOUT_SECONDS) as client:
            response = client.post(
                OLLAMA_GENERATE_PATH,
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                },
            )
            response.raise_for_status()
            body = response.json()
    except httpx.HTTPError as exc:
        logger.warning("Ollama request failed for %s%s: %s", base_url, OLLAMA_GENERATE_PATH, exc)
        return {"executive_summary": None, "quick_wins": []}
    except ValueError as exc:
        logger.warning("Ollama response parsing failed: %s", exc)
        return {"executive_summary": None, "quick_wins": []}

    raw_response = body.get("response", "")
    try:
        parsed = json.loads(raw_response)
    except json.JSONDecodeError as exc:
        logger.warning("Ollama returned invalid JSON: %s", exc)
        return {"executive_summary": None, "quick_wins": []}

    executive_summary = parsed.get("executive_summary")
    quick_wins = parsed.get("quick_wins", [])

    if not isinstance(executive_summary, str):
        executive_summary = None
    else:
        executive_summary = _clean_text(executive_summary)
        if not executive_summary:
            executive_summary = None

    if not isinstance(quick_wins, list):
        quick_wins = []

    quick_wins = _clean_quick_wins(quick_wins)

    return {
        "executive_summary": executive_summary,
        "quick_wins": quick_wins,
    }


def _build_report_payload(report: EnrichedReportResponse) -> dict:
    risk_findings = [item for item in report.top_issues if item.severity.lower() != "info"]
    informational_findings = [item for item in report.top_issues if item.severity.lower() == "info"]

    return {
        "target": report.target,
        "score": report.score,
        "severity_summary": report.summary.model_dump(),
        "top_risk_findings": [
            {
                "title": item.title,
                "severity": item.severity,
                "confidence": item.confidence,
                "category": item.category,
                "tool_name": item.tool_name,
                "remediation_summary": item.remediation_summary,
                "cve_matches": item.cve_matches,
            }
            for item in risk_findings[:4]
        ],
        "informational_findings": [
            {
                "title": item.title,
                "category": item.category,
                "tool_name": item.tool_name,
            }
            for item in informational_findings[:3]
        ],
        "categories": [
            {
                "name": category.name,
                "slug": category.slug,
                "count": category.count,
                "highest_severity": category.highest_severity,
                "sample_remediations": [
                    finding.remediation_summary
                    for finding in category.findings
                    if finding.remediation_summary
                ][:3],
                "findings": [
                    {
                        "title": finding.title,
                        "severity": finding.severity,
                        "tool_name": finding.tool_name,
                        "owasp_category": finding.owasp_category,
                        "remediation_summary": finding.remediation_summary,
                    }
                    for finding in category.findings
                ][:5],
            }
            for category in report.categories
        ],
    }


def _build_prompt(payload: dict) -> str:
    return f"""You are writing a concise executive summary for a web security report.

Use only the structured report data provided below.
Do not invent findings, CVEs, exploits, attack paths, or risks not present in the input.
Do not claim exploitability.
Do not mention NVD or CVEs unless they are present in the supplied data.
Summarize only the supplied report data.

Write `executive_summary` as:
- 2 to 4 sentences maximum
- concise, technical, and credible
- like a real security report summary, not marketing copy
- focused on the main risk area when clear
- explicit about the top 1 to 2 highest-severity findings by name when appropriate
- clear about whether technology fingerprint findings are informational only
- natural in how it mentions the score

Write `quick_wins` as:
- 2 to 4 items maximum
- operationally useful and concise
- based only on the highest-severity findings and remediation summaries already present
- grouped when sensible
- not repetitive

If the report is mostly informational, say that clearly.
If the main issues are missing security headers or transport protections, say that directly.
If fingerprint findings are present without confirmed version-specific risk, treat them as informational context unless the structured report says otherwise.

Return JSON only with exactly these fields:
- executive_summary
- quick_wins

Structured report input:
{json.dumps(payload, indent=2)}
"""


def _normalize_ollama_base_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/api"):
        normalized = normalized[:-4]

    return normalized


def _clean_text(value: str) -> str:
    return " ".join(value.split()).strip()


def _clean_quick_wins(items: list) -> list[str]:
    cleaned: list[str] = []
    seen: set[str] = set()

    for item in items:
        if not isinstance(item, str):
            continue

        normalized = _clean_text(item)
        if not normalized:
            continue

        dedupe_key = normalized.rstrip(".").lower()
        if dedupe_key in seen:
            continue

        seen.add(dedupe_key)
        cleaned.append(normalized)

    return cleaned[:4]
