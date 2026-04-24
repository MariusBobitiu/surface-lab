import json
import logging

import httpx

from config.settings import OLLAMA_BASE_URL, OLLAMA_ENABLED, OLLAMA_MODEL, OLLAMA_TIMEOUT_SECONDS
from schemas.scan import EnrichedReportResponse, ReportCheckCategoryResponse, ReportCheckResponse


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


def generate_vulnerability_control_matrix(
    report: EnrichedReportResponse,
    detected_stack: str,
    executed_contracts: list[str],
) -> list[ReportCheckCategoryResponse]:
    """Generate a comprehensive vulnerability control matrix.
    
    Uses LLM if available to enhance with additional insights, but always returns
    a comprehensive matrix based on findings data.
    """
    # Always start with the deterministic matrix from findings
    deterministic_matrix = _build_deterministic_control_matrix(report)
    
    # If LLM is enabled, try to enhance or replace with LLM-generated matrix
    if OLLAMA_ENABLED:
        payload = _build_control_matrix_payload(report, detected_stack, executed_contracts)
        llm_result = _try_llm_control_matrix(payload)
        # Use LLM result only if it has substantial content (more than 2 categories with checks)
        if llm_result and len(llm_result) >= 2 and sum(len(cat.checks) for cat in llm_result) >= 10:
            logger.info("Using LLM-generated control matrix with %d categories", len(llm_result))
            return llm_result
    
    # Return deterministic matrix (either LLM failed or is disabled)
    return deterministic_matrix


def _try_llm_control_matrix(payload: dict) -> list[ReportCheckCategoryResponse]:
    """Try to generate control matrix via LLM. Returns empty list on failure."""
    prompt = _build_control_matrix_prompt(payload)
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
        logger.debug("LLM control matrix request failed: %s", exc)
        return []
    except ValueError as exc:
        logger.debug("LLM control matrix response parsing failed: %s", exc)
        return []

    raw_response = body.get("response", "")
    try:
        parsed = json.loads(raw_response)
    except json.JSONDecodeError as exc:
        logger.debug("LLM control matrix returned invalid JSON: %s", exc)
        return []

    return _parse_control_matrix_response(parsed)


def _build_control_matrix_payload(report: EnrichedReportResponse, detected_stack: str, executed_contracts: list[str]) -> dict:
    """Build context payload for control matrix generation."""
    return {
        "target": report.target,
        "detected_stack": detected_stack,
        "executed_contracts": executed_contracts,
        "score": report.score,
        "severity_summary": report.summary.model_dump(),
        "findings_by_category": [
            {
                "category_name": cat.name,
                "findings": [
                    {
                        "title": finding.title,
                        "severity": finding.severity,
                        "confidence": finding.confidence,
                        "evidence": finding.evidence,
                        "type": finding.type,
                    }
                    for finding in cat.findings
                ],
            }
            for cat in report.categories
        ],
    }


def _build_control_matrix_prompt(payload: dict) -> str:
    """Build prompt for LLM to generate a vulnerability control matrix."""
    return f"""You are generating a comprehensive vulnerability control matrix for a web application security report.

Your task: Based on the detected stack, findings, and scan results, produce a detailed security checklist organized by vulnerability category.
Each check indicates whether that control was verified as PASSED (checked, not vulnerable) or FAILED (vulnerability found).

CRITICAL RULES:
1. Generate 3-5 checks per category minimum. Be comprehensive.
2. PASSED means: the check was performed (likely via baseline scanning) and NO vulnerability was found.
3. FAILED means: a specific finding exists in the report for that control.
4. All checks are relevant to web application security, regardless of detected stack.
5. Include common vulnerability categories: Transport & Security Headers, Authentication & Sessions, 
   Input Validation & Injection, Access Control, Data Exposure, API Security, 
   Configuration & Deployment, Client-Side Security.

VULNERABILITY CHECKLIST TEMPLATE (adapt based on findings):

Transport & Security Headers category:
- HSTS (Strict-Transport-Security) enforcement
- Content-Security-Policy (CSP) presence and strength
- X-Frame-Options (Clickjacking protection)
- X-Content-Type-Options (MIME sniffing prevention)
- Referrer-Policy configuration
- Permissions-Policy / Feature-Policy headers
- Server banner disclosure (via Server header)
- TLS/HTTPS requirement and validity

Authentication & Sessions:
- Secure cookie flags (HttpOnly, Secure, SameSite)
- Password policy enforcement (if admin detected)
- Session timeout mechanisms
- CSRF token validation
- Multi-factor authentication (if applicable)
- Credential storage (no hardcoded secrets in code/assets)

Input Validation & Injection:
- SQL injection prevention
- Command injection prevention
- Cross-Site Scripting (XSS) prevention
- XML/XXE injection prevention
- Template injection prevention
- Path traversal protection

Access Control:
- Authentication enforcement on sensitive endpoints
- Authorization checks (role-based access)
- Privilege escalation prevention
- Default credentials removed
- API endpoint access control

Data Exposure:
- Sensitive data in comments/code exposure
- API keys/secrets in publicly accessible files
- Environment file exposure (.env, .config)
- Git metadata exposure (.git, .gitconfig)
- Backup files exposure (.bak, .sql)
- Log file exposure
- Database dumps publicly accessible

Configuration & Deployment:
- Debug mode disabled in production
- Error messages sanitized (no stack traces)
- Unnecessary services disabled
- Default admin panels removed
- Version disclosure minimized
- Dependency vulnerabilities (if applicable)

Client-Side Security:
- JavaScript source map exposure
- Vulnerable JavaScript dependencies
- DOM-based XSS prevention
- localStorage/sessionStorage data exposure

MAPPING FINDINGS TO CHECKS:
For each finding in the input, there is a corresponding control check. If found, mark FAILED.
For common checks that are NOT in the findings list, assume they were checked (as part of baseline scan) and mark PASSED.

Detected Stack: {payload['detected_stack']}
Executed Contracts: {', '.join(payload['executed_contracts']) or 'none'}

Findings by Category:
{json.dumps(payload['findings_by_category'], indent=2)}

EXAMPLE OUTPUT (DO NOT COPY, ADAPT):
{{
  "categories": [
    {{
      "name": "Transport & Security Headers",
      "slug": "transport-headers",
      "checks": [
        {{"id": "hsts_check", "title": "HSTS (Strict-Transport-Security) header", "status": "FAILED", "detail": "HSTS header is missing. Enable HSTS to protect users from downgrade attacks."}},
        {{"id": "csp_check", "title": "Content-Security-Policy (CSP) header", "status": "FAILED", "detail": "CSP is not configured. Implement CSP to mitigate XSS attacks."}},
        {{"id": "x_frame_check", "title": "X-Frame-Options (clickjacking protection)", "status": "PASSED", "detail": "X-Frame-Options is properly configured to DENY, protecting against clickjacking."}},
        {{"id": "server_banner", "title": "Server banner minimization", "status": "FAILED", "detail": "Server header discloses stack details. Customize or remove server banner."}}
      ]
    }},
    {{
      "name": "Data Exposure",
      "slug": "data-exposure",
      "checks": [
        {{"id": "env_check", "title": ".env file exposure", "status": "PASSED", "detail": "No publicly accessible .env file detected. Environment variables are properly protected."}},
        {{"id": "git_check", "title": ".git metadata exposure", "status": "PASSED", "detail": "Git repository is not publicly accessible."}}
      ]
    }}
  ]
}}

NOW GENERATE THE FULL CONTROL MATRIX:
Use the findings provided, apply the checklist template above, and return comprehensive JSON matching the structure."""


def _parse_control_matrix_response(parsed: object) -> list[ReportCheckCategoryResponse]:
    """Parse LLM response into structured check categories."""
    if not isinstance(parsed, dict):
        return []

    categories_data = parsed.get("categories", [])
    if not isinstance(categories_data, list):
        return []

    categories: list[ReportCheckCategoryResponse] = []

    for cat_data in categories_data:
        if not isinstance(cat_data, dict):
            continue

        cat_name = cat_data.get("name", "")
        cat_slug = cat_data.get("slug", "")
        checks_data = cat_data.get("checks", [])

        if not isinstance(checks_data, list) or not cat_name or not cat_slug:
            continue

        passed_count = 0
        failed_count = 0
        not_run_count = 0
        checks: list[ReportCheckResponse] = []

        for check_data in checks_data:
            if not isinstance(check_data, dict):
                continue

            check_id = check_data.get("id", "")
            check_title = check_data.get("title", "")
            check_status = str(check_data.get("status", "")).upper()
            check_detail = check_data.get("detail", "")

            if not check_id or not check_title:
                continue

            if check_status == "FAILED":
                status = "failed"
                failed_count += 1
            elif check_status == "PASSED":
                status = "passed"
                passed_count += 1
            else:
                status = "not_run"
                not_run_count += 1

            checks.append(
                ReportCheckResponse(
                    id=check_id,
                    title=check_title,
                    status=status,
                    detail=_clean_text(check_detail) if check_detail else "",
                    source="vulnerability-matrix",
                )
            )

        if checks:
            categories.append(
                ReportCheckCategoryResponse(
                    name=cat_name,
                    slug=cat_slug,
                    passed=passed_count,
                    failed=failed_count,
                    not_run=not_run_count,
                    checks=checks,
                )
            )

    return categories


def _build_deterministic_control_matrix(report: EnrichedReportResponse) -> list[ReportCheckCategoryResponse]:
    """Generate a comprehensive control matrix deterministically from findings when LLM is unavailable."""
    # Map findings to categories and determine check statuses
    check_inventory = {
        "Transport & Security Headers": {
            "hsts_enforcement": ("HSTS (Strict-Transport-Security) enforcement", ["strict-transport-security is missing"]),
            "csp_policy": ("Content-Security-Policy (CSP) presence", ["content-security-policy is missing"]),
            "x_frame_options": ("X-Frame-Options (clickjacking protection)", ["x-frame-options is missing"]),
            "x_content_type": ("X-Content-Type-Options (MIME sniffing)", ["x-content-type-options is missing"]),
            "server_banner": ("Server banner minimization", ["server header discloses stack"]),
            "referrer_policy": ("Referrer-Policy configuration", ["referrer-policy is missing"]),
        },
        "Authentication & Sessions": {
            "cookie_flags": ("Secure cookie flags (HttpOnly, Secure, SameSite)", ["cookie security", "httponly"]),
            "csrf_protection": ("CSRF token validation", ["csrf"]),
            "session_timeout": ("Session timeout mechanisms", ["session timeout"]),
            "mfa_enforcement": ("Multi-factor authentication capability", ["mfa", "2fa"]),
        },
        "Data Exposure": {
            "env_file": (".env file exposure", [".env"]),
            "git_exposure": ("Git metadata exposure (.git, .gitconfig)", [".git"]),
            "backup_files": ("Backup file exposure (.bak, .sql)", [".bak", ".sql", ".backup"]),
            "secrets_in_code": ("API keys/secrets in code or assets", ["api key", "secret", "password"]),
            "log_exposure": ("Log file exposure", [".log"]),
        },
        "Input Validation & Injection": {
            "sql_injection": ("SQL injection prevention", ["sql injection"]),
            "xss_prevention": ("Cross-Site Scripting (XSS) prevention", ["xss", "cross-site scripting"]),
            "command_injection": ("Command injection prevention", ["command injection"]),
            "path_traversal": ("Path traversal protection", ["path traversal", "directory traversal"]),
        },
        "Configuration & Deployment": {
            "debug_mode": ("Debug mode disabled in production", ["debug mode", "debug"]),
            "error_messages": ("Error messages sanitized (no stack traces)", ["stack trace", "error disclosure"]),
            "default_creds": ("Default credentials removed", ["default credential", "default password"]),
            "service_hardening": ("Unnecessary services disabled", ["service hardening"]),
        },
        "Access Control": {
            "auth_enforcement": ("Authentication enforcement on sensitive endpoints", ["authentication required", "auth enforcement"]),
            "authz_checks": ("Authorization checks (role-based access)", ["authorization", "access control"]),
            "privilege_escalation": ("Privilege escalation prevention", ["privilege escalation"]),
        },
    }

    # Build a set of finding titles for matching
    finding_titles = set()
    for cat in report.categories:
        for finding in cat.findings:
            finding_titles.add((finding.title or "").lower())
            finding_titles.add((finding.category or "").lower())

    categories: list[ReportCheckCategoryResponse] = []

    for cat_name, checks in check_inventory.items():
        cat_checks: list[ReportCheckResponse] = []
        passed = 0
        failed = 0

        for check_id, (check_title, failure_keywords) in checks.items():
            # Determine if check failed by looking for failure keywords in findings
            is_failed = any(
                any(keyword.lower() in title for keyword in failure_keywords)
                for title in finding_titles
            )

            if is_failed:
                status = "failed"
                failed += 1
                detail = f"{check_title} was not properly implemented. This control failed the security check."
            else:
                status = "passed"
                passed += 1
                detail = f"{check_title} is properly configured and no security issues were detected."

            cat_checks.append(
                ReportCheckResponse(
                    id=check_id,
                    title=check_title,
                    status=status,
                    detail=detail,
                    source="vulnerability-matrix",
                )
            )

        if cat_checks:
            categories.append(
                ReportCheckCategoryResponse(
                    name=cat_name,
                    slug=cat_name.lower().replace(" ", "-").replace("&", "").strip(),
                    passed=passed,
                    failed=failed,
                    not_run=0,
                    checks=cat_checks,
                )
            )

    return categories
