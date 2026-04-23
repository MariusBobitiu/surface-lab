from dataclasses import dataclass


@dataclass(frozen=True)
class AdvancedScanContract:
    name: str
    description: str
    service: str
    tags: tuple[str, ...]
    signal_triggers: tuple[str, ...]
    legacy_trigger_terms: tuple[str, ...]
    timeout_seconds: float
    retryable: bool
    max_retries: int
    allow_partial_results: bool


ADVANCED_SCAN_CONTRACTS: dict[str, AdvancedScanContract] = {
    "wordpress.v1.run_stack": AdvancedScanContract(
        name="wordpress.v1.run_stack",
        description="Run the wp-stack specialist service for deterministic WordPress surface and exposure checks.",
        service="wp-stack",
        tags=("cms", "wordpress", "php"),
        signal_triggers=("framework.wordpress",),
        legacy_trigger_terms=("wordpress", "wp-content", "wp-json", "generator:wordpress"),
        timeout_seconds=20.0,
        retryable=True,
        max_retries=1,
        allow_partial_results=True,
    ),
    "nextjs.v1.run_stack": AdvancedScanContract(
        name="nextjs.v1.run_stack",
        description="Run Next.js-oriented follow-up checks when baseline findings indicate a Next.js application surface.",
        service="nextjs-specialist",
        tags=("frontend", "nextjs", "react", "nodejs"),
        signal_triggers=("framework.nextjs", "assets.next_static"),
        legacy_trigger_terms=("next.js", "nextjs", "__next", "x-powered-by: next.js"),
        timeout_seconds=20.0,
        retryable=False,
        max_retries=0,
        allow_partial_results=True,
    ),
    "generic_http.v1.run_stack": AdvancedScanContract(
        name="generic_http.v1.run_stack",
        description="Run a safe generic HTTP follow-up path when the stack is unclear but more normalized advanced context is still useful.",
        service="generic-http-specialist",
        tags=("http", "generic", "fallback"),
        signal_triggers=("security.https", "transport.redirected", "assets.js_bundle"),
        legacy_trigger_terms=("http", "https", "headers", "transport"),
        timeout_seconds=10.0,
        retryable=True,
        max_retries=1,
        allow_partial_results=True,
    ),
}


def list_advanced_scan_contracts() -> list[AdvancedScanContract]:
    return list(ADVANCED_SCAN_CONTRACTS.values())


def get_advanced_scan_contract(name: str) -> AdvancedScanContract | None:
    return ADVANCED_SCAN_CONTRACTS.get(name)
