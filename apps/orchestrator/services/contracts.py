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
    "wordpress.v1.verify_stack": AdvancedScanContract(
        name="wordpress.v1.verify_stack",
        description="Alias of wordpress.v1.run_stack. Preferred specialist naming uses verify_stack.",
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
    "nextjs.v1.verify_stack": AdvancedScanContract(
        name="nextjs.v1.verify_stack",
        description="Alias of nextjs.v1.run_stack. Preferred specialist naming uses verify_stack.",
        service="nextjs-specialist",
        tags=("frontend", "nextjs", "react", "nodejs"),
        signal_triggers=("framework.nextjs", "assets.next_static"),
        legacy_trigger_terms=("next.js", "nextjs", "__next", "x-powered-by: next.js"),
        timeout_seconds=20.0,
        retryable=False,
        max_retries=0,
        allow_partial_results=True,
    ),
    "laravel.v1.verify_stack": AdvancedScanContract(
        name="laravel.v1.verify_stack",
        description="Run Laravel-specific external verification checks for suspected Laravel targets selected by baseline/orchestrator context.",
        service="laravel-stack",
        tags=("backend", "laravel", "php"),
        signal_triggers=("framework.laravel", "language.php"),
        legacy_trigger_terms=("laravel", "illuminate", "artisan", "_ignition", "_debugbar"),
        timeout_seconds=20.0,
        retryable=True,
        max_retries=1,
        allow_partial_results=True,
    ),
    "php.v1.verify_stack": AdvancedScanContract(
        name="php.v1.verify_stack",
        description="Run generic PHP external verification checks for suspected PHP targets when a framework-specific specialist is not sufficient.",
        service="php-stack",
        tags=("backend", "php"),
        signal_triggers=("language.php", "header.x_powered_by.present"),
        legacy_trigger_terms=("php", "x-powered-by: php", "phpinfo", ".htaccess"),
        timeout_seconds=20.0,
        retryable=True,
        max_retries=1,
        allow_partial_results=True,
    ),
    "shopify.v1.verify_stack": AdvancedScanContract(
        name="shopify.v1.verify_stack",
        description="Run Shopify storefront posture checks focused on externally observable ecommerce signals.",
        service="ecommerce-stack",
        tags=("ecommerce", "shopify", "storefront"),
        signal_triggers=("platform.shopify", "ecommerce.storefront"),
        legacy_trigger_terms=("shopify", "myshopify", "shopifycdn", "products.json", "cart.js"),
        timeout_seconds=20.0,
        retryable=True,
        max_retries=1,
        allow_partial_results=True,
    ),
    "frontend_frameworks.v1.run_stack": AdvancedScanContract(
        name="frontend_frameworks.v1.run_stack",
        description="Run generic framework follow-up checks for non-Next.js frontend stacks when strong framework markers are present.",
        service="generic-http-specialist",
        tags=("frontend", "frameworks", "vue", "angular", "react", "vite", "remix", "wix"),
        signal_triggers=(
            "framework.react",
            "framework.vue",
            "framework.angular",
            "framework.nuxt",
            "framework.sveltekit",
            "framework.vite",
            "framework.remix",
            "framework.wix",
        ),
        legacy_trigger_terms=("react", "vue", "angular", "nuxt", "sveltekit", "vite", "remix", "wix"),
        timeout_seconds=12.0,
        retryable=True,
        max_retries=1,
        allow_partial_results=True,
    ),
    "backend_frameworks.v1.run_stack": AdvancedScanContract(
        name="backend_frameworks.v1.run_stack",
        description="Run generic backend follow-up checks when backend framework fingerprints are detected.",
        service="generic-http-specialist",
        tags=("backend", "frameworks", "django", "dotnet"),
        signal_triggers=("framework.django", "framework.dotnet"),
        legacy_trigger_terms=("django", "asp.net", "dotnet", "x-aspnet-version"),
        timeout_seconds=12.0,
        retryable=True,
        max_retries=1,
        allow_partial_results=True,
    ),
    "data_services.v1.run_stack": AdvancedScanContract(
        name="data_services.v1.run_stack",
        description="Run data surface checks when managed data service or public bucket signals are detected.",
        service="generic-http-specialist",
        tags=("data", "storage", "database", "supabase", "s3", "r2", "mongodb", "neon"),
        signal_triggers=(
            "tooling.supabase",
            "tooling.s3_public",
            "tooling.cloudflare_r2_public",
            "tooling.mongodb",
            "tooling.neon",
        ),
        legacy_trigger_terms=("supabase", "s3.amazonaws.com", "r2.dev", "mongodb", "neon"),
        timeout_seconds=12.0,
        retryable=True,
        max_retries=1,
        allow_partial_results=True,
    ),
    "deployment_platforms.v1.run_stack": AdvancedScanContract(
        name="deployment_platforms.v1.run_stack",
        description="Run deployment posture checks when managed hosting platform fingerprints are detected.",
        service="generic-http-specialist",
        tags=("hosting", "deployment", "vercel", "netlify", "render", "flyio", "cloudflare"),
        signal_triggers=(
            "hosting.cloudflare",
            "hosting.vercel",
            "hosting.netlify",
            "hosting.render",
            "hosting.flyio",
        ),
        legacy_trigger_terms=("cloudflare", "vercel", "netlify", "render", "fly.io"),
        timeout_seconds=10.0,
        retryable=True,
        max_retries=1,
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

# Contract naming convention:
# - Preferred specialist IDs use *.verify_stack to indicate safe verification behavior.
# - Legacy *.run_stack IDs remain supported as transition aliases.
# - Dispatch/execution should treat alias pairs as equivalent specialists.
CONTRACT_ALIAS_GROUPS: tuple[tuple[str, ...], ...] = (
    ("wordpress.v1.run_stack", "wordpress.v1.verify_stack"),
    ("nextjs.v1.run_stack", "nextjs.v1.verify_stack"),
)


def list_advanced_scan_contracts() -> list[AdvancedScanContract]:
    return list(ADVANCED_SCAN_CONTRACTS.values())


def get_advanced_scan_contract(name: str) -> AdvancedScanContract | None:
    return ADVANCED_SCAN_CONTRACTS.get(name)
