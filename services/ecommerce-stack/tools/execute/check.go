package execute

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/MariusBobitiu/surface-lab/ecommerce-stack/models"
	"github.com/MariusBobitiu/surface-lab/ecommerce-stack/utils"
)

const (
	toolName     = "shopify.v1.verify_stack"
	httpTimeout  = 8 * time.Second
	maxBodyBytes = 160 * 1024
)

const (
	statusConfirmed    = "confirmed"
	statusNotObserved  = "not_observed"
	statusInconclusive = "inconclusive"
	statusSkipped      = "skipped"
	statusFailed       = "failed"
)

type checkOutcome struct {
	CheckID  string                 `json:"check_id"`
	Signal   string                 `json:"signal,omitempty"`
	Status   string                 `json:"status"`
	Summary  string                 `json:"summary"`
	Severity string                 `json:"severity,omitempty"`
	Evidence map[string]interface{} `json:"evidence,omitempty"`
	Error    string                 `json:"error,omitempty"`
}

type probeResult struct {
	Path        string
	URL         string
	StatusCode  int
	ContentType string
	Headers     http.Header
	Body        string
	ReadBytes   int
	Err         error
}

type specialistContext struct {
	matchedSignals        []string
	baselineSignals       []map[string]interface{}
	baselineFindings      []map[string]interface{}
	technologySummary     map[string]interface{}
	vulnerabilityResearch []map[string]interface{}
}

var scriptSrcPattern = regexp.MustCompile(`(?is)<script[^>]+src=['"]([^'"]+)['"]`)

func Run(ctx context.Context, target string, input map[string]interface{}) models.RunStackResult {
	startedAt := time.Now()

	rootURL, err := utils.NormalizeTarget(target)
	if err != nil {
		return models.RunStackResult{
			Tool:       toolName,
			Target:     target,
			Status:     "failed",
			DurationMS: time.Since(startedAt).Milliseconds(),
			Metadata: map[string]interface{}{
				"request_metadata": input,
			},
			Error: err.Error(),
		}
	}

	client := utils.NewHTTPClientNoRedirect(httpTimeout)
	context := parseSpecialistContext(input)
	outcomes := make([]checkOutcome, 0, 6)
	findings := make([]models.Finding, 0, 8)
	confirmedSignals := make([]string, 0, 6)

	appendResult := func(outcome checkOutcome, finding *models.Finding) {
		outcomes = append(outcomes, outcome)
		if outcome.Status == statusConfirmed && outcome.Signal != "" {
			confirmedSignals = append(confirmedSignals, outcome.Signal)
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	appendResult(checkProductsJSON(ctx, client, rootURL))
	appendResult(checkCollectionsJSON(ctx, client, rootURL))
	appendResult(checkCartJSON(ctx, client, rootURL))

	rootProbe := probePath(ctx, client, rootURL, "/", 96*1024)
	scriptOutcome, scriptFindings := checkThirdPartyScripts(rootProbe)
	outcomes = append(outcomes, scriptOutcome)
	if scriptOutcome.Status == statusConfirmed && scriptOutcome.Signal != "" {
		confirmedSignals = append(confirmedSignals, scriptOutcome.Signal)
	}
	findings = append(findings, scriptFindings...)

	appendResult(checkStorefrontHeaders(rootProbe))
	appendResult(checkThemeMetadata(rootProbe))

	metadata := map[string]interface{}{
		"request_metadata": input,
		"context": map[string]interface{}{
			"matched_signals":                context.matchedSignals,
			"baseline_signal_count":          len(context.baselineSignals),
			"baseline_finding_count":         len(context.baselineFindings),
			"vulnerability_research_queries": len(context.vulnerabilityResearch),
		},
		"checks":  outcomesToMetadata(outcomes),
		"signals": uniqueStrings(confirmedSignals),
	}

	return models.RunStackResult{
		Tool:       toolName,
		Target:     target,
		Status:     "completed",
		DurationMS: time.Since(startedAt).Milliseconds(),
		Findings:   dedupeFindings(findings),
		Metadata:   metadata,
	}
}

func checkProductsJSON(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	return checkCatalogEndpoint(ctx, client, rootURL, "/products.json", "products", "public-shopify-product-catalog", "shopify_posture", "verification.shopify.products_json.confirmed")
}

func checkCollectionsJSON(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	return checkCatalogEndpoint(ctx, client, rootURL, "/collections.json", "collections", "public-shopify-collections-catalog", "shopify_posture", "verification.shopify.collections_json.confirmed")
}

func checkCartJSON(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	outcome := checkOutcome{CheckID: "shopify-cart-json-accessible", Signal: "verification.shopify.cart_json.confirmed"}
	probe := probePath(ctx, client, rootURL, "/cart.js", 48*1024)
	if probe.Err != nil {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify Shopify cart JSON endpoint"
		outcome.Error = probe.Err.Error()
		return outcome, nil
	}

	validJSON := false
	if probe.StatusCode == http.StatusOK {
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(probe.Body), &payload); err == nil {
			_, hasItems := payload["items"].([]interface{})
			_, hasCount := payload["item_count"]
			validJSON = hasItems || hasCount
		}
	}

	evidence := map[string]interface{}{"url": probe.URL, "status_code": probe.StatusCode, "content_type": probe.ContentType, "snippet": snippet(probe.Body, 180)}
	if validJSON {
		outcome.Status = statusConfirmed
		outcome.Summary = "Shopify cart JSON endpoint is accessible"
		outcome.Severity = "info"
		outcome.Evidence = evidence
		finding := models.Finding{Type: "shopify-cart-json-accessible", Category: "shopify_posture", Title: "Shopify cart JSON endpoint is accessible", Severity: "info", Confidence: "high", Evidence: "/cart.js returned Shopify cart JSON", Details: map[string]interface{}{"check_status": statusConfirmed, "signal": outcome.Signal, "evidence": evidence}}
		return outcome, &finding
	}

	outcome.Status = statusNotObserved
	outcome.Summary = "No accessible Shopify cart JSON endpoint observed"
	outcome.Evidence = evidence
	return outcome, nil
}

func checkCatalogEndpoint(
	ctx context.Context,
	client *http.Client,
	rootURL string,
	path string,
	arrayKey string,
	findingType string,
	category string,
	signal string,
) (checkOutcome, *models.Finding) {
	outcome := checkOutcome{CheckID: findingType, Signal: signal}
	probe := probePath(ctx, client, rootURL, path, 64*1024)
	if probe.Err != nil {
		outcome.Status = statusInconclusive
		outcome.Summary = fmt.Sprintf("Could not verify Shopify endpoint %s", path)
		outcome.Error = probe.Err.Error()
		return outcome, nil
	}

	validJSON := false
	count := 0
	if probe.StatusCode == http.StatusOK {
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(probe.Body), &payload); err == nil {
			if values, ok := payload[arrayKey].([]interface{}); ok {
				validJSON = true
				count = len(values)
			}
		}
	}

	evidence := map[string]interface{}{"url": probe.URL, "status_code": probe.StatusCode, "content_type": probe.ContentType, "item_count": count, "snippet": snippet(probe.Body, 180)}
	if validJSON {
		outcome.Status = statusConfirmed
		outcome.Summary = fmt.Sprintf("Shopify %s endpoint is publicly accessible", path)
		outcome.Severity = "low"
		outcome.Evidence = evidence
		finding := models.Finding{Type: findingType, Category: category, Title: fmt.Sprintf("Shopify %s endpoint is publicly accessible", path), Severity: "low", Confidence: "high", Evidence: fmt.Sprintf("%s returned product-like JSON payload", path), Details: map[string]interface{}{"check_status": statusConfirmed, "signal": signal, "evidence": evidence}}
		return outcome, &finding
	}

	outcome.Status = statusNotObserved
	outcome.Summary = fmt.Sprintf("No accessible Shopify %s catalog endpoint observed", path)
	outcome.Evidence = evidence
	return outcome, nil
}

func checkThirdPartyScripts(rootProbe probeResult) (checkOutcome, []models.Finding) {
	outcome := checkOutcome{CheckID: "third-party-commerce-scripts", Signal: "verification.shopify.third_party_scripts.confirmed"}
	if rootProbe.Err != nil {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify third-party storefront scripts"
		outcome.Error = rootProbe.Err.Error()
		return outcome, nil
	}

	domains := extractScriptDomains(rootProbe.Body)
	groups := classifyScriptDomains(domains)
	totalThirdParty := len(groups["analytics_ads"]) + len(groups["app_provider"]) + len(groups["unknown_third_party"])
	evidence := map[string]interface{}{
		"url":                   rootProbe.URL,
		"status_code":           rootProbe.StatusCode,
		"shopify_domains":       groups["shopify"],
		"analytics_ads_domains": groups["analytics_ads"],
		"app_provider_domains":  groups["app_provider"],
		"unknown_third_parties": groups["unknown_third_party"],
		"total_script_domains":  len(domains),
		"total_third_party":     totalThirdParty,
	}

	if len(domains) == 0 {
		outcome.Status = statusNotObserved
		outcome.Summary = "No script domains were extracted from storefront HTML"
		outcome.Evidence = evidence
		return outcome, nil
	}

	outcome.Status = statusConfirmed
	outcome.Summary = "Storefront script domains were classified"
	outcome.Severity = "info"
	outcome.Evidence = evidence

	findings := []models.Finding{
		{
			Type:       "third-party-commerce-scripts",
			Category:   "shopify_posture",
			Title:      "Storefront third-party script inventory identified",
			Severity:   "info",
			Confidence: "medium",
			Evidence:   "Storefront HTML includes third-party commerce and analytics scripts",
			Details: map[string]interface{}{
				"check_status": statusConfirmed,
				"signal":       outcome.Signal,
				"evidence":     evidence,
			},
		},
	}

	if totalThirdParty >= 15 || len(groups["unknown_third_party"]) >= 8 {
		severity := "medium"
		if totalThirdParty < 20 {
			severity = "low"
		}
		findings = append(findings, models.Finding{
			Type:       "excessive-third-party-commerce-scripts",
			Category:   "shopify_posture",
			Title:      "High volume of third-party storefront scripts observed",
			Severity:   severity,
			Confidence: "medium",
			Evidence:   fmt.Sprintf("Observed %d third-party script domains on storefront", totalThirdParty),
			Details: map[string]interface{}{
				"check_status":      statusConfirmed,
				"signal":            "verification.shopify.excessive_scripts.confirmed",
				"third_party_total": totalThirdParty,
				"unknown_domains":   groups["unknown_third_party"],
			},
		})
	}

	return outcome, findings
}

func checkStorefrontHeaders(rootProbe probeResult) (checkOutcome, *models.Finding) {
	outcome := checkOutcome{CheckID: "missing-storefront-security-headers", Signal: "verification.shopify.missing_headers.confirmed"}
	if rootProbe.Err != nil {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify storefront security headers"
		outcome.Error = rootProbe.Err.Error()
		return outcome, nil
	}

	missing := missingHeaders(rootProbe.Headers, []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy"})
	evidence := map[string]interface{}{"url": rootProbe.URL, "status_code": rootProbe.StatusCode, "missing_headers": missing}
	if len(missing) == 0 {
		outcome.Status = statusNotObserved
		outcome.Summary = "Storefront security headers are present"
		outcome.Evidence = evidence
		return outcome, nil
	}

	severity := "low"
	if len(missing) >= 3 {
		severity = "medium"
	}
	outcome.Status = statusConfirmed
	outcome.Summary = "Storefront is missing one or more security headers"
	outcome.Severity = severity
	outcome.Evidence = evidence
	finding := models.Finding{Type: "missing-storefront-security-headers", Category: "shopify_posture", Title: "Storefront security headers are missing", Severity: severity, Confidence: "high", Evidence: fmt.Sprintf("Missing headers: %s", strings.Join(missing, ", ")), Details: map[string]interface{}{"check_status": statusConfirmed, "signal": outcome.Signal, "evidence": evidence}}
	return outcome, &finding
}

func checkThemeMetadata(rootProbe probeResult) (checkOutcome, *models.Finding) {
	outcome := checkOutcome{CheckID: "shopify-theme-app-metadata-visible"}
	if rootProbe.Err != nil {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify Shopify theme/app metadata visibility"
		outcome.Error = rootProbe.Err.Error()
		return outcome, nil
	}

	markers := matchIndicators(rootProbe.Body, []string{"Shopify.theme", "Shopify.shop", "cdn.shopify.com/s/files", "shopify-section", "Shopify.designMode", "shopify-features"})
	evidence := map[string]interface{}{"url": rootProbe.URL, "status_code": rootProbe.StatusCode, "markers": markers}
	if len(markers) == 0 {
		outcome.Status = statusNotObserved
		outcome.Summary = "No explicit theme/app metadata markers observed"
		outcome.Evidence = evidence
		return outcome, nil
	}

	outcome.Status = statusConfirmed
	outcome.Summary = "Shopify theme/app metadata markers were observed"
	outcome.Severity = "info"
	outcome.Evidence = evidence
	finding := models.Finding{Type: "shopify-theme-app-metadata-visible", Category: "shopify_posture", Title: "Shopify theme/app metadata is externally visible", Severity: "info", Confidence: "high", Evidence: "Storefront HTML includes Shopify theme/app metadata markers", Details: map[string]interface{}{"check_status": statusConfirmed, "evidence": evidence}}
	return outcome, &finding
}

func probePath(ctx context.Context, client *http.Client, rootURL string, path string, maxRead int64) probeResult {
	result := probeResult{Path: path}
	targetURL, err := joinPath(rootURL, path)
	if err != nil {
		result.Err = err
		return result
	}
	result.URL = targetURL

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		result.Err = err
		return result
	}
	req.Header.Set("User-Agent", utils.DefaultUserAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		result.Err = err
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ContentType = strings.TrimSpace(resp.Header.Get("Content-Type"))
	result.Headers = resp.Header.Clone()

	if maxRead <= 0 {
		maxRead = maxBodyBytes
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	if readErr != nil {
		result.Err = readErr
		return result
	}
	result.ReadBytes = len(body)
	result.Body = string(body)
	return result
}

func extractScriptDomains(html string) []string {
	if strings.TrimSpace(html) == "" {
		return nil
	}
	domains := make([]string, 0)
	for _, match := range scriptSrcPattern.FindAllStringSubmatch(html, -1) {
		if len(match) < 2 {
			continue
		}
		raw := match[1]
		if domain := domainFromScriptURL(raw); domain != "" {
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	return uniqueStrings(domains)
}

func domainFromScriptURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.HasPrefix(trimmed, "/") {
		return ""
	}
	if strings.HasPrefix(trimmed, "//") {
		trimmed = "https:" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parsed.Hostname()))
}

func classifyScriptDomains(domains []string) map[string][]string {
	groups := map[string][]string{
		"shopify":             {},
		"analytics_ads":       {},
		"app_provider":        {},
		"unknown_third_party": {},
	}

	for _, domain := range domains {
		switch {
		case hasAnySuffix(domain, []string{"shopify.com", "shopifycdn.net", "myshopify.com"}):
			groups["shopify"] = append(groups["shopify"], domain)
		case hasAnySuffix(domain, []string{"google-analytics.com", "googletagmanager.com", "doubleclick.net", "facebook.net", "facebook.com", "analytics.tiktok.com", "bing.com"}):
			groups["analytics_ads"] = append(groups["analytics_ads"], domain)
		case hasAnySuffix(domain, []string{"klaviyo.com", "judge.me", "yotpo.com", "cdn.jsdelivr.net", "hotjar.com", "segment.com", "stripe.com", "paypal.com"}):
			groups["app_provider"] = append(groups["app_provider"], domain)
		default:
			groups["unknown_third_party"] = append(groups["unknown_third_party"], domain)
		}
	}

	for key, values := range groups {
		sort.Strings(values)
		groups[key] = uniqueStrings(values)
	}

	return groups
}

func hasAnySuffix(value string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(value, suffix) {
			return true
		}
	}
	return false
}

func missingHeaders(headers http.Header, keys []string) []string {
	missing := make([]string, 0)
	for _, key := range keys {
		if strings.TrimSpace(headers.Get(key)) == "" {
			missing = append(missing, key)
		}
	}
	return missing
}

func matchIndicators(body string, indicators []string) []string {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	lower := strings.ToLower(body)
	matches := make([]string, 0)
	for _, indicator := range indicators {
		if strings.Contains(lower, strings.ToLower(indicator)) {
			matches = append(matches, indicator)
		}
	}
	sort.Strings(matches)
	return uniqueStrings(matches)
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func outcomesToMetadata(outcomes []checkOutcome) []map[string]interface{} {
	items := make([]map[string]interface{}, 0, len(outcomes))
	for _, outcome := range outcomes {
		items = append(items, map[string]interface{}{
			"check_id": outcome.CheckID,
			"signal":   outcome.Signal,
			"status":   outcome.Status,
			"summary":  outcome.Summary,
			"severity": outcome.Severity,
			"evidence": outcome.Evidence,
			"error":    outcome.Error,
		})
	}
	return items
}

func joinPath(rootURL string, path string) (string, error) {
	parsed, err := url.Parse(rootURL)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	return parsed.ResolveReference(ref).String(), nil
}

func snippet(value string, limit int) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || limit <= 0 {
		return ""
	}
	if len(trimmed) <= limit {
		return trimmed
	}
	return strings.TrimSpace(trimmed[:limit])
}

func dedupeFindings(findings []models.Finding) []models.Finding {
	deduped := make([]models.Finding, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		key := finding.Category + "|" + finding.Title + "|" + finding.Evidence
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, finding)
	}
	return deduped
}

func parseSpecialistContext(input map[string]interface{}) specialistContext {
	return specialistContext{
		matchedSignals:        stringList(input["matched_signals"]),
		baselineSignals:       mapList(input["baseline_signals"]),
		baselineFindings:      mapList(input["baseline_findings"]),
		technologySummary:     mapValue(input["technology_summary"]),
		vulnerabilityResearch: mapList(input["vulnerability_research"]),
	}
}

func mapList(value interface{}) []map[string]interface{} {
	rawList, ok := value.([]interface{})
	if !ok {
		return nil
	}
	result := make([]map[string]interface{}, 0, len(rawList))
	for _, item := range rawList {
		if typed, ok := item.(map[string]interface{}); ok {
			result = append(result, typed)
		}
	}
	return result
}

func mapValue(value interface{}) map[string]interface{} {
	typed, ok := value.(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return typed
}

func stringList(value interface{}) []string {
	rawList, ok := value.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(rawList))
	for _, item := range rawList {
		if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
			result = append(result, strings.TrimSpace(text))
		}
	}
	return result
}
