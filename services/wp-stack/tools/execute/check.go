package execute

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/MariusBobitiu/surface-lab/wp-stack/models"
	"github.com/MariusBobitiu/surface-lab/wp-stack/utils"
)

const (
	toolName        = "wordpress.v1.run_stack"
	httpTimeout     = 8 * time.Second
	maxBodyBytes    = 512 * 1024
	maxResearchCVEs = 4
)

var (
	pluginAssetPattern = regexp.MustCompile(`(?i)/wp-content/plugins/([^/"'?#]+)/`)
	themeAssetPattern  = regexp.MustCompile(`(?i)/wp-content/themes/([^/"'?#]+)/`)
	generatorPattern   = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']*wordpress[^"']*)["']`)
)

type endpointCheck struct {
	path string
	name string
}

type endpointResult struct {
	Path   string
	Status int
}

type specialistContext struct {
	matchedSignals         []string
	baselineSignals        []map[string]interface{}
	baselineFindings       []map[string]interface{}
	technologySummary      map[string]interface{}
	vulnerabilityResearch  []map[string]interface{}
	requestedWPVersion     string
	researchDerivedVersion string
}

func Run(ctx context.Context, target string, input map[string]interface{}) models.RunStackResult {
	startedAt := time.Now()

	rootURL, err := normalizeTarget(target)
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

	rootClient := utils.NewHTTPClient(httpTimeout)
	pathClient := utils.NewHTTPClientNoRedirect(httpTimeout)
	findings := make([]models.Finding, 0)
	endpointResults := make([]map[string]interface{}, 0)
	context := parseSpecialistContext(input)

	rootResponse, rootErr := fetchRoot(ctx, rootClient, rootURL)
	if rootErr == nil {
		findings = append(findings, detectRootFindings(rootResponse)...)
	}

	for _, check := range collectEndpointChecks(context) {
		result, checkErr := checkEndpoint(ctx, pathClient, rootURL, check.path)
		if checkErr != nil {
			endpointResults = append(endpointResults, map[string]interface{}{
				"path":  check.path,
				"error": checkErr.Error(),
			})
			continue
		}

		endpointResults = append(endpointResults, map[string]interface{}{
			"path":   result.Path,
			"status": result.Status,
		})
		findings = append(findings, detectEndpointFindings(check.name, result)...)
	}

	status := "completed"
	if rootErr != nil && len(findings) == 0 {
		status = "failed"
	}

	detectedWPVersion := firstNonEmpty(context.requestedWPVersion, context.researchDerivedVersion, detectWPVersionFromRoot(rootResponse))
	researchFindings, researchMetadata := findingsFromVulnerabilityResearch(context.vulnerabilityResearch, detectedWPVersion)
	findings = append(findings, researchFindings...)

	metadata := map[string]interface{}{
		"request_metadata":           input,
		"endpoint_checks":            endpointResults,
		"detected_wordpress_version": detectedWPVersion,
		"vulnerability_research":     researchMetadata,
		"context": map[string]interface{}{
			"matched_signals":                context.matchedSignals,
			"baseline_signal_count":          len(context.baselineSignals),
			"baseline_finding_count":         len(context.baselineFindings),
			"vulnerability_research_queries": len(context.vulnerabilityResearch),
		},
	}
	if rootResponse != nil {
		metadata["root_status"] = rootResponse.StatusCode
		metadata["root_url"] = rootResponse.URL
	}
	if rootErr != nil {
		metadata["root_error"] = rootErr.Error()
	}

	return models.RunStackResult{
		Tool:       toolName,
		Target:     target,
		Status:     status,
		DurationMS: time.Since(startedAt).Milliseconds(),
		Findings:   dedupeFindings(findings),
		Metadata:   metadata,
		Error:      errorString(rootErr, status),
	}
}

type rootFetchResult struct {
	URL        string
	StatusCode int
	HTML       string
	Headers    http.Header
}

func fetchRoot(ctx context.Context, client *http.Client, targetURL string) (*rootFetchResult, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build root request: %w", err)
	}

	request.Header.Set("User-Agent", utils.DefaultUserAgent)
	request.Header.Set("Accept", "text/html,application/xhtml+xml")

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch root page: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read root response: %w", err)
	}

	return &rootFetchResult{
		URL:        response.Request.URL.String(),
		StatusCode: response.StatusCode,
		HTML:       string(body),
		Headers:    response.Header.Clone(),
	}, nil
}

func detectRootFindings(result *rootFetchResult) []models.Finding {
	findings := make([]models.Finding, 0)
	lowerHTML := strings.ToLower(result.HTML)

	assetIndicators := make([]string, 0)
	for _, indicator := range []string{"wp-content/", "wp-includes/", "/wp-json/"} {
		if strings.Contains(lowerHTML, indicator) {
			assetIndicators = append(assetIndicators, indicator)
		}
	}

	if len(assetIndicators) > 0 {
		findings = append(findings, models.Finding{
			Type:       "fingerprint",
			Category:   "wordpress_fingerprint",
			Title:      "WordPress asset indicators detected",
			Severity:   "info",
			Confidence: "high",
			Evidence:   fmt.Sprintf("Homepage HTML referenced %s", strings.Join(assetIndicators, ", ")),
			Details: map[string]interface{}{
				"matched_indicators": assetIndicators,
				"root_status":        result.StatusCode,
				"url":                result.URL,
			},
		})
	}

	if matches := generatorPattern.FindStringSubmatch(result.HTML); len(matches) > 1 {
		findings = append(findings, models.Finding{
			Type:       "fingerprint",
			Category:   "wordpress_fingerprint",
			Title:      "WordPress generator meta tag detected",
			Severity:   "info",
			Confidence: "high",
			Evidence:   fmt.Sprintf("Homepage HTML contained generator tag: %s", matches[1]),
			Details: map[string]interface{}{
				"generator": matches[1],
				"url":       result.URL,
			},
		})
	}

	plugins := extractAssetSlugs(pluginAssetPattern, result.HTML)
	if len(plugins) > 0 {
		findings = append(findings, models.Finding{
			Type:       "fingerprint",
			Category:   "wordpress_fingerprint",
			Title:      "WordPress plugin asset hints detected",
			Severity:   "info",
			Confidence: "medium",
			Evidence:   fmt.Sprintf("Homepage HTML referenced plugin asset paths for %s", strings.Join(plugins, ", ")),
			Details: map[string]interface{}{
				"plugins": plugins,
				"url":     result.URL,
			},
		})
	}

	themes := extractAssetSlugs(themeAssetPattern, result.HTML)
	if len(themes) > 0 {
		findings = append(findings, models.Finding{
			Type:       "fingerprint",
			Category:   "wordpress_fingerprint",
			Title:      "WordPress theme asset hints detected",
			Severity:   "info",
			Confidence: "medium",
			Evidence:   fmt.Sprintf("Homepage HTML referenced theme asset paths for %s", strings.Join(themes, ", ")),
			Details: map[string]interface{}{
				"themes": themes,
				"url":    result.URL,
			},
		})
	}

	return findings
}

func checkEndpoint(ctx context.Context, client *http.Client, targetURL string, path string) (*endpointResult, error) {
	endpointURL, err := joinPath(targetURL, path)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build endpoint request for %s: %w", path, err)
	}

	request.Header.Set("User-Agent", utils.DefaultUserAgent)
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request endpoint %s: %w", path, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read endpoint %s: %w", path, err)
	}

	return &endpointResult{
		Path:   path,
		Status: response.StatusCode,
	}, detectSpecialEndpointBody(path, response.StatusCode, string(body))
}

func detectSpecialEndpointBody(path string, statusCode int, body string) error {
	lowerBody := strings.ToLower(body)

	if path == "/xmlrpc.php" && statusCode == http.StatusMethodNotAllowed && strings.Contains(lowerBody, "xml-rpc server accepts post requests only") {
		return nil
	}

	if statusCode >= 500 {
		return fmt.Errorf("unexpected server error status %d for %s", statusCode, path)
	}

	return nil
}

func detectEndpointFindings(name string, result *endpointResult) []models.Finding {
	switch name {
	case "wp-login":
		if result.Status == http.StatusOK || result.Status == http.StatusFound || result.Status == http.StatusForbidden {
			return []models.Finding{{
				Type:       "surface",
				Category:   "wordpress_surface",
				Title:      "WordPress login endpoint is exposed",
				Severity:   "info",
				Confidence: endpointConfidence(result.Status),
				Evidence:   fmt.Sprintf("%s returned HTTP %d", result.Path, result.Status),
				Details: map[string]interface{}{
					"path":   result.Path,
					"status": result.Status,
				},
			}}
		}
	case "xmlrpc":
		if result.Status == http.StatusOK || result.Status == http.StatusMethodNotAllowed {
			return []models.Finding{{
				Type:       "surface",
				Category:   "wordpress_surface",
				Title:      "WordPress XML-RPC endpoint appears enabled",
				Severity:   "medium",
				Confidence: "high",
				Evidence:   fmt.Sprintf("%s returned HTTP %d", result.Path, result.Status),
				Details: map[string]interface{}{
					"path":   result.Path,
					"status": result.Status,
				},
			}}
		}
	case "readme":
		if result.Status == http.StatusOK {
			return []models.Finding{{
				Type:       "exposure",
				Category:   "wordpress_exposure",
				Title:      "WordPress readme file is publicly accessible",
				Severity:   "low",
				Confidence: "high",
				Evidence:   fmt.Sprintf("%s returned HTTP %d", result.Path, result.Status),
				Details: map[string]interface{}{
					"path":   result.Path,
					"status": result.Status,
				},
			}}
		}
	case "wp-json":
		if result.Status == http.StatusOK {
			return []models.Finding{{
				Type:       "surface",
				Category:   "wordpress_surface",
				Title:      "WordPress REST API endpoint is exposed",
				Severity:   "info",
				Confidence: "high",
				Evidence:   fmt.Sprintf("%s returned HTTP %d", result.Path, result.Status),
				Details: map[string]interface{}{
					"path":   result.Path,
					"status": result.Status,
				},
			}}
		}
	case "wp-admin":
		if result.Status == http.StatusOK || result.Status == http.StatusFound || result.Status == http.StatusForbidden {
			return []models.Finding{{
				Type:       "surface",
				Category:   "wordpress_surface",
				Title:      "WordPress admin endpoint is exposed",
				Severity:   "info",
				Confidence: endpointConfidence(result.Status),
				Evidence:   fmt.Sprintf("%s returned HTTP %d", result.Path, result.Status),
				Details: map[string]interface{}{
					"path":   result.Path,
					"status": result.Status,
				},
			}}
		}
	}

	return nil
}

func endpointConfidence(statusCode int) string {
	if statusCode == http.StatusOK {
		return "high"
	}

	return "medium"
}

func extractAssetSlugs(pattern *regexp.Regexp, html string) []string {
	matches := pattern.FindAllStringSubmatch(html, -1)
	if len(matches) == 0 {
		return nil
	}

	slugs := make([]string, 0, len(matches))
	seen := make(map[string]struct{})
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		slug := strings.ToLower(strings.TrimSpace(match[1]))
		if slug == "" {
			continue
		}

		if _, exists := seen[slug]; exists {
			continue
		}

		seen[slug] = struct{}{}
		slugs = append(slugs, slug)
	}

	slices.Sort(slugs)
	return slugs
}

func dedupeFindings(findings []models.Finding) []models.Finding {
	deduped := make([]models.Finding, 0, len(findings))
	seen := make(map[string]struct{})

	for _, finding := range findings {
		key := finding.Category + "|" + finding.Title + "|" + finding.Evidence
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		deduped = append(deduped, finding)
	}

	return deduped
}

func normalizeTarget(target string) (string, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parse target: %w", err)
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("target must include scheme and host")
	}

	return parsed.String(), nil
}

func joinPath(targetURL string, path string) (string, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("parse target: %w", err)
	}

	joined, err := parsed.Parse(path)
	if err != nil {
		return "", fmt.Errorf("resolve path %s: %w", path, err)
	}

	return joined.String(), nil
}

func errorString(err error, status string) string {
	if err == nil || status == "completed" {
		return ""
	}

	return err.Error()
}

func parseSpecialistContext(input map[string]interface{}) specialistContext {
	ctx := specialistContext{
		matchedSignals:        stringList(input["matched_signals"]),
		baselineSignals:       mapList(input["baseline_signals"]),
		baselineFindings:      mapList(input["baseline_findings"]),
		technologySummary:     mapValue(input["technology_summary"]),
		vulnerabilityResearch: mapList(input["vulnerability_research"]),
	}

	ctx.requestedWPVersion = firstNonEmpty(
		normalizeVersion(stringValue(input["wordpress_version"])),
		extractRequestedWPVersion(input),
		findWPVersionInTechnologySummary(ctx.technologySummary),
	)
	ctx.researchDerivedVersion = findWPVersionInResearch(ctx.vulnerabilityResearch)

	return ctx
}

func collectEndpointChecks(ctx specialistContext) []endpointCheck {
	checks := []endpointCheck{
		{path: "/wp-login.php", name: "wp-login"},
		{path: "/xmlrpc.php", name: "xmlrpc"},
		{path: "/readme.html", name: "readme"},
	}

	if hasWordPressSignalHints(ctx) {
		checks = append(checks,
			endpointCheck{path: "/wp-json/", name: "wp-json"},
			endpointCheck{path: "/wp-admin/", name: "wp-admin"},
		)
	}

	return dedupeEndpointChecks(checks)
}

func dedupeEndpointChecks(checks []endpointCheck) []endpointCheck {
	deduped := make([]endpointCheck, 0, len(checks))
	seen := map[string]struct{}{}
	for _, check := range checks {
		if _, ok := seen[check.path]; ok {
			continue
		}
		seen[check.path] = struct{}{}
		deduped = append(deduped, check)
	}
	return deduped
}

func hasWordPressSignalHints(ctx specialistContext) bool {
	for _, signal := range ctx.baselineSignals {
		key := strings.ToLower(strings.TrimSpace(stringValue(signal["key"])))
		value, ok := signal["value"].(bool)
		if !ok || !value {
			continue
		}
		if strings.Contains(key, "framework.wordpress") || strings.Contains(key, "surface.admin") || strings.Contains(key, "surface.api") {
			return true
		}
	}

	for _, finding := range ctx.baselineFindings {
		combined := strings.ToLower(
			strings.Join([]string{
				stringValue(finding["title"]),
				stringValue(finding["summary"]),
				stringValue(finding["category"]),
			}, " "),
		)
		if strings.Contains(combined, "wordpress") || strings.Contains(combined, "wp-") {
			return true
		}
	}

	return false
}

func detectWPVersionFromRoot(root *rootFetchResult) string {
	if root == nil {
		return ""
	}
	if matches := generatorPattern.FindStringSubmatch(root.HTML); len(matches) > 1 {
		return extractVersion(matches[1])
	}
	return ""
}

func findingsFromVulnerabilityResearch(research []map[string]interface{}, detectedVersion string) ([]models.Finding, map[string]interface{}) {
	findings := make([]models.Finding, 0)
	productsConsidered := make([]interface{}, 0)
	matchedCVEs := 0

	for _, item := range research {
		product := strings.ToLower(strings.TrimSpace(stringValue(item["product"])))
		if product == "" {
			continue
		}
		productsConsidered = append(productsConsidered, product)

		if product != "wordpress" && product != "wp" && product != "wordpress core" {
			continue
		}

		version := firstNonEmpty(normalizeVersion(stringValue(item["version"])), detectedVersion)
		for _, cve := range mapList(item["cve_matches"]) {
			if matchedCVEs >= maxResearchCVEs {
				break
			}
			cveID := strings.TrimSpace(stringValue(cve["cve_id"]))
			if cveID == "" {
				continue
			}

			severity := normalizeResearchSeverity(cve)
			findings = append(findings, models.Finding{
				Type:       "known_vulnerability",
				Category:   "wordpress_vulnerability",
				Title:      fmt.Sprintf("Potential WordPress exposure mapped from pre-specialist research: %s", cveID),
				Severity:   severity,
				Confidence: "medium",
				Evidence:   firstNonEmpty(stringValue(cve["description"]), "Pre-specialist NVD/CVE research matched a potential WordPress issue."),
				Details: map[string]interface{}{
					"product":                  "wordpress",
					"version":                  version,
					"cve_id":                   cveID,
					"cvss_score":               cve["cvss_score"],
					"cvss_severity":            cve["cvss_severity"],
					"source":                   "orchestrator.vulnerability_research",
					"source_identifier":        cve["source_identifier"],
					"published":                cve["published"],
					"last_modified":            cve["last_modified"],
					"requires_version_confirm": true,
				},
			})
			matchedCVEs++
		}
	}

	metadata := map[string]interface{}{
		"products_considered": productsConsidered,
		"matched_cve_count":   matchedCVEs,
	}

	return findings, metadata
}

func normalizeResearchSeverity(cve map[string]interface{}) string {
	value := strings.ToLower(strings.TrimSpace(stringValue(cve["cvss_severity"])))
	switch value {
	case "critical", "high", "medium", "low":
		return value
	default:
		return "medium"
	}
}

func extractRequestedWPVersion(input map[string]interface{}) string {
	for _, key := range []string{"wordpress_version", "wp_version", "framework_version", "version"} {
		if version := normalizeVersion(stringValue(input[key])); version != "" {
			return version
		}
	}

	if version := extractWPVersionFromBaselineSignals(input["baseline_signals"]); version != "" {
		return version
	}

	return ""
}

func extractWPVersionFromBaselineSignals(value interface{}) string {
	for _, signal := range mapList(value) {
		key := strings.ToLower(strings.TrimSpace(stringValue(signal["key"])))
		if !strings.Contains(key, "wordpress") || !strings.Contains(key, "version") {
			continue
		}
		if version := normalizeVersion(stringValue(signal["value"])); version != "" {
			return version
		}
	}

	if rawSignals, ok := value.([]interface{}); ok {
		for _, item := range rawSignals {
			signal, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(stringValue(signal["key"])))
			if !strings.Contains(key, "wordpress") || !strings.Contains(key, "version") {
				continue
			}
			if version := normalizeVersion(stringValue(signal["value"])); version != "" {
				return version
			}
		}
	}

	return ""
}

func findWPVersionInTechnologySummary(summary map[string]interface{}) string {
	versions := mapValue(summary["versions"])
	for _, key := range []string{"wordpress", "wp"} {
		if version := normalizeVersion(stringValue(versions[key])); version != "" {
			return version
		}
	}
	return ""
}

func findWPVersionInResearch(research []map[string]interface{}) string {
	for _, item := range research {
		product := strings.ToLower(strings.TrimSpace(stringValue(item["product"])))
		if product != "wordpress" && product != "wp" && product != "wordpress core" {
			continue
		}
		if version := normalizeVersion(stringValue(item["version"])); version != "" {
			return version
		}
	}
	return ""
}

func extractVersion(value string) string {
	versionPattern := regexp.MustCompile(`(?i)\b\d+(?:\.\d+){1,3}\b`)
	matches := versionPattern.FindStringSubmatch(value)
	if len(matches) == 0 {
		return ""
	}
	return normalizeVersion(matches[0])
}

func normalizeVersion(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(strings.ToLower(value), "v")
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
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

func stringValue(value interface{}) string {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}
