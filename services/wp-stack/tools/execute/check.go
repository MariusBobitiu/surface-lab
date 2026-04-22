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
	toolName     = "wordpress.v1.run_stack"
	httpTimeout  = 8 * time.Second
	maxBodyBytes = 512 * 1024
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

	rootResponse, rootErr := fetchRoot(ctx, rootClient, rootURL)
	if rootErr == nil {
		findings = append(findings, detectRootFindings(rootResponse)...)
	}

	for _, check := range []endpointCheck{
		{path: "/wp-login.php", name: "wp-login"},
		{path: "/xmlrpc.php", name: "xmlrpc"},
		{path: "/readme.html", name: "readme"},
	} {
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

	metadata := map[string]interface{}{
		"request_metadata": input,
		"endpoint_checks":  endpointResults,
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
