package execute

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/MariusBobitiu/surface-lab/nextjs-stack/models"
	"github.com/MariusBobitiu/surface-lab/nextjs-stack/utils"
)

const (
	toolName        = "nextjs.v1.run_stack"
	httpTimeout     = 8 * time.Second
	maxBodyBytes    = 512 * 1024
	maxChunkTargets = 2
)

var (
	nextDataPattern    = regexp.MustCompile(`(?s)<script[^>]+id=["']__NEXT_DATA__["'][^>]*>(.*?)</script>`)
	nextStaticPattern  = regexp.MustCompile(`(?i)/_next/static/([^/"'?#]+)/`)
	nextChunkURL       = regexp.MustCompile(`(?i)(/_next/static/[^"'?#]+\.(?:js|mjs))`)
	sourceMapPattern   = regexp.MustCompile(`(?m)^//# sourceMappingURL=(.+)$`)
	nextVersionPattern = regexp.MustCompile(`(?i)(?:next(?:\.js)?|nextVersion|__NEXT_VERSION__)["'\s:=/v-]+(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)`)
	appRouterMarkerSet = []string{"self.__next_f.push", "__next_router__", "app-router", "__next_rsc__"}
)

type rootFetchResult struct {
	URL        string
	StatusCode int
	HTML       string
	Headers    http.Header
}

type chunkProbeResult struct {
	URL           string
	StatusCode    int
	SourceMapHint string
	NextVersion   string
	BodySnippet   string
}

type artifactProbeResult struct {
	Path       string
	URL        string
	StatusCode int
	Exposed    bool
	Evidence   string
}

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

	client := utils.NewHTTPClient(httpTimeout)
	pathClient := utils.NewHTTPClientNoRedirect(httpTimeout)
	findings := make([]models.Finding, 0)
	metadata := map[string]interface{}{
		"request_metadata": input,
	}

	rootResponse, rootErr := fetchRoot(ctx, client, rootURL)
	if rootErr != nil {
		return models.RunStackResult{
			Tool:       toolName,
			Target:     target,
			Status:     "failed",
			DurationMS: time.Since(startedAt).Milliseconds(),
			Metadata: map[string]interface{}{
				"request_metadata": input,
				"root_error":       rootErr.Error(),
			},
			Error: rootErr.Error(),
		}
	}

	_, analysis := detectRootFindings(rootResponse)
	metadata["root_url"] = rootResponse.URL
	metadata["root_status"] = rootResponse.StatusCode
	metadata["analysis"] = analysis.toMap()

	detectedVersion := firstNonEmpty(extractRequestedNextVersion(input), analysis.nextVersion)

	chunkResults := make([]map[string]interface{}, 0)
	for _, chunkURL := range firstN(analysis.chunkURLs, maxChunkTargets) {
		chunkResult, chunkErr := probeChunk(ctx, client, chunkURL)
		if chunkErr != nil {
			chunkResults = append(chunkResults, map[string]interface{}{
				"url":   chunkURL,
				"error": chunkErr.Error(),
			})
			continue
		}

		chunkResults = append(chunkResults, map[string]interface{}{
			"url":             chunkResult.URL,
			"status":          chunkResult.StatusCode,
			"source_map_hint": chunkResult.SourceMapHint,
			"next_version":    chunkResult.NextVersion,
		})
		if detectedVersion == "" {
			detectedVersion = chunkResult.NextVersion
		}
		findings = append(findings, detectChunkFindings(chunkResult)...)
	}
	metadata["chunk_probes"] = chunkResults

	artifactResults := probeDevelopmentArtifacts(ctx, pathClient, rootResponse.URL)
	metadata["development_artifact_probes"] = artifactResultsToMetadata(artifactResults)
	findings = append(findings, detectDevelopmentArtifactFindings(artifactResults)...)

	if analysis.buildID != "" {
		if dataResult, dataErr := probeNextData(ctx, pathClient, rootResponse.URL, analysis.buildID); dataErr == nil {
			metadata["next_data_probe"] = dataResult
			findings = append(findings, detectNextDataFindings(dataResult)...)
		} else {
			metadata["next_data_probe"] = map[string]interface{}{
				"error": dataErr.Error(),
			}
		}
	}

	metadata["detected_next_version"] = detectedVersion
	advisoryFindings, advisoryMetadata, advisoryErr := lookupNextAdvisories(ctx, client, detectedVersion)
	metadata["advisory_lookup"] = advisoryMetadata
	if advisoryErr != nil {
		metadata["advisory_lookup_error"] = advisoryErr.Error()
	} else {
		findings = append(findings, advisoryFindings...)
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

type rootAnalysis struct {
	buildID         string
	nextVersion     string
	hasNextData     bool
	hasAppRouter    bool
	hasStaticAssets bool
	hasPoweredBy    bool
	chunkURLs       []string
}

func (a rootAnalysis) toMap() map[string]interface{} {
	return map[string]interface{}{
		"build_id":          a.buildID,
		"next_version":      a.nextVersion,
		"has_next_data":     a.hasNextData,
		"has_app_router":    a.hasAppRouter,
		"has_static_assets": a.hasStaticAssets,
		"has_powered_by":    a.hasPoweredBy,
		"chunk_urls":        a.chunkURLs,
	}
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

func detectRootFindings(result *rootFetchResult) ([]models.Finding, rootAnalysis) {
	findings := make([]models.Finding, 0)
	analysis := rootAnalysis{
		hasPoweredBy: strings.EqualFold(strings.TrimSpace(result.Headers.Get("X-Powered-By")), "Next.js"),
	}

	lowerHTML := strings.ToLower(result.HTML)
	analysis.nextVersion = extractNextVersion(result.HTML)
	if strings.Contains(lowerHTML, "/_next/static/") {
		analysis.hasStaticAssets = true
	}

	if matches := nextDataPattern.FindStringSubmatch(result.HTML); len(matches) > 1 {
		analysis.hasNextData = true
		if buildID := extractBuildIDFromNextData(matches[1]); buildID != "" {
			analysis.buildID = buildID
		}
	}

	if analysis.buildID == "" {
		if matches := nextStaticPattern.FindAllStringSubmatch(result.HTML, -1); len(matches) > 0 {
			for _, match := range matches {
				if len(match) > 1 && strings.TrimSpace(match[1]) != "" {
					analysis.buildID = strings.TrimSpace(match[1])
					break
				}
			}
		}
	}

	for _, marker := range appRouterMarkerSet {
		if strings.Contains(lowerHTML, strings.ToLower(marker)) {
			analysis.hasAppRouter = true
			break
		}
	}

	analysis.chunkURLs = uniqueChunkURLs(result.URL, nextChunkURL.FindAllString(result.HTML, -1))

	if analysis.hasStaticAssets || analysis.hasNextData || analysis.hasPoweredBy {
		findings = append(findings, models.Finding{
			Type:       "fingerprint",
			Category:   "nextjs_fingerprint",
			Title:      "Next.js application markers detected",
			Severity:   "info",
			Confidence: "high",
			Evidence:   buildRootEvidence(analysis),
			Details: map[string]interface{}{
				"build_id":          analysis.buildID,
				"next_version":      analysis.nextVersion,
				"has_next_data":     analysis.hasNextData,
				"has_app_router":    analysis.hasAppRouter,
				"has_static_assets": analysis.hasStaticAssets,
				"url":               result.URL,
			},
		})
	}

	if analysis.buildID != "" {
		findings = append(findings, models.Finding{
			Type:       "build_id_exposed",
			Category:   "nextjs_fingerprint",
			Title:      "Next.js build identifier exposed",
			Severity:   "info",
			Confidence: "high",
			Evidence:   fmt.Sprintf("Homepage exposed Next.js build ID %q", analysis.buildID),
			Details: map[string]interface{}{
				"build_id": analysis.buildID,
				"url":      result.URL,
			},
		})
	}

	if analysis.hasAppRouter {
		findings = append(findings, models.Finding{
			Type:       "app_router_detected",
			Category:   "nextjs_surface",
			Title:      "Next.js app router markers detected",
			Severity:   "info",
			Confidence: "medium",
			Evidence:   "Homepage HTML contained app router / React Server Component markers",
			Details: map[string]interface{}{
				"url": result.URL,
			},
		})
	}

	return findings, analysis
}

func extractBuildIDFromNextData(raw string) string {
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &payload); err != nil {
		return ""
	}

	buildID, _ := payload["buildId"].(string)
	return strings.TrimSpace(buildID)
}

func extractRequestedNextVersion(input map[string]interface{}) string {
	for _, key := range []string{"next_version", "nextjs_version", "framework_version", "version"} {
		value, ok := input[key]
		if !ok {
			continue
		}

		if version, ok := value.(string); ok {
			return normalizeVersion(version)
		}
	}

	if version := extractNextVersionFromBaselineSignals(input["baseline_signals"]); version != "" {
		return version
	}
	return ""
}

func extractNextVersionFromBaselineSignals(value interface{}) string {
	signals, ok := value.([]interface{})
	if !ok {
		return ""
	}

	for _, item := range signals {
		signal, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		key, _ := signal["key"].(string)
		if !strings.Contains(strings.ToLower(key), "next") || !strings.Contains(strings.ToLower(key), "version") {
			continue
		}
		if version, ok := signal["value"].(string); ok {
			return normalizeVersion(version)
		}
	}
	return ""
}

func extractNextVersion(content string) string {
	matches := nextVersionPattern.FindStringSubmatch(content)
	if len(matches) < 2 {
		return ""
	}
	return normalizeVersion(matches[1])
}

func normalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(strings.ToLower(version), "v")
	if version == "" {
		return ""
	}
	return version
}

func uniqueChunkURLs(rootURL string, matches []string) []string {
	if len(matches) == 0 {
		return nil
	}

	parsedRoot, err := url.Parse(rootURL)
	if err != nil {
		return nil
	}

	unique := make([]string, 0, len(matches))
	seen := map[string]struct{}{}
	for _, match := range matches {
		ref, err := url.Parse(match)
		if err != nil {
			continue
		}
		resolved := parsedRoot.ResolveReference(ref).String()
		if _, ok := seen[resolved]; ok {
			continue
		}
		seen[resolved] = struct{}{}
		unique = append(unique, resolved)
	}
	slices.Sort(unique)
	return unique
}

func buildRootEvidence(analysis rootAnalysis) string {
	parts := make([]string, 0, 4)
	if analysis.hasNextData {
		parts = append(parts, "__NEXT_DATA__")
	}
	if analysis.hasStaticAssets {
		parts = append(parts, "/_next/static/")
	}
	if analysis.hasPoweredBy {
		parts = append(parts, "X-Powered-By: Next.js")
	}
	if analysis.hasAppRouter {
		parts = append(parts, "app router markers")
	}
	return fmt.Sprintf("Detected Next.js via %s", strings.Join(parts, ", "))
}

func probeChunk(ctx context.Context, client *http.Client, chunkURL string) (*chunkProbeResult, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, chunkURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build chunk request: %w", err)
	}

	request.Header.Set("User-Agent", utils.DefaultUserAgent)
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch chunk: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 256*1024))
	if err != nil {
		return nil, fmt.Errorf("read chunk: %w", err)
	}

	result := &chunkProbeResult{
		URL:         response.Request.URL.String(),
		StatusCode:  response.StatusCode,
		BodySnippet: snippet(body, 160),
	}
	if matches := sourceMapPattern.FindStringSubmatch(string(body)); len(matches) > 1 {
		result.SourceMapHint = strings.TrimSpace(matches[1])
	}
	result.NextVersion = extractNextVersion(string(body))
	return result, nil
}

func detectChunkFindings(result *chunkProbeResult) []models.Finding {
	if result.StatusCode != http.StatusOK || result.SourceMapHint == "" {
		return nil
	}

	return []models.Finding{
		{
			Type:       "source_map_reference",
			Category:   "nextjs_exposure",
			Title:      "Next.js chunk references a source map",
			Severity:   "low",
			Confidence: "medium",
			Evidence:   fmt.Sprintf("Chunk %s referenced source map %q", result.URL, result.SourceMapHint),
			Details: map[string]interface{}{
				"url":             result.URL,
				"source_map_hint": result.SourceMapHint,
				"chunk_status":    result.StatusCode,
				"body_snippet":    result.BodySnippet,
			},
		},
	}
}

func probeNextData(ctx context.Context, client *http.Client, rootURL string, buildID string) (map[string]interface{}, error) {
	parsed, err := url.Parse(rootURL)
	if err != nil {
		return nil, err
	}

	dataPath := fmt.Sprintf("/_next/data/%s/index.json", buildID)
	if trimmed := strings.Trim(parsed.Path, "/"); trimmed != "" {
		dataPath = fmt.Sprintf("/_next/data/%s/%s.json", buildID, trimmed)
	}

	ref, _ := url.Parse(dataPath)
	targetURL := parsed.ResolveReference(ref).String()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build next-data request: %w", err)
	}

	request.Header.Set("User-Agent", utils.DefaultUserAgent)
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch next-data endpoint: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read next-data response: %w", err)
	}

	return map[string]interface{}{
		"url":            response.Request.URL.String(),
		"status":         response.StatusCode,
		"content_type":   response.Header.Get("Content-Type"),
		"body_snippet":   snippet(body, 180),
		"sensitive_keys": stringSliceToInterface(sensitiveKeyHints(string(body))),
	}, nil
}

func detectNextDataFindings(result map[string]interface{}) []models.Finding {
	status, _ := result["status"].(int)
	urlValue, _ := result["url"].(string)
	if status != http.StatusOK {
		return nil
	}

	sensitiveKeys := interfaceSliceToStrings(result["sensitive_keys"])
	findings := make([]models.Finding, 0)
	if len(sensitiveKeys) > 0 {
		findings = append(findings, models.Finding{
			Type:       "next_data_sensitive_props",
			Category:   "nextjs_exposure",
			Title:      "Next.js data endpoint includes sensitive-looking keys",
			Severity:   "medium",
			Confidence: "medium",
			Evidence:   fmt.Sprintf("The Next.js data endpoint at %s returned sensitive-looking keys: %s", urlValue, strings.Join(sensitiveKeys, ", ")),
			Details:    result,
		})
	}

	return findings
}

func probeDevelopmentArtifacts(ctx context.Context, client *http.Client, rootURL string) []artifactProbeResult {
	paths := []string{
		"/_next/static/development/_buildManifest.js",
		"/_next/static/development/_ssgManifest.js",
		"/_next/static/development/_devPagesManifest.json",
		"/_next/development/_devMiddlewareManifest.json",
	}
	results := make([]artifactProbeResult, 0, len(paths))

	for _, path := range paths {
		artifactURL, err := joinPath(rootURL, path)
		if err != nil {
			continue
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifactURL, nil)
		if err != nil {
			continue
		}
		request.Header.Set("User-Agent", utils.DefaultUserAgent)

		response, err := client.Do(request)
		if err != nil {
			results = append(results, artifactProbeResult{Path: path, URL: artifactURL, Evidence: err.Error()})
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 32*1024))
		response.Body.Close()
		if readErr != nil {
			results = append(results, artifactProbeResult{Path: path, URL: artifactURL, StatusCode: response.StatusCode, Evidence: readErr.Error()})
			continue
		}

		exposed, evidence := isDevelopmentArtifact(path, response.StatusCode, string(body))
		results = append(results, artifactProbeResult{
			Path:       path,
			URL:        response.Request.URL.String(),
			StatusCode: response.StatusCode,
			Exposed:    exposed,
			Evidence:   evidence,
		})
	}

	return results
}

func detectDevelopmentArtifactFindings(results []artifactProbeResult) []models.Finding {
	findings := make([]models.Finding, 0)
	for _, result := range results {
		if !result.Exposed {
			continue
		}

		findings = append(findings, models.Finding{
			Type:       "development_artifact_exposed",
			Category:   "nextjs_exposure",
			Title:      "Next.js development artifact is publicly accessible",
			Severity:   "medium",
			Confidence: "high",
			Evidence:   fmt.Sprintf("%s returned a recognizable development artifact", result.URL),
			Details: map[string]interface{}{
				"path":        result.Path,
				"url":         result.URL,
				"status":      result.StatusCode,
				"body_marker": result.Evidence,
			},
		})
	}

	return findings
}

func isDevelopmentArtifact(path string, statusCode int, body string) (bool, string) {
	if statusCode != http.StatusOK {
		return false, ""
	}

	lowerBody := strings.ToLower(body)
	switch {
	case strings.HasSuffix(path, "_buildManifest.js") && strings.Contains(body, "__BUILD_MANIFEST"):
		return true, "__BUILD_MANIFEST"
	case strings.HasSuffix(path, "_ssgManifest.js") && strings.Contains(body, "__SSG_MANIFEST"):
		return true, "__SSG_MANIFEST"
	case strings.HasSuffix(path, "_devPagesManifest.json") && strings.Contains(lowerBody, "pages"):
		return true, "pages"
	case strings.HasSuffix(path, "_devMiddlewareManifest.json") && strings.Contains(lowerBody, "middleware"):
		return true, "middleware"
	default:
		return false, ""
	}
}

func artifactResultsToMetadata(results []artifactProbeResult) []map[string]interface{} {
	metadata := make([]map[string]interface{}, 0, len(results))
	for _, result := range results {
		metadata = append(metadata, map[string]interface{}{
			"path":     result.Path,
			"url":      result.URL,
			"status":   result.StatusCode,
			"exposed":  result.Exposed,
			"evidence": result.Evidence,
		})
	}
	return metadata
}

func sensitiveKeyHints(body string) []string {
	keys := []string{"secret", "token", "password", "apikey", "api_key", "authorization", "credential", "private_key"}
	lowerBody := strings.ToLower(body)
	matches := make([]string, 0)
	for _, key := range keys {
		if strings.Contains(lowerBody, key) {
			matches = append(matches, key)
		}
	}
	return matches
}

func stringSliceToInterface(values []string) []interface{} {
	result := make([]interface{}, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func interfaceSliceToStrings(value interface{}) []string {
	values, ok := value.([]interface{})
	if !ok {
		return nil
	}

	result := make([]string, 0, len(values))
	for _, item := range values {
		if text, ok := item.(string); ok && text != "" {
			result = append(result, text)
		}
	}
	return result
}

func joinPath(rootURL string, path string) (string, error) {
	parsed, err := url.Parse(rootURL)
	if err != nil {
		return "", err
	}

	ref, _ := url.Parse(path)
	return parsed.ResolveReference(ref).String(), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
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

func firstN(values []string, limit int) []string {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return values[:limit]
}

func snippet(body []byte, limit int) string {
	if limit <= 0 || len(body) == 0 {
		return ""
	}
	if len(body) > limit {
		body = body[:limit]
	}
	return strings.TrimSpace(string(body))
}
