package v1

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
	"github.com/MariusBobitiu/surface-lab/scanner-service/utils"
)

const fingerprintTimeout = 10 * time.Second

func Check(ctx context.Context, target string) models.ToolResult {
	startedAt := time.Now()
	result := models.ToolResult{
		Tool:     "fingerprint/v1",
		Target:   target,
		Status:   models.StatusFailed,
		Findings: []models.Finding{},
		Metadata: map[string]interface{}{
			"tool_version": "v1",
		},
	}

	targetURL := utils.NormalizeTarget(target, "https")
	result.Target = targetURL

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		result.DurationMs = time.Since(startedAt).Milliseconds()
		result.Error = fmt.Sprintf("build request: %v", err)
		return result
	}

	req.Header.Set("User-Agent", utils.DefaultUserAgent)

	resp, err := utils.NewHTTPClient(fingerprintTimeout).Do(req)
	if err != nil {
		result.DurationMs = time.Since(startedAt).Milliseconds()
		result.Error = fmt.Sprintf("request target: %v", err)
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	html := string(body)

	result.Metadata["status_code"] = resp.StatusCode
	result.Metadata["final_url"] = resp.Request.URL.String()

	signals := []interface{}{}
	detectedServers := []interface{}{}
	detectedFrameworks := []interface{}{}
	detectedEdge := []interface{}{}
	detectedGenerators := []interface{}{}

	serverHeader := strings.TrimSpace(resp.Header.Get("Server"))
	if serverHeader != "" {
		detectedServers = append(detectedServers, serverHeader)
		signals = append(signals, "server:"+serverHeader)
		result.Findings = append(result.Findings, technologyFinding(
			"fingerprint_server",
			"Detected server technology",
			serverHeader,
			models.ConfidenceHigh,
			fmt.Sprintf("Server header returned %q", serverHeader),
		))
	}

	poweredBy := strings.TrimSpace(resp.Header.Get("X-Powered-By"))
	if poweredBy != "" {
		detectedFrameworks = appendUnique(detectedFrameworks, poweredBy)
		signals = append(signals, "x-powered-by:"+poweredBy)
		result.Findings = append(result.Findings, technologyFinding(
			"fingerprint_framework",
			"Detected framework",
			poweredBy,
			models.ConfidenceHigh,
			fmt.Sprintf("X-Powered-By header returned %q", poweredBy),
		))
	}

	if cfRay := strings.TrimSpace(resp.Header.Get("CF-Ray")); cfRay != "" {
		detectedEdge = appendUnique(detectedEdge, "Cloudflare")
		signals = append(signals, "cf-ray")
		result.Findings = append(result.Findings, technologyFinding(
			"fingerprint_edge",
			"Detected CDN or edge provider",
			"Cloudflare",
			models.ConfidenceHigh,
			"CF-Ray header is present",
		))
	}

	generator := detectGenerator(html)
	if generator != "" {
		detectedGenerators = appendUnique(detectedGenerators, generator)
		signals = append(signals, "meta-generator:"+generator)
		result.Findings = append(result.Findings, technologyFinding(
			"fingerprint_generator",
			"Detected generator or CMS",
			generator,
			models.ConfidenceHigh,
			fmt.Sprintf("meta generator tag indicates %q", generator),
		))
	}

	if containsAnyFold(html, "/_next/", "__next") {
		detectedFrameworks = appendUnique(detectedFrameworks, "Next.js")
		signals = append(signals, "html:_next")
		result.Findings = appendIfMissing(result.Findings, technologyFinding(
			"fingerprint_framework",
			"Detected framework",
			"Next.js",
			models.ConfidenceMedium,
			"HTML contains Next.js asset or container hints",
		))
	}

	if containsAnyFold(html, "/wp-content/", "/wp-includes/") {
		detectedGenerators = appendUnique(detectedGenerators, "WordPress")
		signals = append(signals, "html:wordpress")
		result.Findings = appendIfMissing(result.Findings, technologyFinding(
			"fingerprint_generator",
			"Detected generator or CMS",
			"WordPress",
			models.ConfidenceHigh,
			"HTML contains WordPress asset paths",
		))
	}

	result.Metadata["detected_servers"] = detectedServers
	result.Metadata["detected_frameworks"] = detectedFrameworks
	result.Metadata["detected_edge"] = detectedEdge
	result.Metadata["detected_generators"] = detectedGenerators
	result.Metadata["signals"] = signals
	result.DurationMs = time.Since(startedAt).Milliseconds()
	result.Status = models.StatusSuccess

	return result
}

func technologyFinding(category string, title string, technology string, confidence string, evidence string) models.Finding {
	return models.Finding{
		Type:       "detected_technology",
		Category:   category,
		Title:      title,
		Severity:   models.SeverityInfo,
		Confidence: confidence,
		Evidence:   evidence,
		Details: map[string]interface{}{
			"technology":   technology,
			"tool_version": "v1",
		},
	}
}

func detectGenerator(html string) string {
	lower := strings.ToLower(html)
	marker := `meta name="generator" content="`
	index := strings.Index(lower, marker)
	if index == -1 {
		marker = `meta content="`
		index = strings.Index(lower, marker)
		if index == -1 {
			return ""
		}

		nameIndex := strings.Index(lower[index:], `name="generator"`)
		if nameIndex == -1 {
			return ""
		}
	}

	start := index + len(marker)
	if start >= len(html) {
		return ""
	}

	end := strings.Index(html[start:], `"`)
	if end == -1 {
		return ""
	}

	return strings.TrimSpace(html[start : start+end])
}

func containsAnyFold(value string, needles ...string) bool {
	lower := strings.ToLower(value)
	for _, needle := range needles {
		if strings.Contains(lower, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func appendUnique(values []interface{}, value string) []interface{} {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendIfMissing(findings []models.Finding, candidate models.Finding) []models.Finding {
	for _, finding := range findings {
		if finding.Category == candidate.Category && finding.Details["technology"] == candidate.Details["technology"] {
			return findings
		}
	}
	return append(findings, candidate)
}
