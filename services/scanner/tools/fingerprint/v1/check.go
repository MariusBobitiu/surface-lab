package v1

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
	"github.com/MariusBobitiu/surface-lab/scanner-service/tools/common"
	"github.com/MariusBobitiu/surface-lab/scanner-service/utils"
)

const fingerprintTimeout = 10 * time.Second

var versionPattern = regexp.MustCompile(`(?i)\b\d+(?:\.\d+){1,3}\b`)

func Check(ctx context.Context, target string) models.ToolResult {
	startedAt := time.Now()
	result := common.NewToolResult("fingerprint/v1", target, "v1")

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

	headersEvidenceID := common.AddEvidence(&result, "response_headers", resp.Request.URL.String(), map[string]interface{}{
		"status_code": resp.StatusCode,
		"headers": common.HeaderSnapshot(
			resp.Header,
			"Server",
			"X-Powered-By",
			"CF-Ray",
			"X-Vercel-Id",
		),
	})

	generator := detectGenerator(html)
	if generator != "" {
		generatorEvidenceID := common.AddEvidence(&result, "meta_generator", resp.Request.URL.String(), map[string]interface{}{
			"generator": generator,
		})
		result.Findings = append(result.Findings, disclosureFinding(
			"generator-disclosure",
			"information_disclosure",
			"Generator disclosure detected",
			fmt.Sprintf("The application discloses %q via a generator marker.", generator),
			models.SeverityInfo,
			models.ConfidenceHigh,
			[]string{generatorEvidenceID},
			map[string]interface{}{"generator": generator},
		))
	}

	scriptURLs := extractScriptURLs(html)
	htmlMarkers := detectHTMLMarkers(html)
	htmlEvidenceID := common.AddEvidence(&result, "html_markers", resp.Request.URL.String(), map[string]interface{}{
		"body_sha1":    common.BodySHA1(body),
		"body_snippet": common.BodySnippet(body, 240),
		"script_urls":  scriptURLs,
		"markers":      htmlMarkers,
	})

	serverHeader := strings.TrimSpace(resp.Header.Get("Server"))
	common.AddSignal(&result, models.SignalHeaderServerPresent, serverHeader != "", models.ConfidenceHigh, "fingerprint.headers", headersEvidenceID)
	cloudflareDetected := false
	vercelDetected := false
	if serverHeader != "" {
		if strings.Contains(strings.ToLower(serverHeader), "cloudflare") {
			cloudflareDetected = true
		}
		if strings.Contains(strings.ToLower(serverHeader), "vercel") {
			vercelDetected = true
		}
		result.Findings = append(result.Findings, disclosureFinding(
			"exposed-tech-header",
			"information_disclosure",
			"Server header discloses stack details",
			fmt.Sprintf("The response exposes the server header value %q.", serverHeader),
			models.SeverityInfo,
			models.ConfidenceHigh,
			[]string{headersEvidenceID},
			map[string]interface{}{"header": "Server", "value": serverHeader},
		))
		if containsVersion(serverHeader) {
			result.Findings = append(result.Findings, disclosureFinding(
				"version-disclosure",
				"information_disclosure",
				"Version disclosure detected in Server header",
				fmt.Sprintf("The server header appears to expose a version string: %q.", serverHeader),
				models.SeverityLow,
				models.ConfidenceMedium,
				[]string{headersEvidenceID},
				map[string]interface{}{"header": "Server", "value": serverHeader},
			))
		}
	}

	poweredBy := strings.TrimSpace(resp.Header.Get("X-Powered-By"))
	common.AddSignal(&result, models.SignalHeaderXPoweredByPresent, poweredBy != "", models.ConfidenceHigh, "fingerprint.headers", headersEvidenceID)
	if poweredBy != "" {
		result.Findings = append(result.Findings, disclosureFinding(
			"exposed-tech-header",
			"information_disclosure",
			"X-Powered-By header discloses stack details",
			fmt.Sprintf("The response exposes the X-Powered-By value %q.", poweredBy),
			models.SeverityInfo,
			models.ConfidenceHigh,
			[]string{headersEvidenceID},
			map[string]interface{}{"header": "X-Powered-By", "value": poweredBy},
		))
		if containsVersion(poweredBy) {
			result.Findings = append(result.Findings, disclosureFinding(
				"version-disclosure",
				"information_disclosure",
				"Version disclosure detected in X-Powered-By header",
				fmt.Sprintf("The X-Powered-By header appears to expose a version string: %q.", poweredBy),
				models.SeverityLow,
				models.ConfidenceMedium,
				[]string{headersEvidenceID},
				map[string]interface{}{"header": "X-Powered-By", "value": poweredBy},
			))
		}
	}

	if strings.TrimSpace(resp.Header.Get("CF-Ray")) != "" {
		cloudflareDetected = true
	}

	if strings.TrimSpace(resp.Header.Get("X-Vercel-Id")) != "" {
		vercelDetected = true
	}
	common.AddSignal(&result, models.SignalHostingCloudflare, cloudflareDetected, models.ConfidenceHigh, "fingerprint.headers", headersEvidenceID)
	common.AddSignal(&result, models.SignalHostingVercel, vercelDetected, models.ConfidenceHigh, "fingerprint.headers", headersEvidenceID)

	hasJSBundles := len(scriptURLs) > 0
	common.AddSignal(&result, models.SignalAssetsJSBundle, hasJSBundles, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)

	hasNextAssets := htmlMarkers["next_static"] == true
	common.AddSignal(&result, models.SignalAssetsNextStatic, hasNextAssets, models.ConfidenceHigh, "fingerprint.html", htmlEvidenceID)
	nextDetected := hasNextAssets || strings.EqualFold(poweredBy, "Next.js")
	common.AddSignal(&result, models.SignalFrameworkNextJS, nextDetected, models.ConfidenceHigh, "fingerprint.combined", htmlEvidenceID, headersEvidenceID)

	wordpressDetected := htmlMarkers["wordpress"] == true || strings.Contains(strings.ToLower(generator), "wordpress")
	common.AddSignal(&result, models.SignalFrameworkWordPress, wordpressDetected, models.ConfidenceHigh, "fingerprint.html", htmlEvidenceID)

	result.Metadata["status_code"] = resp.StatusCode
	result.Metadata["final_url"] = resp.Request.URL.String()
	result.Metadata["script_url_count"] = len(scriptURLs)
	result.Metadata["markers"] = htmlMarkers
	result.DurationMs = time.Since(startedAt).Milliseconds()
	result.Status = models.StatusSuccess

	return result
}

func disclosureFinding(
	findingType string,
	category string,
	title string,
	summary string,
	severity string,
	confidence string,
	evidenceRefs []string,
	details map[string]interface{},
) models.Finding {
	return models.Finding{
		Type:         findingType,
		Category:     category,
		Title:        title,
		Summary:      summary,
		Severity:     severity,
		Confidence:   confidence,
		Evidence:     summary,
		EvidenceRefs: evidenceRefs,
		Details:      details,
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
		if strings.Index(lower[index:], `name="generator"`) == -1 {
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

func extractScriptURLs(html string) []interface{} {
	results := make([]interface{}, 0, 4)
	lower := strings.ToLower(html)
	search := `script src="`
	offset := 0
	for len(results) < 6 {
		index := strings.Index(lower[offset:], search)
		if index == -1 {
			break
		}
		start := offset + index + len(search)
		end := strings.Index(html[start:], `"`)
		if end == -1 {
			break
		}
		results = append(results, strings.TrimSpace(html[start:start+end]))
		offset = start + end
	}
	return results
}

func detectHTMLMarkers(html string) map[string]interface{} {
	lower := strings.ToLower(html)
	return map[string]interface{}{
		"next_static": strings.Contains(lower, "/_next/static/") || strings.Contains(lower, "__next"),
		"wordpress":   strings.Contains(lower, "/wp-content/") || strings.Contains(lower, "/wp-includes/"),
	}
}

func containsVersion(value string) bool {
	return versionPattern.MatchString(value)
}
