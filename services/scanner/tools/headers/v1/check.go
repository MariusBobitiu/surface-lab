package v1

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
	"github.com/MariusBobitiu/surface-lab/scanner-service/utils"
)

var requiredHeaders = []struct {
	Name     string
	Severity string
}{
	{Name: "Strict-Transport-Security", Severity: models.SeverityHigh},
	{Name: "Content-Security-Policy", Severity: models.SeverityHigh},
	{Name: "X-Content-Type-Options", Severity: models.SeverityMedium},
	{Name: "X-Frame-Options", Severity: models.SeverityMedium},
	{Name: "Referrer-Policy", Severity: models.SeverityLow},
}

func Check(ctx context.Context, target string) models.ToolResult {
	startedAt := time.Now()
	result := models.ToolResult{
		Tool:     "headers/v1",
		Target:   target,
		Status:   models.StatusFailed,
		Findings: []models.Finding{},
		Metadata: map[string]interface{}{
			"tool_version": "v1",
		},
	}

	normalizedTarget := utils.NormalizeTarget(target, "https")
	result.Target = normalizedTarget

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedTarget, nil)
	if err != nil {
		result.DurationMs = time.Since(startedAt).Milliseconds()
		result.Error = fmt.Sprintf("build request: %v", err)
		return result
	}

	req.Header.Set("User-Agent", utils.DefaultUserAgent)

	client := utils.NewHTTPClient(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		result.DurationMs = time.Since(startedAt).Milliseconds()
		result.Error = fmt.Sprintf("request target: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.Metadata["status_code"] = resp.StatusCode
	result.Metadata["final_url"] = resp.Request.URL.String()
	result.Metadata["checked_headers"] = headerNames()
	result.Metadata["present_headers"] = presentHeaders(resp.Header)

	for _, header := range requiredHeaders {
		if resp.Header.Get(header.Name) != "" {
			continue
		}

		result.Findings = append(result.Findings, models.Finding{
			Type:       "missing_header",
			Category:   "http_headers",
			Title:      fmt.Sprintf("%s is missing", header.Name),
			Severity:   header.Severity,
			Confidence: models.ConfidenceHigh,
			Evidence:   fmt.Sprintf("response did not include %s", header.Name),
			Details: map[string]interface{}{
				"header":       header.Name,
				"tool_version": "v1",
			},
		})
	}

	result.DurationMs = time.Since(startedAt).Milliseconds()
	result.Status = models.StatusSuccess
	return result
}

func headerNames() []interface{} {
	names := make([]interface{}, 0, len(requiredHeaders))
	for _, header := range requiredHeaders {
		names = append(names, header.Name)
	}

	return names
}

func presentHeaders(headers http.Header) []interface{} {
	names := make([]interface{}, 0, len(headers))
	for name, values := range headers {
		if len(values) == 0 {
			continue
		}

		names = append(names, name)
	}

	return names
}
