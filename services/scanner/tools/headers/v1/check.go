package v1

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
	"github.com/MariusBobitiu/surface-lab/scanner-service/tools/common"
	"github.com/MariusBobitiu/surface-lab/scanner-service/utils"
)

type headerExpectation struct {
	Name      string
	Severity  string
	SignalKey string
	FindingID string
}

var requiredHeaders = []headerExpectation{
	{Name: "Strict-Transport-Security", Severity: models.SeverityHigh, SignalKey: models.SignalSecurityHSTSPresent, FindingID: "missing-hsts"},
	{Name: "Content-Security-Policy", Severity: models.SeverityHigh, SignalKey: models.SignalSecurityCSPPresent, FindingID: "missing-csp"},
	{Name: "X-Content-Type-Options", Severity: models.SeverityMedium, SignalKey: models.SignalSecurityXContentTypePresent, FindingID: "missing-x-content-type-options"},
	{Name: "X-Frame-Options", Severity: models.SeverityMedium, SignalKey: models.SignalSecurityXFrameOptionsPresent, FindingID: "missing-x-frame-options"},
	{Name: "Referrer-Policy", Severity: models.SeverityLow, SignalKey: models.SignalSecurityReferrerPolicyPresent, FindingID: "missing-referrer-policy"},
}

func Check(ctx context.Context, target string) models.ToolResult {
	startedAt := time.Now()
	result := common.NewToolResult("headers/v1", target, "v1")

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

	headersEvidenceID := common.AddEvidence(&result, "response_headers", resp.Request.URL.String(), map[string]interface{}{
		"status_code": resp.StatusCode,
		"headers":     flattenHeaders(resp.Header),
	})

	result.Metadata["status_code"] = resp.StatusCode
	result.Metadata["final_url"] = resp.Request.URL.String()
	result.Metadata["checked_headers"] = headerNames()

	for _, header := range requiredHeaders {
		present := resp.Header.Get(header.Name) != ""
		common.AddSignal(&result, header.SignalKey, present, models.ConfidenceHigh, "headers.response", headersEvidenceID)

		if present {
			continue
		}

		summary := fmt.Sprintf("The main response is missing the %s security header.", header.Name)
		result.Findings = append(result.Findings, models.Finding{
			Type:         header.FindingID,
			Category:     "http_headers",
			Title:        fmt.Sprintf("%s is missing", header.Name),
			Summary:      summary,
			Severity:     header.Severity,
			Confidence:   models.ConfidenceHigh,
			Evidence:     summary,
			EvidenceRefs: []string{headersEvidenceID},
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

func flattenHeaders(headers http.Header) map[string]interface{} {
	flattened := make(map[string]interface{}, len(headers))
	for name, values := range headers {
		if len(values) == 0 {
			continue
		}

		if len(values) == 1 {
			flattened[name] = values[0]
			continue
		}

		list := make([]interface{}, 0, len(values))
		for _, value := range values {
			list = append(list, value)
		}
		flattened[name] = list
	}
	return flattened
}
