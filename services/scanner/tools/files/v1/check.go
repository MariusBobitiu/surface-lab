package v1

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
	"github.com/MariusBobitiu/surface-lab/scanner-service/utils"
)

const fileCheckTimeout = 10 * time.Second

type checkTarget struct {
	Path      string
	Category  string
	Title     string
	Severity  string
	Sensitive bool
}

type fileCheckResult struct {
	target     checkTarget
	url        string
	status     int
	accessible bool
	evidence   string
}

var fileTargets = []checkTarget{
	{Path: "/robots.txt", Category: "public_files", Title: "robots.txt is accessible", Severity: models.SeverityInfo},
	{Path: "/.well-known/security.txt", Category: "public_files", Title: "security.txt is accessible", Severity: models.SeverityInfo},
	{Path: "/sitemap.xml", Category: "public_files", Title: "sitemap.xml is accessible", Severity: models.SeverityInfo},
	{Path: "/.env", Category: "sensitive_file_exposure", Title: ".env is publicly accessible", Severity: models.SeverityHigh, Sensitive: true},
	{Path: "/.git/config", Category: "sensitive_file_exposure", Title: ".git/config is publicly accessible", Severity: models.SeverityHigh, Sensitive: true},
	{Path: "/backup.zip", Category: "sensitive_file_exposure", Title: "backup.zip is publicly accessible", Severity: models.SeverityHigh, Sensitive: true},
}

func Check(ctx context.Context, target string) models.ToolResult {
	startedAt := time.Now()
	result := models.ToolResult{
		Tool:     "files/v1",
		Target:   target,
		Status:   models.StatusFailed,
		Findings: []models.Finding{},
		Metadata: map[string]interface{}{
			"tool_version": "v1",
		},
	}

	baseURL, err := utils.NormalizeBaseURL(target, "https")
	if err != nil || baseURL.Host == "" {
		result.DurationMs = time.Since(startedAt).Milliseconds()
		if err != nil {
			result.Error = fmt.Sprintf("normalize target: %v", err)
		} else {
			result.Error = "normalize target: missing host"
		}
		return result
	}

	result.Target = baseURL.String()
	result.Metadata["final_base_url"] = baseURL.String()
	result.Metadata["checked_paths"] = toInterfaceSlice(pathsToCheck())

	client := utils.NewHTTPClient(fileCheckTimeout)
	statusCodes := map[string]interface{}{}
	accessiblePaths := make([]interface{}, 0, len(fileTargets))

	for _, target := range fileTargets {
		checkResult := checkPath(ctx, client, baseURL, target)
		statusCodes[target.Path] = checkResult.status

		if !checkResult.accessible {
			continue
		}

		accessiblePaths = append(accessiblePaths, target.Path)
		result.Findings = append(result.Findings, findingForResult(checkResult))
	}

	result.Metadata["accessible_paths"] = accessiblePaths
	result.Metadata["status_codes"] = statusCodes
	result.DurationMs = time.Since(startedAt).Milliseconds()
	result.Status = models.StatusSuccess
	return result
}

func checkPath(ctx context.Context, client *http.Client, baseURL *url.URL, target checkTarget) fileCheckResult {
	fullURL := resolvePath(baseURL, target.Path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return fileCheckResult{target: target, url: fullURL}
	}

	req.Header.Set("User-Agent", utils.DefaultUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return fileCheckResult{target: target, url: fullURL}
	}
	defer resp.Body.Close()

	checkResult := fileCheckResult{
		target: target,
		url:    resp.Request.URL.String(),
		status: resp.StatusCode,
	}

	if resp.StatusCode != http.StatusOK {
		return checkResult
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	bodyText := string(body)

	if target.Sensitive {
		checkResult.accessible, checkResult.evidence = detectSensitiveExposure(target.Path, resp, body)
	} else {
		checkResult.accessible = true
		checkResult.evidence = fmt.Sprintf("%s returned HTTP 200", target.Path)
		if looksLikeDirectoryListing(bodyText) {
			checkResult.evidence = fmt.Sprintf("%s returned HTTP 200 and resembles a directory listing", target.Path)
		}
	}

	return checkResult
}

func detectSensitiveExposure(targetPath string, resp *http.Response, body []byte) (bool, string) {
	bodyText := string(body)
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	contentDisposition := strings.ToLower(resp.Header.Get("Content-Disposition"))

	switch targetPath {
	case "/.env":
		if strings.Contains(bodyText, "=") {
			return true, fmt.Sprintf("%s returned HTTP 200 with environment-style key/value content", targetPath)
		}
	case "/.git/config":
		if strings.Contains(bodyText, "[core]") {
			return true, fmt.Sprintf("%s returned HTTP 200 with git config content", targetPath)
		}
	case "/backup.zip":
		if strings.Contains(contentType, "zip") || strings.Contains(contentDisposition, "zip") || strings.HasPrefix(string(body), "PK") {
			return true, fmt.Sprintf("%s returned HTTP 200 with ZIP-like content", targetPath)
		}
	}

	return true, fmt.Sprintf("%s returned HTTP 200", targetPath)
}

func findingForResult(result fileCheckResult) models.Finding {
	findingType := "public_file_accessible"
	if result.target.Sensitive {
		findingType = "sensitive_file_exposure"
	}

	return models.Finding{
		Type:       findingType,
		Category:   result.target.Category,
		Title:      result.target.Title,
		Severity:   result.target.Severity,
		Confidence: models.ConfidenceHigh,
		Evidence:   result.evidence,
		Details: map[string]interface{}{
			"path":         result.target.Path,
			"url":          result.url,
			"status_code":  result.status,
			"tool_version": "v1",
		},
	}
}

func resolvePath(baseURL *url.URL, targetPath string) string {
	resolved := *baseURL
	resolved.Path = path.Clean(targetPath)
	if !strings.HasPrefix(resolved.Path, "/") {
		resolved.Path = "/" + resolved.Path
	}
	return resolved.String()
}

func pathsToCheck() []string {
	paths := make([]string, 0, len(fileTargets))
	for _, target := range fileTargets {
		paths = append(paths, target.Path)
	}
	return paths
}

func toInterfaceSlice(values []string) []interface{} {
	result := make([]interface{}, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func looksLikeDirectoryListing(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "<title>index of") || strings.Contains(lower, "<h1>index of")
}
