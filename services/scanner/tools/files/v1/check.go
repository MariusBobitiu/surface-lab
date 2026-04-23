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
	"github.com/MariusBobitiu/surface-lab/scanner-service/tools/common"
	"github.com/MariusBobitiu/surface-lab/scanner-service/utils"
)

const fileCheckTimeout = 10 * time.Second

type checkTarget struct {
	Path        string
	Category    string
	Title       string
	Severity    string
	Sensitive   bool
	SignalKey   string
	FindingType string
	EmitFinding bool
}

type fileCheckResult struct {
	target       checkTarget
	url          string
	status       int
	accessible   bool
	evidence     string
	contentType  string
	bodySnippet  string
	bodySHA1     string
	evidenceID   string
	redirectedTo string
}

var fileTargets = []checkTarget{
	{Path: "/robots.txt", Category: "public_files", Title: "robots.txt is accessible", Severity: models.SeverityInfo, SignalKey: models.SignalSurfaceRobotsTxt, FindingType: "public-robots-txt", EmitFinding: true},
	{Path: "/.well-known/security.txt", Category: "public_files", Title: "security.txt is accessible", Severity: models.SeverityInfo, SignalKey: models.SignalSurfaceSecurityTxt, FindingType: "public-security-txt", EmitFinding: true},
	{Path: "/sitemap.xml", Category: "public_files", Title: "sitemap.xml is accessible", Severity: models.SeverityInfo, SignalKey: models.SignalSurfaceSitemapXML, FindingType: "public-sitemap-xml", EmitFinding: true},
	{Path: "/.env", Category: "sensitive_file_exposure", Title: ".env is publicly accessible", Severity: models.SeverityHigh, Sensitive: true, SignalKey: models.SignalExposureEnvFile, FindingType: "public-env-file", EmitFinding: true},
	{Path: "/.git/config", Category: "sensitive_file_exposure", Title: ".git/config is publicly accessible", Severity: models.SeverityHigh, Sensitive: true, SignalKey: models.SignalExposureGitConfig, FindingType: "public-git-config", EmitFinding: true},
	{Path: "/backup.zip", Category: "sensitive_file_exposure", Title: "backup.zip is publicly accessible", Severity: models.SeverityHigh, Sensitive: true, SignalKey: models.SignalExposureBackupArchive, FindingType: "public-backup-archive", EmitFinding: true},
	{Path: "/login", Category: "surface_map", Title: "Login surface detected", Severity: models.SeverityInfo, SignalKey: models.SignalSurfaceLogin, FindingType: "surface-login", EmitFinding: false},
	{Path: "/admin", Category: "surface_map", Title: "Admin surface detected", Severity: models.SeverityInfo, SignalKey: models.SignalSurfaceAdmin, FindingType: "surface-admin", EmitFinding: false},
	{Path: "/api", Category: "surface_map", Title: "API surface detected", Severity: models.SeverityInfo, SignalKey: models.SignalSurfaceAPI, FindingType: "surface-api", EmitFinding: false},
}

func Check(ctx context.Context, target string) models.ToolResult {
	startedAt := time.Now()
	result := common.NewToolResult("files/v1", target, "v1")

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
		checkResult := checkPath(ctx, client, baseURL, target, &result)
		statusCodes[target.Path] = checkResult.status
		common.AddSignal(&result, target.SignalKey, checkResult.accessible, models.ConfidenceHigh, "files.path_probe", checkResult.evidenceID)
		if !checkResult.accessible {
			continue
		}

		accessiblePaths = append(accessiblePaths, target.Path)
		if !target.EmitFinding {
			continue
		}
		result.Findings = append(result.Findings, findingForResult(checkResult))
	}

	result.Metadata["accessible_paths"] = accessiblePaths
	result.Metadata["status_codes"] = statusCodes
	result.DurationMs = time.Since(startedAt).Milliseconds()
	result.Status = models.StatusSuccess
	return result
}

func checkPath(
	ctx context.Context,
	client *http.Client,
	baseURL *url.URL,
	target checkTarget,
	result *models.ToolResult,
) fileCheckResult {
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

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	bodyText := string(body)
	checkResult := fileCheckResult{
		target:      target,
		url:         resp.Request.URL.String(),
		status:      resp.StatusCode,
		contentType: resp.Header.Get("Content-Type"),
		bodySnippet: common.BodySnippet(body, 180),
		bodySHA1:    common.BodySHA1(body),
	}

	checkResult.evidenceID = common.AddEvidence(result, "path_probe", checkResult.url, map[string]interface{}{
		"path":         target.Path,
		"status_code":  resp.StatusCode,
		"content_type": resp.Header.Get("Content-Type"),
		"body_sha1":    checkResult.bodySHA1,
		"body_snippet": checkResult.bodySnippet,
	})

	if resp.StatusCode != http.StatusOK {
		return checkResult
	}

	if target.Sensitive {
		checkResult.accessible, checkResult.evidence = detectSensitiveExposure(target.Path, resp, body)
		return checkResult
	}

	if target.Category == "surface_map" {
		checkResult.accessible = looksLikeSurface(target.Path, resp, bodyText)
		checkResult.evidence = fmt.Sprintf("%s returned HTTP %d", target.Path, resp.StatusCode)
		return checkResult
	}

	checkResult.accessible = true
	checkResult.evidence = fmt.Sprintf("%s returned HTTP 200", target.Path)
	if looksLikeDirectoryListing(bodyText) {
		checkResult.evidence = fmt.Sprintf("%s returned HTTP 200 and resembles a directory listing", target.Path)
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
	return models.Finding{
		Type:         result.target.FindingType,
		Category:     result.target.Category,
		Title:        result.target.Title,
		Summary:      result.evidence,
		Severity:     result.target.Severity,
		Confidence:   models.ConfidenceHigh,
		Evidence:     result.evidence,
		EvidenceRefs: []string{result.evidenceID},
		Details: map[string]interface{}{
			"path":         result.target.Path,
			"url":          result.url,
			"status_code":  result.status,
			"content_type": result.contentType,
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

func looksLikeSurface(targetPath string, resp *http.Response, body string) bool {
	if resp.StatusCode != http.StatusOK {
		return false
	}

	lower := strings.ToLower(body)
	switch targetPath {
	case "/login":
		return strings.Contains(lower, "login") || strings.Contains(lower, "sign in")
	case "/admin":
		return strings.Contains(lower, "admin") || strings.Contains(lower, "dashboard")
	case "/api":
		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		return strings.Contains(contentType, "json") || strings.Contains(lower, "api")
	default:
		return false
	}
}
