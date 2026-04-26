package execute

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/MariusBobitiu/surface-lab/php-stack/models"
	"github.com/MariusBobitiu/surface-lab/php-stack/utils"
)

const (
	toolName     = "php.v1.verify_stack"
	httpTimeout  = 8 * time.Second
	maxBodyBytes = 128 * 1024
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
	Method      string
	StatusCode  int
	ContentType string
	Body        string
	ReadBytes   int
	Headers     http.Header
	Err         error
}

type specialistContext struct {
	matchedSignals        []string
	baselineSignals       []map[string]interface{}
	baselineFindings      []map[string]interface{}
	technologySummary     map[string]interface{}
	vulnerabilityResearch []map[string]interface{}
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

	client := utils.NewHTTPClientNoRedirect(httpTimeout)
	context := parseSpecialistContext(input)
	outcomes := make([]checkOutcome, 0, 7)
	findings := make([]models.Finding, 0, 7)
	confirmedSignals := make([]string, 0, 7)

	appendResult := func(outcome checkOutcome, finding *models.Finding) {
		outcomes = append(outcomes, outcome)
		if outcome.Status == statusConfirmed && outcome.Signal != "" {
			confirmedSignals = append(confirmedSignals, outcome.Signal)
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	appendResult(checkPHPInfo(ctx, client, rootURL))
	appendResult(checkConfigExposure(ctx, client, rootURL))
	appendResult(checkSQLDumpExposure(ctx, client, rootURL))
	appendResult(checkBackupArchiveExposure(ctx, client, rootURL))
	appendResult(checkHtaccessExposure(ctx, client, rootURL))
	appendResult(checkUserINIExposure(ctx, client, rootURL))
	appendResult(checkPHPVersionDisclosure(ctx, client, rootURL, input))

	metadata := map[string]interface{}{
		"request_metadata": input,
		"context": map[string]interface{}{
			"matched_signals":                context.matchedSignals,
			"baseline_signal_count":          len(context.baselineSignals),
			"baseline_finding_count":         len(context.baselineFindings),
			"vulnerability_research_queries": len(context.vulnerabilityResearch),
		},
		"checks":  outcomesToMetadata(outcomes),
		"signals": confirmedSignals,
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

func checkPHPInfo(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	outcome := checkOutcome{CheckID: "exposed-phpinfo", Signal: "verification.php.phpinfo.confirmed"}
	paths := []string{"/phpinfo.php", "/info.php", "/test.php"}
	probes, confirmed := probeForIndicators(ctx, client, rootURL, paths, []string{"PHP Version", "phpinfo()", "Loaded Configuration File", "phpinfo"}, 64*1024)
	if confirmed != nil {
		evidence := map[string]interface{}{
			"path":         confirmed.Path,
			"url":          confirmed.URL,
			"status_code":  confirmed.StatusCode,
			"content_type": confirmed.ContentType,
			"snippet":      snippet(redactSecrets(confirmed.Body), 220),
			"probes":       probesToMetadata(probes),
		}
		severity := "medium"
		if strings.Contains(strings.ToLower(confirmed.Body), "loaded configuration file") {
			severity = "high"
		}
		outcome.Status = statusConfirmed
		outcome.Summary = "Public phpinfo endpoint exposure confirmed"
		outcome.Severity = severity
		outcome.Evidence = evidence
		finding := models.Finding{Type: "exposed-phpinfo", Category: "php_exposure", Title: "Public phpinfo endpoint is accessible", Severity: severity, Confidence: "high", Evidence: fmt.Sprintf("%s returned phpinfo markers", confirmed.Path), Details: map[string]interface{}{"check_status": statusConfirmed, "signal": outcome.Signal, "evidence": evidence}}
		return outcome, &finding
	}

	if allProbesErrored(probes) {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify phpinfo endpoint exposure"
		outcome.Error = "all phpinfo probes failed"
		outcome.Evidence = map[string]interface{}{"probes": probesToMetadata(probes)}
		return outcome, nil
	}

	outcome.Status = statusNotObserved
	outcome.Summary = "No exposed phpinfo endpoint observed"
	outcome.Evidence = map[string]interface{}{"probes": probesToMetadata(probes)}
	return outcome, nil
}

func checkConfigExposure(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	outcome := checkOutcome{CheckID: "exposed-config-file", Signal: "verification.php.config.confirmed"}
	paths := []string{"/config.php", "/config.bak", "/config.old"}
	probes, confirmed := probeForIndicators(ctx, client, rootURL, paths, []string{"DB_PASSWORD", "DB_USER", "DB_HOST", "$db", "mysqli_connect", "PDO", "database"}, 64*1024)
	if confirmed != nil {
		evidence := map[string]interface{}{
			"path":         confirmed.Path,
			"url":          confirmed.URL,
			"status_code":  confirmed.StatusCode,
			"content_type": confirmed.ContentType,
			"snippet":      snippet(redactSecrets(confirmed.Body), 220),
			"probes":       probesToMetadata(probes),
		}
		outcome.Status = statusConfirmed
		outcome.Summary = "Public PHP config file exposure confirmed"
		outcome.Severity = "high"
		outcome.Evidence = evidence
		finding := models.Finding{Type: "exposed-config-file", Category: "php_exposure", Title: "Potential PHP config file exposure", Severity: "high", Confidence: "high", Evidence: fmt.Sprintf("%s returned config-style markers", confirmed.Path), Details: map[string]interface{}{"check_status": statusConfirmed, "signal": outcome.Signal, "evidence": evidence}}
		return outcome, &finding
	}

	if allProbesErrored(probes) {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify config file exposure"
		outcome.Error = "all config probes failed"
		outcome.Evidence = map[string]interface{}{"probes": probesToMetadata(probes)}
		return outcome, nil
	}

	outcome.Status = statusNotObserved
	outcome.Summary = "No exposed config file was observed"
	outcome.Evidence = map[string]interface{}{"probes": probesToMetadata(probes)}
	return outcome, nil
}

func checkSQLDumpExposure(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	outcome := checkOutcome{CheckID: "exposed-sql-dump", Signal: "verification.php.sql_dump.confirmed"}
	paths := []string{"/database.sql", "/db.sql"}
	probes, confirmed := probeForIndicators(ctx, client, rootURL, paths, []string{"CREATE TABLE", "INSERT INTO", "phpMyAdmin SQL Dump", "-- MySQL dump"}, 64*1024)
	if confirmed != nil {
		hash := sha256.Sum256([]byte(confirmed.Body))
		evidence := map[string]interface{}{
			"path":           confirmed.Path,
			"url":            confirmed.URL,
			"status_code":    confirmed.StatusCode,
			"content_type":   confirmed.ContentType,
			"content_length": confirmed.ReadBytes,
			"snippet":        snippet(redactSecrets(confirmed.Body), 160),
			"body_sha256":    hex.EncodeToString(hash[:]),
			"probes":         probesToMetadata(probes),
		}
		outcome.Status = statusConfirmed
		outcome.Summary = "Public SQL dump exposure confirmed"
		outcome.Severity = "high"
		outcome.Evidence = evidence
		finding := models.Finding{Type: "exposed-sql-dump", Category: "php_exposure", Title: "SQL dump appears publicly accessible", Severity: "high", Confidence: "high", Evidence: fmt.Sprintf("%s returned SQL dump markers", confirmed.Path), Details: map[string]interface{}{"check_status": statusConfirmed, "signal": outcome.Signal, "evidence": evidence}}
		return outcome, &finding
	}

	if allProbesErrored(probes) {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify SQL dump exposure"
		outcome.Error = "all SQL dump probes failed"
		outcome.Evidence = map[string]interface{}{"probes": probesToMetadata(probes)}
		return outcome, nil
	}

	outcome.Status = statusNotObserved
	outcome.Summary = "No exposed SQL dump observed"
	outcome.Evidence = map[string]interface{}{"probes": probesToMetadata(probes)}
	return outcome, nil
}

func checkBackupArchiveExposure(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	outcome := checkOutcome{CheckID: "exposed-backup-archive", Signal: "verification.php.backup.confirmed"}
	paths := []string{"/backup.zip", "/backup.tar.gz"}
	probes := make([]probeResult, 0)

	for _, path := range paths {
		headProbe := probePath(ctx, client, rootURL, path, http.MethodHead, 0, "")
		probes = append(probes, headProbe)
		if headProbe.Err == nil && isArchiveResponse(headProbe, nil) {
			evidence := map[string]interface{}{
				"path":                headProbe.Path,
				"url":                 headProbe.URL,
				"status_code":         headProbe.StatusCode,
				"content_type":        headProbe.ContentType,
				"content_disposition": headProbe.Headers.Get("Content-Disposition"),
				"probes":              probesToMetadata(probes),
			}
			outcome.Status = statusConfirmed
			outcome.Summary = "Public backup archive exposure confirmed"
			outcome.Severity = "high"
			outcome.Evidence = evidence
			finding := models.Finding{Type: "exposed-backup-archive", Category: "php_exposure", Title: "Backup archive appears publicly accessible", Severity: "high", Confidence: "high", Evidence: fmt.Sprintf("%s returned archive-like headers", headProbe.Path), Details: map[string]interface{}{"check_status": statusConfirmed, "signal": outcome.Signal, "evidence": evidence}}
			return outcome, &finding
		}

		getProbe := probePath(ctx, client, rootURL, path, http.MethodGet, 1024, "bytes=0-1023")
		probes = append(probes, getProbe)
		if getProbe.Err == nil && isArchiveResponse(getProbe, []byte(getProbe.Body)) {
			evidence := map[string]interface{}{
				"path":         getProbe.Path,
				"url":          getProbe.URL,
				"status_code":  getProbe.StatusCode,
				"content_type": getProbe.ContentType,
				"magic_hex":    hex.EncodeToString([]byte(getProbe.Body)[:min(len(getProbe.Body), 8)]),
				"probes":       probesToMetadata(probes),
			}
			outcome.Status = statusConfirmed
			outcome.Summary = "Public backup archive exposure confirmed"
			outcome.Severity = "high"
			outcome.Evidence = evidence
			finding := models.Finding{Type: "exposed-backup-archive", Category: "php_exposure", Title: "Backup archive appears publicly accessible", Severity: "high", Confidence: "medium", Evidence: fmt.Sprintf("%s returned archive signature markers", getProbe.Path), Details: map[string]interface{}{"check_status": statusConfirmed, "signal": outcome.Signal, "evidence": evidence}}
			return outcome, &finding
		}
	}

	if allProbesErrored(probes) {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify backup archive exposure"
		outcome.Error = "all archive probes failed"
		outcome.Evidence = map[string]interface{}{"probes": probesToMetadata(probes)}
		return outcome, nil
	}

	outcome.Status = statusNotObserved
	outcome.Summary = "No exposed backup archive observed"
	outcome.Evidence = map[string]interface{}{"probes": probesToMetadata(probes)}
	return outcome, nil
}

func checkHtaccessExposure(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	return checkSingleFileExposure(ctx, client, rootURL, "/.htaccess", "exposed-htaccess", "verification.php.htaccess.confirmed", "php_exposure", "Apache .htaccess appears publicly accessible", "medium", []string{"RewriteEngine", "Require all", "DirectoryIndex", "AuthType", "FilesMatch"})
}

func checkUserINIExposure(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	return checkSingleFileExposure(ctx, client, rootURL, "/.user.ini", "exposed-user-ini", "verification.php.user_ini.confirmed", "php_exposure", "PHP .user.ini appears publicly accessible", "medium", []string{"auto_prepend_file", "upload_max_filesize", "display_errors", "memory_limit"})
}

func checkPHPVersionDisclosure(ctx context.Context, client *http.Client, rootURL string, input map[string]interface{}) (checkOutcome, *models.Finding) {
	outcome := checkOutcome{CheckID: "php-version-disclosure", Signal: "verification.php.version_disclosure.confirmed"}
	probe := probePath(ctx, client, rootURL, "/", http.MethodGet, 48*1024, "")
	if probe.Err != nil {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify PHP version disclosure"
		outcome.Error = probe.Err.Error()
		return outcome, nil
	}

	xPoweredBy := strings.TrimSpace(probe.Headers.Get("X-Powered-By"))
	server := strings.TrimSpace(probe.Headers.Get("Server"))
	baselineVersion := findPHPVersionInBaseline(input)
	isDisclosed := strings.Contains(strings.ToLower(xPoweredBy), "php") || strings.Contains(strings.ToLower(server), "php") || baselineVersion != ""

	evidence := map[string]interface{}{
		"url":              probe.URL,
		"status_code":      probe.StatusCode,
		"x_powered_by":     xPoweredBy,
		"server_header":    server,
		"baseline_version": baselineVersion,
	}
	if !isDisclosed {
		outcome.Status = statusNotObserved
		outcome.Summary = "No PHP version disclosure markers observed"
		outcome.Evidence = evidence
		return outcome, nil
	}

	severity := "info"
	if baselineVersion != "" {
		severity = "low"
	}
	outcome.Status = statusConfirmed
	outcome.Summary = "PHP version disclosure markers were observed"
	outcome.Severity = severity
	outcome.Evidence = evidence
	finding := models.Finding{
		Type:       "php-version-disclosure",
		Category:   "php_posture",
		Title:      "PHP version or runtime header disclosure detected",
		Severity:   severity,
		Confidence: "medium",
		Evidence:   "Response headers or baseline context disclosed PHP runtime details",
		Details: map[string]interface{}{
			"check_status": statusConfirmed,
			"signal":       outcome.Signal,
			"evidence":     evidence,
		},
	}
	return outcome, &finding
}

func checkSingleFileExposure(
	ctx context.Context,
	client *http.Client,
	rootURL string,
	path string,
	checkID string,
	signal string,
	category string,
	title string,
	severity string,
	markers []string,
) (checkOutcome, *models.Finding) {
	outcome := checkOutcome{CheckID: checkID, Signal: signal}
	probe := probePath(ctx, client, rootURL, path, http.MethodGet, 48*1024, "")
	if probe.Err != nil {
		outcome.Status = statusInconclusive
		outcome.Summary = fmt.Sprintf("Could not verify %s exposure", path)
		outcome.Error = probe.Err.Error()
		return outcome, nil
	}
	matched := matchIndicators(probe.Body, markers)
	evidence := map[string]interface{}{"path": probe.Path, "url": probe.URL, "status_code": probe.StatusCode, "content_type": probe.ContentType, "matched_markers": matched, "snippet": snippet(redactSecrets(probe.Body), 220)}
	if probe.StatusCode == http.StatusOK && len(matched) > 0 {
		outcome.Status = statusConfirmed
		outcome.Summary = fmt.Sprintf("Public %s exposure confirmed", path)
		outcome.Severity = severity
		outcome.Evidence = evidence
		finding := models.Finding{Type: checkID, Category: category, Title: title, Severity: severity, Confidence: "high", Evidence: fmt.Sprintf("%s returned marker content", path), Details: map[string]interface{}{"check_status": statusConfirmed, "signal": signal, "evidence": evidence}}
		return outcome, &finding
	}
	outcome.Status = statusNotObserved
	outcome.Summary = fmt.Sprintf("No exposed %s content observed", path)
	outcome.Evidence = evidence
	return outcome, nil
}

func probeForIndicators(ctx context.Context, client *http.Client, rootURL string, paths []string, indicators []string, maxRead int64) ([]probeResult, *probeResult) {
	probes := make([]probeResult, 0, len(paths))
	for _, path := range paths {
		probe := probePath(ctx, client, rootURL, path, http.MethodGet, maxRead, "")
		probes = append(probes, probe)
		if probe.Err != nil || probe.StatusCode != http.StatusOK {
			continue
		}
		if len(matchIndicators(probe.Body, indicators)) > 0 {
			confirmed := probe
			return probes, &confirmed
		}
	}
	return probes, nil
}

func probePath(ctx context.Context, client *http.Client, rootURL string, path string, method string, maxRead int64, rangeHeader string) probeResult {
	result := probeResult{Path: path, Method: method}
	targetURL, err := joinPath(rootURL, path)
	if err != nil {
		result.Err = err
		return result
	}
	result.URL = targetURL

	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		result.Err = err
		return result
	}
	req.Header.Set("User-Agent", utils.DefaultUserAgent)
	req.Header.Set("Accept", "*/*")
	if strings.TrimSpace(rangeHeader) != "" {
		req.Header.Set("Range", rangeHeader)
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Err = err
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ContentType = strings.TrimSpace(resp.Header.Get("Content-Type"))
	result.Headers = resp.Header.Clone()
	if strings.EqualFold(method, http.MethodHead) {
		return result
	}

	if maxRead <= 0 {
		maxRead = maxBodyBytes
	}
	bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	if readErr != nil {
		result.Err = readErr
		return result
	}
	result.ReadBytes = len(bodyBytes)
	result.Body = string(bodyBytes)
	return result
}

func isArchiveResponse(probe probeResult, body []byte) bool {
	if probe.StatusCode != http.StatusOK && probe.StatusCode != http.StatusPartialContent {
		return false
	}
	lowerCT := strings.ToLower(probe.ContentType)
	lowerCD := strings.ToLower(probe.Headers.Get("Content-Disposition"))
	if strings.Contains(lowerCT, "zip") || strings.Contains(lowerCT, "gzip") || strings.Contains(lowerCT, "x-tar") {
		return true
	}
	if strings.Contains(lowerCD, ".zip") || strings.Contains(lowerCD, ".tar.gz") || strings.Contains(lowerCD, ".tgz") {
		return true
	}
	if len(body) >= 4 {
		if body[0] == 'P' && body[1] == 'K' && body[2] == 0x03 && body[3] == 0x04 {
			return true
		}
	}
	if len(body) >= 2 {
		if body[0] == 0x1f && body[1] == 0x8b {
			return true
		}
	}
	return false
}

func allProbesErrored(probes []probeResult) bool {
	if len(probes) == 0 {
		return true
	}
	for _, probe := range probes {
		if probe.Err == nil {
			return false
		}
	}
	return true
}

func findPHPVersionInBaseline(input map[string]interface{}) string {
	rawSignals, ok := input["baseline_signals"].([]interface{})
	if !ok {
		return ""
	}
	for _, raw := range rawSignals {
		signal, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		key, _ := signal["key"].(string)
		if !strings.Contains(strings.ToLower(key), "php") || !strings.Contains(strings.ToLower(key), "version") {
			continue
		}
		if value, ok := signal["value"].(string); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func redactSecrets(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	lines := strings.Split(strings.ReplaceAll(value, "\r", ""), "\n")
	for i, line := range lines {
		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			if strings.Contains(key, "password") || strings.Contains(key, "secret") || strings.Contains(key, "token") || strings.Contains(key, "key") {
				lines[i] = parts[0] + "=[REDACTED]"
			}
		}
	}
	return strings.Join(lines, "\n")
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

func probesToMetadata(probes []probeResult) []map[string]interface{} {
	items := make([]map[string]interface{}, 0, len(probes))
	for _, probe := range probes {
		items = append(items, map[string]interface{}{
			"path":         probe.Path,
			"url":          probe.URL,
			"method":       probe.Method,
			"status_code":  probe.StatusCode,
			"content_type": probe.ContentType,
			"read_bytes":   probe.ReadBytes,
			"error":        errorString(probe.Err),
		})
	}
	return items
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
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

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
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
