package execute

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/MariusBobitiu/surface-lab/laravel-stack/models"
	"github.com/MariusBobitiu/surface-lab/laravel-stack/utils"
)

const (
	toolName     = "laravel.v1.verify_stack"
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
	Err         error
}

type specialistContext struct {
	matchedSignals        []string
	baselineSignals       []map[string]interface{}
	baselineFindings      []map[string]interface{}
	technologySummary     map[string]interface{}
	vulnerabilityResearch []map[string]interface{}
}

var (
	envKeyPattern         = regexp.MustCompile(`(?m)^\s*([A-Z0-9_]{3,})\s*=`)
	secretKVPattern       = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|app_key|db_password|mail_password)\s*[:=]\s*([^\s]+)`)
	pathDisclosurePattern = regexp.MustCompile(`(?i)(/var/www|/home/[^\s]+|\\\\www\\\\|\.env|bootstrap/cache|storage/logs)`)
)

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
	outcomes := make([]checkOutcome, 0, 6)
	findings := make([]models.Finding, 0, 6)
	confirmedSignals := make([]string, 0, 6)

	appendResult := func(outcome checkOutcome, finding *models.Finding) {
		outcomes = append(outcomes, outcome)
		if outcome.Status == statusConfirmed && outcome.Signal != "" {
			confirmedSignals = append(confirmedSignals, outcome.Signal)
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	appendResult(checkPublicEnv(ctx, client, rootURL))
	appendResult(checkLaravelLogs(ctx, client, rootURL))
	appendResult(checkComposerInstalled(ctx, client, rootURL))
	appendResult(checkDebugbar(ctx, client, rootURL))
	appendResult(checkIgnition(ctx, client, rootURL))
	appendResult(checkDebugDisclosure(ctx, client, rootURL))

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

func checkPublicEnv(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	probe := probePath(ctx, client, rootURL, "/.env", http.MethodGet, 48*1024)
	outcome := checkOutcome{
		CheckID: "public-laravel-env",
		Signal:  "verification.laravel.env.confirmed",
	}

	if probe.Err != nil {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify /.env exposure"
		outcome.Error = probe.Err.Error()
		return outcome, nil
	}

	matched := matchIndicators(probe.Body, []string{"APP_KEY=", "APP_ENV=", "DB_HOST=", "DB_DATABASE=", "MAIL_HOST="})
	evidence := map[string]interface{}{
		"url":          probe.URL,
		"status_code":  probe.StatusCode,
		"content_type": probe.ContentType,
		"matched_keys": matched,
		"snippet":      snippet(probe.Body, 220),
	}
	if probe.StatusCode == http.StatusOK && len(matched) >= 2 {
		outcome.Status = statusConfirmed
		outcome.Summary = "Public Laravel .env exposure confirmed"
		outcome.Severity = "high"
		outcome.Evidence = evidence
		finding := models.Finding{
			Type:       "public-laravel-env",
			Category:   "laravel_exposure",
			Title:      "Public Laravel environment file exposure",
			Severity:   "high",
			Confidence: "high",
			Evidence:   fmt.Sprintf("%s returned %d with Laravel env keys: %s", probe.Path, probe.StatusCode, strings.Join(matched, ", ")),
			Details: map[string]interface{}{
				"check_status": statusConfirmed,
				"signal":       outcome.Signal,
				"evidence":     evidence,
			},
		}
		return outcome, &finding
	}

	outcome.Status = statusNotObserved
	outcome.Summary = "No publicly exposed Laravel .env content was observed"
	outcome.Evidence = evidence
	return outcome, nil
}

func checkLaravelLogs(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	probe := probePath(ctx, client, rootURL, "/storage/logs/laravel.log", http.MethodGet, 64*1024)
	outcome := checkOutcome{
		CheckID: "public-laravel-log",
		Signal:  "verification.laravel.logs.confirmed",
	}
	if probe.Err != nil {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify Laravel log exposure"
		outcome.Error = probe.Err.Error()
		return outcome, nil
	}

	matched := matchIndicators(probe.Body, []string{"local.ERROR", "production.ERROR", "Illuminate\\", "Stack trace", "Next Illuminate"})
	evidence := map[string]interface{}{
		"url":             probe.URL,
		"status_code":     probe.StatusCode,
		"content_type":    probe.ContentType,
		"matched_markers": matched,
		"snippet":         snippet(probe.Body, 220),
	}
	if probe.StatusCode == http.StatusOK && len(matched) > 0 {
		severity := "medium"
		if containsAny(matched, []string{"local.ERROR", "production.ERROR", "Illuminate\\"}) {
			severity = "high"
		}
		outcome.Status = statusConfirmed
		outcome.Summary = "Public Laravel log exposure confirmed"
		outcome.Severity = severity
		outcome.Evidence = evidence
		finding := models.Finding{
			Type:       "public-laravel-log",
			Category:   "laravel_exposure",
			Title:      "Laravel log file appears publicly accessible",
			Severity:   severity,
			Confidence: "high",
			Evidence:   fmt.Sprintf("%s returned %d and contained Laravel log markers", probe.Path, probe.StatusCode),
			Details: map[string]interface{}{
				"check_status": statusConfirmed,
				"signal":       outcome.Signal,
				"evidence":     evidence,
			},
		}
		return outcome, &finding
	}

	outcome.Status = statusNotObserved
	outcome.Summary = "No exposed Laravel log content observed"
	outcome.Evidence = evidence
	return outcome, nil
}

func checkComposerInstalled(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	probe := probePath(ctx, client, rootURL, "/vendor/composer/installed.json", http.MethodGet, 64*1024)
	outcome := checkOutcome{
		CheckID: "public-composer-installed-json",
		Signal:  "verification.laravel.composer.confirmed",
	}
	if probe.Err != nil {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify composer metadata exposure"
		outcome.Error = probe.Err.Error()
		return outcome, nil
	}

	isComposer, keyHints := detectComposerMetadata(probe.Body)
	evidence := map[string]interface{}{
		"url":           probe.URL,
		"status_code":   probe.StatusCode,
		"content_type":  probe.ContentType,
		"composer_keys": keyHints,
		"snippet":       snippet(probe.Body, 220),
	}
	if probe.StatusCode == http.StatusOK && isComposer {
		outcome.Status = statusConfirmed
		outcome.Summary = "Composer installed metadata is publicly exposed"
		outcome.Severity = "medium"
		outcome.Evidence = evidence
		finding := models.Finding{
			Type:       "public-composer-installed-json",
			Category:   "laravel_exposure",
			Title:      "Composer installed metadata appears publicly accessible",
			Severity:   "medium",
			Confidence: "high",
			Evidence:   fmt.Sprintf("%s returned %d and looked like Composer metadata", probe.Path, probe.StatusCode),
			Details: map[string]interface{}{
				"check_status": statusConfirmed,
				"signal":       outcome.Signal,
				"evidence":     evidence,
			},
		}
		return outcome, &finding
	}

	outcome.Status = statusNotObserved
	outcome.Summary = "No exposed Composer installed metadata observed"
	outcome.Evidence = evidence
	return outcome, nil
}

func checkDebugbar(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	probe := probePath(ctx, client, rootURL, "/_debugbar/open", http.MethodGet, 64*1024)
	outcome := checkOutcome{
		CheckID: "exposed-laravel-debugbar",
		Signal:  "verification.laravel.debugbar.confirmed",
	}
	if probe.Err != nil {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify Laravel Debugbar exposure"
		outcome.Error = probe.Err.Error()
		return outcome, nil
	}

	matched := matchIndicators(probe.Body, []string{"debugbar", "phpdebugbar", "Laravel Debugbar", "messages", "collector"})
	evidence := map[string]interface{}{
		"url":             probe.URL,
		"status_code":     probe.StatusCode,
		"content_type":    probe.ContentType,
		"matched_markers": matched,
		"snippet":         snippet(probe.Body, 220),
	}
	if probe.StatusCode == http.StatusOK && len(matched) > 0 {
		severity := "medium"
		if len(matched) >= 2 {
			severity = "high"
		}
		outcome.Status = statusConfirmed
		outcome.Summary = "Laravel Debugbar endpoint appears exposed"
		outcome.Severity = severity
		outcome.Evidence = evidence
		finding := models.Finding{
			Type:       "exposed-laravel-debugbar",
			Category:   "laravel_debug",
			Title:      "Laravel Debugbar endpoint appears externally reachable",
			Severity:   severity,
			Confidence: "medium",
			Evidence:   fmt.Sprintf("%s returned %d with debugbar markers", probe.Path, probe.StatusCode),
			Details: map[string]interface{}{
				"check_status": statusConfirmed,
				"signal":       outcome.Signal,
				"evidence":     evidence,
			},
		}
		return outcome, &finding
	}

	outcome.Status = statusNotObserved
	outcome.Summary = "No exposed Laravel Debugbar endpoint observed"
	outcome.Evidence = evidence
	return outcome, nil
}

func checkIgnition(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	outcome := checkOutcome{
		CheckID: "exposed-laravel-ignition",
		Signal:  "verification.laravel.ignition.confirmed",
	}

	paths := []string{"/_ignition/health-check", "/_ignition/execute-solution"}
	probes := make([]probeResult, 0, len(paths))
	matched := make([]string, 0)
	confirmedPath := ""
	severity := "medium"
	allErrored := true

	for _, path := range paths {
		for _, method := range []string{http.MethodHead, http.MethodGet} {
			probe := probePath(ctx, client, rootURL, path, method, 32*1024)
			probes = append(probes, probe)
			if probe.Err != nil {
				continue
			}
			allErrored = false
			markers := matchIndicators(probe.Body, []string{"ignition", "laravel", "flare", "execute-solution", "health-check"})
			if len(markers) > 0 && (probe.StatusCode == http.StatusOK || probe.StatusCode == http.StatusMethodNotAllowed || probe.StatusCode == http.StatusBadRequest) {
				matched = append(matched, markers...)
				confirmedPath = path
				if path == "/_ignition/execute-solution" {
					severity = "high"
				}
				break
			}
		}
		if confirmedPath != "" {
			break
		}
	}

	if allErrored {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify Laravel Ignition exposure"
		outcome.Error = "all Ignition probes failed"
		outcome.Evidence = map[string]interface{}{"probes": probesToMetadata(probes)}
		return outcome, nil
	}

	if confirmedPath != "" {
		sort.Strings(matched)
		matched = uniqueStrings(matched)
		evidence := map[string]interface{}{
			"confirmed_path":  confirmedPath,
			"matched_markers": matched,
			"probes":          probesToMetadata(probes),
		}
		outcome.Status = statusConfirmed
		outcome.Summary = "Laravel Ignition endpoint appears externally reachable"
		outcome.Severity = severity
		outcome.Evidence = evidence
		finding := models.Finding{
			Type:       "exposed-laravel-ignition",
			Category:   "laravel_debug",
			Title:      "Laravel Ignition endpoint appears externally reachable",
			Severity:   severity,
			Confidence: "medium",
			Evidence:   fmt.Sprintf("%s returned recognizable Ignition markers", confirmedPath),
			Details: map[string]interface{}{
				"check_status": statusConfirmed,
				"signal":       outcome.Signal,
				"evidence":     evidence,
			},
		}
		return outcome, &finding
	}

	outcome.Status = statusNotObserved
	outcome.Summary = "No publicly exposed Ignition endpoint was observed"
	outcome.Evidence = map[string]interface{}{"probes": probesToMetadata(probes)}
	return outcome, nil
}

func checkDebugDisclosure(ctx context.Context, client *http.Client, rootURL string) (checkOutcome, *models.Finding) {
	outcome := checkOutcome{
		CheckID: "laravel-debug-disclosure",
		Signal:  "verification.laravel.debug_leak.confirmed",
	}
	paths := []string{"/", "/index.php", "/__surface_lab_probe__"}
	probes := make([]probeResult, 0, len(paths))
	allErrored := true

	bestMarkers := []string{}
	bestProbe := probeResult{}
	for _, path := range paths {
		probe := probePath(ctx, client, rootURL, path, http.MethodGet, 64*1024)
		probes = append(probes, probe)
		if probe.Err != nil {
			continue
		}
		allErrored = false
		markers := matchIndicators(probe.Body, []string{"Illuminate\\", "Whoops", "FatalThrowableError", "ErrorException", "Stack trace", "APP_DEBUG", ".env"})
		if pathDisclosurePattern.MatchString(probe.Body) {
			markers = append(markers, "application_path")
		}
		if len(markers) > len(bestMarkers) {
			bestMarkers = uniqueStrings(markers)
			bestProbe = probe
		}
	}

	if allErrored {
		outcome.Status = statusInconclusive
		outcome.Summary = "Could not verify Laravel debug disclosure markers"
		outcome.Error = "all debug disclosure probes failed"
		outcome.Evidence = map[string]interface{}{"probes": probesToMetadata(probes)}
		return outcome, nil
	}

	if len(bestMarkers) >= 2 {
		evidence := map[string]interface{}{
			"url":             bestProbe.URL,
			"path":            bestProbe.Path,
			"status_code":     bestProbe.StatusCode,
			"content_type":    bestProbe.ContentType,
			"matched_markers": bestMarkers,
			"snippet":         snippet(bestProbe.Body, 240),
			"probes":          probesToMetadata(probes),
		}
		outcome.Status = statusConfirmed
		outcome.Summary = "Laravel debug disclosure markers were observed"
		outcome.Severity = "medium"
		outcome.Evidence = evidence
		finding := models.Finding{
			Type:       "laravel-debug-disclosure",
			Category:   "laravel_debug",
			Title:      "Laravel debug/error disclosure markers are externally visible",
			Severity:   "medium",
			Confidence: "medium",
			Evidence:   fmt.Sprintf("%s returned debug disclosure markers: %s", bestProbe.Path, strings.Join(bestMarkers, ", ")),
			Details: map[string]interface{}{
				"check_status": statusConfirmed,
				"signal":       outcome.Signal,
				"evidence":     evidence,
			},
		}
		return outcome, &finding
	}

	outcome.Status = statusNotObserved
	outcome.Summary = "No Laravel debug disclosure markers were observed"
	outcome.Evidence = map[string]interface{}{"probes": probesToMetadata(probes)}
	return outcome, nil
}

func probePath(ctx context.Context, client *http.Client, rootURL string, path string, method string, maxRead int64) probeResult {
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

	resp, err := client.Do(req)
	if err != nil {
		result.Err = err
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ContentType = strings.TrimSpace(resp.Header.Get("Content-Type"))
	if strings.EqualFold(method, http.MethodHead) {
		return result
	}

	if maxRead <= 0 {
		maxRead = maxBodyBytes
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	if readErr != nil {
		result.Err = readErr
		return result
	}
	result.ReadBytes = len(body)
	result.Body = sanitizeSnippet(string(body))
	return result
}

func detectComposerMetadata(body string) (bool, []string) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return false, nil
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &payload); err == nil {
		hints := make([]string, 0)
		for _, key := range []string{"packages", "packages-dev", "dev", "plugin-api-version", "root"} {
			if _, ok := payload[key]; ok {
				hints = append(hints, key)
			}
		}
		if len(hints) > 0 {
			return true, hints
		}
	}

	for _, token := range []string{"name", "version", "composer", "package", "autoload"} {
		if strings.Contains(strings.ToLower(trimmed), `"`+token+`"`) {
			return true, []string{token}
		}
	}

	return false, nil
}

func sanitizeSnippet(raw string) string {
	text := strings.ReplaceAll(raw, "\r", "")
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if key := envKey(trimmed); key != "" && sensitiveKey(key) {
			lines[i] = key + "=[REDACTED]"
			continue
		}
		lines[i] = secretKVPattern.ReplaceAllString(lines[i], "$1=[REDACTED]")
	}
	return strings.Join(lines, "\n")
}

func envKey(line string) string {
	matches := envKeyPattern.FindStringSubmatch(line)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func sensitiveKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	for _, token := range []string{"password", "secret", "token", "key", "app_key", "mail_", "db_"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
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

func containsAny(values []string, targets []string) bool {
	for _, value := range values {
		for _, target := range targets {
			if strings.EqualFold(value, target) {
				return true
			}
		}
	}
	return false
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
