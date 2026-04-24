package execute

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/MariusBobitiu/surface-lab/nextjs-stack/models"
)

const osvQueryURL = "https://api.osv.dev/v1/query"

type osvQueryRequest struct {
	Version string     `json:"version"`
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQueryResponse struct {
	Vulns []osvVulnerability `json:"vulns"`
}

type osvVulnerability struct {
	ID               string                 `json:"id"`
	Summary          string                 `json:"summary"`
	Details          string                 `json:"details"`
	Aliases          []string               `json:"aliases"`
	Published        string                 `json:"published"`
	Modified         string                 `json:"modified"`
	References       []osvReference         `json:"references"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func lookupNextAdvisories(ctx context.Context, client *http.Client, version string) ([]models.Finding, map[string]interface{}, error) {
	version = normalizeVersion(version)
	if version == "" {
		return nil, map[string]interface{}{
			"status": "skipped",
			"reason": "next_version_not_detected",
		}, nil
	}

	payload, err := json.Marshal(osvQueryRequest{
		Version: version,
		Package: osvPackage{
			Name:      "next",
			Ecosystem: "npm",
		},
	})
	if err != nil {
		return nil, map[string]interface{}{"status": "failed", "version": version}, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, osvQueryURL, bytes.NewReader(payload))
	if err != nil {
		return nil, map[string]interface{}{"status": "failed", "version": version}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return nil, map[string]interface{}{"status": "failed", "version": version}, fmt.Errorf("query OSV: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return nil, map[string]interface{}{"status": "failed", "version": version, "http_status": response.StatusCode}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, map[string]interface{}{"status": "failed", "version": version, "http_status": response.StatusCode}, fmt.Errorf("query OSV: HTTP %d", response.StatusCode)
	}

	var result osvQueryResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, map[string]interface{}{"status": "failed", "version": version, "http_status": response.StatusCode}, err
	}

	findings := make([]models.Finding, 0, len(result.Vulns))
	advisoryIDs := make([]string, 0, len(result.Vulns))
	for _, vuln := range result.Vulns {
		advisoryIDs = append(advisoryIDs, vuln.ID)
		findings = append(findings, osvVulnerabilityFinding(version, vuln))
	}

	return findings, map[string]interface{}{
		"status":         "completed",
		"source":         "osv",
		"package":        "next",
		"ecosystem":      "npm",
		"version":        version,
		"advisory_count": len(result.Vulns),
		"advisory_ids":   advisoryIDs,
	}, nil
}

func osvVulnerabilityFinding(version string, vuln osvVulnerability) models.Finding {
	summary := firstNonEmpty(vuln.Summary, firstSentence(vuln.Details), "Known Next.js advisory matched this version")
	referenceURLs := make([]string, 0, len(vuln.References))
	for _, ref := range vuln.References {
		if strings.TrimSpace(ref.URL) != "" {
			referenceURLs = append(referenceURLs, ref.URL)
		}
	}

	return models.Finding{
		Type:       "known_vulnerability",
		Category:   "nextjs_vulnerability",
		Title:      fmt.Sprintf("Next.js %s matches known advisory %s", version, vuln.ID),
		Severity:   osvSeverity(vuln),
		Confidence: "high",
		Evidence:   summary,
		Details: map[string]interface{}{
			"product":      "next",
			"version":      version,
			"advisory_id":  vuln.ID,
			"aliases":      vuln.Aliases,
			"published":    vuln.Published,
			"modified":     vuln.Modified,
			"references":   referenceURLs,
			"osv_summary":  vuln.Summary,
			"osv_database": vuln.DatabaseSpecific,
		},
	}
}

func osvSeverity(vuln osvVulnerability) string {
	if raw, ok := vuln.DatabaseSpecific["severity"].(string); ok {
		normalized := strings.ToLower(strings.TrimSpace(raw))
		switch normalized {
		case "critical", "high", "medium", "low":
			return normalized
		}
	}

	return "medium"
}

func firstSentence(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	for _, separator := range []string{". ", "\n"} {
		if index := strings.Index(value, separator); index > 0 {
			return strings.TrimSpace(value[:index+1])
		}
	}
	return value
}
