package common

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
)

func NewToolResult(tool string, target string, version string) models.ToolResult {
	return models.ToolResult{
		Tool:     tool,
		Target:   target,
		Status:   models.StatusFailed,
		Signals:  []models.Signal{},
		Findings: []models.Finding{},
		Evidence: []models.Evidence{},
		Metadata: map[string]interface{}{
			"tool_version": version,
		},
	}
}

func AddEvidence(result *models.ToolResult, kind string, target string, data map[string]interface{}) string {
	id := fmt.Sprintf("%s-e%d-%s", sanitizeIdentifier(result.Tool), len(result.Evidence)+1, randomHex(4))
	result.Evidence = append(result.Evidence, models.Evidence{
		ID:     id,
		Kind:   kind,
		Target: target,
		Data:   data,
	})
	return id
}

func AddSignal(
	result *models.ToolResult,
	key string,
	value interface{},
	confidence string,
	source string,
	evidenceRefs ...string,
) {
	result.Signals = append(result.Signals, models.Signal{
		Key:          key,
		Value:        value,
		Confidence:   confidence,
		Source:       source,
		EvidenceRefs: compactStrings(evidenceRefs),
	})
}

func HeaderSnapshot(headers http.Header, names ...string) map[string]interface{} {
	snapshot := map[string]interface{}{}
	for _, name := range names {
		if value := strings.TrimSpace(headers.Get(name)); value != "" {
			snapshot[name] = value
		}
	}
	return snapshot
}

func BodySnippet(body []byte, limit int) string {
	if limit <= 0 || len(body) == 0 {
		return ""
	}

	if len(body) > limit {
		body = body[:limit]
	}

	snippet := strings.TrimSpace(string(body))
	return strings.ReplaceAll(snippet, "\x00", "")
}

func BodySHA1(body []byte) string {
	sum := sha1.Sum(body)
	return hex.EncodeToString(sum[:])
}

func BoolToInterface(value bool) interface{} {
	return value
}

func compactStrings(values []string) []string {
	compacted := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		compacted = append(compacted, value)
	}
	return compacted
}

func sanitizeIdentifier(value string) string {
	replacer := strings.NewReplacer("/", "-", ".", "-", ":", "-", " ", "-")
	return replacer.Replace(strings.ToLower(value))
}

func randomHex(size int) string {
	if size <= 0 {
		return ""
	}

	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "randerr"
	}

	return hex.EncodeToString(buf)
}
