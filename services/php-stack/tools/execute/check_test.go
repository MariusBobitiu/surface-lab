package execute

import (
	"net/http"
	"strings"
	"testing"
)

func TestMatchIndicatorsFindsSQLMarkers(t *testing.T) {
	matches := matchIndicators("CREATE TABLE users (id int);", []string{"CREATE TABLE", "INSERT INTO"})
	if len(matches) != 1 {
		t.Fatalf("expected one SQL marker, got %d", len(matches))
	}
}

func TestRedactSecretsRemovesSensitiveValues(t *testing.T) {
	raw := "DB_PASSWORD=super-secret\nDB_HOST=localhost"
	redacted := redactSecrets(raw)
	if redacted == raw {
		t.Fatalf("expected redaction to modify output")
	}
	if !strings.Contains(redacted, "DB_PASSWORD=[REDACTED]") {
		t.Fatalf("expected DB_PASSWORD to be redacted")
	}
}

func TestIsArchiveResponseUsesHeaders(t *testing.T) {
	probe := probeResult{StatusCode: http.StatusOK, ContentType: "application/zip", Headers: http.Header{}}
	if !isArchiveResponse(probe, nil) {
		t.Fatalf("expected archive detection from content-type")
	}
}

func TestFindPHPVersionInBaseline(t *testing.T) {
	version := findPHPVersionInBaseline(map[string]interface{}{
		"baseline_signals": []interface{}{
			map[string]interface{}{"key": "framework.php.version", "value": "8.2.12"},
		},
	})
	if version != "8.2.12" {
		t.Fatalf("expected version 8.2.12, got %q", version)
	}
}
