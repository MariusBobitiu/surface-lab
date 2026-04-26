package execute

import (
	"strings"
	"testing"
)

func TestDetectComposerMetadata(t *testing.T) {
	isComposer, keys := detectComposerMetadata(`{"packages":[{"name":"laravel/framework"}]}`)
	if !isComposer {
		t.Fatalf("expected composer metadata to be detected")
	}
	if len(keys) == 0 {
		t.Fatalf("expected composer keys to be returned")
	}
}

func TestSanitizeSnippetRedactsSecrets(t *testing.T) {
	raw := "APP_KEY=base64:abcdefghijklmnop\nDB_PASSWORD=super-secret\nMAIL_HOST=smtp.example.com"
	sanitized := sanitizeSnippet(raw)
	if strings.Contains(sanitized, "super-secret") {
		t.Fatalf("expected DB_PASSWORD to be redacted")
	}
	if strings.Contains(sanitized, "abcdefghijklmnop") {
		t.Fatalf("expected APP_KEY to be redacted")
	}
	if !strings.Contains(sanitized, "MAIL_HOST=[REDACTED]") {
		t.Fatalf("expected MAIL_HOST to be redacted")
	}
}

func TestMatchIndicatorsCaseInsensitive(t *testing.T) {
	matches := matchIndicators("local.error Illuminate\\\\Database", []string{"local.ERROR", "Illuminate\\"})
	if len(matches) != 2 {
		t.Fatalf("expected 2 markers, got %d", len(matches))
	}
}

func TestOutcomesToMetadataIncludesStatus(t *testing.T) {
	items := outcomesToMetadata([]checkOutcome{{
		CheckID: "public-laravel-env",
		Status:  statusConfirmed,
	}})
	if len(items) != 1 {
		t.Fatalf("expected one metadata item")
	}
	if items[0]["status"] != statusConfirmed {
		t.Fatalf("expected status %s", statusConfirmed)
	}
}
