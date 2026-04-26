package execute

import (
	"net/http"
	"testing"
)

func TestExtractScriptDomains(t *testing.T) {
	html := `<script src="https://cdn.shopify.com/s/files/test.js"></script><script src="https://www.googletagmanager.com/gtm.js"></script>`
	domains := extractScriptDomains(html)
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}
}

func TestClassifyScriptDomains(t *testing.T) {
	groups := classifyScriptDomains([]string{"cdn.shopify.com", "www.googletagmanager.com", "unknown.example.org"})
	if len(groups["shopify"]) != 1 {
		t.Fatalf("expected one shopify domain")
	}
	if len(groups["analytics_ads"]) != 1 {
		t.Fatalf("expected one analytics domain")
	}
	if len(groups["unknown_third_party"]) != 1 {
		t.Fatalf("expected one unknown domain")
	}
}

func TestMissingHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Set("Content-Security-Policy", "default-src 'self'")
	missing := missingHeaders(headers, []string{"Content-Security-Policy", "Referrer-Policy"})
	if len(missing) != 1 || missing[0] != "Referrer-Policy" {
		t.Fatalf("expected Referrer-Policy to be missing")
	}
}

func TestMatchIndicators(t *testing.T) {
	markers := matchIndicators("Shopify.theme = {}; shopify-section", []string{"Shopify.theme", "shopify-section"})
	if len(markers) != 2 {
		t.Fatalf("expected 2 markers")
	}
}
