package execute

import (
	"net/http"
	"testing"
)

func TestDetectRootFindings(t *testing.T) {
	findings := detectRootFindings(&rootFetchResult{
		URL:        "https://example.test",
		StatusCode: http.StatusOK,
		HTML: `
			<html>
				<head>
					<meta name="generator" content="WordPress 6.8" />
					<link rel="stylesheet" href="/wp-content/themes/twentytwentyfive/style.css">
				</head>
				<body>
					<script src="/wp-content/plugins/contact-form-7/script.js"></script>
					<a href="/wp-json/">api</a>
				</body>
			</html>
		`,
	})

	if len(findings) != 4 {
		t.Fatalf("expected 4 root findings, got %d", len(findings))
	}
}

func TestDetectEndpointFindings(t *testing.T) {
	findings := append(
		detectEndpointFindings("wp-login", &endpointResult{Path: "/wp-login.php", Status: http.StatusOK}),
		detectEndpointFindings("xmlrpc", &endpointResult{Path: "/xmlrpc.php", Status: http.StatusMethodNotAllowed})...,
	)
	findings = append(findings, detectEndpointFindings("readme", &endpointResult{Path: "/readme.html", Status: http.StatusOK})...)

	if len(findings) != 3 {
		t.Fatalf("expected 3 endpoint findings, got %d", len(findings))
	}
}

func TestParseSpecialistContextExtractsWPVersionFromResearch(t *testing.T) {
	ctx := parseSpecialistContext(map[string]interface{}{
		"vulnerability_research": []interface{}{
			map[string]interface{}{
				"product": "wordpress",
				"version": "6.5.2",
			},
		},
	})

	if ctx.researchDerivedVersion != "6.5.2" {
		t.Fatalf("expected research version 6.5.2, got %q", ctx.researchDerivedVersion)
	}
}

func TestFindingsFromVulnerabilityResearchUsesWordPressCVEs(t *testing.T) {
	findings, metadata := findingsFromVulnerabilityResearch([]map[string]interface{}{
		{
			"product": "wordpress",
			"version": "6.5.2",
			"cve_matches": []interface{}{
				map[string]interface{}{
					"cve_id":        "CVE-2099-0002",
					"cvss_severity": "CRITICAL",
					"description":   "Test WordPress vulnerability",
				},
			},
		},
	}, "6.5.2")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from research, got %d", len(findings))
	}
	if findings[0].Category != "wordpress_vulnerability" {
		t.Fatalf("expected wordpress_vulnerability category, got %q", findings[0].Category)
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("expected critical severity, got %q", findings[0].Severity)
	}

	if metadata["matched_cve_count"] != 1 {
		t.Fatalf("expected metadata matched_cve_count=1, got %#v", metadata["matched_cve_count"])
	}
}
