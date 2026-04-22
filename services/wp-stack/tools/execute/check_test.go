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
