package execute

import "testing"

func TestDetectRootFindings(t *testing.T) {
	findings, analysis := detectRootFindings(&rootFetchResult{
		URL:        "https://example.test",
		StatusCode: 200,
		Headers: map[string][]string{
			"X-Powered-By": {"Next.js"},
		},
		HTML: `
			<html>
				<head>
					<script id="__NEXT_DATA__" type="application/json">{"buildId":"build123"}</script>
				</head>
				<body>
					<script src="/_next/static/chunks/main-app.js"></script>
					<script>self.__next_f.push([])</script>
				</body>
			</html>
		`,
	})

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	if analysis.buildID != "build123" {
		t.Fatalf("expected build ID build123, got %q", analysis.buildID)
	}
	if !analysis.hasAppRouter {
		t.Fatalf("expected app router markers to be detected")
	}
}

func TestDetectChunkFindings(t *testing.T) {
	findings := detectChunkFindings(&chunkProbeResult{
		URL:           "https://example.test/_next/static/chunks/main.js",
		StatusCode:    200,
		SourceMapHint: "main.js.map",
		BodySnippet:   "//# sourceMappingURL=main.js.map",
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestExtractNextVersion(t *testing.T) {
	version := extractNextVersion(`self.__NEXT_VERSION__ = "14.2.24";`)
	if version != "14.2.24" {
		t.Fatalf("expected version 14.2.24, got %q", version)
	}
}

func TestDetectNextDataSensitiveKeys(t *testing.T) {
	findings := detectNextDataFindings(map[string]interface{}{
		"url":            "https://example.test/_next/data/build/index.json",
		"status":         200,
		"sensitive_keys": stringSliceToInterface([]string{"token"}),
	})

	if len(findings) != 1 {
		t.Fatalf("expected sensitive key finding, got %d", len(findings))
	}
	if findings[0].Type != "next_data_sensitive_props" {
		t.Fatalf("expected sensitive props finding, got %q", findings[0].Type)
	}
}

func TestDetectDevelopmentArtifactFindings(t *testing.T) {
	exposed, marker := isDevelopmentArtifact(
		"/_next/static/development/_buildManifest.js",
		200,
		"self.__BUILD_MANIFEST = {}",
	)
	if !exposed || marker != "__BUILD_MANIFEST" {
		t.Fatalf("expected development artifact to be detected")
	}
}

func TestOSVVulnerabilityFinding(t *testing.T) {
	finding := osvVulnerabilityFinding("14.2.24", osvVulnerability{
		ID:      "GHSA-test",
		Summary: "Test advisory",
		Aliases: []string{
			"CVE-2099-0001",
		},
		DatabaseSpecific: map[string]interface{}{
			"severity": "HIGH",
		},
	})

	if finding.Category != "nextjs_vulnerability" {
		t.Fatalf("expected nextjs_vulnerability category, got %q", finding.Category)
	}
	if finding.Severity != "high" {
		t.Fatalf("expected high severity, got %q", finding.Severity)
	}
}
