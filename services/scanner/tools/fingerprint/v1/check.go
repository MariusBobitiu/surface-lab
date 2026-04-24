package v1

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
	"github.com/MariusBobitiu/surface-lab/scanner-service/tools/common"
	"github.com/MariusBobitiu/surface-lab/scanner-service/utils"
)

const fingerprintTimeout = 10 * time.Second

var versionPattern = regexp.MustCompile(`(?i)\b\d+(?:\.\d+){1,3}\b`)
var nextVersionPattern = regexp.MustCompile(`(?i)(?:next(?:\.js)?|nextjs|nextVersion|__NEXT_VERSION__)["'\s:=/v-]+(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)`)
var wordpressVersionPattern = regexp.MustCompile(`(?i)(?:wordpress["'\s:=/v-]+|wp-(?:includes|content)[^"'<>?]*ver=)(\d+\.\d+(?:\.\d+)?)`)
var djangoVersionPattern = regexp.MustCompile(`(?i)django["'\s:=/v-]+(\d+\.\d+(?:\.\d+)?)`)
var dotNetVersionPattern = regexp.MustCompile(`(?i)(?:asp\.?net(?:\s*core)?|dotnet|x-aspnet-version)["'\s:=/v-]+(\d+\.\d+(?:\.\d+)?)`)

func Check(ctx context.Context, target string) models.ToolResult {
	startedAt := time.Now()
	result := common.NewToolResult("fingerprint/v1", target, "v1")

	targetURL := utils.NormalizeTarget(target, "https")
	result.Target = targetURL

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		result.DurationMs = time.Since(startedAt).Milliseconds()
		result.Error = fmt.Sprintf("build request: %v", err)
		return result
	}

	req.Header.Set("User-Agent", utils.DefaultUserAgent)

	resp, err := utils.NewHTTPClient(fingerprintTimeout).Do(req)
	if err != nil {
		result.DurationMs = time.Since(startedAt).Milliseconds()
		result.Error = fmt.Sprintf("request target: %v", err)
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	html := string(body)

	headersEvidenceID := common.AddEvidence(&result, "response_headers", resp.Request.URL.String(), map[string]interface{}{
		"status_code": resp.StatusCode,
		"headers": common.HeaderSnapshot(
			resp.Header,
			"Server",
			"X-Powered-By",
			"X-AspNet-Version",
			"X-AspNetMvc-Version",
			"CF-Ray",
			"X-Vercel-Id",
			"X-Render-Origin-Server",
			"Fly-Request-Id",
			"X-Nf-Request-Id",
		),
	})

	baseURL := resp.Request.URL.String()
	generator := detectGenerator(html)
	if generator != "" {
		generatorEvidenceID := common.AddEvidence(&result, "meta_generator", baseURL, map[string]interface{}{
			"generator": generator,
		})
		result.Findings = append(result.Findings, disclosureFinding(
			"generator-disclosure",
			"information_disclosure",
			"Generator disclosure detected",
			fmt.Sprintf("The application discloses %q via a generator marker.", generator),
			models.SeverityInfo,
			models.ConfidenceHigh,
			[]string{generatorEvidenceID},
			map[string]interface{}{"generator": generator},
		))
	}

	scripts := extractScripts(html, baseURL)
	scriptURLs := scriptSources(scripts)
	htmlMarkers := detectHTMLMarkers(html, scripts)
	htmlEvidenceID := common.AddEvidence(&result, "html_markers", baseURL, map[string]interface{}{
		"body_sha1":    common.BodySHA1(body),
		"body_snippet": common.BodySnippet(body, 240),
		"scripts":      scripts,
		"markers":      htmlMarkers,
	})

	serverHeader := strings.TrimSpace(resp.Header.Get("Server"))
	common.AddSignal(&result, models.SignalHeaderServerPresent, serverHeader != "", models.ConfidenceHigh, "fingerprint.headers", headersEvidenceID)
	cloudflareDetected := false
	vercelDetected := false
	renderDetected := false
	flyIODetected := false
	if serverHeader != "" {
		if strings.Contains(strings.ToLower(serverHeader), "cloudflare") {
			cloudflareDetected = true
		}
		if strings.Contains(strings.ToLower(serverHeader), "vercel") {
			vercelDetected = true
		}
		if strings.Contains(strings.ToLower(serverHeader), "render") {
			renderDetected = true
		}
		if strings.Contains(strings.ToLower(serverHeader), "fly.io") || strings.Contains(strings.ToLower(serverHeader), "fly") {
			flyIODetected = true
		}
		result.Findings = append(result.Findings, disclosureFinding(
			"exposed-tech-header",
			"information_disclosure",
			"Server header discloses stack details",
			fmt.Sprintf("The response exposes the server header value %q.", serverHeader),
			models.SeverityInfo,
			models.ConfidenceHigh,
			[]string{headersEvidenceID},
			map[string]interface{}{"header": "Server", "value": serverHeader},
		))
		if containsVersion(serverHeader) {
			result.Findings = append(result.Findings, disclosureFinding(
				"version-disclosure",
				"information_disclosure",
				"Version disclosure detected in Server header",
				fmt.Sprintf("The server header appears to expose a version string: %q.", serverHeader),
				models.SeverityLow,
				models.ConfidenceMedium,
				[]string{headersEvidenceID},
				map[string]interface{}{"header": "Server", "value": serverHeader},
			))
		}
	}

	poweredBy := strings.TrimSpace(resp.Header.Get("X-Powered-By"))
	common.AddSignal(&result, models.SignalHeaderXPoweredByPresent, poweredBy != "", models.ConfidenceHigh, "fingerprint.headers", headersEvidenceID)
	nextVersion := extractNextVersion(poweredBy)
	if poweredBy != "" {
		result.Findings = append(result.Findings, disclosureFinding(
			"exposed-tech-header",
			"information_disclosure",
			"X-Powered-By header discloses stack details",
			fmt.Sprintf("The response exposes the X-Powered-By value %q.", poweredBy),
			models.SeverityInfo,
			models.ConfidenceHigh,
			[]string{headersEvidenceID},
			map[string]interface{}{"header": "X-Powered-By", "value": poweredBy},
		))
		if containsVersion(poweredBy) {
			result.Findings = append(result.Findings, disclosureFinding(
				"version-disclosure",
				"information_disclosure",
				"Version disclosure detected in X-Powered-By header",
				fmt.Sprintf("The X-Powered-By header appears to expose a version string: %q.", poweredBy),
				models.SeverityLow,
				models.ConfidenceMedium,
				[]string{headersEvidenceID},
				map[string]interface{}{"header": "X-Powered-By", "value": poweredBy, "product": productFromPoweredBy(poweredBy), "version": firstNonEmpty(nextVersion, extractVersion(poweredBy))},
			))
		}
	}

	if strings.TrimSpace(resp.Header.Get("CF-Ray")) != "" {
		cloudflareDetected = true
	}

	if strings.TrimSpace(resp.Header.Get("X-Vercel-Id")) != "" {
		vercelDetected = true
	}

	if strings.TrimSpace(resp.Header.Get("X-Render-Origin-Server")) != "" {
		renderDetected = true
	}

	if strings.TrimSpace(resp.Header.Get("Fly-Request-Id")) != "" {
		flyIODetected = true
	}

	netlifyDetected := strings.TrimSpace(resp.Header.Get("X-Nf-Request-Id")) != "" || strings.Contains(strings.ToLower(serverHeader), "netlify")
	common.AddSignal(&result, models.SignalHostingCloudflare, cloudflareDetected, models.ConfidenceHigh, "fingerprint.headers", headersEvidenceID)
	common.AddSignal(&result, models.SignalHostingVercel, vercelDetected, models.ConfidenceHigh, "fingerprint.headers", headersEvidenceID)
	common.AddSignal(&result, models.SignalHostingNetlify, netlifyDetected, models.ConfidenceHigh, "fingerprint.headers", headersEvidenceID)
	common.AddSignal(&result, models.SignalHostingRender, renderDetected, models.ConfidenceHigh, "fingerprint.headers", headersEvidenceID)
	common.AddSignal(&result, models.SignalHostingFlyIO, flyIODetected, models.ConfidenceHigh, "fingerprint.headers", headersEvidenceID)

	hasJSBundles := len(scriptURLs) > 0
	common.AddSignal(&result, models.SignalAssetsJSBundle, hasJSBundles, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)
	common.AddSignal(&result, models.SignalAssetsScriptSources, scriptURLs, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)

	hasNextAssets := htmlMarkers["next_static"] == true
	common.AddSignal(&result, models.SignalAssetsNextStatic, hasNextAssets, models.ConfidenceHigh, "fingerprint.html", htmlEvidenceID)
	nextDetected := hasNextAssets || strings.Contains(strings.ToLower(poweredBy), "next")
	common.AddSignal(&result, models.SignalFrameworkNextJS, nextDetected, models.ConfidenceHigh, "fingerprint.combined", htmlEvidenceID, headersEvidenceID)
	if nextVersion == "" {
		nextVersion = extractNextVersion(html)
	}
	if nextDetected && nextVersion != "" {
		common.AddSignal(&result, models.SignalFrameworkNextJSVersion, nextVersion, models.ConfidenceMedium, "fingerprint.combined", htmlEvidenceID, headersEvidenceID)
		result.Metadata["nextjs_version"] = nextVersion
	}

	wordpressDetected := htmlMarkers["wordpress"] == true || strings.Contains(strings.ToLower(generator), "wordpress")
	common.AddSignal(&result, models.SignalFrameworkWordPress, wordpressDetected, models.ConfidenceHigh, "fingerprint.html", htmlEvidenceID)
	wordpressVersion := firstNonEmpty(extractWordPressVersion(generator), extractWordPressVersion(html))
	if wordpressDetected && wordpressVersion != "" {
		common.AddSignal(&result, models.SignalFrameworkWordPressVersion, wordpressVersion, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)
		result.Metadata["wordpress_version"] = wordpressVersion
	}

	reactDetected := htmlMarkers["react"] == true || nextDetected
	vueDetected := htmlMarkers["vue"] == true
	angularDetected := htmlMarkers["angular"] == true
	nuxtDetected := htmlMarkers["nuxt"] == true
	svelteKitDetected := htmlMarkers["sveltekit"] == true
	djangoDetected := htmlMarkers["django"] == true
	dotNetDetected := htmlMarkers["dotnet"] == true || strings.TrimSpace(resp.Header.Get("X-AspNet-Version")) != "" || strings.TrimSpace(resp.Header.Get("X-AspNetMvc-Version")) != "" || strings.Contains(strings.ToLower(poweredBy), "asp.net")
	viteDetected := htmlMarkers["vite"] == true
	remixDetected := htmlMarkers["remix"] == true
	wixDetected := htmlMarkers["wix"] == true
	supabaseDetected := htmlMarkers["supabase"] == true
	s3PublicDetected := htmlMarkers["s3_public"] == true
	r2PublicDetected := htmlMarkers["r2_public"] == true
	mongoDetected := htmlMarkers["mongodb"] == true
	neonDetected := htmlMarkers["neon"] == true
	common.AddSignal(&result, models.SignalFrameworkReact, reactDetected, confidenceForDerivedFramework(reactDetected, nextDetected), "fingerprint.html", htmlEvidenceID)
	common.AddSignal(&result, models.SignalFrameworkVue, vueDetected, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)
	common.AddSignal(&result, models.SignalFrameworkAngular, angularDetected, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)
	common.AddSignal(&result, models.SignalFrameworkNuxt, nuxtDetected, models.ConfidenceHigh, "fingerprint.html", htmlEvidenceID)
	common.AddSignal(&result, models.SignalFrameworkSvelteKit, svelteKitDetected, models.ConfidenceHigh, "fingerprint.html", htmlEvidenceID)
	common.AddSignal(&result, models.SignalFrameworkDjango, djangoDetected, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)
	common.AddSignal(&result, models.SignalFrameworkDotNet, dotNetDetected, models.ConfidenceHigh, "fingerprint.headers", headersEvidenceID)
	common.AddSignal(&result, models.SignalFrameworkVite, viteDetected, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)
	common.AddSignal(&result, models.SignalFrameworkRemix, remixDetected, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)
	common.AddSignal(&result, models.SignalFrameworkWix, wixDetected, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)
	common.AddSignal(&result, models.SignalToolingSupabase, supabaseDetected, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)
	common.AddSignal(&result, models.SignalToolingS3Public, s3PublicDetected, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)
	common.AddSignal(&result, models.SignalToolingCloudflareR2Public, r2PublicDetected, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)
	common.AddSignal(&result, models.SignalToolingMongoDB, mongoDetected, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)
	common.AddSignal(&result, models.SignalToolingNeon, neonDetected, models.ConfidenceMedium, "fingerprint.html", htmlEvidenceID)

	djangoVersion := firstNonEmpty(
		extractDjangoVersion(generator),
		extractDjangoVersion(poweredBy),
		extractDjangoVersion(html),
	)
	dotNetVersion := firstNonEmpty(
		strings.TrimSpace(resp.Header.Get("X-AspNet-Version")),
		strings.TrimSpace(resp.Header.Get("X-AspNetMvc-Version")),
		extractDotNetVersion(poweredBy),
		extractDotNetVersion(serverHeader),
	)

	technologySummary := buildTechnologySummary(map[string]bool{
		"nextjs":    nextDetected,
		"react":     reactDetected,
		"wordpress": wordpressDetected,
		"vue":       vueDetected,
		"angular":   angularDetected,
		"nuxt":      nuxtDetected,
		"sveltekit": svelteKitDetected,
		"django":    djangoDetected,
		"dotnet":    dotNetDetected,
		"vite":      viteDetected,
		"remix":     remixDetected,
		"wix":       wixDetected,
	}, map[string]string{
		"nextjs":    nextVersion,
		"wordpress": wordpressVersion,
		"django":    djangoVersion,
		"dotnet":    normalizeVersion(dotNetVersion),
	}, map[string]bool{
		"cloudflare": cloudflareDetected,
		"vercel":     vercelDetected,
		"netlify":    netlifyDetected,
		"render":     renderDetected,
		"flyio":      flyIODetected,
	}, map[string]bool{
		"supabase":             supabaseDetected,
		"s3_public":            s3PublicDetected,
		"cloudflare_r2_public": r2PublicDetected,
		"mongodb":              mongoDetected,
		"neon":                 neonDetected,
	}, serverHeader, poweredBy, generator, scriptHostnames(scripts))
	common.AddSignal(&result, models.SignalTechnologySummary, technologySummary, models.ConfidenceMedium, "fingerprint.summary", htmlEvidenceID, headersEvidenceID)
	result.Metadata["technology_summary"] = technologySummary

	result.Metadata["status_code"] = resp.StatusCode
	result.Metadata["final_url"] = baseURL
	result.Metadata["script_url_count"] = len(scriptURLs)
	result.Metadata["markers"] = htmlMarkers
	result.DurationMs = time.Since(startedAt).Milliseconds()
	result.Status = models.StatusSuccess

	return result
}

func disclosureFinding(
	findingType string,
	category string,
	title string,
	summary string,
	severity string,
	confidence string,
	evidenceRefs []string,
	details map[string]interface{},
) models.Finding {
	return models.Finding{
		Type:         findingType,
		Category:     category,
		Title:        title,
		Summary:      summary,
		Severity:     severity,
		Confidence:   confidence,
		Evidence:     summary,
		EvidenceRefs: evidenceRefs,
		Details:      details,
	}
}

func detectGenerator(html string) string {
	lower := strings.ToLower(html)
	marker := `meta name="generator" content="`
	index := strings.Index(lower, marker)
	if index == -1 {
		marker = `meta content="`
		index = strings.Index(lower, marker)
		if index == -1 {
			return ""
		}
		if !strings.Contains(lower[index:], `name="generator"`) {
			return ""
		}
	}

	start := index + len(marker)
	if start >= len(html) {
		return ""
	}

	end := strings.Index(html[start:], `"`)
	if end == -1 {
		return ""
	}

	return strings.TrimSpace(html[start : start+end])
}

func extractScripts(html string, baseURL string) []interface{} {
	results := make([]interface{}, 0, 8)
	lower := strings.ToLower(html)
	search := `script src="`
	offset := 0
	for len(results) < 6 {
		index := strings.Index(lower[offset:], search)
		if index == -1 {
			break
		}
		start := offset + index + len(search)
		end := strings.Index(html[start:], `"`)
		if end == -1 {
			break
		}
		src := strings.TrimSpace(html[start : start+end])
		results = append(results, map[string]interface{}{
			"src":         src,
			"resolved":    resolveReference(baseURL, src),
			"host":        hostname(resolveReference(baseURL, src)),
			"is_next":     strings.Contains(strings.ToLower(src), "/_next/"),
			"is_wp":       strings.Contains(strings.ToLower(src), "/wp-content/") || strings.Contains(strings.ToLower(src), "/wp-includes/"),
			"is_external": isExternal(baseURL, src),
		})
		offset = start + end
	}
	return results
}

func detectHTMLMarkers(html string, scripts []interface{}) map[string]interface{} {
	lower := strings.ToLower(html)
	scriptText := strings.ToLower(fmt.Sprint(scripts))
	return map[string]interface{}{
		"next_static": strings.Contains(lower, "/_next/static/") || strings.Contains(lower, "__next"),
		"wordpress":   strings.Contains(lower, "/wp-content/") || strings.Contains(lower, "/wp-includes/"),
		"react":       strings.Contains(lower, "react") || strings.Contains(lower, "__react") || strings.Contains(scriptText, "react"),
		"vue":         strings.Contains(lower, "data-v-") || strings.Contains(lower, "__vue__") || strings.Contains(scriptText, "vue"),
		"angular":     strings.Contains(lower, "ng-version") || strings.Contains(lower, "ng-app") || strings.Contains(scriptText, "angular"),
		"nuxt":        strings.Contains(lower, "__nuxt") || strings.Contains(scriptText, "/_nuxt/"),
		"sveltekit":   strings.Contains(lower, "__sveltekit") || strings.Contains(scriptText, "/_app/immutable/"),
		"django":      strings.Contains(lower, "csrfmiddlewaretoken") || strings.Contains(lower, "django"),
		"dotnet":      strings.Contains(lower, "__aspnetcore") || strings.Contains(lower, "asp.net") || strings.Contains(scriptText, "aspnet"),
		"vite":        strings.Contains(lower, "/@vite/client") || strings.Contains(lower, "__vite") || strings.Contains(scriptText, "vite"),
		"remix":       strings.Contains(lower, "__remixcontext") || strings.Contains(scriptText, "@remix-run") || strings.Contains(lower, "remix"),
		"wix":         strings.Contains(lower, "wix") || strings.Contains(scriptText, "wixstatic.com") || strings.Contains(lower, "wix-bi-session"),
		"supabase":    strings.Contains(lower, "supabase") || strings.Contains(scriptText, "supabase.co"),
		"s3_public":   strings.Contains(lower, "s3.amazonaws.com") || strings.Contains(scriptText, ".s3."),
		"r2_public":   strings.Contains(lower, ".r2.dev") || strings.Contains(lower, ".r2.cloudflarestorage.com") || strings.Contains(scriptText, "r2.dev"),
		"mongodb":     strings.Contains(lower, "mongodb") || strings.Contains(scriptText, "mongodb.net"),
		"neon":        strings.Contains(lower, "neon.tech") || strings.Contains(scriptText, "neon.tech"),
	}
}

func containsVersion(value string) bool {
	return versionPattern.MatchString(value)
}

func extractNextVersion(value string) string {
	matches := nextVersionPattern.FindStringSubmatch(value)
	if len(matches) < 2 {
		return ""
	}
	return normalizeVersion(matches[1])
}

func extractWordPressVersion(value string) string {
	matches := wordpressVersionPattern.FindStringSubmatch(value)
	if len(matches) < 2 {
		return ""
	}
	return normalizeVersion(matches[1])
}

func extractDjangoVersion(value string) string {
	matches := djangoVersionPattern.FindStringSubmatch(value)
	if len(matches) < 2 {
		return ""
	}
	return normalizeVersion(matches[1])
}

func extractDotNetVersion(value string) string {
	matches := dotNetVersionPattern.FindStringSubmatch(value)
	if len(matches) < 2 {
		return ""
	}
	return normalizeVersion(matches[1])
}

func extractVersion(value string) string {
	matches := versionPattern.FindStringSubmatch(value)
	if len(matches) == 0 {
		return ""
	}
	return normalizeVersion(matches[0])
}

func normalizeVersion(value string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "v")
}

func productFromPoweredBy(value string) string {
	if strings.Contains(strings.ToLower(value), "next") {
		return "next"
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func scriptSources(scripts []interface{}) []interface{} {
	sources := make([]interface{}, 0, len(scripts))
	for _, item := range scripts {
		script, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if src, ok := script["src"].(string); ok && src != "" {
			sources = append(sources, src)
		}
	}
	return sources
}

func scriptHostnames(scripts []interface{}) []interface{} {
	hosts := make([]string, 0)
	seen := map[string]struct{}{}
	for _, item := range scripts {
		script, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		host, _ := script["host"].(string)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)

	result := make([]interface{}, 0, len(hosts))
	for _, host := range hosts {
		result = append(result, host)
	}
	return result
}

func buildTechnologySummary(frameworks map[string]bool, versions map[string]string, hosting map[string]bool, tooling map[string]bool, serverHeader string, poweredBy string, generator string, scriptHosts []interface{}) map[string]interface{} {
	detectedFrameworks := make([]interface{}, 0)
	for _, name := range []string{"nextjs", "react", "wordpress", "vue", "angular", "nuxt", "sveltekit", "django", "dotnet", "vite", "remix", "wix"} {
		if frameworks[name] {
			detectedFrameworks = append(detectedFrameworks, name)
		}
	}

	detectedHosting := make([]interface{}, 0)
	for _, name := range []string{"cloudflare", "vercel", "netlify", "render", "flyio"} {
		if hosting[name] {
			detectedHosting = append(detectedHosting, name)
		}
	}

	detectedTooling := make([]interface{}, 0)
	for _, name := range []string{"supabase", "s3_public", "cloudflare_r2_public", "mongodb", "neon"} {
		if tooling[name] {
			detectedTooling = append(detectedTooling, name)
		}
	}

	cleanVersions := map[string]interface{}{}
	for key, value := range versions {
		if value != "" {
			cleanVersions[key] = value
		}
	}

	return map[string]interface{}{
		"frameworks":       detectedFrameworks,
		"versions":         cleanVersions,
		"hosting":          detectedHosting,
		"tooling":          detectedTooling,
		"server_header":    serverHeader,
		"x_powered_by":     poweredBy,
		"generator":        generator,
		"script_hosts":     scriptHosts,
		"confidence_basis": "headers, html markers, script paths, generator metadata",
	}
}

func confidenceForDerivedFramework(detected bool, derivedFromNext bool) string {
	if !detected {
		return models.ConfidenceMedium
	}
	if derivedFromNext {
		return models.ConfidenceHigh
	}
	return models.ConfidenceMedium
}

func resolveReference(baseURL string, raw string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return raw
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return base.ResolveReference(ref).String()
}

func hostname(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func isExternal(baseURL string, raw string) bool {
	baseHost := hostname(baseURL)
	refHost := hostname(resolveReference(baseURL, raw))
	return baseHost != "" && refHost != "" && baseHost != refHost
}
