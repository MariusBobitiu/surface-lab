package v1

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
	"github.com/MariusBobitiu/surface-lab/scanner-service/tools/common"
	"github.com/MariusBobitiu/surface-lab/scanner-service/utils"
)

const targetingTimeout = 10 * time.Second

type Resolution struct {
	CanonicalTarget string
	Result          models.ToolResult
}

func Check(ctx context.Context, target string) Resolution {
	startedAt := time.Now()
	result := common.NewToolResult("targeting/v1", target, "v1")

	normalizedTarget := utils.NormalizeTarget(target, "https")
	result.Target = normalizedTarget

	finalURL, redirects, err := resolveCanonicalURL(ctx, normalizedTarget)
	if err != nil {
		httpFallback := utils.NormalizeTarget(target, "http")
		if httpFallback != normalizedTarget {
			finalURL, redirects, err = resolveCanonicalURL(ctx, httpFallback)
		}
	}
	if err != nil {
		result.DurationMs = time.Since(startedAt).Milliseconds()
		result.Error = fmt.Sprintf("resolve target: %v", err)
		return Resolution{CanonicalTarget: normalizedTarget, Result: result}
	}

	redirectEvidenceID := common.AddEvidence(&result, "redirect_chain", finalURL, map[string]interface{}{
		"requested_target": normalizedTarget,
		"final_url":        finalURL,
		"redirect_chain":   redirects,
	})

	redirected := len(redirects) > 0
	common.AddSignal(&result, models.SignalTransportRedirected, redirected, models.ConfidenceHigh, "targeting.redirect_chain", redirectEvidenceID)
	common.AddSignal(&result, models.SignalTransportCanonicalURL, finalURL, models.ConfidenceHigh, "targeting.redirect_chain", redirectEvidenceID)

	result.Metadata["requested_target"] = normalizedTarget
	result.Metadata["canonical_target"] = finalURL
	result.Metadata["redirect_chain"] = redirects
	result.DurationMs = time.Since(startedAt).Milliseconds()
	result.Status = models.StatusSuccess

	return Resolution{
		CanonicalTarget: finalURL,
		Result:          result,
	}
}

func resolveCanonicalURL(ctx context.Context, input string) (string, []interface{}, error) {
	current := input
	redirects := make([]interface{}, 0, 4)
	client := utils.NewHTTPClientNoRedirect(targetingTimeout)

	for attempts := 0; attempts < 10; attempts++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return "", redirects, err
		}
		req.Header.Set("User-Agent", utils.DefaultUserAgent)

		resp, err := client.Do(req)
		if err != nil {
			return "", redirects, err
		}

		location := resp.Header.Get("Location")
		finalURL := resp.Request.URL.String()
		statusCode := resp.StatusCode
		resp.Body.Close()

		if location == "" || statusCode < 300 || statusCode >= 400 {
			return finalURL, redirects, nil
		}

		nextURL, err := resolveLocation(finalURL, location)
		if err != nil {
			return finalURL, redirects, nil
		}

		redirects = append(redirects, map[string]interface{}{
			"from":        finalURL,
			"status_code": statusCode,
			"location":    location,
			"to":          nextURL,
		})

		if nextURL == current {
			return finalURL, redirects, nil
		}

		current = nextURL
	}

	return current, redirects, nil
}

func resolveLocation(baseURL string, location string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	next, err := url.Parse(location)
	if err != nil {
		return "", err
	}

	return base.ResolveReference(next).String(), nil
}
