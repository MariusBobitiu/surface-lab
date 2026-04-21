package v1

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
	"github.com/MariusBobitiu/surface-lab/scanner-service/utils"
)

const (
	httpTimeout      = 10 * time.Second
	expiringSoonDays = 30
)

func Check(ctx context.Context, target string) models.ToolResult {
	startedAt := time.Now()
	result := models.ToolResult{
		Tool:     "tls/v1",
		Target:   target,
		Status:   models.StatusFailed,
		Findings: []models.Finding{},
		Metadata: map[string]interface{}{
			"tool_version": "v1",
		},
	}

	httpTarget, httpsTarget, hostname, err := buildTargets(target)
	if err != nil {
		result.DurationMs = time.Since(startedAt).Milliseconds()
		result.Error = fmt.Sprintf("normalize target: %v", err)
		return result
	}

	result.Target = httpsTarget

	httpsReachable, certState := checkHTTPS(ctx, httpsTarget, hostname)
	result.Metadata["https_reachable"] = httpsReachable
	result.Metadata["certificate_valid"] = certState.valid

	if certState.expiresAt != nil {
		result.Metadata["cert_expires_at"] = certState.expiresAt.UTC().Format(time.RFC3339)
		result.Metadata["cert_days_remaining"] = certState.daysRemaining
	}

	if !httpsReachable {
		result.Findings = append(result.Findings, models.Finding{
			Type:       "https_unavailable",
			Category:   "transport_security",
			Title:      "HTTPS is not available",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceHigh,
			Evidence:   fmt.Sprintf("unable to establish a usable HTTPS connection to %s", httpsTarget),
			Details: map[string]interface{}{
				"target":       httpsTarget,
				"tool_version": "v1",
			},
		})
	}

	if httpsReachable && !certState.valid {
		result.Findings = append(result.Findings, models.Finding{
			Type:       "invalid_certificate",
			Category:   "transport_security",
			Title:      "TLS certificate is invalid",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceHigh,
			Evidence:   certState.validationError,
			Details: map[string]interface{}{
				"target":       httpsTarget,
				"tool_version": "v1",
			},
		})
	}

	if certState.valid && certState.daysRemaining >= 0 && certState.daysRemaining <= expiringSoonDays {
		result.Findings = append(result.Findings, models.Finding{
			Type:       "certificate_expiring_soon",
			Category:   "transport_security",
			Title:      "TLS certificate expires soon",
			Severity:   models.SeverityMedium,
			Confidence: models.ConfidenceHigh,
			Evidence:   fmt.Sprintf("certificate expires in %d days", certState.daysRemaining),
			Details: map[string]interface{}{
				"cert_expires_at":     certState.expiresAt.UTC().Format(time.RFC3339),
				"cert_days_remaining": certState.daysRemaining,
				"tool_version":        "v1",
			},
		})
	}

	redirectsToHTTPS, redirectURL := checkHTTPRedirect(ctx, httpTarget)
	result.Metadata["http_redirects_to_https"] = redirectsToHTTPS
	if redirectURL != "" {
		result.Metadata["http_redirect_location"] = redirectURL
	}

	if !redirectsToHTTPS {
		result.Findings = append(result.Findings, models.Finding{
			Type:       "missing_https_redirect",
			Category:   "transport_security",
			Title:      "HTTP does not redirect to HTTPS",
			Severity:   models.SeverityMedium,
			Confidence: models.ConfidenceMedium,
			Evidence:   fmt.Sprintf("%s did not redirect to an HTTPS URL", httpTarget),
			Details: map[string]interface{}{
				"target":       httpTarget,
				"tool_version": "v1",
			},
		})
	}

	result.DurationMs = time.Since(startedAt).Milliseconds()
	result.Status = models.StatusSuccess
	return result
}

type certificateState struct {
	valid           bool
	expiresAt       *time.Time
	daysRemaining   int64
	validationError string
}

func buildTargets(target string) (string, string, string, error) {
	normalized := utils.NormalizeTarget(target, "https")
	parsed, err := url.Parse(normalized)
	if err != nil {
		return "", "", "", err
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return "", "", "", fmt.Errorf("missing hostname")
	}

	httpURL := *parsed
	httpURL.Scheme = "http"
	httpsURL := *parsed
	httpsURL.Scheme = "https"

	return httpURL.String(), httpsURL.String(), hostname, nil
}

func checkHTTPS(ctx context.Context, httpsTarget string, hostname string) (bool, certificateState) {
	state := certificateState{}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpsTarget, nil)
	if err == nil {
		req.Header.Set("User-Agent", utils.DefaultUserAgent)
		resp, reqErr := utils.NewHTTPClient(httpTimeout).Do(req)
		if reqErr == nil {
			defer resp.Body.Close()
			state.valid = true
			if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
				populateCertificateState(&state, resp.TLS.PeerCertificates[0])
			}
			return true, state
		}

		state.validationError = reqErr.Error()
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: httpTimeout},
		Config: &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true,
		},
	}

	conn, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(hostname, "443"))
	if dialErr != nil {
		if state.validationError == "" {
			state.validationError = dialErr.Error()
		}
		return false, state
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		if state.validationError == "" {
			state.validationError = "connection is not TLS"
		}
		return false, state
	}

	connectionState := tlsConn.ConnectionState()
	if len(connectionState.PeerCertificates) == 0 {
		if state.validationError == "" {
			state.validationError = "no peer certificate presented"
		}
		return true, state
	}

	populateCertificateState(&state, connectionState.PeerCertificates[0])
	if state.validationError == "" {
		state.validationError = "certificate validation failed"
	}

	return true, state
}

func checkHTTPRedirect(ctx context.Context, httpTarget string) (bool, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpTarget, nil)
	if err != nil {
		return false, ""
	}

	req.Header.Set("User-Agent", utils.DefaultUserAgent)

	resp, err := utils.NewHTTPClientNoRedirect(httpTimeout).Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if location == "" {
		return false, ""
	}

	redirectURL, err := resp.Location()
	if err != nil {
		return false, location
	}

	if strings.EqualFold(redirectURL.Scheme, "https") {
		return true, redirectURL.String()
	}

	return false, redirectURL.String()
}

func populateCertificateState(state *certificateState, cert *x509.Certificate) {
	expiresAt := cert.NotAfter.UTC()
	state.expiresAt = &expiresAt
	state.daysRemaining = int64(time.Until(expiresAt).Hours() / 24)
}
