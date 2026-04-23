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
	"github.com/MariusBobitiu/surface-lab/scanner-service/tools/common"
	"github.com/MariusBobitiu/surface-lab/scanner-service/utils"
)

const (
	httpTimeout      = 10 * time.Second
	expiringSoonDays = 30
)

func Check(ctx context.Context, target string) models.ToolResult {
	startedAt := time.Now()
	result := common.NewToolResult("tls/v1", target, "v1")

	httpTarget, httpsTarget, hostname, err := buildTargets(target)
	if err != nil {
		result.DurationMs = time.Since(startedAt).Milliseconds()
		result.Error = fmt.Sprintf("normalize target: %v", err)
		return result
	}

	result.Target = httpsTarget

	httpsReachable, certState := checkHTTPS(ctx, httpsTarget, hostname)
	tlsEvidenceID := common.AddEvidence(&result, "tls_summary", httpsTarget, map[string]interface{}{
		"https_reachable":   httpsReachable,
		"certificate_valid": certState.valid,
		"validation_error":  certState.validationError,
		"expires_at":        certState.expiresAtString(),
		"days_remaining":    certState.daysRemaining,
		"issuer":            certState.issuer,
		"subject":           certState.subject,
	})

	common.AddSignal(&result, models.SignalSecurityHTTPS, httpsReachable, models.ConfidenceHigh, "tls.handshake", tlsEvidenceID)
	common.AddSignal(&result, models.SignalSecurityTLSCertValid, certState.valid, models.ConfidenceHigh, "tls.handshake", tlsEvidenceID)

	expiringSoon := certState.valid && certState.daysRemaining >= 0 && certState.daysRemaining <= expiringSoonDays
	common.AddSignal(&result, models.SignalSecurityTLSCertExpiringSoon, expiringSoon, models.ConfidenceHigh, "tls.certificate", tlsEvidenceID)

	if !httpsReachable {
		summary := fmt.Sprintf("Unable to establish a usable HTTPS connection to %s.", httpsTarget)
		result.Findings = append(result.Findings, models.Finding{
			Type:         "https-unavailable",
			Category:     "transport_security",
			Title:        "HTTPS is not available",
			Summary:      summary,
			Severity:     models.SeverityHigh,
			Confidence:   models.ConfidenceHigh,
			Evidence:     summary,
			EvidenceRefs: []string{tlsEvidenceID},
			Details: map[string]interface{}{
				"target":       httpsTarget,
				"tool_version": "v1",
			},
		})
	}

	if httpsReachable && !certState.valid {
		summary := fmt.Sprintf("The TLS certificate could not be validated: %s.", certState.validationError)
		result.Findings = append(result.Findings, models.Finding{
			Type:         "invalid-tls-certificate",
			Category:     "transport_security",
			Title:        "TLS certificate is invalid",
			Summary:      summary,
			Severity:     models.SeverityHigh,
			Confidence:   models.ConfidenceHigh,
			Evidence:     summary,
			EvidenceRefs: []string{tlsEvidenceID},
			Details: map[string]interface{}{
				"target":       httpsTarget,
				"tool_version": "v1",
			},
		})
	}

	if expiringSoon {
		summary := fmt.Sprintf("The TLS certificate expires in %d days.", certState.daysRemaining)
		result.Findings = append(result.Findings, models.Finding{
			Type:         "certificate-expiring-soon",
			Category:     "transport_security",
			Title:        "TLS certificate expires soon",
			Summary:      summary,
			Severity:     models.SeverityMedium,
			Confidence:   models.ConfidenceHigh,
			Evidence:     summary,
			EvidenceRefs: []string{tlsEvidenceID},
			Details: map[string]interface{}{
				"cert_expires_at":     certState.expiresAtString(),
				"cert_days_remaining": certState.daysRemaining,
				"tool_version":        "v1",
			},
		})
	}

	redirectsToHTTPS, redirectURL, redirectStatus := checkHTTPRedirect(ctx, httpTarget)
	redirectEvidenceID := common.AddEvidence(&result, "http_redirect_probe", httpTarget, map[string]interface{}{
		"redirects_to_https": redirectsToHTTPS,
		"status_code":        redirectStatus,
		"location":           redirectURL,
	})
	common.AddSignal(&result, models.SignalSecurityHTTPRedirectsToHTTPS, redirectsToHTTPS, models.ConfidenceHigh, "tls.http_redirect", redirectEvidenceID)

	if !redirectsToHTTPS {
		summary := fmt.Sprintf("%s did not redirect to an HTTPS URL.", httpTarget)
		result.Findings = append(result.Findings, models.Finding{
			Type:         "no-http-to-https-redirect",
			Category:     "transport_security",
			Title:        "HTTP does not redirect to HTTPS",
			Summary:      summary,
			Severity:     models.SeverityMedium,
			Confidence:   models.ConfidenceMedium,
			Evidence:     summary,
			EvidenceRefs: []string{redirectEvidenceID},
			Details: map[string]interface{}{
				"target":       httpTarget,
				"tool_version": "v1",
			},
		})
	}

	result.Metadata["https_target"] = httpsTarget
	result.Metadata["http_target"] = httpTarget
	result.DurationMs = time.Since(startedAt).Milliseconds()
	result.Status = models.StatusSuccess
	return result
}

type certificateState struct {
	valid           bool
	expiresAt       *time.Time
	daysRemaining   int64
	validationError string
	issuer          string
	subject         string
}

func (c certificateState) expiresAtString() string {
	if c.expiresAt == nil {
		return ""
	}

	return c.expiresAt.UTC().Format(time.RFC3339)
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

func checkHTTPRedirect(ctx context.Context, httpTarget string) (bool, string, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpTarget, nil)
	if err != nil {
		return false, "", 0
	}

	req.Header.Set("User-Agent", utils.DefaultUserAgent)

	resp, err := utils.NewHTTPClientNoRedirect(httpTimeout).Do(req)
	if err != nil {
		return false, "", 0
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if location == "" {
		return false, "", resp.StatusCode
	}

	redirectURL, err := resp.Location()
	if err != nil {
		return false, location, resp.StatusCode
	}

	if strings.EqualFold(redirectURL.Scheme, "https") {
		return true, redirectURL.String(), resp.StatusCode
	}

	return false, redirectURL.String(), resp.StatusCode
}

func populateCertificateState(state *certificateState, cert *x509.Certificate) {
	expiresAt := cert.NotAfter.UTC()
	state.expiresAt = &expiresAt
	state.daysRemaining = int64(time.Until(expiresAt).Hours() / 24)
	state.issuer = cert.Issuer.String()
	state.subject = cert.Subject.String()
}
