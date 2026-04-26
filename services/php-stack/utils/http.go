package utils

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultUserAgent = "SurfaceLab-PHP-Stack/1.0"

func NewHTTPClient(timeout time.Duration) *http.Client {
	return newHTTPClient(timeout, true)
}

func NewHTTPClientNoRedirect(timeout time.Duration) *http.Client {
	return newHTTPClient(timeout, false)
}

func newHTTPClient(timeout time.Duration, followRedirects bool) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !followRedirects {
				return http.ErrUseLastResponse
			}

			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}

			req.Header.Set("User-Agent", DefaultUserAgent)
			return nil
		},
	}
}

func NormalizeTarget(target string) (string, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return "", url.InvalidHostError("")
	}

	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}

	if parsed.Host == "" {
		return "", url.InvalidHostError(trimmed)
	}

	if parsed.Path == "" {
		parsed.Path = "/"
	}

	return parsed.String(), nil
}
