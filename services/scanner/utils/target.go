package utils

import (
	"net/url"
	"strings"
)

func NormalizeTarget(target string, defaultScheme string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err == nil && parsed.Scheme != "" {
		return trimmed
	}

	return defaultScheme + "://" + trimmed
}

func NormalizeBaseURL(target string, defaultScheme string) (*url.URL, error) {
	normalized := NormalizeTarget(target, defaultScheme)
	parsed, err := url.Parse(normalized)
	if err != nil {
		return nil, err
	}

	parsed.Path = ""
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return parsed, nil
}
