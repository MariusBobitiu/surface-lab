package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
)

func TestCheckEmitsFrameworkAndHostingSignals(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("X-Powered-By", "Next.js")
		w.Header().Set("CF-Ray", "test")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.5"></head><body><script src="/_next/static/app.js"></script></body></html>`))
	}))
	defer server.Close()

	result := Check(context.Background(), server.URL)

	if result.Status != models.StatusSuccess {
		t.Fatalf("expected success status, got %s", result.Status)
	}

	assertSignalValue(t, result.Signals, models.SignalFrameworkWordPress, true)
	assertSignalValue(t, result.Signals, models.SignalFrameworkNextJS, true)
	assertSignalValue(t, result.Signals, models.SignalHostingCloudflare, true)
	assertSignalValue(t, result.Signals, models.SignalAssetsNextStatic, true)

	if len(result.Evidence) == 0 {
		t.Fatalf("expected evidence to be recorded")
	}
}

func assertSignalValue(t *testing.T, signals []models.Signal, key string, expected bool) {
	t.Helper()
	for _, signal := range signals {
		if signal.Key != key {
			continue
		}
		value, ok := signal.Value.(bool)
		if !ok {
			t.Fatalf("signal %s had non-bool value %#v", key, signal.Value)
		}
		if value != expected {
			t.Fatalf("signal %s expected %v, got %v", key, expected, value)
		}
		return
	}

	t.Fatalf("signal %s not found", key)
}
