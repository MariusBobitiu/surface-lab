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
		w.Header().Set("X-Powered-By", "Next.js 14.2.24")
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
	assertSignalString(t, result.Signals, models.SignalFrameworkNextJSVersion, "14.2.24")
	assertSignalString(t, result.Signals, models.SignalFrameworkWordPressVersion, "6.5")
	assertSignalValue(t, result.Signals, models.SignalHostingCloudflare, true)
	assertSignalValue(t, result.Signals, models.SignalAssetsNextStatic, true)
	assertSignalValue(t, result.Signals, models.SignalFrameworkReact, true)

	if len(result.Evidence) == 0 {
		t.Fatalf("expected evidence to be recorded")
	}
}

func TestCheckEmitsExpandedStackAndToolingSignals(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "render")
		w.Header().Set("X-Render-Origin-Server", "render")
		w.Header().Set("Fly-Request-Id", "fly")
		w.Header().Set("X-AspNet-Version", "4.0.30319")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head></head><body>
			<div id="app" data-v-app></div>
			<script src="/@vite/client"></script>
			<script src="https://cdn.jsdelivr.net/npm/@remix-run/router"></script>
			<script src="https://static.wixstatic.com/media/app.js"></script>
			<script src="https://example-bucket.s3.amazonaws.com/public.js"></script>
			<script src="https://public-assets.r2.dev/client.js"></script>
			<script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js"></script>
			<script src="https://cdn.mongodb.com/widget.js"></script>
			<script src="https://cdn.neon.tech/sdk.js"></script>
			<form><input type="hidden" name="csrfmiddlewaretoken" value="x"></form>
		</body></html>`))
	}))
	defer server.Close()

	result := Check(context.Background(), server.URL)

	if result.Status != models.StatusSuccess {
		t.Fatalf("expected success status, got %s", result.Status)
	}

	assertSignalValue(t, result.Signals, models.SignalFrameworkDjango, true)
	assertSignalValue(t, result.Signals, models.SignalFrameworkDotNet, true)
	assertSignalValue(t, result.Signals, models.SignalFrameworkVite, true)
	assertSignalValue(t, result.Signals, models.SignalFrameworkRemix, true)
	assertSignalValue(t, result.Signals, models.SignalFrameworkWix, true)
	assertSignalValue(t, result.Signals, models.SignalHostingRender, true)
	assertSignalValue(t, result.Signals, models.SignalHostingFlyIO, true)
	assertSignalValue(t, result.Signals, models.SignalToolingSupabase, true)
	assertSignalValue(t, result.Signals, models.SignalToolingS3Public, true)
	assertSignalValue(t, result.Signals, models.SignalToolingCloudflareR2Public, true)
	assertSignalValue(t, result.Signals, models.SignalToolingMongoDB, true)
	assertSignalValue(t, result.Signals, models.SignalToolingNeon, true)
}

func assertSignalString(t *testing.T, signals []models.Signal, key string, expected string) {
	t.Helper()
	for _, signal := range signals {
		if signal.Key != key {
			continue
		}
		value, ok := signal.Value.(string)
		if !ok {
			t.Fatalf("signal %s had non-string value %#v", key, signal.Value)
		}
		if value != expected {
			t.Fatalf("signal %s expected %q, got %q", key, expected, value)
		}
		return
	}

	t.Fatalf("signal %s not found", key)
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
