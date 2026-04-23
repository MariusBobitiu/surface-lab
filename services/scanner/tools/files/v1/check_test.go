package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
)

func TestCheckEmitsExposureAndSurfaceSignals(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("APP_KEY=test"))
		case "/login":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>Login</html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result := Check(context.Background(), server.URL)

	if result.Status != models.StatusSuccess {
		t.Fatalf("expected success status, got %s", result.Status)
	}

	assertFileSignal(t, result.Signals, models.SignalExposureEnvFile, true)
	assertFileSignal(t, result.Signals, models.SignalSurfaceLogin, true)
	assertFileSignal(t, result.Signals, models.SignalSurfaceAdmin, false)

	if len(result.Findings) == 0 {
		t.Fatalf("expected findings to be recorded")
	}
}

func assertFileSignal(t *testing.T, signals []models.Signal, key string, expected bool) {
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
