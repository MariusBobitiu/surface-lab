package utils

import (
	"log/slog"
	"os"
)

func NewLogger(serviceName string, environment string) *slog.Logger {
	level := slog.LevelInfo
	if environment == "development" {
		level = slog.LevelDebug
	}

	handlerOptions := &slog.HandlerOptions{
		Level: level,
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, handlerOptions)).With(
		"service", serviceName,
		"component", "grpc",
	)
}
