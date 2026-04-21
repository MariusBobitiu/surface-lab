package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultPort = 50051

type Config struct {
	Port                  int
	DatabaseURL           string
	Environment           string
	ServiceToken          string
	RateLimitRPS          float64
	RateLimitBurst        int
	MaxConcurrentRequests int
	RequestTimeout        time.Duration
}

func Load() Config {
	if err := loadEnvFiles(defaultEnvFiles); err != nil {
		log.Printf("load env files: %v", err)
	}

	cfg := Config{
		Port:                  getEnvInt("GRPC_PORT", defaultPort),
		DatabaseURL:           os.Getenv("DATABASE_URL"),
		Environment:           normalizeEnvironment(os.Getenv("APP_ENV")),
		ServiceToken:          strings.TrimSpace(os.Getenv("SCANNER_SERVICE_TOKEN")),
		RateLimitRPS:          getEnvFloat("SCANNER_RATE_LIMIT_RPS", 5),
		RateLimitBurst:        getEnvInt("SCANNER_RATE_LIMIT_BURST", 10),
		MaxConcurrentRequests: getEnvInt("SCANNER_MAX_CONCURRENT_REQUESTS", 4),
		RequestTimeout:        time.Duration(getEnvInt("SCANNER_REQUEST_TIMEOUT_SECONDS", 30)) * time.Second,
	}

	if cfg.IsDevelopment() && cfg.ServiceToken == "" {
		cfg.ServiceToken = "dev-scanner-token"
	}

	return cfg
}

func (c Config) Address() string {
	return fmt.Sprintf(":%d", c.Port)
}

func (c Config) IsDevelopment() bool {
	return c.Environment == "development"
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.DatabaseURL) == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}

	if strings.TrimSpace(c.ServiceToken) == "" {
		if c.IsDevelopment() {
			return nil
		}

		return fmt.Errorf("SCANNER_SERVICE_TOKEN is required when APP_ENV is not development")
	}

	if c.RateLimitRPS <= 0 {
		return fmt.Errorf("SCANNER_RATE_LIMIT_RPS must be greater than 0")
	}

	if c.RateLimitBurst <= 0 {
		return fmt.Errorf("SCANNER_RATE_LIMIT_BURST must be greater than 0")
	}

	if c.MaxConcurrentRequests <= 0 {
		return fmt.Errorf("SCANNER_MAX_CONCURRENT_REQUESTS must be greater than 0")
	}

	if c.RequestTimeout <= 0 {
		return fmt.Errorf("SCANNER_REQUEST_TIMEOUT_SECONDS must be greater than 0")
	}

	return nil
}

func getEnvInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return fallback
	}

	return parsed
}

func getEnvFloat(key string, fallback float64) float64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	parsed, err := strconv.ParseFloat(raw, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}

	return parsed
}

func normalizeEnvironment(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return "development"
	}

	return normalized
}
