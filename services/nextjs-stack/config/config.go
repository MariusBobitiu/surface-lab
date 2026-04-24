package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultPort = 50061

type Config struct {
	Port                  int
	Environment           string
	ServiceToken          string
	GRPCTLSEnabled        bool
	GRPCTLSCertFile       string
	GRPCTLSKeyFile        string
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
		Environment:           normalizeEnvironment(os.Getenv("APP_ENV")),
		ServiceToken:          strings.TrimSpace(os.Getenv("SERVICE_TOKEN")),
		GRPCTLSEnabled:        getEnvBool("GRPC_TLS_ENABLED", false),
		GRPCTLSCertFile:       strings.TrimSpace(os.Getenv("GRPC_TLS_CERT_FILE")),
		GRPCTLSKeyFile:        strings.TrimSpace(os.Getenv("GRPC_TLS_KEY_FILE")),
		RateLimitRPS:          getEnvFloat("RATE_LIMIT_RPS", 5),
		RateLimitBurst:        getEnvInt("RATE_LIMIT_BURST", 10),
		MaxConcurrentRequests: getEnvInt("MAX_CONCURRENT_REQUESTS", 4),
		RequestTimeout:        time.Duration(getEnvInt("REQUEST_TIMEOUT_SECONDS", 30)) * time.Second,
	}

	if cfg.IsDevelopment() && cfg.ServiceToken == "" {
		cfg.ServiceToken = "dev-nextjs-stack-token"
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
	if strings.TrimSpace(c.ServiceToken) == "" {
		if c.IsDevelopment() {
			return nil
		}

		return fmt.Errorf("SERVICE_TOKEN is required when APP_ENV is not development")
	}

	if c.GRPCTLSEnabled {
		if c.GRPCTLSCertFile == "" {
			return fmt.Errorf("GRPC_TLS_CERT_FILE is required when GRPC_TLS_ENABLED=true")
		}

		if c.GRPCTLSKeyFile == "" {
			return fmt.Errorf("GRPC_TLS_KEY_FILE is required when GRPC_TLS_ENABLED=true")
		}
	}

	if c.RateLimitRPS <= 0 {
		return fmt.Errorf("RATE_LIMIT_RPS must be greater than 0")
	}

	if c.RateLimitBurst <= 0 {
		return fmt.Errorf("RATE_LIMIT_BURST must be greater than 0")
	}

	if c.MaxConcurrentRequests <= 0 {
		return fmt.Errorf("MAX_CONCURRENT_REQUESTS must be greater than 0")
	}

	if c.RequestTimeout <= 0 {
		return fmt.Errorf("REQUEST_TIMEOUT_SECONDS must be greater than 0")
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

func getEnvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func normalizeEnvironment(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return "development"
	}

	return normalized
}
