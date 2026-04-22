package main

import (
	"log/slog"
	"net"
	"os"

	"github.com/MariusBobitiu/surface-lab/wp-stack/config"
	wpstackgrpc "github.com/MariusBobitiu/surface-lab/wp-stack/transport/grpc"
	"github.com/MariusBobitiu/surface-lab/wp-stack/utils"
)

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		slog.Error("invalid wp-stack config", "error", err)
		os.Exit(1)
	}

	logger := utils.NewLogger("wp-stack", cfg.Environment)
	slog.SetDefault(logger)

	lis, err := net.Listen("tcp", cfg.Address())
	if err != nil {
		logger.Error("listen failed", "address", cfg.Address(), "error", err)
		os.Exit(1)
	}

	server, err := wpstackgrpc.NewServer(logger, wpstackgrpc.ServerOptions{
		ServiceToken:          cfg.ServiceToken,
		TLSEnabled:            cfg.GRPCTLSEnabled,
		TLSCertFile:           cfg.GRPCTLSCertFile,
		TLSKeyFile:            cfg.GRPCTLSKeyFile,
		RateLimitRPS:          cfg.RateLimitRPS,
		RateLimitBurst:        cfg.RateLimitBurst,
		MaxConcurrentRequests: cfg.MaxConcurrentRequests,
		RequestTimeout:        cfg.RequestTimeout,
		EnableReflection:      cfg.IsDevelopment(),
	})
	if err != nil {
		logger.Error("create gRPC server failed", "error", err)
		os.Exit(1)
	}

	logger.Info(
		"wp-stack gRPC server listening",
		"address", cfg.Address(),
		"env", cfg.Environment,
		"reflection_enabled", cfg.IsDevelopment(),
		"tls_enabled", cfg.GRPCTLSEnabled,
	)

	if err := server.Serve(lis); err != nil {
		logger.Error("serve gRPC failed", "error", err)
		os.Exit(1)
	}
}
