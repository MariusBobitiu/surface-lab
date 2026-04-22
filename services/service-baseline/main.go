package main

import (
	"log/slog"
	"net"
	"os"

	"github.com/MariusBobitiu/surface-lab/service-baseline/config"
	baselinegrpc "github.com/MariusBobitiu/surface-lab/service-baseline/transport/grpc"
	"github.com/MariusBobitiu/surface-lab/service-baseline/utils"
)

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		slog.Error("invalid service-baseline config", "error", err)
		os.Exit(1)
	}

	logger := utils.NewLogger("service-baseline", cfg.Environment)
	slog.SetDefault(logger)

	lis, err := net.Listen("tcp", cfg.Address())
	if err != nil {
		logger.Error("listen failed", "address", cfg.Address(), "error", err)
		os.Exit(1)
	}

	server, err := baselinegrpc.NewServer(logger, baselinegrpc.ServerOptions{
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
		"service-baseline gRPC server listening",
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
