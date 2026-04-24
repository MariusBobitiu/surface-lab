package main

import (
	"log/slog"
	"net"
	"os"

	"github.com/MariusBobitiu/surface-lab/nextjs-stack/config"
	nextjsgrpc "github.com/MariusBobitiu/surface-lab/nextjs-stack/transport/grpc"
	"github.com/MariusBobitiu/surface-lab/nextjs-stack/utils"
)

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		slog.Error("invalid nextjs-stack config", "error", err)
		os.Exit(1)
	}

	logger := utils.NewLogger("nextjs-stack", cfg.Environment)
	slog.SetDefault(logger)

	lis, err := net.Listen("tcp", cfg.Address())
	if err != nil {
		logger.Error("listen failed", "address", cfg.Address(), "error", err)
		os.Exit(1)
	}

	server, err := nextjsgrpc.NewServer(logger, nextjsgrpc.ServerOptions{
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
		"nextjs-stack gRPC server listening",
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
