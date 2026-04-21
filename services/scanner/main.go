package main

import (
	"context"
	"log"
	"net"

	"github.com/MariusBobitiu/surface-lab/scanner-service/config"
	"github.com/MariusBobitiu/surface-lab/scanner-service/db"
	scannergrpc "github.com/MariusBobitiu/surface-lab/scanner-service/transport/grpc"
)

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid scanner config: %v", err)
	}

	ctx := context.Background()

	dbClient, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer dbClient.Close()

	lis, err := net.Listen("tcp", cfg.Address())
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.Address(), err)
	}

	server, err := scannergrpc.NewServer(dbClient, scannergrpc.ServerOptions{
		ServiceToken:          cfg.ServiceToken,
		TLSEnabled:            cfg.GRPCTLSEnabled,
		TLSCertFile:           cfg.GRPCTLSCertFile,
		TLSKeyFile:            cfg.GRPCTLSKeyFile,
		TLSCAFile:             cfg.GRPCTLSCAFile,
		RateLimitRPS:          cfg.RateLimitRPS,
		RateLimitBurst:        cfg.RateLimitBurst,
		MaxConcurrentRequests: cfg.MaxConcurrentRequests,
		RequestTimeout:        cfg.RequestTimeout,
		EnableReflection:      cfg.IsDevelopment(),
	})
	if err != nil {
		log.Fatalf("create gRPC server: %v", err)
	}

	log.Printf(
		"msg=%q address=%s env=%s reflection_enabled=%t tls_enabled=%t internal_only=%t",
		"scanner gRPC server listening",
		cfg.Address(),
		cfg.Environment,
		cfg.IsDevelopment(),
		cfg.GRPCTLSEnabled,
		true,
	)

	if err := server.Serve(lis); err != nil {
		log.Fatalf("serve gRPC: %v", err)
	}
}
