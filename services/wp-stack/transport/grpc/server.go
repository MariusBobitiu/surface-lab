package grpc

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

type ServerOptions struct {
	ServiceToken          string
	TLSEnabled            bool
	TLSCertFile           string
	TLSKeyFile            string
	RateLimitRPS          float64
	RateLimitBurst        int
	MaxConcurrentRequests int
	RequestTimeout        time.Duration
	EnableReflection      bool
}

func NewServer(logger *slog.Logger, opts ServerOptions) (*grpc.Server, error) {
	serverOptions := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			requestLoggingUnaryInterceptor(logger),
			authUnaryInterceptor(logger, opts.ServiceToken),
			rateLimitUnaryInterceptor(logger, newTokenBucketLimiter(opts.RateLimitRPS, opts.RateLimitBurst)),
			protectionUnaryInterceptor(logger, newConcurrencyLimiter(opts.MaxConcurrentRequests), opts.RequestTimeout),
		),
	}

	if opts.TLSEnabled {
		tlsConfig, err := loadServerTLSConfig(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			return nil, err
		}

		serverOptions = append(serverOptions, grpc.Creds(credentials.NewTLS(tlsConfig)))
		logger.Info("gRPC TLS enabled", "cert_file", opts.TLSCertFile, "key_file", opts.TLSKeyFile)
	} else {
		logger.Info("gRPC TLS disabled")
	}

	server := grpc.NewServer(serverOptions...)
	RegisterWordPressStackServiceServer(server, NewWordPressStackServiceServer(logger))
	if opts.EnableReflection {
		reflection.Register(server)
		logger.Debug("gRPC reflection enabled")
	}

	return server, nil
}

func loadServerTLSConfig(certFile string, keyFile string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load gRPC TLS certificate: %w", err)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}, nil
}
