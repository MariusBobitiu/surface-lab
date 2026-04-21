package grpc

import (
	"crypto/tls"
	"fmt"
	"log"
	"time"

	"github.com/MariusBobitiu/surface-lab/scanner-service/db"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

type ServerOptions struct {
	ServiceToken          string
	TLSEnabled            bool
	TLSCertFile           string
	TLSKeyFile            string
	TLSCAFile             string
	RateLimitRPS          float64
	RateLimitBurst        int
	MaxConcurrentRequests int
	RequestTimeout        time.Duration
	EnableReflection      bool
}

func NewServer(dbClient *db.Client, opts ServerOptions) (*grpc.Server, error) {
	// The scanner only exposes internal gRPC methods and should not be internet-facing.
	serverOptions := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			authUnaryInterceptor(opts.ServiceToken),
			rateLimitUnaryInterceptor(newTokenBucketLimiter(opts.RateLimitRPS, opts.RateLimitBurst)),
			protectionUnaryInterceptor(newConcurrencyLimiter(opts.MaxConcurrentRequests), opts.RequestTimeout),
		),
	}

	if opts.TLSEnabled {
		tlsConfig, err := loadServerTLSConfig(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			return nil, err
		}

		serverOptions = append(serverOptions, grpc.Creds(credentials.NewTLS(tlsConfig)))
		log.Printf("msg=%q cert_file=%s key_file=%s", "scanner gRPC TLS enabled", opts.TLSCertFile, opts.TLSKeyFile)
	} else {
		log.Printf("msg=%q", "scanner gRPC TLS disabled")
	}

	server := grpc.NewServer(serverOptions...)
	RegisterToolServiceServer(server, NewToolServiceServer(dbClient))
	if opts.EnableReflection {
		reflection.Register(server)
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
