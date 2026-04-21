package grpc

import (
	"time"

	"github.com/MariusBobitiu/surface-lab/scanner-service/db"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type ServerOptions struct {
	ServiceToken          string
	RateLimitRPS          float64
	RateLimitBurst        int
	MaxConcurrentRequests int
	RequestTimeout        time.Duration
	EnableReflection      bool
}

func NewServer(dbClient *db.Client, opts ServerOptions) *grpc.Server {
	// The scanner only exposes internal gRPC methods and should not be internet-facing.
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(
		authUnaryInterceptor(opts.ServiceToken),
		rateLimitUnaryInterceptor(newTokenBucketLimiter(opts.RateLimitRPS, opts.RateLimitBurst)),
		protectionUnaryInterceptor(newConcurrencyLimiter(opts.MaxConcurrentRequests), opts.RequestTimeout),
	))
	RegisterToolServiceServer(server, NewToolServiceServer(dbClient))
	if opts.EnableReflection {
		reflection.Register(server)
	}
	return server
}
