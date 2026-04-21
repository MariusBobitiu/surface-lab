package grpc

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func authUnaryInterceptor(expectedToken string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !isAuthorized(ctx, expectedToken) {
			log.Printf("msg=%q method=%s", "scanner unauthorized request", info.FullMethod)
			return nil, status.Error(codes.Unauthenticated, "missing or invalid service token")
		}

		return handler(ctx, req)
	}
}

func rateLimitUnaryInterceptor(limiter *tokenBucketLimiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !limiter.Allow() {
			log.Printf("msg=%q method=%s", "scanner rate limit exceeded", info.FullMethod)
			return nil, status.Error(codes.ResourceExhausted, "scanner rate limit exceeded")
		}

		return handler(ctx, req)
	}
}

func protectionUnaryInterceptor(limiter *concurrencyLimiter, timeout time.Duration) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !limiter.TryAcquire() {
			log.Printf("msg=%q method=%s", "scanner concurrency limit reached", info.FullMethod)
			return nil, status.Error(codes.ResourceExhausted, "scanner is at max concurrency")
		}
		defer limiter.Release()

		timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		resp, err := handler(timeoutCtx, req)
		if err == nil {
			return resp, nil
		}

		if errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			log.Printf("msg=%q method=%s timeout=%s", "scanner request timed out", info.FullMethod, timeout)
			return nil, status.Error(codes.DeadlineExceeded, "scanner request timed out")
		}

		return resp, err
	}
}

func isAuthorized(ctx context.Context, expectedToken string) bool {
	if strings.TrimSpace(expectedToken) == "" {
		return false
	}

	token := serviceTokenFromMetadata(ctx)
	if token == "" {
		return false
	}

	return token == expectedToken
}

func serviceTokenFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	if token := bearerToken(md.Get("authorization")); token != "" {
		return token
	}

	for _, value := range md.Get("x-service-token") {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}

	return ""
}

func bearerToken(values []string) string {
	for _, value := range values {
		parts := strings.SplitN(strings.TrimSpace(value), " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			continue
		}

		token := strings.TrimSpace(parts[1])
		if token != "" {
			return token
		}
	}

	return ""
}

type concurrencyLimiter struct {
	slots chan struct{}
}

func newConcurrencyLimiter(limit int) *concurrencyLimiter {
	return &concurrencyLimiter{
		slots: make(chan struct{}, limit),
	}
}

func (l *concurrencyLimiter) TryAcquire() bool {
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *concurrencyLimiter) Release() {
	select {
	case <-l.slots:
	default:
	}
}

type tokenBucketLimiter struct {
	mu         sync.Mutex
	rate       float64
	burst      float64
	tokens     float64
	lastRefill time.Time
}

func newTokenBucketLimiter(rate float64, burst int) *tokenBucketLimiter {
	now := time.Now()
	return &tokenBucketLimiter{
		rate:       rate,
		burst:      float64(burst),
		tokens:     float64(burst),
		lastRefill: now,
	}
}

func (l *tokenBucketLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastRefill).Seconds()
	l.lastRefill = now

	l.tokens += elapsed * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}

	if l.tokens < 1 {
		return false
	}

	l.tokens--
	return true
}
