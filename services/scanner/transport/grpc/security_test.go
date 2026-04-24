package grpc

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestAuthUnaryInterceptorAcceptsBearerToken(t *testing.T) {
	interceptor := authUnaryInterceptor(testLogger(), "scanner-token")
	info := &grpc.UnaryServerInfo{FullMethod: "/surfacelab.scanner.v1.ToolService/CheckHeaders"}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer scanner-token"))

	called := false
	_, err := interceptor(ctx, nil, info, func(ctx context.Context, req any) (any, error) {
		called = true
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if !called {
		t.Fatal("expected handler to be called")
	}
}

func TestAuthUnaryInterceptorRejectsMissingToken(t *testing.T) {
	interceptor := authUnaryInterceptor(testLogger(), "scanner-token")
	info := &grpc.UnaryServerInfo{FullMethod: "/surfacelab.scanner.v1.ToolService/CheckHeaders"}

	_, err := interceptor(context.Background(), nil, info, func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", status.Code(err))
	}
}

func TestAuthUnaryInterceptorAcceptsXServiceToken(t *testing.T) {
	interceptor := authUnaryInterceptor(testLogger(), "scanner-token")
	info := &grpc.UnaryServerInfo{FullMethod: "/surfacelab.scanner.v1.ToolService/CheckHeaders"}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-service-token", "scanner-token"))

	_, err := interceptor(ctx, nil, info, func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestRateLimitUnaryInterceptorRejectsAfterBurst(t *testing.T) {
	interceptor := rateLimitUnaryInterceptor(testLogger(), newTokenBucketLimiter(1, 1))
	info := &grpc.UnaryServerInfo{FullMethod: "/surfacelab.scanner.v1.ToolService/CheckHeaders"}

	_, err := interceptor(context.Background(), nil, info, func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("expected first request to succeed, got %v", err)
	}

	_, err = interceptor(context.Background(), nil, info, func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected resource exhausted, got %v", status.Code(err))
	}
}

func TestProtectionUnaryInterceptorRejectsConcurrentRequests(t *testing.T) {
	interceptor := protectionUnaryInterceptor(testLogger(), newConcurrencyLimiter(1), time.Second)
	info := &grpc.UnaryServerInfo{FullMethod: "/surfacelab.scanner.v1.ToolService/RunBaselineScan"}

	release := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		_, _ = interceptor(context.Background(), nil, info, func(ctx context.Context, req any) (any, error) {
			<-release
			return "ok", nil
		})
	}()

	time.Sleep(50 * time.Millisecond)

	_, err := interceptor(context.Background(), nil, info, func(ctx context.Context, req any) (any, error) {
		t.Fatal("second handler should not be called")
		return nil, nil
	})
	close(release)
	<-done

	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected resource exhausted, got %v", status.Code(err))
	}
}

func TestProtectionUnaryInterceptorTimesOut(t *testing.T) {
	interceptor := protectionUnaryInterceptor(testLogger(), newConcurrencyLimiter(1), 20*time.Millisecond)
	info := &grpc.UnaryServerInfo{FullMethod: "/surfacelab.scanner.v1.ToolService/RunBaselineScan"}

	_, err := interceptor(context.Background(), nil, info, func(ctx context.Context, req any) (any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("expected deadline exceeded, got %v", status.Code(err))
	}
}
