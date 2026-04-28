package grpc

import (
	"context"
	"log/slog"
	"reflect"
	"time"

	"github.com/MariusBobitiu/surface-lab/laravel-stack/models"
	"github.com/MariusBobitiu/surface-lab/laravel-stack/tools/execute"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type laravelStackServiceServer struct {
	UnimplementedLaravelStackServiceServer
	logger *slog.Logger
}

func NewLaravelStackServiceServer(logger *slog.Logger) LaravelStackServiceServer {
	return &laravelStackServiceServer{
		logger: logger,
	}
}

func (s *laravelStackServiceServer) RunStack(ctx context.Context, req *RunStackRequest) (*RunStackResponse, error) {
	if req.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}

	metadata := map[string]interface{}{}
	if req.GetMetadata() != nil {
		metadata = req.GetMetadata().AsMap()
	}

	startedAt := time.Now()
	s.logger.Info("RunStack execution started", "target", req.GetTarget(), "metadata_keys", len(metadata))

	result := execute.Run(ctx, req.GetTarget(), metadata)
	fields := []any{
		"target", req.GetTarget(),
		"status", result.Status,
		"finding_count", len(result.Findings),
		"duration_ms", time.Since(startedAt).Milliseconds(),
	}
	if result.Error != "" {
		fields = append(fields, "error", result.Error)
		s.logger.Warn("RunStack execution completed with error", fields...)
	} else {
		s.logger.Info("RunStack execution completed", fields...)
	}
	return toProtoRunStackResponse(result), nil
}

func toProtoRunStackResponse(result models.RunStackResult) *RunStackResponse {
	findings := make([]*StackFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		findings = append(findings, &StackFinding{
			Type:       finding.Type,
			Category:   finding.Category,
			Title:      finding.Title,
			Severity:   finding.Severity,
			Confidence: finding.Confidence,
			Evidence:   finding.Evidence,
			Details:    toStruct(finding.Details),
		})
	}

	return &RunStackResponse{
		Tool:       result.Tool,
		Target:     result.Target,
		Status:     result.Status,
		DurationMs: result.DurationMS,
		Findings:   findings,
		Metadata:   toStruct(result.Metadata),
		Error:      result.Error,
	}
}

func toStruct(values map[string]interface{}) *structpb.Struct {
	if len(values) == 0 {
		return &structpb.Struct{Fields: map[string]*structpb.Value{}}
	}

	result, err := structpb.NewStruct(normalizeStructMap(values))
	if err != nil {
		return &structpb.Struct{Fields: map[string]*structpb.Value{
			"conversion_error": structpb.NewStringValue(err.Error()),
		}}
	}

	return result
}

func normalizeStructMap(values map[string]interface{}) map[string]interface{} {
	normalized := make(map[string]interface{}, len(values))
	for key, value := range values {
		normalized[key] = normalizeStructValue(value)
	}
	return normalized
}

func normalizeStructValue(value interface{}) interface{} {
	if value == nil {
		return nil
	}

	switch typed := value.(type) {
	case map[string]interface{}:
		return normalizeStructMap(typed)
	case []interface{}:
		normalized := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			normalized = append(normalized, normalizeStructValue(item))
		}
		return normalized
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return normalizeStructValue(rv.Elem().Interface())
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return value
		}
		normalized := make(map[string]interface{}, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			normalized[iter.Key().String()] = normalizeStructValue(iter.Value().Interface())
		}
		return normalized
	case reflect.Slice, reflect.Array:
		normalized := make([]interface{}, 0, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			normalized = append(normalized, normalizeStructValue(rv.Index(i).Interface()))
		}
		return normalized
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(rv.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return float64(rv.Uint())
	case reflect.Float32, reflect.Float64:
		return rv.Float()
	case reflect.Bool:
		return rv.Bool()
	case reflect.String:
		return rv.String()
	default:
		return value
	}
}
