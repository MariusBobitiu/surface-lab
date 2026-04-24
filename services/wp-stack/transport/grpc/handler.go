package grpc

import (
	"context"
	"log/slog"
	"time"

	"github.com/MariusBobitiu/surface-lab/wp-stack/models"
	"github.com/MariusBobitiu/surface-lab/wp-stack/tools/execute"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type wordPressStackServiceServer struct {
	UnimplementedWordPressStackServiceServer
	logger *slog.Logger
}

func NewWordPressStackServiceServer(logger *slog.Logger) WordPressStackServiceServer {
	return &wordPressStackServiceServer{
		logger: logger,
	}
}

func (s *wordPressStackServiceServer) RunStack(ctx context.Context, req *RunStackRequest) (*RunStackResponse, error) {
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

	result, err := structpb.NewStruct(values)
	if err != nil {
		return &structpb.Struct{Fields: map[string]*structpb.Value{
			"conversion_error": structpb.NewStringValue(err.Error()),
		}}
	}

	return result
}
