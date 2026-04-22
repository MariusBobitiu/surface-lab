package grpc

import (
	"context"
	"log/slog"

	"github.com/MariusBobitiu/surface-lab/service-baseline/models"
	"github.com/MariusBobitiu/surface-lab/service-baseline/tools/execute"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type baselineServiceServer struct {
	UnimplementedBaselineServiceServer
	logger *slog.Logger
}

func NewBaselineServiceServer(logger *slog.Logger) BaselineServiceServer {
	return &baselineServiceServer{
		logger: logger,
	}
}

func (s *baselineServiceServer) RunStack(ctx context.Context, req *RunStackRequest) (*RunStackResponse, error) {
	if req.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}

	input := map[string]interface{}{}
	if req.GetInput() != nil {
		input = req.GetInput().AsMap()
	}

	s.logger.Info("RunStack request received", "target", req.GetTarget())

	result := execute.Run(ctx, req.GetTarget(), input)
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
		Service:    result.Service,
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
