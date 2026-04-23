package grpc

import (
	"context"

	baselinescan "github.com/MariusBobitiu/surface-lab/scanner-service/baseline_scan"
	"github.com/MariusBobitiu/surface-lab/scanner-service/db"
	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
	filesv1 "github.com/MariusBobitiu/surface-lab/scanner-service/tools/files/v1"
	fingerprintv1 "github.com/MariusBobitiu/surface-lab/scanner-service/tools/fingerprint/v1"
	headersv1 "github.com/MariusBobitiu/surface-lab/scanner-service/tools/headers/v1"
	tlsv1 "github.com/MariusBobitiu/surface-lab/scanner-service/tools/tls/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type toolServiceServer struct {
	UnimplementedToolServiceServer
	baselineScan *baselinescan.Service
}

func NewToolServiceServer(dbClient *db.Client) ToolServiceServer {
	server := &toolServiceServer{}
	if dbClient != nil {
		server.baselineScan = baselinescan.New(dbClient.Queries)
	}
	return server
}

func (s *toolServiceServer) CheckHeaders(ctx context.Context, req *ToolRequest) (*ToolResult, error) {
	if req.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}

	result := headersv1.Check(ctx, req.GetTarget())
	return toProtoToolResult(result), nil
}

func (s *toolServiceServer) CheckTLS(ctx context.Context, req *ToolRequest) (*ToolResult, error) {
	if req.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}

	result := tlsv1.Check(ctx, req.GetTarget())
	return toProtoToolResult(result), nil
}

func (s *toolServiceServer) CheckFileExposure(ctx context.Context, req *ToolRequest) (*ToolResult, error) {
	if req.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}

	result := filesv1.Check(ctx, req.GetTarget())
	return toProtoToolResult(result), nil
}

func (s *toolServiceServer) Fingerprint(ctx context.Context, req *ToolRequest) (*ToolResult, error) {
	if req.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}

	result := fingerprintv1.Check(ctx, req.GetTarget())
	return toProtoToolResult(result), nil
}

func (s *toolServiceServer) RunBaselineScan(ctx context.Context, req *BaselineScanRequest) (*BaselineScanResponse, error) {
	if req.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}

	if s.baselineScan == nil {
		return nil, status.Error(codes.FailedPrecondition, "baseline scan service is not configured")
	}

	result, err := s.baselineScan.Run(ctx, req.GetTarget())
	if err != nil {
		return &BaselineScanResponse{
			ScanId: result.ScanID,
			Status: result.Status,
		}, status.Errorf(codes.Internal, "run baseline scan: %v", err)
	}

	return &BaselineScanResponse{
		ScanId: result.ScanID,
		Status: result.Status,
	}, nil
}

func toProtoToolResult(result models.ToolResult) *ToolResult {
	findings := make([]*Finding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		details := cloneMap(finding.Details)
		if finding.Summary != "" {
			details["summary"] = finding.Summary
		}
		if len(finding.EvidenceRefs) > 0 {
			details["evidence_refs"] = toInterfaceSlice(finding.EvidenceRefs)
		}
		findings = append(findings, &Finding{
			Type:       finding.Type,
			Category:   finding.Category,
			Title:      finding.Title,
			Severity:   finding.Severity,
			Confidence: finding.Confidence,
			Evidence:   finding.Evidence,
			Details:    toStruct(details),
		})
	}

	metadata := cloneMap(result.Metadata)
	metadata["signals"] = result.Signals
	metadata["evidence"] = result.Evidence

	return &ToolResult{
		Tool:       result.Tool,
		Target:     result.Target,
		Status:     result.Status,
		DurationMs: result.DurationMs,
		Findings:   findings,
		Metadata:   toStruct(metadata),
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

func cloneMap(values map[string]interface{}) map[string]interface{} {
	if len(values) == 0 {
		return map[string]interface{}{}
	}

	cloned := make(map[string]interface{}, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func toInterfaceSlice(values []string) []interface{} {
	result := make([]interface{}, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}
