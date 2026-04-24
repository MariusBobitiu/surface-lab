package grpc

import (
	"context"
	"log/slog"
	"time"

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
	logger       *slog.Logger
}

func NewToolServiceServer(logger *slog.Logger, dbClient *db.Client) ToolServiceServer {
	server := &toolServiceServer{
		logger: logger,
	}
	if dbClient != nil {
		server.baselineScan = baselinescan.New(dbClient.Queries, logger)
	}
	return server
}

func (s *toolServiceServer) CheckHeaders(ctx context.Context, req *ToolRequest) (*ToolResult, error) {
	if req.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}

	s.logger.Info("tool check started", "tool", "headers.v1.check", "target", req.GetTarget())
	startedAt := time.Now()
	result := headersv1.Check(ctx, req.GetTarget())
	s.logToolResult("headers.v1.check", result.Status, req.GetTarget(), startedAt, result.Error, len(result.Findings))
	return toProtoToolResult(result), nil
}

func (s *toolServiceServer) CheckTLS(ctx context.Context, req *ToolRequest) (*ToolResult, error) {
	if req.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}

	s.logger.Info("tool check started", "tool", "tls.v1.check", "target", req.GetTarget())
	startedAt := time.Now()
	result := tlsv1.Check(ctx, req.GetTarget())
	s.logToolResult("tls.v1.check", result.Status, req.GetTarget(), startedAt, result.Error, len(result.Findings))
	return toProtoToolResult(result), nil
}

func (s *toolServiceServer) CheckFileExposure(ctx context.Context, req *ToolRequest) (*ToolResult, error) {
	if req.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}

	s.logger.Info("tool check started", "tool", "files.v1.check", "target", req.GetTarget())
	startedAt := time.Now()
	result := filesv1.Check(ctx, req.GetTarget())
	s.logToolResult("files.v1.check", result.Status, req.GetTarget(), startedAt, result.Error, len(result.Findings))
	return toProtoToolResult(result), nil
}

func (s *toolServiceServer) Fingerprint(ctx context.Context, req *ToolRequest) (*ToolResult, error) {
	if req.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}

	s.logger.Info("tool check started", "tool", "fingerprint.v1.check", "target", req.GetTarget())
	startedAt := time.Now()
	result := fingerprintv1.Check(ctx, req.GetTarget())
	s.logToolResult("fingerprint.v1.check", result.Status, req.GetTarget(), startedAt, result.Error, len(result.Findings))
	return toProtoToolResult(result), nil
}

func (s *toolServiceServer) RunBaselineScan(ctx context.Context, req *BaselineScanRequest) (*BaselineScanResponse, error) {
	if req.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}

	if s.baselineScan == nil {
		return nil, status.Error(codes.FailedPrecondition, "baseline scan service is not configured")
	}

	s.logger.Info("baseline scan started", "target", req.GetTarget())
	startedAt := time.Now()
	result, err := s.baselineScan.Run(ctx, req.GetTarget())
	if err != nil {
		s.logger.Error("baseline scan failed", "target", req.GetTarget(), "scan_id", result.ScanID, "status", result.Status, "duration_ms", time.Since(startedAt).Milliseconds(), "error", err)
		return &BaselineScanResponse{
			ScanId: result.ScanID,
			Status: result.Status,
		}, status.Errorf(codes.Internal, "run baseline scan: %v", err)
	}

	s.logger.Info("baseline scan completed", "target", req.GetTarget(), "scan_id", result.ScanID, "status", result.Status, "duration_ms", time.Since(startedAt).Milliseconds())
	return &BaselineScanResponse{
		ScanId: result.ScanID,
		Status: result.Status,
	}, nil
}

func (s *toolServiceServer) logToolResult(tool string, status string, target string, startedAt time.Time, errMessage string, findingCount int) {
	fields := []any{
		"tool", tool,
		"target", target,
		"status", status,
		"finding_count", findingCount,
		"duration_ms", time.Since(startedAt).Milliseconds(),
	}
	if errMessage != "" {
		fields = append(fields, "error", errMessage)
		s.logger.Warn("tool check completed with error", fields...)
		return
	}

	s.logger.Info("tool check completed", fields...)
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
