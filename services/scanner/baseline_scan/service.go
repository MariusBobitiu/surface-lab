package baselinescan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	generateddb "github.com/MariusBobitiu/surface-lab/scanner-service/db/generated"
	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
	files "github.com/MariusBobitiu/surface-lab/scanner-service/tools/files"
	fingerprint "github.com/MariusBobitiu/surface-lab/scanner-service/tools/fingerprint"
	headers "github.com/MariusBobitiu/surface-lab/scanner-service/tools/headers"
	targeting "github.com/MariusBobitiu/surface-lab/scanner-service/tools/targeting/v1"
	tls "github.com/MariusBobitiu/surface-lab/scanner-service/tools/tls"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	statusRunning   = "running"
	statusCompleted = "completed"
	statusFailed    = "failed"
)

type toolRunner func(context.Context, string) models.ToolResult

type toolSpec struct {
	name string
	run  toolRunner
}

type Result struct {
	ScanID string
	Status string
}

type Service struct {
	queries *generateddb.Queries
	tools   []toolSpec
	logger  *slog.Logger
}

func New(queries *generateddb.Queries, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}

	return &Service{
		queries: queries,
		logger:  logger,
		tools: []toolSpec{
			{name: "fingerprint", run: fingerprint.Check},
			{name: "headers", run: headers.Check},
			{name: "tls", run: tls.Check},
			{name: "files", run: files.Check},
		},
	}
}

func (s *Service) Run(ctx context.Context, target string) (Result, error) {
	if s == nil || s.queries == nil {
		return Result{}, fmt.Errorf("baseline scan service is not configured")
	}

	if target == "" {
		return Result{}, fmt.Errorf("target is required")
	}

	scanID := newUUID()
	startedAt := time.Now().UTC()
	s.logger.Info("creating baseline scan record", "target", target, "scan_id", uuidString(scanID))

	if _, err := s.queries.CreateScan(ctx, newScanParams(scanID, target, startedAt)); err != nil {
		s.logger.Error("create baseline scan record failed", "target", target, "scan_id", uuidString(scanID), "error", err)
		return Result{}, fmt.Errorf("create scan: %w", err)
	}

	s.logger.Info("baseline scan step started", "scan_id", uuidString(scanID), "tool", "targeting", "target", target)
	resolution := targeting.Check(ctx, target)
	s.logger.Info("baseline scan step completed", "scan_id", uuidString(scanID), "tool", resolution.Result.Tool, "target", target, "status", resolution.Result.Status, "duration_ms", resolution.Result.DurationMs, "finding_count", len(resolution.Result.Findings), "signal_count", len(resolution.Result.Signals), "evidence_count", len(resolution.Result.Evidence), "error", resolution.Result.Error)
	if err := s.persistToolResult(ctx, scanID, resolution.Result); err != nil {
		s.logger.Error("persist baseline scan step failed", "scan_id", uuidString(scanID), "tool", resolution.Result.Tool, "error", err)
		return s.failScan(ctx, scanID, fmt.Sprintf("persist %s step: %v", resolution.Result.Tool, err), err)
	}
	if isToolFailure(resolution.Result) {
		return s.failScan(ctx, scanID, toolErrorMessage(resolution.Result), nil)
	}

	effectiveTarget := target
	if resolution.CanonicalTarget != "" {
		effectiveTarget = resolution.CanonicalTarget
	}

	for _, tool := range s.tools {
		s.logger.Info("baseline scan step started", "scan_id", uuidString(scanID), "tool", tool.name, "target", effectiveTarget)
		result := tool.run(ctx, effectiveTarget)
		s.logger.Info("baseline scan step completed", "scan_id", uuidString(scanID), "tool", result.Tool, "target", effectiveTarget, "status", result.Status, "duration_ms", result.DurationMs, "finding_count", len(result.Findings), "signal_count", len(result.Signals), "evidence_count", len(result.Evidence), "error", result.Error)

		if err := s.persistToolResult(ctx, scanID, result); err != nil {
			s.logger.Error("persist baseline scan step failed", "scan_id", uuidString(scanID), "tool", tool.name, "error", err)
			return s.failScan(ctx, scanID, fmt.Sprintf("persist %s step: %v", tool.name, err), err)
		}

		if isToolFailure(result) {
			return s.failScan(ctx, scanID, toolErrorMessage(result), nil)
		}
	}

	if err := s.queries.UpdateScanStatus(ctx, generateddb.UpdateScanStatusParams{
		ID:           scanID,
		Status:       statusCompleted,
		ErrorMessage: pgtype.Text{},
		StartedAt:    pgtype.Timestamptz{},
		CompletedAt:  timestampValue(time.Now().UTC()),
	}); err != nil {
		s.logger.Error("complete baseline scan failed", "scan_id", uuidString(scanID), "error", err)
		return Result{}, fmt.Errorf("complete scan: %w", err)
	}

	s.logger.Info("baseline scan marked completed", "scan_id", uuidString(scanID), "duration_ms", time.Since(startedAt).Milliseconds())
	return Result{
		ScanID: uuidString(scanID),
		Status: statusCompleted,
	}, nil
}

func (s *Service) failScan(ctx context.Context, scanID pgtype.UUID, message string, cause error) (Result, error) {
	s.logger.Error("baseline scan marked failed", "scan_id", uuidString(scanID), "message", message, "error", cause)
	updateErr := s.queries.UpdateScanStatus(ctx, generateddb.UpdateScanStatusParams{
		ID:           scanID,
		Status:       statusFailed,
		ErrorMessage: textValue(message),
		StartedAt:    pgtype.Timestamptz{},
		CompletedAt:  timestampValue(time.Now().UTC()),
	})
	if updateErr != nil {
		if cause == nil {
			cause = errors.New(message)
		}

		return Result{
			ScanID: uuidString(scanID),
			Status: statusFailed,
		}, fmt.Errorf("%w; mark scan failed: %v", cause, updateErr)
	}

	return Result{
		ScanID: uuidString(scanID),
		Status: statusFailed,
	}, cause
}

func (s *Service) persistToolResult(ctx context.Context, scanID pgtype.UUID, result models.ToolResult) error {
	if _, err := s.queries.CreateScanStep(ctx, newScanStepParams(scanID, result)); err != nil {
		return err
	}

	for _, evidence := range result.Evidence {
		if _, err := s.queries.CreateEvidence(ctx, newEvidenceParams(scanID, result.Tool, evidence)); err != nil {
			return fmt.Errorf("persist %s evidence: %w", result.Tool, err)
		}
	}

	for _, signal := range result.Signals {
		if _, err := s.queries.CreateSignal(ctx, newSignalParams(scanID, result.Tool, signal)); err != nil {
			return fmt.Errorf("persist %s signal: %w", result.Tool, err)
		}
	}

	for _, finding := range result.Findings {
		if _, err := s.queries.CreateFinding(ctx, newFindingParams(scanID, result.Tool, finding)); err != nil {
			return fmt.Errorf("persist %s finding: %w", result.Tool, err)
		}
	}

	return nil
}

func isToolFailure(result models.ToolResult) bool {
	return result.Status == models.StatusFailed
}

func toolErrorMessage(result models.ToolResult) string {
	if result.Error != "" {
		return fmt.Sprintf("%s failed: %s", result.Tool, result.Error)
	}

	return fmt.Sprintf("%s failed", result.Tool)
}
