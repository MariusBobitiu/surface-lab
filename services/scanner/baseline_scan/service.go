package baselinescan

import (
	"context"
	"errors"
	"fmt"
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
}

func New(queries *generateddb.Queries) *Service {
	return &Service{
		queries: queries,
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

	if _, err := s.queries.CreateScan(ctx, newScanParams(scanID, target, startedAt)); err != nil {
		return Result{}, fmt.Errorf("create scan: %w", err)
	}

	resolution := targeting.Check(ctx, target)
	if err := s.persistToolResult(ctx, scanID, resolution.Result); err != nil {
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
		result := tool.run(ctx, effectiveTarget)

		if err := s.persistToolResult(ctx, scanID, result); err != nil {
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
		return Result{}, fmt.Errorf("complete scan: %w", err)
	}

	return Result{
		ScanID: uuidString(scanID),
		Status: statusCompleted,
	}, nil
}

func (s *Service) failScan(ctx context.Context, scanID pgtype.UUID, message string, cause error) (Result, error) {
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
