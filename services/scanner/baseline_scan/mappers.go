package baselinescan

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	generateddb "github.com/MariusBobitiu/surface-lab/scanner-service/db/generated"
	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
	"github.com/jackc/pgx/v5/pgtype"
)

func newScanParams(scanID pgtype.UUID, target string, startedAt time.Time) generateddb.CreateScanParams {
	return generateddb.CreateScanParams{
		ID:           scanID,
		Target:       target,
		Status:       statusRunning,
		ErrorMessage: pgtype.Text{},
		StartedAt:    timestampValue(startedAt),
		CompletedAt:  pgtype.Timestamptz{},
	}
}

func newScanStepParams(scanID pgtype.UUID, result models.ToolResult) generateddb.CreateScanStepParams {
	return generateddb.CreateScanStepParams{
		ID:          newUUID(),
		ScanID:      scanID,
		ToolName:    result.Tool,
		Status:      result.Status,
		DurationMs:  result.DurationMs,
		RawMetadata: jsonBytes(stepMetadata(result)),
	}
}

func newFindingParams(scanID pgtype.UUID, toolName string, finding models.Finding) generateddb.CreateFindingParams {
	return generateddb.CreateFindingParams{
		ID:         newUUID(),
		ScanID:     scanID,
		ToolName:   toolName,
		Type:       finding.Type,
		Category:   finding.Category,
		Title:      finding.Title,
		Severity:   finding.Severity,
		Confidence: finding.Confidence,
		Evidence:   finding.Evidence,
		Details:    jsonBytes(finding.Details),
	}
}

func timestampValue(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{
		Time:  value.UTC(),
		Valid: true,
	}
}

func textValue(value string) pgtype.Text {
	if value == "" {
		return pgtype.Text{}
	}

	return pgtype.Text{
		String: value,
		Valid:  true,
	}
}

func stepMetadata(result models.ToolResult) map[string]interface{} {
	return map[string]interface{}{
		"target":   result.Target,
		"metadata": result.Metadata,
		"error":    result.Error,
	}
}

func jsonBytes(value interface{}) []byte {
	data, err := json.Marshal(value)
	if err == nil {
		return data
	}

	fallback, fallbackErr := json.Marshal(map[string]string{
		"marshal_error": err.Error(),
	})
	if fallbackErr == nil {
		return fallback
	}

	return []byte(`{}`)
}

func newUUID() pgtype.UUID {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(fmt.Sprintf("generate uuid: %v", err))
	}

	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80

	return pgtype.UUID{
		Bytes: value,
		Valid: true,
	}
}

func uuidString(value pgtype.UUID) string {
	if !value.Valid {
		return ""
	}

	raw := value.Bytes
	return fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		raw[0], raw[1], raw[2], raw[3],
		raw[4], raw[5],
		raw[6], raw[7],
		raw[8], raw[9],
		raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
	)
}
