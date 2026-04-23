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
	findingID := newUUID()
	if finding.ID != "" {
		findingID = parseOrNewUUID(finding.ID)
	}

	return generateddb.CreateFindingParams{
		ID:           findingID,
		ScanID:       scanID,
		ToolName:     toolName,
		Type:         finding.Type,
		Category:     finding.Category,
		Title:        finding.Title,
		Summary:      coalesceFindingSummary(finding),
		Severity:     finding.Severity,
		Confidence:   finding.Confidence,
		Evidence:     coalesceFindingEvidence(finding),
		EvidenceRefs: jsonBytes(finding.EvidenceRefs),
		Details:      jsonBytes(finding.Details),
	}
}

func newSignalParams(scanID pgtype.UUID, toolName string, signal models.Signal) generateddb.CreateSignalParams {
	return generateddb.CreateSignalParams{
		ID:           newUUID(),
		ScanID:       scanID,
		ToolName:     toolName,
		Key:          signal.Key,
		Value:        jsonBytes(signal.Value),
		Confidence:   signal.Confidence,
		Source:       signal.Source,
		EvidenceRefs: jsonBytes(signal.EvidenceRefs),
	}
}

func newEvidenceParams(scanID pgtype.UUID, toolName string, evidence models.Evidence) generateddb.CreateEvidenceParams {
	return generateddb.CreateEvidenceParams{
		ID:       evidence.ID,
		ScanID:   scanID,
		ToolName: toolName,
		Kind:     evidence.Kind,
		Target:   textValue(evidence.Target),
		Data:     jsonBytes(evidence.Data),
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
		"signals":  result.Signals,
		"evidence": result.Evidence,
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

func parseOrNewUUID(value string) pgtype.UUID {
	var raw [16]byte
	if _, err := fmt.Sscanf(
		value,
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		&raw[0], &raw[1], &raw[2], &raw[3],
		&raw[4], &raw[5],
		&raw[6], &raw[7],
		&raw[8], &raw[9],
		&raw[10], &raw[11], &raw[12], &raw[13], &raw[14], &raw[15],
	); err != nil {
		return newUUID()
	}

	return pgtype.UUID{
		Bytes: raw,
		Valid: true,
	}
}

func coalesceFindingSummary(finding models.Finding) string {
	if finding.Summary != "" {
		return finding.Summary
	}

	return finding.Title
}

func coalesceFindingEvidence(finding models.Finding) string {
	if finding.Evidence != "" {
		return finding.Evidence
	}

	if finding.Summary != "" {
		return finding.Summary
	}

	return finding.Title
}
