-- name: CreateFinding :one
INSERT INTO findings (
  id, scan_id, tool_name, type, category, title, summary, severity, confidence, evidence, evidence_refs, details
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
)
RETURNING *;

-- name: ListFindingsByScanID :many
SELECT * FROM findings
WHERE scan_id = $1
ORDER BY created_at ASC;
