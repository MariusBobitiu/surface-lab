-- name: CreateSignal :one
INSERT INTO signals (
  id, scan_id, tool_name, key, value, confidence, source, evidence_refs
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8
)
RETURNING *;

-- name: ListSignalsByScanID :many
SELECT * FROM signals
WHERE scan_id = $1
ORDER BY created_at ASC;
