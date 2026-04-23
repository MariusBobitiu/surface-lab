-- name: CreateEvidence :one
INSERT INTO evidence (
  id, scan_id, tool_name, kind, target, data
) VALUES (
  $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- name: ListEvidenceByScanID :many
SELECT * FROM evidence
WHERE scan_id = $1
ORDER BY created_at ASC;
