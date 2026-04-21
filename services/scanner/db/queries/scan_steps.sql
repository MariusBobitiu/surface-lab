-- name: CreateScanStep :one
INSERT INTO scan_steps (
  id, scan_id, tool_name, status, duration_ms, raw_metadata
) VALUES (
  $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- name: ListScanStepsByScanID :many
SELECT * FROM scan_steps
WHERE scan_id = $1
ORDER BY created_at ASC;