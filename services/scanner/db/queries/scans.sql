-- name: CreateScan :one
INSERT INTO scans (
  id, target, status, error_message, started_at, completed_at
) VALUES (
  $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- name: GetScanByID :one
SELECT * FROM scans
WHERE id = $1;

-- name: UpdateScanStatus :exec
UPDATE scans
SET
  status = $2,
  error_message = $3,
  updated_at = NOW(),
  started_at = COALESCE($4, started_at),
  completed_at = COALESCE($5, completed_at)
WHERE id = $1;