DROP INDEX IF EXISTS idx_evidence_tool_name;
DROP INDEX IF EXISTS idx_evidence_scan_id;
DROP INDEX IF EXISTS idx_signals_key;
DROP INDEX IF EXISTS idx_signals_tool_name;
DROP INDEX IF EXISTS idx_signals_scan_id;

DROP TABLE IF EXISTS evidence;
DROP TABLE IF EXISTS signals;

ALTER TABLE findings
  DROP COLUMN IF EXISTS evidence_refs,
  DROP COLUMN IF EXISTS summary;
