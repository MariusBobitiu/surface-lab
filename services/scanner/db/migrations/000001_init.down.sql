DROP INDEX IF EXISTS idx_findings_severity;
DROP INDEX IF EXISTS idx_findings_tool_name;
DROP INDEX IF EXISTS idx_findings_scan_id;
DROP INDEX IF EXISTS idx_scan_steps_scan_id;

DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS scan_steps;
DROP TABLE IF EXISTS scans;
