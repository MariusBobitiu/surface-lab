ALTER TABLE findings
  ADD COLUMN summary TEXT NOT NULL DEFAULT '',
  ADD COLUMN evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb;

UPDATE findings
SET summary = title
WHERE summary = '';

CREATE TABLE signals (
  id UUID PRIMARY KEY,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  tool_name TEXT NOT NULL,
  key TEXT NOT NULL,
  value JSONB NOT NULL DEFAULT 'null'::jsonb,
  confidence TEXT NOT NULL,
  source TEXT NOT NULL,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE evidence (
  id TEXT PRIMARY KEY,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  tool_name TEXT NOT NULL,
  kind TEXT NOT NULL,
  target TEXT,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_signals_scan_id ON signals(scan_id);
CREATE INDEX idx_signals_tool_name ON signals(tool_name);
CREATE INDEX idx_signals_key ON signals(key);
CREATE INDEX idx_evidence_scan_id ON evidence(scan_id);
CREATE INDEX idx_evidence_tool_name ON evidence(tool_name);
