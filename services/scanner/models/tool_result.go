package models

const (
	SeverityInfo   = "info"
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"
)

const (
	ConfidenceLow    = "low"
	ConfidenceMedium = "medium"
	ConfidenceHigh   = "high"
)

const (
	StatusSuccess = "success"
	StatusPartial = "partial"
	StatusFailed  = "failed"
)

type ToolResult struct {
	Tool       string                 `json:"tool"`
	Target     string                 `json:"target"`
	Status     string                 `json:"status"`
	DurationMs int64                  `json:"duration_ms"`
	Findings   []Finding              `json:"findings"`
	Metadata   map[string]interface{} `json:"metadata"`
	Error      string                 `json:"error"`
}

type Finding struct {
	Type       string                 `json:"type"`
	Category   string                 `json:"category"`
	Title      string                 `json:"title"`
	Severity   string                 `json:"severity"`
	Confidence string                 `json:"confidence"`
	Evidence   string                 `json:"evidence"`
	Details    map[string]interface{} `json:"details"`
}
