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
	Signals    []Signal               `json:"signals,omitempty"`
	Findings   []Finding              `json:"findings"`
	Evidence   []Evidence             `json:"evidence,omitempty"`
	Metadata   map[string]interface{} `json:"metadata"`
	Error      string                 `json:"error"`
}

type Signal struct {
	Key          string      `json:"key"`
	Value        interface{} `json:"value"`
	Confidence   string      `json:"confidence"`
	Source       string      `json:"source"`
	EvidenceRefs []string    `json:"evidence_refs,omitempty"`
}

type Finding struct {
	ID           string                 `json:"id,omitempty"`
	Type         string                 `json:"type"`
	Category     string                 `json:"category"`
	Title        string                 `json:"title"`
	Summary      string                 `json:"summary,omitempty"`
	Severity     string                 `json:"severity"`
	Confidence   string                 `json:"confidence"`
	Evidence     string                 `json:"evidence,omitempty"`
	EvidenceRefs []string               `json:"evidence_refs,omitempty"`
	Details      map[string]interface{} `json:"details"`
}

type Evidence struct {
	ID     string                 `json:"id"`
	Kind   string                 `json:"kind"`
	Target string                 `json:"target,omitempty"`
	Data   map[string]interface{} `json:"data"`
}
