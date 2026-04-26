package models

type Finding struct {
	Type       string
	Category   string
	Title      string
	Severity   string
	Confidence string
	Evidence   string
	Details    map[string]interface{}
}

type RunStackResult struct {
	Tool       string
	Target     string
	Status     string
	DurationMS int64
	Findings   []Finding
	Metadata   map[string]interface{}
	Error      string
}
