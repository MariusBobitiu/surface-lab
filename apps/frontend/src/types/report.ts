export type Severity = "critical" | "high" | "medium" | "low" | "info"

export type CreateScanResponse = {
  scan_id: string
  status: string
}

export type ScanStepResponse = {
  id: string
  tool_name: string
  status: string
  duration_ms: number
  raw_metadata: Record<string, unknown>
  created_at: string
}

export type ReportSummaryResponse = {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export type EnrichedFindingResponse = {
  id: string
  tool_name: string
  type: string
  category: string
  title: string
  severity: Severity
  confidence: string
  evidence: string
  details: Record<string, unknown>
  created_at: string
  owasp_category: string | null
  wstg_reference: string | null
  remediation_summary: string | null
  source_references: string[]
  cve_matches: Array<Record<string, unknown>>
  cpe_matches: Array<Record<string, unknown>>
}

export type EnrichedReportCategoryResponse = {
  name: string
  slug: string
  count: number
  highest_severity: Severity
  findings: EnrichedFindingResponse[]
}

export type ReportCheckStatus = "passed" | "failed" | "not_run"

export type ReportCheckResponse = {
  id: string
  title: string
  status: ReportCheckStatus
  detail: string
  source: string | null
}

export type ReportCheckCategoryResponse = {
  name: string
  slug: string
  passed: number
  failed: number
  not_run: number
  checks: ReportCheckResponse[]
}

export type EnrichedReportResponse = {
  scan_id: string
  target: string
  status: string
  score: number
  summary: ReportSummaryResponse
  top_issues: EnrichedFindingResponse[]
  categories: EnrichedReportCategoryResponse[]
  created_at: string
  completed_at: string | null
  executive_summary: string | null
  quick_wins: string[]
  check_categories: ReportCheckCategoryResponse[]
}

export type SeverityChartDatum = {
  severity: Severity
  label: string
  value: number
}

export type ScanDetailsResponse = {
  scan_id: string
  target: string
  status: string
  error_message: string | null
  created_at: string
  updated_at: string
  started_at: string | null
  completed_at: string | null
  summary: ReportSummaryResponse
  steps: ScanStepResponse[]
  findings: EnrichedFindingResponse[]
}

export type ScanWorkflowEventType =
  | "scan.started"
  | "baseline.started"
  | "baseline.completed"
  | "vuln.research.planning.started"
  | "vuln.research.planning.completed"
  | "vuln.research.started"
  | "vuln.research.completed"
  | "planner.started"
  | "planner.completed"
  | "contracts.selected"
  | "contract.started"
  | "contract.completed"
  | "contract.failed"
  | "retry.started"
  | "retry.completed"
  | "replan.started"
  | "replan.completed"
  | "merge.started"
  | "merge.completed"
  | "summary.started"
  | "summary.completed"
  | "scan.completed"

export type ScanWorkflowEvent = {
  scan_id: string
  type: ScanWorkflowEventType | string
  message: string
  timestamp: string
  metadata: Record<string, unknown>
}
