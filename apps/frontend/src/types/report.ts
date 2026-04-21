export type Severity = "critical" | "high" | "medium" | "low" | "info"

export type CreateScanResponse = {
  scan_id: string
  status: string
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
}

export type SeverityChartDatum = {
  severity: Severity
  label: string
  value: number
}
