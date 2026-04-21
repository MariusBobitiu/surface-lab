import type { ReportSummaryResponse, Severity, SeverityChartDatum } from "@/types/report"

export function formatDateTime(value: string | null) {
  if (!value) {
    return "Pending"
  }

  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value))
}

export function severityLabel(value: string) {
  return value.replace(/_/g, " ")
}

export function getSeverityTone(severity: string) {
  const toneMap: Record<string, { badge: string; surface: string; border: string; dot: string }> = {
    critical: {
      badge: "bg-destructive/10 text-destructive",
      surface: "bg-card",
      border: "border-border",
      dot: "bg-destructive",
    },
    high: {
      badge: "bg-destructive/10 text-destructive",
      surface: "bg-card",
      border: "border-border",
      dot: "bg-destructive",
    },
    medium: {
      badge: "bg-chart-1/15 text-chart-1",
      surface: "bg-card",
      border: "border-border",
      dot: "bg-chart-1",
    },
    low: {
      badge: "bg-secondary text-secondary-foreground",
      surface: "bg-card",
      border: "border-border",
      dot: "bg-muted-foreground",
    },
    info: {
      badge: "bg-secondary text-secondary-foreground",
      surface: "bg-card",
      border: "border-border",
      dot: "bg-primary",
    },
    total: {
      badge: "bg-secondary text-secondary-foreground",
      surface: "bg-card",
      border: "border-border",
      dot: "bg-foreground",
    },
  }

  return toneMap[severity.toLowerCase()] ?? toneMap.info
}

export function severityChartData(summary: ReportSummaryResponse): SeverityChartDatum[] {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"]

  return order.map((severity) => ({
    severity,
    label: severityLabel(severity),
    value: summary[severity],
  }))
}
