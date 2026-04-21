"use client"

import { ArrowLeft, CalendarClock, CircleAlert, ShieldCheck } from "lucide-react"
import Link from "next/link"

import type { EnrichedFindingResponse, Severity } from "@/types/report"
import { useEnrichedReport } from "@/hooks/use-enriched-report"
import { formatDateTime, getSeverityTone, severityLabel } from "@/utils/format"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"

type ReportViewProps = {
  scanId: string
}

const ACTION_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"]

export function ReportView({ scanId }: ReportViewProps) {
  const reportQuery = useEnrichedReport(scanId)

  if (reportQuery.isLoading) {
    return <ReportSkeleton />
  }

  if (reportQuery.isError) {
    return (
      <main className="mx-auto min-h-screen w-full max-w-7xl px-6 py-10 sm:px-10 lg:px-12">
        <div className="rounded-3xl bg-card px-6 py-6">
          <h1 className="text-xl font-semibold">Unable to load report</h1>
          <p className="mt-2 text-sm leading-7 text-muted-foreground">{reportQuery.error.message}</p>
          <Button asChild variant="ghost" className="mt-6 px-0">
            <Link href="/">
              <ArrowLeft className="size-4" />
              Back to dashboard
            </Link>
          </Button>
        </div>
      </main>
    )
  }

  const report = reportQuery.data
  if (!report) {
    return <ReportSkeleton />
  }

  const severityItems = ACTION_ORDER.filter((severity) => report.summary[severity] > 0).map((severity) => ({
    severity,
    value: report.summary[severity],
  }))

  const immediateSeverity: Severity =
    report.summary.critical > 0 ? "critical" : report.summary.high > 0 ? "high" : "medium"

  const immediateIssues = report.top_issues.filter((issue) => issue.severity === immediateSeverity).slice(0, 5)
  const fallbackIssues =
    immediateIssues.length > 0
      ? immediateIssues
      : report.top_issues.filter((issue) => ACTION_ORDER.indexOf(issue.severity) <= ACTION_ORDER.indexOf("medium")).slice(0, 5)
  const primaryIssues = fallbackIssues.slice(0, 2)
  const secondaryIssues = fallbackIssues.slice(2)

  return (
    <main className="mx-auto min-h-screen w-full max-w-7xl px-6 py-8 sm:px-10 lg:px-12">
      <div className="space-y-32 pb-24">
        <section className="relative flex min-h-[80vh] items-center overflow-hidden py-8">
          <div className="pointer-events-none absolute inset-0 -z-10">
            <div className="absolute left-[8%] top-[18%] h-72 w-72 rounded-full bg-chart-2/8 blur-3xl" />
            <div className={`absolute right-[8%] top-1/2 h-96 w-96 -translate-y-1/2 rounded-full blur-3xl ${getDonutGlowClass(report.score)}`} />
          </div>

          <div className="absolute inset-x-0 top-8 flex items-center justify-between">
            <Button asChild variant="ghost" className="px-0 text-muted-foreground hover:text-foreground">
              <Link href="/">
                <ArrowLeft className="size-4" />
                New scan
              </Link>
            </Button>
            {reportQuery.isFetching ? (
              <span className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Refreshing</span>
            ) : null}
          </div>

          <div className="mt-10 grid min-h-[calc(80vh-6rem)] items-center gap-16 lg:grid-cols-[minmax(0,1.2fr)_minmax(320px,0.8fr)]">
            <div className="space-y-9">
              <div className="space-y-3">
                <p className="text-xs font-medium uppercase tracking-[0.28em] text-muted-foreground">
                  Enriched report
                </p>
                <h1 className="font-heading text-balance text-5xl font-semibold tracking-tight sm:text-6xl lg:text-7xl">
                  {report.target}
                </h1>
              </div>

              <p className="max-w-4xl text-[1.35rem] font-medium leading-8 text-foreground sm:text-[1.55rem] [display:-webkit-box] [-webkit-box-orient:vertical] [-webkit-line-clamp:2] overflow-hidden">
                {report.executive_summary ??
                  "This report is available, but a generated executive summary was not returned. Review the immediate-action section and grouped findings below."}
              </p>

              <div className="rounded-2xl bg-card/55 px-5 py-4">
                <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm text-muted-foreground">
                  {severityItems.length ? (
                    severityItems.map(({ severity, value }) => {
                      const tone = getSeverityTone(severity)
                      return (
                        <span key={severity} className="inline-flex items-center gap-2">
                          <span className={`size-2 rounded-full ${tone.dot}`} />
                          <span className="font-semibold text-foreground">{value}</span>
                          <span>{severityLabel(severity)}</span>
                        </span>
                      )
                    })
                  ) : (
                    <span className="text-muted-foreground">No findings recorded yet.</span>
                  )}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm text-muted-foreground">
                <span className="inline-flex items-center gap-2">
                  {report.completed_at ? <ShieldCheck className="size-4" /> : <CalendarClock className="size-4" />}
                  {report.completed_at
                    ? `Completed ${formatDateTime(report.completed_at)}`
                    : `Created ${formatDateTime(report.created_at)}`}
                </span>
                {getScanDuration(report.created_at, report.completed_at) ? (
                  <span className="inline-flex items-center gap-2">
                    <span className="text-border">·</span>
                    Duration: {getScanDuration(report.created_at, report.completed_at)}
                  </span>
                ) : report.completed_at ? null : (
                  <span className="inline-flex items-center gap-2">
                    <CircleAlert className="size-4" />
                    Scan still running
                  </span>
                )}
              </div>
            </div>

            <div className="flex justify-center lg:justify-end">
              <ScoreDonut score={report.score} />
            </div>
          </div>
        </section>

        <section className="flex min-h-[80vh] flex-col justify-center border-t border-border/70 pt-20">
          <div className="space-y-3">
            <p className="text-xs font-medium uppercase tracking-[0.26em] text-muted-foreground">
              Immediate action
            </p>
            <h2 className="font-heading text-3xl font-semibold tracking-tight">
              {report.summary.critical > 0 ? "Critical changes needed." : "Address these findings first."}
            </h2>
            <p className="max-w-3xl text-base leading-7 text-muted-foreground">
              {report.summary.critical > 0
                ? "Critical findings are present and should be remediated before lower-severity work."
                : report.summary.high > 0
                  ? "No critical findings were recorded. These high-severity issues are the most important next changes."
                  : "No critical or high findings were recorded. These are still the strongest next actions to improve the target’s security posture."}
            </p>
          </div>

          <div className="mt-14 space-y-14">
            <div className="space-y-10">
              {primaryIssues.length ? (
                <div className="grid gap-6 lg:grid-cols-2">
                  {primaryIssues.map((issue) => (
                    <PriorityIssueRow key={`${issue.tool_name}-${issue.title}`} issue={issue} prominent />
                  ))}
                </div>
              ) : (
                <div className="rounded-2xl border border-dashed border-border px-5 py-4 text-sm text-muted-foreground">
                  No immediate-action findings were surfaced for this report.
                </div>
              )}

              {secondaryIssues.length ? (
                <div className="space-y-6">
                  {secondaryIssues.map((issue, index) => (
                    <div key={`${issue.tool_name}-${issue.title}`}>
                      {index > 0 ? <Separator className="mb-6" /> : null}
                      <PriorityIssueRow issue={issue} />
                    </div>
                  ))}
                </div>
              ) : null}
            </div>

            <div className="space-y-4">
              <p className="text-xs font-medium uppercase tracking-[0.22em] text-muted-foreground">Quick wins</p>
              {report.quick_wins.length ? (
                <ol className="space-y-3">
                  {report.quick_wins.slice(0, 4).map((item, index) => (
                    <li key={item} className="grid grid-cols-[1.5rem_minmax(0,1fr)] items-start gap-3 text-base leading-7 text-foreground/88">
                      <span className="pt-0.5 text-sm font-semibold text-muted-foreground">
                        {index + 1}.
                      </span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ol>
              ) : (
                <div className="rounded-2xl border border-dashed border-border px-5 py-4 text-sm text-muted-foreground">
                  No quick wins were generated for this report.
                </div>
              )}
            </div>
          </div>
        </section>

        <section className="grid gap-10 border-t border-border/70 pt-20 lg:grid-cols-[168px_minmax(0,1fr)] lg:items-start">
          <aside className="space-y-4 lg:sticky lg:top-8">
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-[0.26em] text-muted-foreground">Deep dive</p>
              <h2 className="font-heading text-2xl font-semibold tracking-tight">Documentation view</h2>
            </div>

            <nav className="space-y-1">
              {report.categories.map((category) => (
                <a
                  key={category.slug}
                  href={`#${category.slug}`}
                  className="flex items-center justify-between rounded-xl px-3 py-2 text-sm text-muted-foreground transition hover:bg-accent hover:text-foreground"
                >
                  <span className="truncate">{category.name}</span>
                  <span className="ml-3 text-xs">{category.count}</span>
                </a>
              ))}
            </nav>
          </aside>

          <div className="space-y-16 lg:border-l lg:border-border/70 lg:pl-10">
            {report.categories.map((category, categoryIndex) => (
              <section key={category.slug} id={category.slug} className="scroll-mt-8">
                {categoryIndex > 0 ? <Separator className="mb-14" /> : null}

                <div className="space-y-3">
                  <div className="flex flex-wrap items-center gap-3">
                    <h3 className="font-heading text-3xl font-semibold tracking-tight">{category.name}</h3>
                    <CategoryMetaBadge count={category.count} severity={category.highest_severity} />
                  </div>
                  <p className="text-sm leading-7 text-muted-foreground">
                    {getCategoryDescription(category.name)}
                  </p>
                </div>

                {isInformationalCategory(category.name) ? (
                  <div className="mt-8 divide-y divide-border/60 rounded-2xl bg-card/25 px-5">
                    {category.findings.map((finding) => (
                      <FingerprintFindingRow
                        key={`${category.slug}-${finding.title}-${finding.tool_name}`}
                        finding={finding}
                      />
                    ))}
                  </div>
                ) : (
                  <div className="mt-8 space-y-10">
                    {category.findings.map((finding, index) => (
                      <article key={`${category.slug}-${finding.title}-${finding.tool_name}`} className="space-y-4">
                        {index > 0 ? <Separator className="mb-10" /> : null}
                        <FindingBlock finding={finding} />
                      </article>
                    ))}
                  </div>
                )}
              </section>
            ))}
          </div>
        </section>
      </div>
    </main>
  )
}

function getRiskLabel(score: number) {
  if (score >= 80) {
    return "Low risk"
  }

  if (score >= 60) {
    return "Moderate risk"
  }

  return "High risk"
}

function ScoreDonut({ score }: { score: number }) {
  const radius = 88
  const strokeWidth = 14
  const circumference = 2 * Math.PI * radius
  const progress = Math.max(0, Math.min(100, score))
  const dashOffset = circumference - (progress / 100) * circumference
  const ringColor = getScoreRingColor(score)
  const labelColor = getScoreLabelColor(score)

  return (
    <div className="relative flex h-[300px] w-[300px] items-center justify-center sm:h-[340px] sm:w-[340px]">
      <svg viewBox="0 0 220 220" className="h-full w-full -rotate-90">
        <circle
          cx="110"
          cy="110"
          r={radius}
          fill="none"
          stroke="var(--border)"
          strokeOpacity="0.5"
          strokeWidth={strokeWidth}
        />
        <circle
          cx="110"
          cy="110"
          r={radius}
          fill="none"
          stroke={ringColor}
          strokeLinecap="round"
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          strokeOpacity="0.92"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <div className="flex items-end gap-1">
          <span className="text-6xl font-semibold tracking-[-0.04em] sm:text-7xl">{score}</span>
          <span className="pb-3 text-base text-muted-foreground">/100</span>
        </div>
        <p className={`mt-3 text-base font-medium ${labelColor}`}>{getRiskLabel(score)}</p>
      </div>
    </div>
  )
}

function PriorityIssueRow({
  issue,
  prominent = false,
}: {
  issue: EnrichedFindingResponse
  prominent?: boolean
}) {
  const tone = getSeverityTone(issue.severity)

  return (
    <article
      className={prominent ? "space-y-3 rounded-3xl bg-card/45 px-6 py-6" : "space-y-3 py-2"}
    >
      <div className="flex flex-wrap items-center gap-3">
        <Badge
          className={`${tone.badge} border-0 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em]`}
        >
          {severityLabel(issue.severity)}
        </Badge>
        <span className="text-xs uppercase tracking-[0.18em] text-muted-foreground">{issue.tool_name}</span>
      </div>
      <div className="space-y-2">
        <h3 className={prominent ? "text-2xl font-semibold tracking-tight" : "text-xl font-semibold tracking-tight"}>
          {issue.title}
        </h3>
        <p className="text-sm leading-7 text-muted-foreground">{issue.evidence}</p>
        {issue.remediation_summary ? <p className="text-sm leading-7">{issue.remediation_summary}</p> : null}
      </div>
    </article>
  )
}

function FindingBlock({ finding }: { finding: EnrichedFindingResponse }) {
  const tone = getSeverityTone(finding.severity)

  return (
    <div className="space-y-4 rounded-3xl border border-border/60 bg-card/30 px-6 py-6">
      <div className="flex flex-wrap items-center gap-3">
        <Badge
          className={`${tone.badge} border-0 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em]`}
        >
          {severityLabel(finding.severity)}
        </Badge>
        <span className="text-xs uppercase tracking-[0.18em] text-muted-foreground">{finding.tool_name}</span>
        <span className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
          confidence {finding.confidence}
        </span>
      </div>

      <div className="space-y-3">
        <h4 className="text-xl font-semibold tracking-tight">{finding.title}</h4>
        <p className="text-sm leading-7 text-muted-foreground">{finding.evidence}</p>
        {finding.remediation_summary ? (
          <p className="text-sm leading-7">{finding.remediation_summary}</p>
        ) : null}
      </div>

      {finding.source_references.length ? (
        <div className="flex flex-wrap gap-x-4 gap-y-2">
          {finding.source_references.map((reference) => (
            <span key={reference} className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
              {reference}
            </span>
          ))}
        </div>
      ) : null}
    </div>
  )
}

function FingerprintFindingRow({ finding }: { finding: EnrichedFindingResponse }) {
  const label = getFingerprintLabel(finding)
  const value = getFingerprintValue(finding)

  return (
    <div className="grid gap-2 py-4 sm:grid-cols-[120px_minmax(0,1fr)] sm:items-start sm:gap-5">
      <dt className="text-sm font-medium text-foreground">{label}</dt>
      <dd className="space-y-2">
        <p className="text-sm leading-7 text-muted-foreground">{value}</p>
        {finding.source_references.length ? (
          <div className="flex flex-wrap gap-x-4 gap-y-2">
            {finding.source_references.map((reference) => (
              <span key={reference} className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                {reference}
              </span>
            ))}
          </div>
        ) : null}
      </dd>
    </div>
  )
}

function CategoryMetaBadge({
  count,
  severity,
}: {
  count: number
  severity: Severity
}) {
  const tone = getSeverityTone(severity)

  return (
    <div className="flex items-center gap-3 text-sm text-muted-foreground">
      <Badge
        className={`${tone.badge} border-0 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em]`}
      >
        {severityLabel(severity)}
      </Badge>
      <span>
        {count} finding{count === 1 ? "" : "s"}
      </span>
    </div>
  )
}

function getCategoryDescription(name: string) {
  const descriptions: Record<string, string> = {
    "HTTP Headers":
      "Response header findings that affect transport hardening, browser isolation, and baseline application security policy.",
    "Public Exposure":
      "Publicly accessible files and deployment artifacts that increase the exposed surface area of the target.",
    "Sensitive File Exposure":
      "Direct exposure of sensitive files or artifacts that should not be publicly retrievable.",
    "Technology Fingerprint":
      "Observed infrastructure and framework signals that help explain the stack but are not necessarily vulnerabilities on their own.",
    Other:
      "Additional findings that did not map cleanly into the primary report sections but still contribute to the overall review.",
  }

  return descriptions[name] ?? "Findings grouped by the report pipeline for deeper technical review and remediation planning."
}

function isInformationalCategory(name: string) {
  return name === "Technology Fingerprint" || name === "Other"
}

function getScoreRingColor(score: number) {
  if (score >= 80) {
    return "var(--chart-5)"
  }

  if (score >= 60) {
    return "var(--chart-1)"
  }

  return "var(--destructive)"
}

function getScoreLabelColor(score: number) {
  if (score >= 80) {
    return "text-chart-5"
  }

  if (score >= 60) {
    return "text-chart-1"
  }

  return "text-destructive"
}

function getDonutGlowClass(score: number) {
  if (score >= 80) {
    return "bg-chart-5/10"
  }

  if (score >= 60) {
    return "bg-chart-1/10"
  }

  return "bg-destructive/10"
}

function getScanDuration(createdAt: string, completedAt: string | null) {
  if (!completedAt) {
    return null
  }

  const created = new Date(createdAt).getTime()
  const completed = new Date(completedAt).getTime()

  if (Number.isNaN(created) || Number.isNaN(completed) || completed <= created) {
    return null
  }

  const totalSeconds = Math.round((completed - created) / 1000)

  if (totalSeconds < 60) {
    return `${totalSeconds}s`
  }

  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60

  if (seconds === 0) {
    return `${minutes}m`
  }

  return `${minutes}m ${seconds}s`
}

function getFingerprintLabel(finding: EnrichedFindingResponse) {
  const source = `${finding.type} ${finding.category} ${finding.title}`.toLowerCase()

  if (source.includes("framework")) {
    return "Framework"
  }

  if (source.includes("server")) {
    return "Server"
  }

  if (source.includes("edge") || source.includes("cdn")) {
    return "CDN"
  }

  if (source.includes("generator")) {
    return "Generator"
  }

  return finding.title
}

function getFingerprintValue(finding: EnrichedFindingResponse) {
  const detailValues = Object.values(finding.details ?? {}).filter((value): value is string => typeof value === "string" && value.trim().length > 0)

  if (detailValues.length) {
    return detailValues.join(" ").trim()
  }

  return finding.evidence
    .replace(/^detected\s+/i, "")
    .replace(/^(framework|server technology|cdn or edge provider|generator)\s*/i, "")
    .replace(/^[:\-]\s*/, "")
    .trim()
}

function ReportSkeleton() {
  return (
    <main className="mx-auto min-h-screen w-full max-w-7xl px-6 py-8 sm:px-10 lg:px-12">
      <div className="space-y-24">
        <div className="flex min-h-[80vh] flex-col justify-center gap-12 lg:flex-row lg:items-center lg:justify-between">
          <div className="space-y-5">
            <Skeleton className="h-4 w-28 rounded-full" />
            <Skeleton className="h-16 w-2/3 rounded-2xl" />
            <Skeleton className="h-20 w-full rounded-3xl" />
            <Skeleton className="h-6 w-3/4 rounded-xl" />
            <Skeleton className="h-6 w-1/2 rounded-xl" />
          </div>
          <Skeleton className="h-[300px] w-[300px] rounded-full sm:h-[340px] sm:w-[340px]" />
        </div>

        <div className="min-h-[80vh] space-y-10">
          <div className="space-y-3">
            <Skeleton className="h-4 w-32 rounded-full" />
            <Skeleton className="h-10 w-4/5 rounded-2xl" />
            <Skeleton className="h-16 w-full rounded-3xl" />
          </div>
          <div className="space-y-5">
            {Array.from({ length: 3 }).map((_, index) => (
              <Skeleton key={index} className="h-40 rounded-3xl" />
            ))}
          </div>
        </div>

        <div className="grid gap-10 lg:grid-cols-[220px_minmax(0,1fr)]">
          <div className="space-y-3">
            <Skeleton className="h-4 w-24 rounded-full" />
            <Skeleton className="h-10 w-32 rounded-2xl" />
            {Array.from({ length: 4 }).map((_, index) => (
              <Skeleton key={index} className="h-10 rounded-xl" />
            ))}
          </div>
          <div className="space-y-8">
            {Array.from({ length: 3 }).map((_, index) => (
              <Skeleton key={index} className="h-52 rounded-3xl" />
            ))}
          </div>
        </div>
      </div>
    </main>
  )
}
