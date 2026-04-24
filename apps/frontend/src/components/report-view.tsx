"use client"

import { ArrowLeft, CalendarClock, CheckCircle2, CircleAlert, CircleDashed, ShieldCheck, XCircle } from "lucide-react"
import Link from "next/link"

import type {
  EnrichedFindingResponse,
  EnrichedReportResponse,
  ReportCheckCategoryResponse,
  ReportCheckResponse,
  ReportCheckStatus,
  Severity,
} from "@/types/report"
import { formatDateTime, getSeverityTone, severityLabel } from "@/utils/format"
import { Badge } from "@/components/ui/badge"

type ReportViewProps = {
  report: EnrichedReportResponse
}

const ACTION_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"]

// All content uses this consistent left margin.
// Header is full-bleed. Everything inside is left-aligned to this rail.
const rail = "px-6 sm:px-10 lg:px-16"
const innerMax = "max-w-3xl"

function Mark() {
  return (
    <svg width="16" height="16" viewBox="0 0 18 18" fill="none" aria-hidden>
      <rect x="1" y="1" width="7" height="7" fill="currentColor" opacity="0.9" />
      <rect x="10" y="1" width="7" height="7" fill="currentColor" opacity="0.35" />
      <rect x="1" y="10" width="7" height="7" fill="currentColor" opacity="0.35" />
      <rect x="10" y="10" width="7" height="7" fill="currentColor" opacity="0.7" />
    </svg>
  )
}

export function ReportView({ report }: ReportViewProps) {
  const severityItems = ACTION_ORDER.filter((s) => report.summary[s] > 0).map((s) => ({
    severity: s,
    value: report.summary[s],
  }))

  const immediateSeverity: Severity =
    report.summary.critical > 0 ? "critical" : report.summary.high > 0 ? "high" : "medium"

  const immediateIssues = report.top_issues
    .filter((i) => i.severity === immediateSeverity)
    .slice(0, 5)
  const fallbackIssues =
    immediateIssues.length > 0
      ? immediateIssues
      : report.top_issues
          .filter((i) => ACTION_ORDER.indexOf(i.severity) <= ACTION_ORDER.indexOf("medium"))
          .slice(0, 5)
  const primaryIssues = fallbackIssues.slice(0, 2)
  const secondaryIssues = fallbackIssues.slice(2)

  return (
    <div className="min-h-screen bg-background text-foreground">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <header className={`flex items-center justify-between py-5 ${rail}`}>
        <div className="flex items-center gap-2.5">
          <Mark />
          <span className="text-sm font-semibold tracking-tight">SurfaceLab</span>
        </div>
        <Link
          href="/"
          className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.22em] text-muted-foreground/50 transition-colors hover:text-foreground"
        >
          <ArrowLeft className="size-3" />
          New scan
        </Link>
      </header>

      {/* ── Cover — target name + score side by side ─────────────────────── */}
      {/*
        Full-bleed section. Left side: eyebrow + target name + counts + meta.
        Right side: score — separated by a right-side border so it reads as
        a distinct column, not a floating widget.
      */}
      <section className="border-t border-border/40">
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px]">

          {/* Left — report identity */}
          <div className={`py-12 lg:py-16 ${rail}`}>
            <p className="mb-4 text-[10px] font-semibold uppercase tracking-[0.32em] text-muted-foreground/40">
              Security report
            </p>
            <h1 className="font-heading text-[2rem] font-semibold leading-tight tracking-tight sm:text-[2.5rem] lg:text-[3rem]">
              {report.target}
            </h1>

            {severityItems.length > 0 && (
              <div className="mt-6 flex flex-wrap items-center gap-x-6 gap-y-2">
                {severityItems.map(({ severity, value }) => {
                  const tone = getSeverityTone(severity)
                  return (
                    <div key={severity} className="flex items-center gap-2">
                      <span className={`size-1.5 rounded-full ${tone.dot}`} />
                      <span className="text-sm font-semibold tabular-nums leading-none">{value}</span>
                      <span className="text-sm text-muted-foreground">{severityLabel(severity)}</span>
                    </div>
                  )
                })}
              </div>
            )}

            <div className="mt-5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground/40">
              {report.completed_at ? (
                <span className="inline-flex items-center gap-1.5">
                  <ShieldCheck className="size-3" />
                  Completed {formatDateTime(report.completed_at)}
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5">
                  <CalendarClock className="size-3" />
                  Created {formatDateTime(report.created_at)}
                </span>
              )}
              {getScanDuration(report.created_at, report.completed_at) && (
                <span>· {getScanDuration(report.created_at, report.completed_at)}</span>
              )}
              {!report.completed_at && (
                <span className="inline-flex items-center gap-1.5 text-chart-1/80">
                  <CircleAlert className="size-3" />
                  Scan still running
                </span>
              )}
            </div>
          </div>

          {/* Right — score, vertically centred in its column */}
          <div className="flex justify-center items-center border-t border-border/40 px-8 py-10 lg:border-l lg:border-t-0 lg:px-10">
            <ScoreDisplay score={report.score} />
          </div>
        </div>
      </section>

      {/* ── Executive summary ────────────────────────────────────────────── */}
      {report.executive_summary && (
        <section className={`border-t border-border/40 py-10 ${rail}`}>
          <p className={`text-[0.9375rem] leading-[1.9] text-foreground/75 ${innerMax}`}>
            {report.executive_summary}
          </p>
        </section>
      )}

      {/* ── Immediate action ─────────────────────────────────────────────── */}
      <section className={`border-t border-border/40 py-12 lg:py-16 ${rail}`}>
        <div className={innerMax}>

          {/* Section label */}
          <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.32em] text-muted-foreground/40">
            Immediate action
          </p>
          <h2 className="font-heading text-xl font-semibold tracking-tight">
            {report.summary.critical > 0
              ? "Critical changes needed."
              : report.summary.high > 0
                ? "Address these first."
                : "Strongest next actions."}
          </h2>
          <p className="mt-2 text-sm leading-[1.8] text-muted-foreground">
            {report.summary.critical > 0
              ? "Critical findings present. Remediate these before lower-severity work."
              : report.summary.high > 0
                ? "No critical findings. These high-severity issues are the most important next changes."
                : "No critical or high findings. These are the strongest remaining actions."}
          </p>

          {/* Primary findings */}
          <div className="mt-10 space-y-10">
            {primaryIssues.length > 0 ? (
              primaryIssues.map((issue) => (
                <PrimaryIssue key={`${issue.tool_name}-${issue.title}`} issue={issue} />
              ))
            ) : (
              <p className="text-sm text-muted-foreground">
                No immediate-action findings were surfaced for this report.
              </p>
            )}
          </div>

          {/* Secondary findings */}
          {secondaryIssues.length > 0 && (
            <div className="mt-10 space-y-8 border-t border-border/30 pt-10">
              {secondaryIssues.map((issue) => (
                <SecondaryIssue key={`${issue.tool_name}-${issue.title}`} issue={issue} />
              ))}
            </div>
          )}

          {/* Quick wins */}
          {report.quick_wins.length > 0 && (
            <div className="mt-10 border-t border-border/30 pt-10">
              <p className="mb-5 text-[10px] font-semibold uppercase tracking-[0.32em] text-muted-foreground/40">
                Quick wins
              </p>
              <ol className="space-y-3">
                {report.quick_wins.slice(0, 4).map((item, i) => (
                  <li key={item} className="grid grid-cols-[1.5rem_1fr] gap-x-3 text-sm leading-[1.8]">
                    <span className="pt-px text-right font-mono text-xs tabular-nums text-muted-foreground/30">
                      {i + 1}.
                    </span>
                    <span>{item}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      </section>

      {/* ── Deep dive ────────────────────────────────────────────────────── */}
      {/*
        Two-column layout: narrow sticky sidebar on the left for navigation,
        findings content on the right. Both columns share the same `rail` left
        edge so everything aligns to the same vertical line as sections above.
      */}
      <section className={`border-t border-border/40 pb-28 ${rail}`}>
        <div className="grid grid-cols-1 gap-0 pt-0 lg:grid-cols-[160px_1fr] lg:gap-12">

          {/* Sidebar — sticky nav */}
          <div className="hidden pt-12 lg:block">
            <div className="sticky top-8">
              <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.32em] text-muted-foreground/35">
                Categories
              </p>
              <nav className="space-y-0.5">
                {report.categories.map((cat) => (
                  <a
                    key={cat.slug}
                    href={`#${cat.slug}`}
                    className="flex items-center justify-between py-1.5 text-[13px] text-muted-foreground/50 transition-colors hover:text-foreground"
                  >
                    <span className="truncate">{cat.name}</span>
                    <span className="ml-3 shrink-0 font-mono text-[11px] tabular-nums text-muted-foreground/30">
                      {cat.count}
                    </span>
                  </a>
                ))}
              </nav>
            </div>
          </div>

          {/* Findings content */}
          <div className={`${innerMax} divide-y divide-border/30`}>
            {report.categories.map((category) => (
              <div key={category.slug} id={category.slug} className="scroll-mt-8 py-12">

                <div className="mb-7">
                  <div className="flex flex-wrap items-baseline gap-2.5">
                    <h3 className="font-heading text-lg font-semibold tracking-tight">
                      {category.name}
                    </h3>
                    <CategoryTag count={category.count} severity={category.highest_severity} />
                  </div>
                  <p className="mt-2 text-sm leading-[1.8] text-muted-foreground">
                    {getCategoryDescription(category.name)}
                  </p>
                </div>

                {isInformationalCategory(category.name) ? (
                  <div className="divide-y divide-border/25">
                    {category.findings.map((finding) => (
                      <FingerprintRow
                        key={`${category.slug}-${finding.title}-${finding.tool_name}`}
                        finding={finding}
                      />
                    ))}
                  </div>
                ) : (
                  <div className="divide-y divide-border/25">
                    {category.findings.map((finding) => (
                      <FindingRow
                        key={`${category.slug}-${finding.title}-${finding.tool_name}`}
                        finding={finding}
                      />
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Verification coverage ───────────────────────────────────────── */}
      {report.check_categories.length > 0 && (
        <section className={`border-t border-border/40 py-12 lg:py-16 ${rail}`}>
          <div className={innerMax}>
            <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.32em] text-muted-foreground/40">
              Verification coverage
            </p>
            <h2 className="font-heading text-xl font-semibold tracking-tight">
              Everything checked in this run.
            </h2>
            <p className="mt-2 text-sm leading-[1.8] text-muted-foreground">
              Findings above show what needs attention. This section shows the full checklist, including checks that passed.
            </p>

            <div className="mt-8 space-y-8">
              {report.check_categories.map((category) => (
                <CheckCategoryBlock key={category.slug} category={category} />
              ))}
            </div>
          </div>
        </section>
      )}
    </div>
  )
}

export function ReportErrorView({ message }: { message: string }) {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className={`flex items-center justify-between py-5 ${rail}`}>
        <div className="flex items-center gap-2.5">
          <Mark />
          <span className="text-sm font-semibold tracking-tight">SurfaceLab</span>
        </div>
      </header>
      <div className={`flex min-h-[calc(100vh-60px)] flex-col justify-center ${rail}`}>
        <div className="max-w-md space-y-4">
          <p className="text-[10px] font-semibold uppercase tracking-[0.32em] text-muted-foreground/40">
            Error
          </p>
          <h1 className="font-heading text-2xl font-semibold tracking-tight">
            Unable to load report
          </h1>
          <p className="text-sm leading-[1.8] text-muted-foreground">{message}</p>
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.22em] text-muted-foreground/50 transition-colors hover:text-foreground"
          >
            <ArrowLeft className="size-3" />
            Back to home
          </Link>
        </div>
      </div>
    </div>
  )
}

// ── Score ─────────────────────────────────────────────────────────────────────

function ScoreDisplay({ score }: { score: number }) {
  const r = 42
  const sw = 5.5
  const circ = 2 * Math.PI * r
  const offset = circ - (Math.max(0, Math.min(100, score)) / 100) * circ
  const ringColor = getScoreRingColor(score)
  const labelColor = getScoreLabelColor(score)

  return (
    <div className="flex flex-col items-center justify-center gap-3">
      <div className="relative flex size-40 items-center justify-center">
        <svg viewBox="0 0 88 88" className="h-full w-full -rotate-90">
          <circle cx="44" cy="44" r={r} fill="none" stroke="var(--border)" strokeOpacity="0.4" strokeWidth={sw} />
          <circle
            cx="44" cy="44" r={r} fill="none"
            stroke={ringColor} strokeLinecap="round" strokeWidth={sw}
            strokeDasharray={circ} strokeDashoffset={offset}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-6xl font-semibold tabular-nums leading-none">{score}</span>
        </div>
      </div>
      <div>
        <p className={`text-xs font-semibold ${labelColor}`}>{getRiskLabel(score)}</p>
        <p className="text-[10px] text-muted-foreground/40">Security score</p>
      </div>
    </div>
  )
}

// ── Issue components ──────────────────────────────────────────────────────────

function PrimaryIssue({ issue }: { issue: EnrichedFindingResponse }) {
  const tone = getSeverityTone(issue.severity)
  return (
    <article>
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className={`size-1.5 rounded-full ${tone.dot}`} />
        <span className="text-[10px] font-semibold uppercase tracking-[0.22em] text-muted-foreground/60">
          {severityLabel(issue.severity)}
        </span>
        <span className="text-muted-foreground/25">·</span>
        <span className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground/40">
          {issue.tool_name}
        </span>
      </div>
      <h3 className="font-heading text-[1.125rem] font-semibold leading-snug tracking-tight">
        {issue.title}
      </h3>
      <p className="mt-2 text-sm leading-[1.85] text-muted-foreground">{issue.evidence}</p>
      {issue.remediation_summary && (
        <p className="mt-2 text-sm leading-[1.85] text-foreground/65">{issue.remediation_summary}</p>
      )}
    </article>
  )
}

function SecondaryIssue({ issue }: { issue: EnrichedFindingResponse }) {
  const tone = getSeverityTone(issue.severity)
  return (
    <article>
      <div className="mb-1.5 flex flex-wrap items-center gap-2">
        <span className={`size-1.5 rounded-full ${tone.dot}`} />
        <span className="text-[10px] font-semibold uppercase tracking-[0.22em] text-muted-foreground/60">
          {severityLabel(issue.severity)}
        </span>
        <span className="text-muted-foreground/25">·</span>
        <span className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground/40">
          {issue.tool_name}
        </span>
      </div>
      <h3 className="text-sm font-semibold leading-snug">{issue.title}</h3>
      <p className="mt-1.5 text-sm leading-[1.85] text-muted-foreground">{issue.evidence}</p>
      {issue.remediation_summary && (
        <p className="mt-1.5 text-sm leading-[1.85] text-foreground/65">{issue.remediation_summary}</p>
      )}
    </article>
  )
}

function FindingRow({ finding }: { finding: EnrichedFindingResponse }) {
  const tone = getSeverityTone(finding.severity)
  return (
    <div className="py-7">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className={`size-1.5 rounded-full ${tone.dot}`} />
        <span className="text-[10px] font-semibold uppercase tracking-[0.22em] text-muted-foreground/60">
          {severityLabel(finding.severity)}
        </span>
        <span className="text-muted-foreground/25">·</span>
        <span className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground/40">
          {finding.tool_name}
        </span>
        {finding.confidence && (
          <>
            <span className="text-muted-foreground/25">·</span>
            <span className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground/35">
              {finding.confidence}
            </span>
          </>
        )}
      </div>
      <h4 className="text-sm font-semibold leading-snug">{finding.title}</h4>
      <p className="mt-1.5 text-sm leading-[1.85] text-muted-foreground">{finding.evidence}</p>
      {finding.remediation_summary && (
        <p className="mt-1.5 text-sm leading-[1.85] text-foreground/65">{finding.remediation_summary}</p>
      )}
      {finding.source_references.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-x-3 gap-y-1">
          {finding.source_references.map((r) => (
            <span key={r} className="font-mono text-[10px] text-muted-foreground/30">{r}</span>
          ))}
        </div>
      )}
    </div>
  )
}

function FingerprintRow({ finding }: { finding: EnrichedFindingResponse }) {
  const label = getFingerprintLabel(finding)
  const value = getFingerprintValue(finding)
  return (
    <div className="grid gap-x-8 gap-y-1 py-4 sm:grid-cols-[100px_1fr] sm:items-baseline">
      <dt className="text-[10px] font-semibold uppercase tracking-[0.22em] text-muted-foreground/40">
        {label}
      </dt>
      <dd>
        <p className="text-sm text-muted-foreground">{value}</p>
        {finding.source_references.length > 0 && (
          <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
            {finding.source_references.map((r) => (
              <span key={r} className="font-mono text-[10px] text-muted-foreground/30">{r}</span>
            ))}
          </div>
        )}
      </dd>
    </div>
  )
}

function CategoryTag({ count, severity }: { count: number; severity: Severity }) {
  const tone = getSeverityTone(severity)
  return (
    <div className="flex items-center gap-2">
      <Badge className={`${tone.badge} border-0 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-[0.15em]`}>
        {severityLabel(severity)}
      </Badge>
      <span className="text-[11px] text-muted-foreground/40">
        {count} finding{count === 1 ? "" : "s"}
      </span>
    </div>
  )
}

function CheckCategoryBlock({ category }: { category: ReportCheckCategoryResponse }) {
  return (
    <div className="border-t border-border/30 pt-7 first:border-t-0 first:pt-0">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-heading text-lg font-semibold tracking-tight">{category.name}</h3>
        <div className="flex flex-wrap items-center gap-4 text-[11px] uppercase tracking-[0.18em] text-muted-foreground/50">
          <span className="text-destructive/80">{category.failed} failed</span>
          <span className="text-chart-5/80">{category.passed} passed</span>
          <span>{category.not_run} not run</span>
        </div>
      </div>

      <div className="divide-y divide-border/25">
        {category.checks.map((check) => (
          <CheckRow key={check.id} check={check} />
        ))}
      </div>
    </div>
  )
}

function CheckRow({ check }: { check: ReportCheckResponse }) {
  const statusTone = getCheckStatusTone(check.status)

  return (
    <div className="grid gap-x-4 gap-y-1 py-4 sm:grid-cols-[22px_1fr] sm:items-start">
      <div className="pt-0.5 text-muted-foreground/80">{statusTone.icon}</div>
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <h4 className="text-sm font-semibold leading-snug">{check.title}</h4>
          <Badge className={`${statusTone.badge} border-0 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-[0.15em]`}>
            {statusTone.label}
          </Badge>
        </div>
        <p className="mt-1 text-sm leading-[1.8] text-muted-foreground">{check.detail}</p>
      </div>
    </div>
  )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function getRiskLabel(score: number) {
  if (score >= 80) return "Low risk"
  if (score >= 60) return "Moderate risk"
  return "High risk"
}

function getScoreRingColor(score: number) {
  if (score >= 80) return "var(--chart-5)"
  if (score >= 60) return "var(--chart-1)"
  return "var(--destructive)"
}

function getScoreLabelColor(score: number) {
  if (score >= 80) return "text-chart-5"
  if (score >= 60) return "text-chart-1"
  return "text-destructive"
}

function getScanDuration(createdAt: string, completedAt: string | null) {
  if (!completedAt) return null
  const d = new Date(completedAt).getTime() - new Date(createdAt).getTime()
  if (Number.isNaN(d) || d <= 0) return null
  const s = Math.round(d / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  const rem = s % 60
  return rem === 0 ? `${m}m` : `${m}m ${rem}s`
}

function getCategoryDescription(name: string) {
  const map: Record<string, string> = {
    "HTTP Headers": "Response header findings affecting transport hardening, browser isolation, and baseline security policy.",
    "Public Exposure": "Publicly accessible files and deployment artifacts that increase the exposed surface area.",
    "Sensitive File Exposure": "Direct exposure of sensitive files or artifacts that should not be publicly retrievable.",
    "Technology Fingerprint": "Observed infrastructure and framework signals. Informational — not vulnerabilities on their own.",
    "Next.js Stack": "Next.js framework markers, routing surfaces, build metadata, and deployment artifacts observed during specialist checks.",
    "WordPress Stack": "WordPress-specific application surface findings and exposed platform artifacts observed during specialist checks.",
    Other: "Additional findings that did not map cleanly into the primary report sections.",
  }
  return map[name] ?? "Findings grouped for deeper technical review and remediation planning."
}

function isInformationalCategory(name: string) {
  return name === "Technology Fingerprint"
}

function getFingerprintLabel(finding: EnrichedFindingResponse) {
  const src = `${finding.type} ${finding.category} ${finding.title}`.toLowerCase()
  if (src.includes("framework")) return "Framework"
  if (src.includes("server")) return "Server"
  if (src.includes("edge") || src.includes("cdn")) return "CDN"
  if (src.includes("generator")) return "Generator"
  return finding.title
}

function getFingerprintValue(finding: EnrichedFindingResponse) {
  const details = finding.details ?? {}
  for (const key of ["framework", "server", "cdn", "generator", "name", "product", "value"]) {
    const value = details[key]
    if (typeof value === "string" && value.trim()) return value.trim()
  }

  return finding.evidence
    .replace(/^detected\s+/i, "")
    .replace(/^(framework|server technology|cdn or edge provider|generator)\s*/i, "")
    .replace(/^[:\-]\s*/, "")
    .trim()
}

function getCheckStatusTone(status: ReportCheckStatus) {
  if (status === "failed") {
    return {
      label: "failed",
      badge: "bg-destructive/15 text-destructive",
      icon: <XCircle className="size-4 text-destructive" />,
    }
  }

  if (status === "passed") {
    return {
      label: "passed",
      badge: "bg-chart-5/15 text-chart-5",
      icon: <CheckCircle2 className="size-4 text-chart-5" />,
    }
  }

  return {
    label: "not run",
    badge: "bg-muted text-muted-foreground",
    icon: <CircleDashed className="size-4 text-muted-foreground/70" />,
  }
}
