"use client"

import * as React from "react"
import { AlertTriangle, Check, LoaderCircle } from "lucide-react"
import { useRouter } from "next/navigation"

import type { ScanWorkflowEvent } from "@/types/report"
import { cn } from "@/utils/utils"

type ScanProgressProps = {
  scanId: string
}

type ProgressStepStatus = "active" | "completed" | "failed"

type ProgressStep = {
  id: string
  label: string
  detail?: string
  status: ProgressStepStatus
}

const INITIAL_STEPS: ProgressStep[] = [
  { id: "stream.connecting", label: "Connecting...", status: "active" },
]

const REVEAL_INTERVAL_MS = 300

export function ScanProgress({ scanId }: ScanProgressProps) {
  const router = useRouter()
  const [visibleSteps, setVisibleSteps] = React.useState<ProgressStep[]>(INITIAL_STEPS)
  const [connectionState, setConnectionState] = React.useState<"connecting" | "live" | "reconnecting" | "completed">("connecting")
  const [completionRequested, setCompletionRequested] = React.useState(false)

  const canonicalStepsRef = React.useRef<ProgressStep[]>(INITIAL_STEPS)
  const pendingRevealRef = React.useRef<ProgressStep[]>([])
  const revealTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null)
  const scanCompletedRef = React.useRef(false)

  const hasOpenedStreamRef = React.useRef(false)
  const hasReceivedEventRef = React.useRef(false)
  const loggedConnectionErrorRef = React.useRef(false)

  const scheduleReveal = React.useCallback(() => {
    if (revealTimerRef.current !== null) return

    const tick = () => {
      revealTimerRef.current = null
      const queue = pendingRevealRef.current
      if (queue.length === 0) return

      const next = queue[0]!
      pendingRevealRef.current = queue.slice(1)
      setVisibleSteps((current) => mergeStep(current, next))

      if (pendingRevealRef.current.length > 0) {
        const delay = scanCompletedRef.current ? 80 : REVEAL_INTERVAL_MS
        revealTimerRef.current = setTimeout(tick, delay)
      }
    }

    const delay = scanCompletedRef.current ? 80 : REVEAL_INTERVAL_MS
    revealTimerRef.current = setTimeout(tick, delay)
  }, [])

  const enqueueStepUpdate = React.useCallback(
    (stepUpdate: ProgressStep) => {
      const existing = pendingRevealRef.current.findIndex((s) => s.id === stepUpdate.id)
      if (existing >= 0) {
        const updated = [...pendingRevealRef.current]
        updated[existing] = stepUpdate
        pendingRevealRef.current = updated
      } else {
        pendingRevealRef.current = [...pendingRevealRef.current, stepUpdate]
      }
      scheduleReveal()
    },
    [scheduleReveal],
  )

  React.useEffect(() => {
    let cancelled = false
    const connectionGracePeriodId = window.setTimeout(() => {
      if (!cancelled && !hasOpenedStreamRef.current && !hasReceivedEventRef.current) {
        setConnectionState((current) => (current === "completed" ? current : "reconnecting"))
      }
    }, 8_000)

    const eventSource = new EventSource(`/api/scans/${scanId}/events`)

    eventSource.onopen = () => {
      if (cancelled) return
      hasOpenedStreamRef.current = true
      loggedConnectionErrorRef.current = false
      setConnectionState((current) => (current === "completed" ? current : "live"))
      // Once the stream opens, remove the placeholder — the first real event
      // will replace it. Don't replace with "Waiting for scan events..." which
      // reads as a debug string, not a product state.
      setVisibleSteps((current) => removePlaceholderStep(current))
    }

    eventSource.onmessage = (message) => {
      if (cancelled) return

      try {
        const event = JSON.parse(message.data) as ScanWorkflowEvent
        hasReceivedEventRef.current = true
        setConnectionState((current) => (current === "completed" ? current : "live"))

        const stepUpdate = mapEventToStep(event)
        if (stepUpdate) {
          canonicalStepsRef.current = applyWorkflowEvent(canonicalStepsRef.current, stepUpdate)
          enqueueStepUpdate(stepUpdate)

          if (stepUpdate.status === "active") {
            findClosedSteps(canonicalStepsRef.current, stepUpdate.id).forEach((s) =>
              enqueueStepUpdate(s),
            )
          }
        }

        if (event.type === "scan.completed") {
          scanCompletedRef.current = true
          setConnectionState("completed")
          setCompletionRequested(true)
          eventSource.close()
          scheduleReveal()
        }
      } catch {
        setConnectionState((current) => (current === "completed" ? current : "reconnecting"))
      }
    }

    eventSource.onerror = () => {
      if (!cancelled) {
        if (process.env.NODE_ENV === "development" && !loggedConnectionErrorRef.current) {
          console.error("[scan-progress] SSE stream disconnected; waiting for reconnect")
          loggedConnectionErrorRef.current = true
        }
        setConnectionState((current) => (current === "completed" ? current : "reconnecting"))
      }
    }

    return () => {
      cancelled = true
      window.clearTimeout(connectionGracePeriodId)
      if (revealTimerRef.current !== null) clearTimeout(revealTimerRef.current)
      eventSource.close()
    }
  }, [scanId, enqueueStepUpdate, scheduleReveal])

  React.useEffect(() => {
    if (connectionState !== "reconnecting") return
    setVisibleSteps((current) => {
      const lastActiveIndex = [...current].reverse().findIndex((s) => s.status === "active")
      if (lastActiveIndex === -1) return current
      const index = current.length - 1 - lastActiveIndex
      const updated = [...current]
      updated[index] = { ...updated[index]!, label: "Reconnecting..." }
      return updated
    })
  }, [connectionState])

  React.useEffect(() => {
    if (!completionRequested) return
    const refreshId = window.setTimeout(() => router.refresh(), 900)
    return () => window.clearTimeout(refreshId)
  }, [completionRequested, router])

  return (
    <ScanPageShell>
      <ProgressList steps={visibleSteps} />
    </ScanPageShell>
  )
}

export function ScanProgressPlaceholder() {
  return (
    <ScanPageShell>
      <ProgressList steps={INITIAL_STEPS} />
    </ScanPageShell>
  )
}

// ---------------------------------------------------------------------------
// Page shell
// ---------------------------------------------------------------------------

const rail = "px-6 sm:px-10 lg:px-16"

function ScanPageShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background text-foreground">

      {/* Header — identical rail to report/landing */}
      <header className={`flex items-center justify-between py-5 ${rail}`}>
        <div className="flex items-center gap-2.5">
          <svg width="16" height="16" viewBox="0 0 18 18" fill="none" aria-hidden>
            <rect x="1" y="1" width="7" height="7" fill="currentColor" opacity="0.9" />
            <rect x="10" y="1" width="7" height="7" fill="currentColor" opacity="0.35" />
            <rect x="1" y="10" width="7" height="7" fill="currentColor" opacity="0.35" />
            <rect x="10" y="10" width="7" height="7" fill="currentColor" opacity="0.7" />
          </svg>
          <span className="text-sm font-semibold tracking-tight">SurfaceLab</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="relative flex size-1.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-chart-2 opacity-50" />
            <span className="relative inline-flex size-1.5 rounded-full bg-chart-2" />
          </span>
          <span className="text-[10px] font-semibold uppercase tracking-[0.25em] text-muted-foreground/40">
            Scanning
          </span>
        </div>
      </header>

      {/* Body — split at lg: step list left, report outline right */}
      <div className={`grid min-h-[calc(100vh-56px)] border-t border-border/40 lg:grid-cols-[1fr_1fr]`}>

        {/* Left — progress */}
        <div className={`flex flex-col justify-center border-b border-border/40 py-16 lg:border-b-0 lg:border-r lg:py-20 ${rail}`}>
          <p className="mb-8 text-[10px] font-semibold uppercase tracking-[0.32em] text-muted-foreground/35">
            Scan in progress
          </p>

          {children}

          <p className="mt-10 text-[11px] text-muted-foreground/30">
            Keep this tab open. The report opens automatically when the scan completes.
          </p>
        </div>

        {/* Right — report structure preview, visible on lg+ */}
        <div className={`hidden lg:flex lg:flex-col lg:justify-center lg:py-20 ${rail}`}>
          <ReportOutline />
        </div>

      </div>
    </div>
  )
}

// Report outline — a skeleton that mirrors the actual report structure
// with enough visual weight to be meaningful, not just decorative.
function ReportOutline() {
  return (
    <div className="max-w-sm space-y-0">

      {/* Cover section */}
      <div className="border-b border-border/30 pb-8">
        <div className="mb-3 h-2 w-20 rounded-full bg-border/50" />
        <div className="mb-4 h-5 w-48 rounded bg-border/40" />
        <div className="flex gap-3">
          <div className="flex items-center gap-1.5">
            <div className="h-1.5 w-1.5 rounded-full bg-destructive/50" />
            <div className="h-2 w-8 rounded-full bg-border/30" />
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-1.5 w-1.5 rounded-full bg-chart-1/50" />
            <div className="h-2 w-10 rounded-full bg-border/30" />
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-1.5 w-1.5 rounded-full bg-border/60" />
            <div className="h-2 w-6 rounded-full bg-border/30" />
          </div>
        </div>
      </div>

      {/* Executive summary */}
      <div className="border-b border-border/30 py-8">
        <div className="space-y-1.5">
          <div className="h-2 w-full rounded-full bg-border/25" />
          <div className="h-2 w-5/6 rounded-full bg-border/20" />
          <div className="h-2 w-4/5 rounded-full bg-border/18" />
          <div className="h-2 w-3/5 rounded-full bg-border/15" />
        </div>
      </div>

      {/* Immediate action */}
      <div className="border-b border-border/30 py-8">
        <div className="mb-3 h-2 w-24 rounded-full bg-border/40" />
        <div className="mb-3 h-4 w-40 rounded bg-border/30" />
        <div className="space-y-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5">
              <div className="h-1.5 w-1.5 rounded-full bg-destructive/40" />
              <div className="h-1.5 w-12 rounded-full bg-border/25" />
            </div>
            <div className="h-3 w-36 rounded bg-border/25" />
            <div className="h-2 w-full rounded-full bg-border/18" />
          </div>
          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5">
              <div className="h-1.5 w-1.5 rounded-full bg-destructive/35" />
              <div className="h-1.5 w-16 rounded-full bg-border/20" />
            </div>
            <div className="h-3 w-32 rounded bg-border/20" />
            <div className="h-2 w-4/5 rounded-full bg-border/15" />
          </div>
        </div>
      </div>

      {/* Deep dive */}
      <div className="pt-8">
        <div className="mb-3 h-2 w-16 rounded-full bg-border/35" />
        <div className="space-y-2">
          {[32, 40, 28, 36].map((w, i) => (
            <div key={i} className="flex items-center justify-between">
              <div className={`h-2 w-${w} rounded-full bg-border/20`} />
              <div className="h-1.5 w-3 rounded-full bg-border/15" />
            </div>
          ))}
        </div>
      </div>

    </div>
  )
}

// ---------------------------------------------------------------------------
// Step list
// ---------------------------------------------------------------------------

function ProgressList({ steps }: { steps: ProgressStep[] }) {
  const completed = steps.filter((s) => s.status === "completed")
  const current = steps.filter((s) => s.status !== "completed")

  return (
    <div>
      {/* Completed — small, quiet, stacked above */}
      {completed.length > 0 && (
        <div className="mb-6 space-y-1.5 border-b border-border/30 pb-6">
          {completed.map((step) => (
            <div key={step.id} className="flex items-center gap-2.5">
              <Check className="size-3 shrink-0 text-muted-foreground/30" strokeWidth={2} />
              <span className="text-[13px] text-muted-foreground/35">{step.label}</span>
            </div>
          ))}
        </div>
      )}

      {/* Active / failed — prominent */}
      <div className="space-y-5">
        {current.map((step) => (
          <div key={step.id}>
            <div className="flex items-center gap-3">
              <span
                className={cn(
                  "shrink-0",
                  step.status === "active" && "text-foreground",
                  step.status === "failed" && "text-amber-400",
                )}
              >
                {step.status === "active" ? (
                  <LoaderCircle className="size-3.5 animate-spin" />
                ) : (
                  <AlertTriangle className="size-3.5" />
                )}
              </span>
              <span
                className={cn(
                  "text-[15px] font-medium leading-snug",
                  step.status === "active" && "text-foreground",
                  step.status === "failed" && "text-amber-300",
                )}
              >
                {step.label}
              </span>
            </div>
            {step.detail && (
              <p className="ml-6.5 mt-1 text-[12px] leading-relaxed text-muted-foreground/45">
                {step.detail}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Step list helpers
// ---------------------------------------------------------------------------

function removePlaceholderStep(steps: ProgressStep[]) {
  return steps.filter((step) => step.id !== "stream.connecting")
}

function mergeStep(steps: ProgressStep[], update: ProgressStep): ProgressStep[] {
  const index = steps.findIndex((s) => s.id === update.id)
  if (index >= 0) {
    const next = [...steps]
    next[index] = { ...next[index], ...update }
    return next
  }
  return [...steps, update]
}

function applyWorkflowEvent(steps: ProgressStep[], stepUpdate: ProgressStep): ProgressStep[] {
  let next = stepUpdate.status === "active" ? closeOtherActiveSteps(steps, stepUpdate.id) : steps
  next = removePlaceholderStep(next)
  return mergeStep(next, stepUpdate)
}

function closeOtherActiveSteps(steps: ProgressStep[], activeStepId: string): ProgressStep[] {
  return steps.map((step) => {
    if (step.id === activeStepId || step.status !== "active") return step
    return { ...step, status: "completed" as const }
  })
}

function findClosedSteps(steps: ProgressStep[], activeStepId: string): ProgressStep[] {
  return steps.filter((s) => s.id !== activeStepId && s.status === "completed")
}

// ---------------------------------------------------------------------------
// Event → step mapping
// ---------------------------------------------------------------------------

function mapEventToStep(event: ScanWorkflowEvent): ProgressStep | null {
  switch (event.type) {
    case "scan.started":
      return { id: "scan", label: "Starting scan...", status: "active" }

    case "baseline.started":
      return { id: "baseline", label: "Running basic scan...", status: "active" }

    case "baseline.completed":
      return { id: "baseline", label: "Basic scan completed", status: "completed" }

    case "vuln.research.planning.started":
      return { id: "vuln.research.plan", label: "Planning vulnerability lookups...", status: "active" }

    case "vuln.research.planning.completed":
      return { id: "vuln.research.plan", label: "Vulnerability lookups planned", status: "completed" }

    case "vuln.research.started":
      return { id: "vuln.research", label: "Searching NVD/CVE databases...", status: "active" }

    case "vuln.research.completed":
      return {
        id: "vuln.research",
        label: "Vulnerability research completed",
        detail: getVulnerabilityResearchDetail(event),
        status: "completed",
      }

    case "planner.started":
      return { id: "planner", label: "Planning advanced checks...", status: "active" }

    case "planner.completed":
      return { id: "planner", label: "Advanced checks planned", status: "completed" }

    case "contracts.selected":
      return {
        id: "contracts.selected",
        label: "Specialist checks selected",
        detail: getSelectedContractsDetail(event),
        status: "completed",
      }

    case "contract.started": {
      const name = getContractName(event)
      return { id: `contract:${name}`, label: `Running ${getContractLabel(name)}...`, status: "active" }
    }

    case "contract.completed": {
      const name = getContractName(event)
      return { id: `contract:${name}`, label: `${getContractLabel(name)} completed`, status: "completed" }
    }

    case "contract.failed": {
      const name = getContractName(event)
      return {
        id: `contract:${name}`,
        label: `${getContractLabel(name)} failed`,
        detail: getContractFailureDetail(event),
        status: "failed",
      }
    }

    case "retry.started":
      return {
        id: getAttemptStepId("retry", event),
        label: "Retrying failed check...",
        detail: getContractsListDetail(event),
        status: "active",
      }

    case "retry.completed":
      return {
        id: getAttemptStepId("retry", event),
        label: "Retry completed",
        detail: getContractsListDetail(event),
        status: "completed",
      }

    case "replan.started":
      return { id: "replan", label: "Revisiting scan strategy...", status: "active" }

    case "replan.completed":
      return { id: "replan", label: "Scan strategy updated", status: "completed" }

    case "merge.started":
      return { id: "merge", label: "Processing findings...", status: "active" }

    case "merge.completed":
      return { id: "merge", label: "Findings processed", status: "completed" }

    case "summary.started":
      return { id: "summary", label: "Generating summary...", status: "active" }

    case "summary.completed":
      return { id: "summary", label: "Summary generated", status: "completed" }

    case "scan.completed":
      return { id: "scan.completed", label: "Scan completed", status: "completed" }

    default:
      return null
  }
}

// ---------------------------------------------------------------------------
// Metadata helpers
// ---------------------------------------------------------------------------

function getContractName(event: ScanWorkflowEvent) {
  const contract = event.metadata.contract
  return typeof contract === "string" && contract.trim() ? contract : "advanced check"
}

function getContractLabel(contractName: string) {
  if (contractName === "wordpress.v1.run_stack") return "WordPress checks"
  if (contractName === "generic_http.v1.run_stack") return "Generic HTTP checks"
  if (contractName === "nextjs.v1.run_stack") return "Next.js checks"
  return contractName
    .replace(/\.v\d+\./g, " ")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

function getSelectedContractsDetail(event: ScanWorkflowEvent) {
  const contracts =
    getStringArray(event.metadata.executed_contracts) ??
    getStringArray(event.metadata.selected_contracts)
  const confidence =
    typeof event.metadata.confidence === "string" ? event.metadata.confidence : null
  if (!contracts?.length) return confidence ? `Confidence: ${confidence}` : undefined
  return `${contracts.map(getContractLabel).join(", ")}${confidence ? ` · ${confidence}` : ""}`
}

function getContractFailureDetail(event: ScanWorkflowEvent) {
  const error = event.metadata.error
  return typeof error === "string" && error.trim() ? error : undefined
}

function getContractsListDetail(event: ScanWorkflowEvent) {
  const contracts = getStringArray(event.metadata.contracts)
  return contracts?.length ? contracts.map(getContractLabel).join(", ") : undefined
}

function getAttemptStepId(prefix: "retry", event: ScanWorkflowEvent) {
  const contracts = getStringArray(event.metadata.contracts)
  return contracts?.length ? `${prefix}:${contracts.join("|")}` : `${prefix}:${event.timestamp}`
}

function getVulnerabilityResearchDetail(event: ScanWorkflowEvent) {
  const queryCount = typeof event.metadata.query_count === "number" ? event.metadata.query_count : null
  const cveCount = typeof event.metadata.cve_match_count === "number" ? event.metadata.cve_match_count : null

  if (queryCount === null && cveCount === null) return undefined
  if (queryCount !== null && cveCount !== null) return `${queryCount} queries · ${cveCount} CVE matches`
  if (queryCount !== null) return `${queryCount} queries`
  return `${cveCount} CVE matches`
}

function getStringArray(value: unknown) {
  if (!Array.isArray(value)) return null
  const values = value.filter(
    (item): item is string => typeof item === "string" && item.trim().length > 0,
  )
  return values.length ? values : null
}
