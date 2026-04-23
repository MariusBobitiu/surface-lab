import { ScanForm } from "@/components/scan-form"

const rail = "px-6 sm:px-10 lg:px-16"

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

export default function HomePage() {
  return (
    <div className="overflow-x-hidden bg-background text-foreground">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <header className={`flex items-center justify-between py-5 ${rail}`}>
        <div className="flex items-center gap-2.5">
          <Mark />
          <span className="text-sm font-semibold tracking-tight">SurfaceLab</span>
        </div>
        <span className="text-[10px] font-semibold uppercase tracking-[0.25em] text-muted-foreground/40">
          Security Analysis
        </span>
      </header>

      {/* ── Hero ────────────────────────────────────────────────────────── */}
      {/*
        Split: left has the full product statement and CTA.
        Right has a visible representation of the report — not a decorative
        blur, but actual structured content that signals what gets produced.
        Both sides share the same vertical rhythm. The border-t anchors both.
      */}
      <section className="grid min-h-[88vh] grid-cols-1 border-t border-border/40 lg:grid-cols-[1fr_1fr]">

        {/* Left — headline + CTA */}
        <div className={`flex flex-col justify-center border-b border-border/40 py-16 lg:border-b-0 lg:border-r lg:py-20 ${rail}`}>

          <p className="mb-6 text-[10px] font-semibold uppercase tracking-[0.32em] text-muted-foreground/40">
            Web security reporting
          </p>

          <h1 className="font-heading text-[2.5rem] font-semibold leading-[1.06] tracking-[-0.02em] sm:text-[3rem] lg:text-[3.5rem]">
            Surface what&rsquo;s exposed.
            <br />
            <span className="text-muted-foreground/50">Understand the risk.</span>
          </h1>

          <p className="mt-6 max-w-xs text-sm leading-[1.85] text-muted-foreground">
            Paste a URL. Get a full security report — findings ranked by severity, enriched with context, built for real triage.
          </p>

          <div className="mt-9 max-w-sm">
            <ScanForm />
          </div>

          <div className="mt-10 flex flex-wrap items-center gap-x-5 gap-y-2 text-[10px] font-semibold uppercase tracking-[0.25em] text-muted-foreground/30">
            <span>HTTP headers</span>
            <span className="h-px w-2 bg-current" />
            <span>Exposure</span>
            <span className="h-px w-2 bg-current" />
            <span>Fingerprint</span>
            <span className="h-px w-2 bg-current" />
            <span>Score</span>
          </div>
        </div>

        {/* Right — actual report preview, enough opacity to be real */}
        <div className={`hidden flex-col justify-center py-20 lg:flex ${rail}`}>
          <ReportPreview />
        </div>

      </section>

      {/* ── What it does ────────────────────────────────────────────────── */}
      <section className="border-t border-border/40 bg-card/25">
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_1fr]">

          <div className={`border-b border-border/40 py-14 lg:border-b-0 lg:border-r lg:py-16 ${rail}`}>
            <p className="mb-5 text-[10px] font-semibold uppercase tracking-[0.32em] text-muted-foreground/40">
              What it does
            </p>
            <h2 className="font-heading text-2xl font-semibold leading-snug tracking-tight lg:text-3xl">
              Not another header checker.
              <br />A real security report.
            </h2>
            <p className="mt-4 max-w-xs text-sm leading-[1.85] text-muted-foreground">
              A multi-stage pipeline — baseline checks, stack detection, specialist modules — producing a structured, enriched report you can act on.
            </p>
          </div>

          <div className={`py-14 lg:py-16 ${rail}`}>
            <Capability index="01" label="Severity-ranked findings" detail="Critical through informational, each with evidence and remediation guidance." />
            <Capability index="02" label="Executive summary" detail="Written from the actual findings — not a template. Readable by an engineer or a stakeholder." />
            <Capability index="03" label="Specialist stack checks" detail="Stack detected, targeted modules run: WordPress, Next.js, generic HTTP." />
          </div>

        </div>
      </section>

      {/* ── How it works ────────────────────────────────────────────────── */}
      <section className={`border-t border-border/40 py-16 lg:py-20 ${rail}`}>
        <div className="max-w-lg">
          <p className="mb-10 text-[10px] font-semibold uppercase tracking-[0.32em] text-muted-foreground/40">
            How it works
          </p>
          <Step n={1} heading="Paste a target URL" body="Enter any web target. The scan begins immediately." />
          <Step n={2} heading="Baseline scan runs" body="HTTP headers, exposed files, public paths, and technology signals collected." />
          <Step n={3} heading="Stack identified, specialist checks run" body="The system selects and runs the right modules based on detected technology." />
          <Step n={4} heading="Report generated" body="Findings enriched, ranked, grouped, and written into a structured report with a security score." />
        </div>
      </section>

      {/* ── Closing CTA ─────────────────────────────────────────────────── */}
      <section className={`border-t border-border/40 bg-card/20 py-14 lg:py-16 ${rail}`}>
        <div className="grid grid-cols-1 gap-8 lg:grid-cols-[1fr_auto] lg:items-center">
          <div>
            <h2 className="font-heading text-xl font-semibold tracking-tight sm:text-2xl">
              Ready to scan a target?
            </h2>
            <p className="mt-2 text-sm text-muted-foreground">
              The report opens immediately. No account required.
            </p>
          </div>
          <div className="w-full max-w-sm">
            <ScanForm />
          </div>
        </div>
      </section>

    </div>
  )
}

// ── Report preview — right column of the hero ─────────────────────────────────
// This should look like a miniaturised, real version of the report output —
// visible enough to be meaningful, quiet enough not to compete with the CTA.
function ReportPreview() {
  return (
    <div className="max-w-xs space-y-0 text-[13px]">

      {/* Cover */}
      <div className="border-b border-border/40 pb-7">
        <p className="mb-2 text-[9px] font-semibold uppercase tracking-[0.3em] text-muted-foreground/40">
          Security report
        </p>
        <p className="font-heading text-base font-semibold text-foreground/70">
          example.com
        </p>
        <div className="mt-3 flex items-center gap-4 text-[11px]">
          <span className="flex items-center gap-1.5">
            <span className="size-1.5 rounded-full bg-destructive/70" />
            <span className="text-muted-foreground/50">3 critical</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="size-1.5 rounded-full bg-chart-1/70" />
            <span className="text-muted-foreground/50">5 high</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="size-1.5 rounded-full bg-muted-foreground/40" />
            <span className="text-muted-foreground/40">8 medium</span>
          </span>
        </div>
      </div>

      {/* Executive summary */}
      <div className="border-b border-border/40 py-6">
        <p className="mb-2.5 text-[9px] font-semibold uppercase tracking-[0.3em] text-muted-foreground/35">
          Executive summary
        </p>
        <p className="text-[12px] leading-[1.75] text-muted-foreground/50">
          The target exposes several misconfigured security headers and has publicly accessible deployment artefacts. Critical: missing Content-Security-Policy and exposed .env file.
        </p>
      </div>

      {/* Top findings */}
      <div className="border-b border-border/40 py-6">
        <p className="mb-4 text-[9px] font-semibold uppercase tracking-[0.3em] text-muted-foreground/35">
          Immediate action
        </p>
        <div className="space-y-4">
          <div>
            <div className="mb-1 flex items-center gap-1.5">
              <span className="size-1.5 rounded-full bg-destructive/70" />
              <span className="text-[9px] font-semibold uppercase tracking-[0.2em] text-muted-foreground/50">Critical</span>
            </div>
            <p className="text-[12px] font-medium text-foreground/60">Exposed .env file</p>
            <p className="mt-0.5 text-[11px] leading-[1.7] text-muted-foreground/40">
              /.env is publicly accessible and contains database credentials.
            </p>
          </div>
          <div>
            <div className="mb-1 flex items-center gap-1.5">
              <span className="size-1.5 rounded-full bg-destructive/70" />
              <span className="text-[9px] font-semibold uppercase tracking-[0.2em] text-muted-foreground/50">Critical</span>
            </div>
            <p className="text-[12px] font-medium text-foreground/60">Missing Content-Security-Policy</p>
            <p className="mt-0.5 text-[11px] leading-[1.7] text-muted-foreground/40">
              No CSP header returned. XSS and injection attacks are unrestricted.
            </p>
          </div>
        </div>
      </div>

      {/* Score */}
      <div className="pt-6">
        <div className="flex items-center gap-3">
          <div className="relative flex h-10 w-10 items-center justify-center">
            <svg viewBox="0 0 40 40" className="h-full w-full -rotate-90">
              <circle cx="20" cy="20" r="16" fill="none" stroke="var(--border)" strokeOpacity="0.4" strokeWidth="3" />
              <circle cx="20" cy="20" r="16" fill="none" stroke="var(--destructive)" strokeLinecap="round"
                strokeWidth="3" strokeDasharray={`${2 * Math.PI * 16}`}
                strokeDashoffset={`${2 * Math.PI * 16 * (1 - 42 / 100)}`} strokeOpacity="0.6" />
            </svg>
            <span className="absolute text-[10px] font-semibold tabular-nums">42</span>
          </div>
          <div>
            <p className="text-[11px] font-semibold text-destructive/70">High risk</p>
            <p className="text-[10px] text-muted-foreground/35">Security score</p>
          </div>
        </div>
      </div>

    </div>
  )
}

function Capability({ index, label, detail }: { index: string; label: string; detail: string }) {
  return (
    <div className="grid grid-cols-[2rem_1fr] gap-x-4 border-t border-border/30 py-6">
      <span className="pt-px text-[10px] font-semibold tracking-[0.2em] text-muted-foreground/25">
        {index}
      </span>
      <div>
        <p className="text-sm font-semibold">{label}</p>
        <p className="mt-1 text-sm leading-[1.75] text-muted-foreground">{detail}</p>
      </div>
    </div>
  )
}

function Step({ n, heading, body }: { n: number; heading: string; body: string }) {
  return (
    <div className="grid grid-cols-[2rem_1fr] gap-x-4 border-t border-border/30 py-6">
      <span className="pt-px font-mono text-[11px] tabular-nums text-muted-foreground/30">{n}</span>
      <div>
        <p className="text-sm font-semibold">{heading}</p>
        <p className="mt-1 text-sm leading-[1.8] text-muted-foreground">{body}</p>
      </div>
    </div>
  )
}
