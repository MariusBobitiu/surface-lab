import { ScanForm } from "@/components/scan-form"

export default function HomePage() {
  return (
    <main className="min-h-screen bg-background text-foreground">
      <div className="mx-auto flex min-h-screen w-full max-w-5xl flex-col px-6 py-8 sm:px-10">
        <header className="flex items-center justify-between">
          <div className="inline-flex items-center gap-3">
            <div className="size-2 rounded-full bg-primary" />
            <span className="text-xs font-medium uppercase tracking-[0.28em] text-muted-foreground">
              SurfaceLab
            </span>
          </div>
          <span className="text-xs uppercase tracking-[0.2em] text-muted-foreground">
            Security reporting
          </span>
        </header>

        <section className="flex flex-1 items-center justify-center py-20 sm:py-28">
          <div className="mx-auto flex w-full max-w-3xl flex-col items-center text-center">
            <div className="space-y-6">
              <h1 className="font-heading text-balance text-5xl font-semibold tracking-tight sm:text-6xl">
                Security reporting for the modern web.
              </h1>
              <p className="mx-auto max-w-2xl text-pretty text-lg leading-8 text-muted-foreground">
                Scan a target, enrich the findings, and get a report built for triage.
              </p>
            </div>

            <div className="mt-10 w-full">
              <ScanForm />
            </div>

            <div className="mt-10 flex flex-wrap items-center justify-center gap-x-6 gap-y-3 text-sm text-muted-foreground">
              <span>Severity summary</span>
              <span className="hidden h-1 w-1 rounded-full bg-border sm:block" />
              <span>Grounded executive summary</span>
              <span className="hidden h-1 w-1 rounded-full bg-border sm:block" />
              <span>Grouped findings for triage</span>
            </div>
          </div>
        </section>
      </div>
    </main>
  )
}
