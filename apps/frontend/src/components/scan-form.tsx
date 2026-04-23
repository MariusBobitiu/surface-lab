"use client"

import * as React from "react"
import { ArrowRight, LoaderCircle } from "lucide-react"
import { useRouter } from "next/navigation"

import { useCreateScan } from "@/hooks/use-create-scan"

export function ScanForm() {
  const router = useRouter()
  const [target, setTarget] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)
  const [focused, setFocused] = React.useState(false)
  const createScan = useCreateScan()

  function handleSubmit(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault()

    const normalizedTarget = target.trim()
    if (!normalizedTarget) {
      setError("Enter a target URL or hostname.")
      return
    }

    setError(null)
    createScan.execute({ target: normalizeTargetForSubmit(normalizedTarget) })
  }

  React.useEffect(() => {
    if (createScan.result.data?.scan_id) {
      router.push(`/reports/${createScan.result.data.scan_id}`)
    }
  }, [createScan.result.data?.scan_id, router])

  const serverError = createScan.result.serverError
  const validationError = createScan.result.validationErrors?.target?._errors?.[0]
  const displayError = error ?? validationError ?? serverError ?? null

  return (
    <div className="space-y-4">
      <form onSubmit={handleSubmit}>
        {/* Input row */}
        <div
          className={`flex items-stretch border-b transition-colors duration-150 ${
            focused ? "border-foreground/70" : "border-border/70"
          }`}
        >
          <div className="flex flex-1 items-center gap-2 py-4">
            <span className="shrink-0 select-none text-sm font-medium text-muted-foreground/60">
              https://
            </span>
            <input
              id="target"
              type="text"
              placeholder="example.com"
              value={target}
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => {
                setTarget(normalizeTargetInput(e.target.value))
                setError(null)
              }}
              onFocus={() => setFocused(true)}
              onBlur={() => setFocused(false)}
              className="flex-1 bg-transparent text-base text-foreground placeholder:text-muted-foreground/30 focus:outline-none"
            />
          </div>

          <button
            type="submit"
            disabled={createScan.isExecuting}
            className="group ml-4 flex shrink-0 items-center gap-2 py-4 text-sm font-medium text-muted-foreground transition-colors duration-150 hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
          >
            {createScan.isExecuting ? (
              <>
                <LoaderCircle className="size-3.5 animate-spin" />
                <span>Starting</span>
              </>
            ) : (
              <>
                <span>Run scan</span>
                <ArrowRight className="size-3.5 transition-transform duration-150 group-hover:translate-x-0.5" />
              </>
            )}
          </button>
        </div>
      </form>

      <div className="min-h-5">
        {displayError ? (
          <p className="text-xs text-destructive">{displayError}</p>
        ) : (
          <p className="text-xs text-muted-foreground/50">
            Report opens immediately with a live workflow monitor while the scan runs.
          </p>
        )}
      </div>
    </div>
  )
}

function normalizeTargetInput(value: string) {
  return value.trimStart().replace(/^https?:\/\//i, "")
}

function normalizeTargetForSubmit(value: string) {
  return `https://${normalizeTargetInput(value).trim()}`
}
