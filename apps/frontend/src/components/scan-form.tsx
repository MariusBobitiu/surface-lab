"use client"

import * as React from "react"
import { ArrowRight, LoaderCircle } from "lucide-react"
import { useRouter } from "next/navigation"

import { useCreateScan } from "@/hooks/use-create-scan"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

export function ScanForm() {
  const router = useRouter()
  const [target, setTarget] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)
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
      <form
        onSubmit={handleSubmit}
        className="rounded-[1.75rem] border border-border bg-card/80 p-3 shadow-sm transition focus-within:border-ring"
      >
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="flex min-w-0 flex-1 items-center gap-3 px-3 py-2">
            <span className="shrink-0 text-sm font-medium text-muted-foreground">https://</span>
            <Input
              id="target"
              placeholder="example.com"
              value={target}
              onChange={(e) => {
                setTarget(normalizeTargetInput(e.target.value))
                setError(null)
              }}
              className="h-auto border-0 bg-transparent px-0 text-base shadow-none focus-visible:ring-0"
            />
          </div>
          <Button
            type="submit"
            disabled={createScan.isExecuting}
            className="h-12 shrink-0 rounded-[1rem] px-5 text-sm font-medium"
          >
            {createScan.isExecuting ? (
              <>
                <LoaderCircle className="size-4 animate-spin" />
                Starting scan
              </>
            ) : (
              <>
                Run scan
                <ArrowRight className="size-4" />
              </>
            )}
          </Button>
        </div>
      </form>

      {displayError ? (
        <p className="text-sm text-destructive">{displayError}</p>
      ) : (
        <p className="text-sm text-muted-foreground">
          The report opens immediately and refreshes while the scan is still completing.
        </p>
      )}
    </div>
  )
}

function normalizeTargetInput(value: string) {
  return value.trimStart().replace(/^https?:\/\//i, "")
}

function normalizeTargetForSubmit(value: string) {
  return `https://${normalizeTargetInput(value).trim()}`
}
