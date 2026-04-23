import "server-only"

import type { CreateScanResponse, EnrichedReportResponse, ScanDetailsResponse } from "@/types/report"

const DEFAULT_TIMEOUT_MS = 10_000

function getRequiredEnv(name: "ORCHESTRATOR_BASE_URL" | "ORCHESTRATOR_API_KEY"): string {
  const value = process.env[name]?.trim()
  if (!value) {
    throw new Error(`${name} is required`)
  }

  return value
}

function getTimeoutMs(): number {
  const rawValue = process.env.ORCHESTRATOR_REQUEST_TIMEOUT_MS?.trim()
  if (!rawValue) {
    return DEFAULT_TIMEOUT_MS
  }

  const parsedValue = Number.parseInt(rawValue, 10)
  if (!Number.isFinite(parsedValue) || parsedValue <= 0) {
    throw new Error("ORCHESTRATOR_REQUEST_TIMEOUT_MS must be a positive integer")
  }

  return parsedValue
}

function resolveTimeoutMs(timeoutMs?: number): number {
  if (timeoutMs == null) {
    return getTimeoutMs()
  }

  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("timeoutMs must be a positive number")
  }

  return Math.floor(timeoutMs)
}

function getBaseUrl(): string {
  return getRequiredEnv("ORCHESTRATOR_BASE_URL").replace(/\/+$/, "")
}

export class OrchestratorRequestError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = "OrchestratorRequestError"
    this.status = status
  }
}

async function orchestratorRequest<T>(path: string, init?: RequestInit, timeoutMs?: number): Promise<T> {
  const headers = new Headers(init?.headers)
  headers.set("x-api-key", getRequiredEnv("ORCHESTRATOR_API_KEY"))
  headers.set("accept", "application/json")
  if (init?.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json")
  }

  const response = await fetch(`${getBaseUrl()}${path}`, {
    ...init,
    headers,
    cache: "no-store",
    signal: AbortSignal.timeout(resolveTimeoutMs(timeoutMs)),
  })

  if (!response.ok) {
    let detail = "Request failed"

    try {
      const body = (await response.json()) as { detail?: string }
      detail = body.detail ?? detail
    } catch {}

    throw new OrchestratorRequestError(detail, response.status)
  }

  return response.json() as Promise<T>
}

export function createScan(target: string) {
  return orchestratorRequest<CreateScanResponse>("/scans", {
    method: "POST",
    body: JSON.stringify({ target }),
  })
}

export function getEnrichedReport(scanId: string, timeoutMs?: number) {
  return orchestratorRequest<EnrichedReportResponse>(`/scans/${scanId}/report/enriched`, undefined, timeoutMs)
}

export function getScanDetails(scanId: string) {
  return orchestratorRequest<ScanDetailsResponse>(`/scans/${scanId}`)
}
