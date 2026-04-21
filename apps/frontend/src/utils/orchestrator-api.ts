import "server-only"

import type { CreateScanResponse, EnrichedReportResponse } from "@/types/report"

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
  })

  if (!response.ok) {
    let detail = "Request failed"
    try {
      const body = (await response.json()) as { detail?: string }
      detail = body.detail ?? detail
    } catch {}

    throw new Error(detail)
  }

  return response.json() as Promise<T>
}

export function createScanRequest(target: string) {
  return request<CreateScanResponse>("/scans", {
    method: "POST",
    body: JSON.stringify({ target }),
  })
}

export function getEnrichedReportRequest(scanId: string) {
  return request<EnrichedReportResponse>(`/scans/${scanId}/report/enriched`)
}
