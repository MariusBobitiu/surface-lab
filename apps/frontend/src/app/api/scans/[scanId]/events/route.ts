import type { NextRequest } from "next/server"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

function getRequiredEnv(name: "ORCHESTRATOR_BASE_URL" | "ORCHESTRATOR_API_KEY"): string {
  const value = process.env[name]?.trim()
  if (!value) {
    throw new Error(`${name} is required`)
  }

  return value
}

function getOrchestratorEventsUrl(scanId: string): string {
  const baseUrl = getRequiredEnv("ORCHESTRATOR_BASE_URL").replace(/\/+$/, "")
  return `${baseUrl}/scans/${encodeURIComponent(scanId)}/events`
}

export async function GET(request: NextRequest, context: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await context.params
  let upstreamResponse: Response

  try {
    upstreamResponse = await fetch(getOrchestratorEventsUrl(scanId), {
      headers: {
        accept: "text/event-stream",
        "x-api-key": getRequiredEnv("ORCHESTRATOR_API_KEY"),
      },
      cache: "no-store",
      signal: request.signal,
    })
  } catch {
    return new Response("Unable to connect to orchestrator event stream.", {
      status: 502,
      headers: {
        "content-type": "text/plain; charset=utf-8",
      },
    })
  }

  if (!upstreamResponse.ok || !upstreamResponse.body) {
    const detail = await upstreamResponse.text()
    return new Response(detail || "Failed to connect to scan event stream.", {
      status: upstreamResponse.status || 502,
      headers: {
        "content-type": "text/plain; charset=utf-8",
      },
    })
  }

  return new Response(upstreamResponse.body, {
    status: 200,
    headers: {
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "content-type": upstreamResponse.headers.get("content-type") ?? "text/event-stream; charset=utf-8",
      "x-accel-buffering": "no",
    },
  })
}
