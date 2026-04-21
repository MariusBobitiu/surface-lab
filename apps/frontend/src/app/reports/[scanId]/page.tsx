import { z } from "zod"

import { ReportErrorView, ReportView } from "@/components/report-view"
import { getEnrichedReport } from "@/lib/orchestrator"

export const dynamic = "force-dynamic"

type ReportPageProps = {
  params: Promise<{
    scanId: string
  }>
}

export default async function ReportPage({ params }: ReportPageProps) {
  const reportPageParamsSchema = z.object({
    scanId: z.string().trim().uuid("Scan ID must be a valid UUID."),
  })
  const parsedParams = reportPageParamsSchema.safeParse(await params)

  if (!parsedParams.success) {
    return <ReportErrorView message="Invalid scan id." />
  }

  let report
  try {
    report = await getEnrichedReport(parsedParams.data.scanId)
  } catch (error) {
    return <ReportErrorView message={error instanceof Error ? error.message : "Report unavailable."} />
  }

  return <ReportView report={report} />
}
