import { ReportView } from "@/components/report-view"
import { ScanProgress } from "@/components/scan-progress"
import { getEnrichedReport, getScanDetails } from "@/lib/orchestrator"

export const dynamic = "force-dynamic"

const REPORT_READY_CHECK_TIMEOUT_MS = 1_500

type ReportPageProps = {
  params: Promise<{
    scanId: string
  }>
}

export default async function ReportPage({ params }: ReportPageProps) {
  const { scanId } = await params

  if (!scanId.trim()) {
    throw new Error("scanId is required")
  }

  const scan = await getScanDetails(scanId)
  const scanCompleted = scan.status.toLowerCase() === "completed"

  if (!scanCompleted) {
    return <ScanProgress scanId={scanId} />
  }

  let report: Awaited<ReturnType<typeof getEnrichedReport>> | null = null

  try {
    report = await getEnrichedReport(scanId, REPORT_READY_CHECK_TIMEOUT_MS)
  } catch {
    return <ScanProgress scanId={scanId} />
  }

  return <ReportView report={report} />
}
