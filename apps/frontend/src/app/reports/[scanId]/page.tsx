import { ReportView } from "@/components/report-view"

type ReportPageProps = {
  params: Promise<{
    scanId: string
  }>
}

export default async function ReportPage({ params }: ReportPageProps) {
  const { scanId } = await params

  return <ReportView scanId={scanId} />
}
