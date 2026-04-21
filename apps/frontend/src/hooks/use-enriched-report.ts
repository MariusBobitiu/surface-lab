"use client"

import { useQuery } from "@tanstack/react-query"

import { getEnrichedReportAction } from "@/actions/report-actions"

export function useEnrichedReport(scanId: string) {
  return useQuery({
    queryKey: ["enriched-report", scanId],
    queryFn: async () => {
      const result = await getEnrichedReportAction({ scanId })

      if (result?.serverError) {
        throw new Error(result.serverError)
      }

      if (result?.validationErrors) {
        throw new Error("Invalid scan id.")
      }

      if (!result?.data) {
        throw new Error("Report unavailable.")
      }

      return result.data
    },
    enabled: Boolean(scanId),
    refetchInterval: (query) => {
      const report = query.state.data
      if (!report || report.status.toLowerCase() !== "completed") {
        return 3000
      }
      return false
    },
    staleTime: (query) => {
      const report = query.state.data
      return report?.status.toLowerCase() === "completed" ? Infinity : 0
    },
  })
}
