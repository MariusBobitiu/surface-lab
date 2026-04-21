"use client"

import { useAction } from "next-safe-action/hooks"

import { createScanAction } from "@/actions/report-actions"

export function useCreateScan() {
  return useAction(createScanAction)
}
