"use server"

import { z } from "zod"

import { actionClient } from "@/utils/safe-action"
import { createScanRequest, getEnrichedReportRequest } from "@/utils/orchestrator-api"

const createScanSchema = z.object({
  target: z.string().trim().min(1, "Target is required."),
})

const getEnrichedReportSchema = z.object({
  scanId: z.string().trim().uuid("Scan ID must be a valid UUID."),
})

export const createScanAction = actionClient
  .inputSchema(createScanSchema)
  .action(async ({ parsedInput }) => {
    return createScanRequest(parsedInput.target)
  })

export const getEnrichedReportAction = actionClient
  .inputSchema(getEnrichedReportSchema)
  .action(async ({ parsedInput }) => {
    return getEnrichedReportRequest(parsedInput.scanId)
  })
