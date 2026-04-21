"use server"

import { z } from "zod"

import { createScan } from "@/lib/orchestrator"
import { actionClient } from "@/utils/safe-action"

const createScanSchema = z.object({
  target: z.string().trim().min(1, "Target is required."),
})

export const createScanAction = actionClient
  .inputSchema(createScanSchema)
  .action(async ({ parsedInput }) => {
    return createScan(parsedInput.target)
  })
