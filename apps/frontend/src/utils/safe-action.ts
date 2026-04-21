import { createSafeActionClient } from "next-safe-action"

export const actionClient = createSafeActionClient({
  handleServerError(error) {
    console.error("Safe action error:", error.message)
    return error.message || "Something went wrong while contacting the orchestrator."
  },
})
