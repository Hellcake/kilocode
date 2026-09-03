import type { SecurityDecisionTypes as T } from "./types"

/**
 * Extension point for the (deferred) LLM reviewer.
 *
 * The reviewer is *not* a decision value: it is a stage after the core that may only turn a
 * reviewable `ask` into `allow` for the current call. It never touches `deny`, `pass`, explicit
 * policy, a source-conflict ask or a human-only ask, never becomes authority and never writes
 * policy. V1 ships the interface disabled, so every call reports `not_run`.
 */
export namespace SecurityReviewer {
  export type State = "not_run" | "allow" | "keep_ask" | "timeout" | "error"

  export type Outcome = Readonly<{ state: State; reason_code?: string; latency_ms?: number }>

  export const SKIPPED: Outcome = { state: "not_run" }

  export interface Reviewer {
    readonly review: (result: T.Result) => {
      recommendation: "allow" | "keep_ask"
      reason_code: string
      confidence: number
    }
  }

  /** V1 has no reviewer implementation, so the core result always stands unchanged. */
  export function review(result: T.Result): { result: T.Result; outcome: Outcome } {
    return { result, outcome: SKIPPED }
  }
}
