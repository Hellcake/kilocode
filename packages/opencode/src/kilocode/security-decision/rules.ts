import type { SecurityDecisionTypes } from "./types"

/**
 * Rule catalog for the deterministic security layer.
 *
 * `reason` is deliberately the catalog constant itself: the spec forbids echoing any command,
 * path or content into the model-facing text, so the only safe reason is the stable rule id.
 */
export namespace SecurityDecisionRules {
  export const POLICY_VERSION = "kilo.security-decision/v1" as const

  export type Entry = Readonly<{
    id: string
    decision: SecurityDecisionTypes.Decision
    /** Whether the (deferred) reviewer stage may upgrade this ask to allow. */
    reviewable: boolean
    requirements: readonly SecurityDecisionTypes.Requirement[]
  }>

  function entry(
    id: string,
    decision: SecurityDecisionTypes.Decision,
    reviewable = false,
    requirements: readonly SecurityDecisionTypes.Requirement[] = [],
  ): Entry {
    return { id, decision, reviewable, requirements }
  }

  /** `pass` — the layer has no security opinion and the existing pipeline decides. */
  export const NO_OPINION = entry("SEC.V1.NO_OPINION", "pass")

  /** Proven, exact, platform-aware capability: the only cases allowed to deny on the soft path. */
  export const DESTRUCTIVE_ROOT = entry("SEC.V1.DESTRUCTIVE_ROOT", "deny")
  export const GIT_HOOK_WRITE = entry("SEC.V1.GIT_HOOK_WRITE", "deny")

  /** Ambiguity, incompleteness and authority boundaries: ask, never deny. */
  export const AMBIGUOUS_OPERATION = entry("SEC.V1.AMBIGUOUS_OPERATION", "ask")
  export const METADATA_INCOMPLETE = entry("SEC.V1.METADATA_INCOMPLETE", "ask")
  export const EXEC_INCOMPLETE = entry("SEC.V1.EXEC_INCOMPLETE", "ask")
  export const EXEC_COMPOSED = entry("SEC.V1.EXEC_COMPOSED", "ask")
  export const UNKNOWN_TARGET = entry("SEC.V1.UNKNOWN_TARGET", "ask")
  export const SENSITIVE_BOUNDARY = entry("SEC.V1.SENSITIVE_BOUNDARY", "ask")
  export const CI_AUTHORITY = entry("SEC.V1.CI_AUTHORITY", "ask")
  export const PACKAGE_EXECUTION = entry("SEC.V1.PACKAGE_EXECUTION", "ask")
  export const DELEGATED_OPAQUE = entry("SEC.V1.DELEGATED_OPAQUE", "ask")
  /** The XDG user-global floor is stricter than what the merged ruleset resolved. */
  export const AUTHORITY_FLOOR = entry("SEC.V1.AUTHORITY_FLOOR", "ask")

  /** Adapter, core or reviewer failure — always fails closed to ask. */
  export const INTERNAL_ERROR = entry("SEC.V1.INTERNAL_ERROR", "ask")

  /** Soft ambiguity a human routinely resolves: reviewable once a reviewer exists. */
  export const DESTRUCTIVE_FS = entry("SEC.V1.DESTRUCTIVE_FS", "ask", true)

  export function result(rule: Entry): SecurityDecisionTypes.Result {
    return {
      decision: rule.decision,
      reason: rule.id,
      rule_id: rule.id,
      requirements: rule.requirements,
      reviewable: rule.reviewable,
    }
  }
}
