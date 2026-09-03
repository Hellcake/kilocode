import { Effect } from "effect"
import type * as Config from "@/config/config"
import type { PermissionV1 } from "@opencode-ai/core/v1/permission"
import { SecurityAuthority } from "./authority"
import { SecurityDecisionAdapter } from "./adapter"
import { SecurityDecisionRules as R } from "./rules"
import { SecurityReviewer } from "./reviewer"
import type { SecurityDecisionTypes as T } from "./types"

/**
 * The single authoritative entry point the permission pipeline calls.
 *
 * It sits after the existing hard veto and explicit deny and before the auto-return/pending split:
 * it applies the XDG strictness floor, runs the pure core over normalized facts and hands back a
 * recommendation plus the audit record. It can only *tighten* — `pass` leaves the existing pipeline
 * exactly as it was, and every failure fails closed to `ask`.
 */
export namespace KiloSecurityGate {
  export type Resolved = Readonly<{ pattern: string; action: PermissionV1.Action }>

  export type Input = Readonly<{
    config: Pick<Config.Interface, "getGlobal">
    workspace: string
    permission: string
    patterns: readonly string[]
    metadata?: Record<string, unknown>
    sessionID: string
    callID?: string
    /** What the existing pipeline resolved for each pattern, in request order. */
    resolved: readonly Resolved[]
    /** True when an existing human-only or config-protection guard already forces a prompt. */
    humanOnly: boolean
    containment?: T.Containment & { probe_id?: string; checked_at?: number }
  }>

  const UNKNOWN_CONTAINMENT: T.Containment = {
    sandbox: "unknown",
    network: "allow",
    destinations: [],
    escalated: false,
  }

  function rank(action: PermissionV1.Action) {
    return action === "deny" ? 2 : action === "ask" ? 1 : 0
  }

  export const evaluate = Effect.fn("KiloSecurityGate.evaluate")(function* (input: Input) {
    if (!SecurityDecisionAdapter.enabled()) return undefined
    return yield* run(input).pipe(
      // A failure anywhere in the gate must not let the call through: fail closed to ask.
      Effect.catchCause(() => Effect.succeed(failClosed(input))),
    )
  })

  const run = Effect.fn("KiloSecurityGate.run")(function* (input: Input) {
    const snapshot = yield* SecurityAuthority.snapshot(input.config)

    let floor: SecurityAuthority.Floor = { action: "allow", authority: "untrusted", conflict: false }
    let raised = false
    for (const entry of input.resolved) {
      const current = SecurityAuthority.floor({
        permission: input.permission,
        pattern: entry.pattern,
        effective: entry.action,
        xdg: snapshot.rules,
        failed: snapshot.failed,
      })
      if (rank(current.action) > rank(entry.action)) raised = true
      if (rank(current.action) > rank(floor.action)) floor = current
      else if (current.conflict) floor = { ...floor, conflict: true }
    }

    const directive = SecurityDecisionAdapter.evaluate(
      {
        permission: input.permission,
        patterns: input.patterns,
        metadata: input.metadata,
        sessionID: input.sessionID,
        callID: input.callID,
      },
      {
        workspace: input.workspace,
        effective: floor.action,
        humanOnly: input.humanOnly,
        floor,
        containment: input.containment ?? UNKNOWN_CONTAINMENT,
      },
    )

    // The floor is enforcement in its own right: when the XDG scope is stricter than the merged
    // ruleset resolved, the ask stands even where the core has no opinion of its own.
    if (raised && directive.decision !== "deny" && directive.decision !== "ask") {
      const result = R.result(R.AUTHORITY_FLOOR)
      return {
        decision: result.decision,
        rule_id: result.rule_id,
        reviewable: false,
        audit: { ...directive.audit, rule_id: result.rule_id, reason: result.reason, decision: result.decision },
      } satisfies SecurityDecisionAdapter.Directive
    }
    return directive
  })

  function failClosed(input: Input): SecurityDecisionAdapter.Directive {
    const result = R.result(R.INTERNAL_ERROR)
    return {
      decision: result.decision,
      rule_id: result.rule_id,
      reviewable: false,
      audit: {
        schema: "kilo.security-decision/v1",
        policy_version: R.POLICY_VERSION,
        rule_id: result.rule_id,
        reason: result.reason,
        decision: result.decision,
        reviewer: SecurityReviewer.SKIPPED,
        authority_level: "unknown",
        authority_basis: "none",
        authority_conflict: false,
        metadata_complete: false,
        metadata_truncated: false,
        containment: input.containment ?? UNKNOWN_CONTAINMENT,
        requirements: [],
        latency_ms: 0,
        ...(input.callID ? { callID: input.callID } : {}),
        sessionID: input.sessionID,
      },
    }
  }
}
