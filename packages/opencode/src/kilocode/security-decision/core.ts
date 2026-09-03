import type { SecurityDecisionTypes } from "./types"
import { SecurityDecisionRules as R } from "./rules"

/**
 * The pure decision core. No IO, no clock, no randomness, no Effect, no Kilo imports.
 *
 * It returns a *recommendation*; `Permission.ask` stays the enforcement point. `deny` is reserved
 * for a fully recognized, exact signal on the untrusted soft path — every ambiguity degrades to
 * `ask`, and `pass` means the layer has no opinion at all.
 */
export namespace SecurityDecision {
  /** Operations that unambiguously write to their target. */
  const WRITES = new Set(["add", "create", "update", "write", "move", "delete"])
  /** Operations that unambiguously destroy or relocate their target. */
  const DESTRUCTIVE = new Set(["delete", "move"])

  function target(input: SecurityDecisionTypes.Input, fact: SecurityDecisionTypes.PathFact): R.Entry {
    // A shell command can read one target and write another, so a fact's own operation wins.
    const op = fact.operation ?? input.action.operation
    const exec = input.action.exec

    // Exact, fully parsed destruction of a root/device target — the narrow soft-path deny.
    if (fact.class === "root") {
      if (op === "delete" && exec?.complete && !exec.composed) return R.DESTRUCTIVE_ROOT
      return R.DESTRUCTIVE_FS
    }

    if (fact.class === "git_hook") {
      if (WRITES.has(op)) return R.GIT_HOOK_WRITE
      return R.AMBIGUOUS_OPERATION
    }

    // Reading the control plane is ordinary; installing into it is not.
    if (fact.class === "control_plane") {
      if (WRITES.has(op)) return R.CONTROL_PLANE_WRITE
      if (op === "read") return R.NO_OPINION
      return R.AMBIGUOUS_OPERATION
    }

    if (fact.class === "unknown") return R.UNKNOWN_TARGET
    if (fact.class === "sensitive" || !fact.inWorkspace) return R.SENSITIVE_BOUNDARY
    if (fact.class === "ci") return R.CI_AUTHORITY
    // Dependency and lockfile edits are ordinary in V1; only the executable region is authority.
    if (fact.class === "package_manifest" && fact.region === "scripts") return R.PACKAGE_EXECUTION
    if (DESTRUCTIVE.has(op)) return R.DESTRUCTIVE_FS
    return R.NO_OPINION
  }

  /** `deny > ask > allow`; `pass` carries no strictness. */
  function strictness(decision: SecurityDecisionTypes.Decision) {
    return decision === "deny" ? 3 : decision === "ask" ? 2 : decision === "allow" ? 1 : 0
  }

  export function decide(input: SecurityDecisionTypes.Input): SecurityDecisionTypes.Result {
    const rule = evaluate(input)
    // The soft-path deny is only available against untrusted authority, and never against an
    // existing human-only guard: those stay at ask so a human still resolves them.
    if (rule.decision === "deny" && (input.baseline.humanOnly || input.baseline.authority !== "untrusted")) {
      return { ...R.result(rule), decision: "ask", reviewable: false }
    }
    return R.result(rule)
  }

  function evaluate(input: SecurityDecisionTypes.Input): R.Entry {
    // Opaque delegated actions stay opaque in V1: no semantic classification, and their empty
    // metadata must not be reported as a generic metadata gap.
    if (input.action.kind === "mcp") return R.DELEGATED_OPAQUE

    if (!input.metadata.complete || input.metadata.truncated) return R.METADATA_INCOMPLETE

    const exec = input.action.exec
    if (exec) {
      if (!exec.complete) return R.EXEC_INCOMPLETE
      if (exec.composed) return R.EXEC_COMPOSED
    }

    let winner: R.Entry = R.NO_OPINION
    for (const fact of input.action.paths) {
      const rule = target(input, fact)
      if (strictness(rule.decision) > strictness(winner.decision)) winner = rule
    }
    return winner
  }
}
