// kilocode_change - new file
import { SecurityBlocked } from "./block"

/**
 * Turn continuation policy for the deterministic security layer.
 *
 * A security block stops the *call*, not the turn: the tool never ran, the model gets a fixed
 * result naming only the rule id, and it keeps its turn to choose another allowed path. Re-issuing
 * the identical call is not another path, so the second identical block ends the turn instead of
 * spinning. This is scoped to security blocks alone — an ordinary rejection keeps the existing
 * `continue_loop_on_deny` rule.
 */
export namespace SecurityContinuation {
  /** Signatures of the calls already blocked in this turn. */
  export type State = Set<string>

  export type Outcome = "continue" | "stop"

  export function state(): State {
    return new Set<string>()
  }

  /** Stable signature of a tool call: argument order must not make a repeat look like a new path. */
  export function signature(tool: string, input: unknown): string {
    return `${tool} ${stable(input)}`
  }

  function stable(value: unknown): string {
    if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null"
    if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(",")}}`
  }

  /**
   * Outcome for a failed tool call, or `undefined` when the failure is not a security block and the
   * existing rule applies.
   */
  export function after(state: State, error: unknown, call: { tool: string; input: unknown }): Outcome | undefined {
    if (!SecurityBlocked.is(error)) return undefined
    const key = signature(call.tool, call.input)
    if (state.has(key)) return "stop"
    state.add(key)
    return "continue"
  }
}
