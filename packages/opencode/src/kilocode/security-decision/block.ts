import { Schema } from "effect"
import type { SecurityDecisionAdapter } from "./adapter"

/**
 * The typed block the deterministic security layer raises.
 *
 * The model-facing text is fixed and carries nothing but the stable rule id: no command, path,
 * ruleset or external content, and no hint at a way around the policy. The audit record rides
 * along on the error but never reaches the model.
 */
export namespace SecurityBlocked {
  export class Error extends Schema.TaggedErrorClass<Error>()("KiloSecurityBlockedError", {
    rule_id: Schema.String,
    audit: Schema.Any,
  }) {
    override get message() {
      return `Security policy blocked this tool call. rule_id=${this.rule_id}. Contact the user.`
    }
  }

  export function of(rule_id: string, audit: SecurityDecisionAdapter.Audit) {
    return new Error({ rule_id, audit })
  }

  export function is(value: unknown): value is Error {
    return value instanceof Error
  }
}
