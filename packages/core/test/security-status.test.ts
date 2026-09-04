// kilocode_change - new file
import { describe, expect, test } from "bun:test"
import { SecurityStatus } from "@opencode-ai/core/security-status"

/**
 * The four states a client shows for one tool call's security decision.
 *
 * The audit record carries two independent fields — what the reviewer did and how the call was
 * finally enforced — and neither alone is the state a user needs. This collapses the pair into the
 * one thing worth a badge, so the TUI and the web UI cannot drift apart on what "blocked" means.
 */

const record = (reviewer: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
  securityDecision: {
    schema: "kilo.security-decision/v1",
    rule_id: "SEC.V1.UNCLASSIFIED_EXEC",
    decision: "ask",
    reviewer,
    ...extra,
  },
})

describe("SecurityStatus.from", () => {
  test("a reviewer that is still deciding is reviewing", () => {
    const out = SecurityStatus.from(record({ state: "running" }, { final_enforcement: "ask_pending" }))

    expect(out?.kind).toBe("reviewing")
  })

  test("a reviewer verdict of allow is an auto-approval", () => {
    const out = SecurityStatus.from(
      record({ state: "allow", reason_code: "ORDINARY_DEV_COMMAND", latency_ms: 42 }, { final_enforcement: "allow" }),
    )

    expect(out?.kind).toBe("auto-approved")
  })

  test.each([["keep_ask"], ["timeout"], ["error"], ["not_run"]])(
    "a %s verdict on a pending ask needs a human",
    (state) => {
      const out = SecurityStatus.from(record({ state }, { final_enforcement: "ask_pending" }))

      expect(out?.kind).toBe("needs-approval")
    },
  )

  // `reject` is the human answering "no" to a security-raised ask: the call did not run, which is
  // the same thing a user needs to see, so it reads as blocked rather than as no badge at all.
  test.each([["deny"], ["blocked"], ["reject"]])("an enforcement of %s is blocked", (enforcement) => {
    const out = SecurityStatus.from(record({ state: "not_run" }, { final_enforcement: enforcement }))

    expect(out?.kind).toBe("blocked")
  })

  test("a deny decision is blocked even before enforcement is recorded", () => {
    const out = SecurityStatus.from(record({ state: "not_run" }, { decision: "deny" }))

    expect(out?.kind).toBe("blocked")
  })

  test("enforcement outranks the verdict: a keep_ask that was denied is blocked", () => {
    const out = SecurityStatus.from(record({ state: "keep_ask" }, { final_enforcement: "deny" }))

    expect(out?.kind).toBe("blocked")
  })

  test("a call the layer allowed with no reviewer gets no badge", () => {
    // The overwhelming majority of calls: nothing happened worth telling the user about.
    expect(SecurityStatus.from(record({ state: "not_run" }, { final_enforcement: "allow" }))).toBeUndefined()
  })

  test("details ride along for the tooltip, never for the badge", () => {
    const out = SecurityStatus.from(
      record({ state: "allow", reason_code: "ORDINARY_DEV_COMMAND", latency_ms: 42 }, { final_enforcement: "allow" }),
    )

    expect(out).toMatchObject({
      rule_id: "SEC.V1.UNCLASSIFIED_EXEC",
      reason_code: "ORDINARY_DEV_COMMAND",
      latency_ms: 42,
    })
  })

  test("metadata without a security record has no status", () => {
    expect(SecurityStatus.from(undefined)).toBeUndefined()
    expect(SecurityStatus.from({})).toBeUndefined()
    expect(SecurityStatus.from({ securityDecision: "nope" })).toBeUndefined()
    expect(SecurityStatus.from({ approval: { source: "agent" } })).toBeUndefined()
  })

  test("an unrecognized reviewer state is not invented into a state", () => {
    expect(SecurityStatus.from(record({ state: "wat" }, { final_enforcement: "ask_pending" }))).toBeUndefined()
  })
})
