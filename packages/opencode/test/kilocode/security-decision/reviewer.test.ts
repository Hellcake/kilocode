import { test, expect, describe } from "bun:test"
import { SecurityReviewer } from "../../../src/kilocode/security-decision/reviewer"
import { SecurityDecisionRules as R } from "../../../src/kilocode/security-decision/rules"

describe("SecurityReviewer", () => {
  test("is not implemented in V1, so every core result stands unchanged", () => {
    for (const rule of [R.DESTRUCTIVE_FS, R.GIT_HOOK_WRITE, R.NO_OPINION, R.SENSITIVE_BOUNDARY]) {
      const result = R.result(rule)
      const out = SecurityReviewer.review(result)
      expect(out.result).toEqual(result)
      expect(out.outcome).toEqual({ state: "not_run" })
    }
  })

  test("a reviewable ask is the only thing a future reviewer may act on", () => {
    // Only a soft ambiguity is reviewable; authority, sensitivity and deny rules are not.
    expect(R.result(R.DESTRUCTIVE_FS).reviewable).toBe(true)
    expect(R.result(R.SENSITIVE_BOUNDARY).reviewable).toBe(false)
    expect(R.result(R.CI_AUTHORITY).reviewable).toBe(false)
    expect(R.result(R.AUTHORITY_FLOOR).reviewable).toBe(false)
    expect(R.result(R.GIT_HOOK_WRITE).reviewable).toBe(false)
    expect(R.result(R.DESTRUCTIVE_ROOT).reviewable).toBe(false)
  })
})
