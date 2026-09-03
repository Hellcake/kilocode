import { test, expect, describe } from "bun:test"
import { SecurityDecisionAdapter } from "../../../src/kilocode/security-decision/adapter"

const containment = { sandbox: "off", network: "allow", destinations: [], escalated: false } as const

function evaluate(
  request: {
    permission: string
    patterns: readonly string[]
    metadata?: Record<string, unknown>
    sessionID?: string
    callID?: string
  },
  ctx: Partial<Parameters<typeof SecurityDecisionAdapter.evaluate>[1]> = {},
) {
  return SecurityDecisionAdapter.evaluate(
    { sessionID: "ses_1", callID: "call_1", ...request },
    {
      workspace: "/repo",
      effective: "allow",
      humanOnly: false,
      floor: { action: "allow", authority: "untrusted", conflict: false },
      containment,
      ...ctx,
    },
  )
}

describe("SecurityDecisionAdapter.enabled", () => {
  test("is off unless the server environment turns it on", () => {
    expect(SecurityDecisionAdapter.enabled({})).toBe(false)
    expect(SecurityDecisionAdapter.enabled({ KILO_SECURITY_DECISION: "0" })).toBe(false)
    expect(SecurityDecisionAdapter.enabled({ KILO_SECURITY_DECISION: "1" })).toBe(true)
    expect(SecurityDecisionAdapter.enabled({ KILO_SECURITY_DECISION: "true" })).toBe(true)
  })
})

describe("SecurityDecisionAdapter.evaluate", () => {
  test("denies an edit that writes a git hook", () => {
    const out = evaluate({ permission: "edit", patterns: [".git/hooks/pre-commit"], metadata: { filepath: "x" } })
    expect(out.decision).toBe("deny")
    expect(out.rule_id).toBe("SEC.V1.GIT_HOOK_WRITE")
  })

  test("asks for an edit of a CI workflow", () => {
    const out = evaluate({ permission: "edit", patterns: [".github/workflows/ci.yml"], metadata: { filepath: "x" } })
    expect(out.rule_id).toBe("SEC.V1.CI_AUTHORITY")
  })

  test("has no opinion on an ordinary workspace edit", () => {
    const out = evaluate({ permission: "edit", patterns: ["src/a.ts"], metadata: { filepath: "x" } })
    expect(out.decision).toBe("pass")
  })

  test("asks for a path outside the workspace", () => {
    const out = evaluate({ permission: "external_directory", patterns: ["/etc/*"], metadata: { access: "read" } })
    expect(out.decision).toBe("ask")
    expect(out.rule_id).toBe("SEC.V1.SENSITIVE_BOUNDARY")
  })

  test("takes the delete operation from apply-patch file metadata", () => {
    const out = evaluate({
      permission: "edit",
      patterns: ["docs/old.md"],
      metadata: { filepath: "docs/old.md", files: [{ relativePath: "docs/old.md", type: "delete" }] },
    })
    expect(out.rule_id).toBe("SEC.V1.DESTRUCTIVE_FS")
  })

  test("treats an unknown permission asking for everything as an opaque delegated action", () => {
    const out = evaluate({ permission: "mymcp_do_thing", patterns: ["*"], metadata: {} })
    expect(out.decision).toBe("ask")
    expect(out.rule_id).toBe("SEC.V1.DELEGATED_OPAQUE")
  })

  test("asks for a shell command whose parse facts are missing", () => {
    const out = evaluate({ permission: "bash", patterns: ["git status"], metadata: { command: "git status" } })
    expect(out.decision).toBe("ask")
    expect(out.rule_id).toBe("SEC.V1.METADATA_INCOMPLETE")
  })

  test("has no opinion on a shell command that parsed completely and is not composed", () => {
    const out = evaluate({
      permission: "bash",
      patterns: ["git status"],
      metadata: { command: "git status", securityFacts: { complete: true, composed: false } },
    })
    expect(out.decision).toBe("pass")
  })

  test("asks for a composed shell command", () => {
    const out = evaluate({
      permission: "bash",
      patterns: ["a | b"],
      metadata: { command: "a | b", securityFacts: { complete: true, composed: true } },
    })
    expect(out.rule_id).toBe("SEC.V1.EXEC_COMPOSED")
  })

  test("carries the xdg floor into the decision so the core cannot deny under it", () => {
    const out = evaluate(
      { permission: "edit", patterns: [".git/hooks/pre-commit"], metadata: { filepath: "x" } },
      { floor: { action: "ask", authority: "xdg_global", conflict: true } },
    )
    expect(out.decision).toBe("ask")
    expect(out.audit.authority_level).toBe("xdg_global")
    expect(out.audit.authority_basis).toBe("xdg_scope")
    expect(out.audit.authority_conflict).toBe(true)
  })

  test("fails closed to ask when normalization throws", () => {
    const hostile = {
      permission: "edit",
      sessionID: "ses_1",
      callID: "call_1",
      metadata: {},
      get patterns(): readonly string[] {
        throw new Error("boom")
      },
    }
    const out = SecurityDecisionAdapter.evaluate(hostile, {
      workspace: "/repo",
      effective: "allow",
      humanOnly: false,
      floor: { action: "allow", authority: "untrusted", conflict: false },
      containment,
    })
    expect(out.decision).toBe("ask")
    expect(out.rule_id).toBe("SEC.V1.INTERNAL_ERROR")
  })

  test("writes an audit record with the mandatory fields and no echoed content", () => {
    const out = evaluate({
      permission: "bash",
      patterns: ["rm -rf /Users/secret/thing"],
      metadata: { command: "rm -rf /Users/secret/thing", securityFacts: { complete: true, composed: false } },
    })
    expect(out.audit.schema).toBe("kilo.security-decision/v1")
    expect(out.audit.policy_version).toBe("kilo.security-decision/v1")
    expect(out.audit.reviewer).toEqual({ state: "not_run" })
    expect(out.audit.metadata_complete).toBe(true)
    expect(out.audit.metadata_truncated).toBe(false)
    expect(out.audit.containment).toMatchObject(containment)
    expect(out.audit.sessionID).toBe("ses_1")
    expect(out.audit.callID).toBe("call_1")
    expect(typeof out.audit.latency_ms).toBe("number")
    expect(JSON.stringify(out.audit)).not.toContain("secret")
    expect(JSON.stringify(out.audit)).not.toContain("rm -rf")
  })

  test("finalize records the enforcement outcome onto the audit", () => {
    const out = evaluate({ permission: "edit", patterns: ["src/a.ts"], metadata: { filepath: "x" } })
    const final = SecurityDecisionAdapter.finalize(out.audit, "allow", "rule")
    expect(final.final_enforcement).toBe("allow")
    expect(final.enforcement_source).toBe("rule")
  })
})
