import { test, expect, describe } from "bun:test"
import { SecurityDecision } from "../../../src/kilocode/security-decision/core"
import type { SecurityDecisionTypes } from "../../../src/kilocode/security-decision/types"

const containment: SecurityDecisionTypes.Containment = {
  sandbox: "off",
  network: "allow",
  destinations: [],
  escalated: false,
}

function input(patch: {
  action: SecurityDecisionTypes.Input["action"]
  baseline?: Partial<SecurityDecisionTypes.Input["baseline"]>
  metadata?: Partial<SecurityDecisionTypes.Input["metadata"]>
  containment?: Partial<SecurityDecisionTypes.Containment>
}): SecurityDecisionTypes.Input {
  return {
    version: 1,
    action: patch.action,
    baseline: { decision: "ask", authority: "untrusted", humanOnly: false, ...patch.baseline },
    metadata: { complete: true, truncated: false, ...patch.metadata },
    containment: { ...containment, ...patch.containment },
  }
}

function path(patch: Partial<SecurityDecisionTypes.PathFact> & { path: string }): SecurityDecisionTypes.PathFact {
  return { path: patch.path, inWorkspace: patch.inWorkspace ?? true, class: patch.class ?? "ordinary" }
}

describe("SecurityDecision.decide", () => {
  test("returns the no-opinion rule id when it has no opinion", () => {
    const out = SecurityDecision.decide(
      input({ action: { kind: "read", operation: "read", paths: [path({ path: "src/a.ts" })] } }),
    )
    expect(out.decision).toBe("pass")
    expect(out.rule_id).toBe("SEC.V1.NO_OPINION")
    expect(out.reason).toBe("SEC.V1.NO_OPINION")
  })

  test("denies a write to a git hook", () => {
    const out = SecurityDecision.decide(
      input({
        action: {
          kind: "edit",
          operation: "update",
          paths: [path({ path: ".git/hooks/pre-commit", class: "git_hook" })],
        },
      }),
    )
    expect(out.decision).toBe("deny")
    expect(out.rule_id).toBe("SEC.V1.GIT_HOOK_WRITE")
  })

  test("asks instead of denying when the git hook target is not exact", () => {
    const out = SecurityDecision.decide(
      input({
        action: {
          kind: "edit",
          operation: "unknown",
          paths: [path({ path: ".git/hooks/pre-commit", class: "git_hook" })],
        },
      }),
    )
    expect(out.decision).toBe("ask")
    expect(out.rule_id).toBe("SEC.V1.AMBIGUOUS_OPERATION")
  })

  test("denies an exact destructive root delete", () => {
    const out = SecurityDecision.decide(
      input({
        action: {
          kind: "bash",
          operation: "delete",
          paths: [path({ path: "/", inWorkspace: false, class: "root" })],
          exec: { complete: true, composed: false, executable: "rm", class: "known" },
        },
      }),
    )
    expect(out.decision).toBe("deny")
    expect(out.rule_id).toBe("SEC.V1.DESTRUCTIVE_ROOT")
  })

  test("asks rather than denying a destructive root delete parsed incompletely", () => {
    const out = SecurityDecision.decide(
      input({
        action: {
          kind: "bash",
          operation: "delete",
          paths: [path({ path: "/", inWorkspace: false, class: "root" })],
          exec: { complete: false, composed: false, executable: "rm", class: "known" },
        },
      }),
    )
    expect(out.decision).toBe("ask")
    expect(out.rule_id).toBe("SEC.V1.EXEC_INCOMPLETE")
  })

  test("asks for a delete of an ordinary workspace file", () => {
    const out = SecurityDecision.decide(
      input({ action: { kind: "edit", operation: "delete", paths: [path({ path: "docs/old.md" })] } }),
    )
    expect(out.decision).toBe("ask")
    expect(out.rule_id).toBe("SEC.V1.DESTRUCTIVE_FS")
  })

  test("asks for a sensitive path read", () => {
    const out = SecurityDecision.decide(
      input({ action: { kind: "read", operation: "read", paths: [path({ path: ".env", class: "sensitive" })] } }),
    )
    expect(out.decision).toBe("ask")
    expect(out.rule_id).toBe("SEC.V1.SENSITIVE_BOUNDARY")
  })

  test("asks for a CI config edit", () => {
    const out = SecurityDecision.decide(
      input({
        action: { kind: "edit", operation: "update", paths: [path({ path: ".github/workflows/ci.yml", class: "ci" })] },
      }),
    )
    expect(out.decision).toBe("ask")
    expect(out.rule_id).toBe("SEC.V1.CI_AUTHORITY")
  })

  test("asks for an opaque delegated MCP action", () => {
    const out = SecurityDecision.decide(
      input({ action: { kind: "mcp", operation: "invoke", paths: [] }, metadata: { complete: false } }),
    )
    expect(out.decision).toBe("ask")
    expect(out.rule_id).toBe("SEC.V1.DELEGATED_OPAQUE")
  })

  test("asks when metadata is incomplete or truncated", () => {
    const incomplete = SecurityDecision.decide(
      input({
        action: { kind: "edit", operation: "update", paths: [path({ path: "src/a.ts" })] },
        metadata: { complete: false },
      }),
    )
    expect(incomplete.decision).toBe("ask")
    expect(incomplete.rule_id).toBe("SEC.V1.METADATA_INCOMPLETE")
    const truncated = SecurityDecision.decide(
      input({
        action: { kind: "edit", operation: "update", paths: [path({ path: "src/a.ts" })] },
        metadata: { truncated: true },
      }),
    )
    expect(truncated.decision).toBe("ask")
    expect(truncated.rule_id).toBe("SEC.V1.METADATA_INCOMPLETE")
  })

  test("one unknown target holds a multi-target result at ask", () => {
    const out = SecurityDecision.decide(
      input({
        action: {
          kind: "edit",
          operation: "update",
          paths: [path({ path: "src/a.ts" }), path({ path: "unknown", class: "unknown" })],
        },
      }),
    )
    expect(out.decision).toBe("ask")
  })

  test("never denies when the baseline is human-only", () => {
    const out = SecurityDecision.decide(
      input({
        action: {
          kind: "edit",
          operation: "update",
          paths: [path({ path: ".git/hooks/pre-commit", class: "git_hook" })],
        },
        baseline: { humanOnly: true },
      }),
    )
    expect(out.decision).toBe("ask")
  })

  test("never denies when the baseline authority is the xdg global floor", () => {
    const out = SecurityDecision.decide(
      input({
        action: {
          kind: "edit",
          operation: "update",
          paths: [path({ path: ".git/hooks/pre-commit", class: "git_hook" })],
        },
        baseline: { authority: "xdg_global" },
      }),
    )
    expect(out.decision).toBe("ask")
  })

  test("marks an ask reviewable only when it is a soft ambiguity", () => {
    const ambiguous = SecurityDecision.decide(
      input({ action: { kind: "edit", operation: "delete", paths: [path({ path: "docs/old.md" })] } }),
    )
    expect(ambiguous.reviewable).toBe(true)
    const sensitive = SecurityDecision.decide(
      input({ action: { kind: "read", operation: "read", paths: [path({ path: ".env", class: "sensitive" })] } }),
    )
    expect(sensitive.reviewable).toBe(false)
  })

  test("reasons never echo a command or a path", () => {
    const out = SecurityDecision.decide(
      input({
        action: {
          kind: "bash",
          operation: "delete",
          paths: [path({ path: "/Users/secret/thing", inWorkspace: false, class: "root" })],
          exec: { complete: true, composed: false, executable: "rm", class: "known" },
        },
      }),
    )
    expect(out.reason).not.toContain("/Users/secret")
    expect(out.reason).not.toContain("rm")
    expect(out.reason).toMatch(/^SEC\.V1\./)
  })
})
