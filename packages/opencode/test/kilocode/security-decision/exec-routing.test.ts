// kilocode_change - new file
import { describe, expect, test } from "bun:test"
import { SecurityDecisionAdapter } from "@/kilocode/security-decision/adapter"

/**
 * A shell command the parser fully recovered, that produced no confident file effect, is not proof
 * of safety — it is an unclassified action. It becomes a reviewable ask instead of passing silently.
 * Deterministic path and effect rules keep absolute priority over that routing.
 */

const ctx: SecurityDecisionAdapter.Context = {
  workspace: "/w",
  effective: "allow",
  humanOnly: false,
  floor: { action: "allow", authority: "untrusted", conflict: false },
  containment: { sandbox: "unknown", network: "allow", destinations: [], escalated: false },
}

const sessionID = "ses_exec"

type Effect = { operation: "read" | "update" | "delete" | "move"; path?: string }

const shell = (command: string, effects: Effect[] = [], override: Record<string, unknown> = {}) => {
  const argv = command.split(/\s+/)
  return SecurityDecisionAdapter.evaluate(
    {
      permission: "bash",
      patterns: [command],
      metadata: {
        securityFacts: { complete: true, composed: false, executable: argv[0], argv, effects, ...override },
      },
      sessionID,
    },
    ctx,
  )
}

describe("unclassified shell actions", () => {
  test.each([
    ["sed -i s/a/b/ src/a.ts"],
    ["git push --force"],
    ["npm publish"],
    ["python -c print(1)"],
    ["npm test"],
    ["curl https://example.com"],
    ["chmod"],
  ])("%s becomes a reviewable ask", (command) => {
    const out = shell(command)

    expect(out.rule_id).toBe("SEC.V1.UNCLASSIFIED_EXEC")
    expect(out.decision).toBe("ask")
    expect(out.reviewable).toBe(true)
  })

  test("a command whose executable the scan could not name is unclassified too", () => {
    const out = shell("weird", [], { executable: undefined, argv: undefined })

    expect(out.rule_id).toBe("SEC.V1.UNCLASSIFIED_EXEC")
    expect(out.reviewable).toBe(true)
  })

  test("the reviewable ask carries a bounded request for the reviewer", () => {
    const out = shell("sed -i s/a/b/ src/a.ts", [{ operation: "update", path: "/w/src/a.ts" }])

    expect(out.review).toBeDefined()
    expect(out.review?.action.executable).toBe("sed")
    expect(out.review?.action.argv).toEqual(["sed", "-i", "s/a/b/", "src/a.ts"])
  })
})

describe("deterministically benign shell actions", () => {
  // Only verbs that emit names and metadata are inert. `diff`, `log`, `show` and `blame` print file
  // contents, so they are covered by the adversarial suite in inert-git.test.ts instead.
  test.each([
    ["git status"],
    ["git status --short"],
    ["git status -sb"],
    ["git rev-parse HEAD"],
    ["git rev-parse --show-toplevel"],
    ["git ls-files --others --exclude-standard"],
    ["ls -la"],
    ["pwd"],
    ["echo hello"],
    ["which node"],
    ["basename src/a.ts"],
  ])("%s keeps no opinion", (command) => {
    const out = shell(command)

    expect(out.rule_id).toBe("SEC.V1.NO_OPINION")
    expect(out.decision).toBe("pass")
  })

  test("a benign executable writing an ordinary file still passes", () => {
    const out = shell("echo hi > README.md", [{ operation: "update", path: "/w/README.md" }])

    expect(out.rule_id).toBe("SEC.V1.NO_OPINION")
  })

  test("a mutating or content-printing git subcommand is not benign", () => {
    expect(shell("git commit -m x").rule_id).toBe("SEC.V1.UNCLASSIFIED_EXEC")
    expect(shell("git config core.hooksPath .githooks").rule_id).toBe("SEC.V1.UNCLASSIFIED_EXEC")
    expect(shell("git").rule_id).toBe("SEC.V1.UNCLASSIFIED_EXEC")
    expect(shell("git diff --stat").rule_id).toBe("SEC.V1.UNCLASSIFIED_EXEC")
    expect(shell("git log --oneline -n 5").rule_id).toBe("SEC.V1.UNCLASSIFIED_EXEC")
    expect(shell("git show HEAD").rule_id).toBe("SEC.V1.UNCLASSIFIED_EXEC")
  })
})

describe("deterministic rules keep priority over exec routing", () => {
  test("a proven root deletion still denies", () => {
    const out = shell("rm -rf /", [{ operation: "delete", path: "/" }])

    expect(out.rule_id).toBe("SEC.V1.DESTRUCTIVE_ROOT")
    expect(out.decision).toBe("deny")
    expect(out.review).toBeUndefined()
  })

  test("a benign executable writing a git hook still denies", () => {
    const out = shell("echo x >> .git/hooks/pre-commit", [{ operation: "update", path: "/w/.git/hooks/pre-commit" }])

    expect(out.rule_id).toBe("SEC.V1.GIT_HOOK_WRITE")
    expect(out.decision).toBe("deny")
    expect(out.review).toBeUndefined()
  })

  test("a sensitive read still wins over exec routing", () => {
    const out = shell("cat .env", [{ operation: "read", path: "/w/.env" }])

    expect(out.rule_id).toBe("SEC.V1.SENSITIVE_BOUNDARY")
    expect(out.reviewable).toBe(false)
  })

  test("composition and parse failures win over exec routing", () => {
    expect(shell("sed -i s/a/b/ f", [], { composed: true }).rule_id).toBe("SEC.V1.EXEC_COMPOSED")
    expect(shell("sed -i s/a/b/ f", [], { complete: false }).rule_id).toBe("SEC.V1.EXEC_INCOMPLETE")
  })

  test("an unresolvable effect target wins over exec routing", () => {
    const out = shell("sed -i s/a/b/ $F", [{ operation: "update" }])

    expect(out.rule_id).toBe("SEC.V1.UNKNOWN_TARGET")
    expect(out.reviewable).toBe(false)
  })

  test("structured file tools are untouched by exec routing", () => {
    const edit = SecurityDecisionAdapter.evaluate(
      { permission: "edit", patterns: ["src/a.ts"], metadata: {}, sessionID },
      ctx,
    )

    expect(edit.rule_id).toBe("SEC.V1.NO_OPINION")
    expect(edit.review).toBeUndefined()
  })

  test("a human-only ask is never handed to the reviewer", () => {
    const out = SecurityDecisionAdapter.evaluate(
      {
        permission: "bash",
        patterns: ["sed -i s/a/b/ f"],
        metadata: { securityFacts: { complete: true, composed: false, executable: "sed", argv: ["sed"], effects: [] } },
        sessionID,
      },
      { ...ctx, humanOnly: true },
    )

    expect(out.decision).toBe("ask")
    expect(out.reviewable).toBe(false)
    expect(out.review).toBeUndefined()
  })
})
