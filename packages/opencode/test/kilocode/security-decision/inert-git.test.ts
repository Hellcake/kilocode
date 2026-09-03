// kilocode_change - new file
import { describe, expect, test } from "bun:test"
import { SecurityDecisionAdapter } from "@/kilocode/security-decision/adapter"

/**
 * Adversarial cases for the inert allowlist.
 *
 * `inert` has to mean "we can prove this is low risk here", not "the verb sounded read-only". git in
 * particular reads file contents, redirects its own repository and executes configured programs, all
 * under verbs that look harmless, so the allowlist is over verb *and* argument combinations.
 */

const ctx: SecurityDecisionAdapter.Context = {
  workspace: "/w",
  effective: "allow",
  humanOnly: false,
  floor: { action: "allow", authority: "untrusted", conflict: false },
  containment: { sandbox: "unknown", network: "allow", destinations: [], escalated: false },
}

const shell = (command: string, effects: Array<{ operation: string; path?: string }> = []) => {
  const argv = command.split(/\s+/)
  return SecurityDecisionAdapter.evaluate(
    {
      permission: "bash",
      patterns: [command],
      metadata: {
        securityFacts: { complete: true, composed: false, executable: argv[0], argv, effects, classified: false },
      },
      sessionID: "ses_inert",
    },
    ctx,
  )
}

const asks = (command: string) => {
  const out = shell(command)
  expect({ command, rule: out.rule_id, decision: out.decision }).toEqual({
    command,
    rule: "SEC.V1.UNCLASSIFIED_EXEC",
    decision: "ask",
  })
  expect(out.reviewable).toBe(true)
}

const passes = (command: string) => {
  const out = shell(command)
  expect({ command, rule: out.rule_id, decision: out.decision }).toEqual({
    command,
    rule: "SEC.V1.NO_OPINION",
    decision: "pass",
  })
}

describe("git cannot be used to read content that a direct read would ask for", () => {
  test.each([
    ["git show HEAD:.env"],
    ["git show :0:.env"],
    ["git show HEAD"],
    ["git diff -- .env"],
    ["git diff"],
    ["git diff --stat"],
    ["git blame .env"],
    ["git blame src/a.ts"],
    ["git log -p -- .env"],
    ["git log --oneline"],
    ["git log"],
  ])("%s asks", (command) => asks(command))

  test("the direct route asks too, so the two agree", () => {
    const read = SecurityDecisionAdapter.evaluate(
      { permission: "read", patterns: [".env"], metadata: {}, sessionID: "ses_inert" },
      ctx,
    )
    expect(read.decision).toBe("ask")
    expect(shell("git show HEAD:.env").decision).toBe("ask")
  })
})

describe("git flags that move or reprogram the operation are never inert", () => {
  test.each([
    ["git --git-dir=/elsewhere/.git status"],
    ["git --work-tree=/outside status"],
    ["git -C /outside status"],
    ["git -c core.pager=curl status"],
    ["git -c diff.external=/tmp/x status"],
    ["git --exec-path=/tmp status"],
    ["git --namespace=x status"],
    ["git -P status"],
  ])("%s asks", (command) => asks(command))
})

describe("unknown or content-bearing arguments fail closed", () => {
  test.each([
    ["git status --output=/tmp/x"],
    ["git status --unknown-flag"],
    ["git status --ext-diff"],
    ["git rev-parse --unknown"],
    ["git ls-files --textconv"],
    ["git"],
    ["git st"],
    ["git config core.hooksPath .githooks"],
    ["git push --force"],
    ["git commit -m x"],
  ])("%s asks", (command) => asks(command))
})

describe("the provable dev flow still passes", () => {
  test.each([
    ["git status"],
    ["git status -s"],
    ["git status -sb"],
    ["git status --short --branch"],
    ["git status --porcelain"],
    ["git status --porcelain=v2"],
    ["git status -uno"],
    ["git status -- src"],
    ["git --no-pager status"],
    ["git rev-parse HEAD"],
    ["git rev-parse --show-toplevel"],
    ["git rev-parse --abbrev-ref HEAD"],
    ["git ls-files"],
    ["git ls-files --others --exclude-standard"],
    ["git ls-files -z"],
  ])("%s passes", (command) => passes(command))
})

describe("deterministic path rules still outrank the inert allowlist", () => {
  test("an inert command writing a git hook is still denied", () => {
    const out = shell("git status > .git/hooks/pre-commit", [{ operation: "update", path: "/w/.git/hooks/pre-commit" }])
    expect(out.rule_id).toBe("SEC.V1.GIT_HOOK_WRITE")
    expect(out.decision).toBe("deny")
  })

  test("an inert command writing a control-plane file still asks", () => {
    const out = shell("git status > .git/config", [{ operation: "update", path: "/w/.git/config" }])
    expect(out.rule_id).toBe("SEC.V1.CONTROL_PLANE_WRITE")
  })

  test("an inert command discarding output still passes", () => {
    const out = shell("git status > /dev/null", [{ operation: "update", path: "/dev/null" }])
    expect(out.rule_id).toBe("SEC.V1.NO_OPINION")
  })
})

describe("non-git inert commands", () => {
  test.each([["ls -la"], ["pwd"], ["echo hello"], ["which node"], ["basename src/a.ts"], ["true"]])(
    "%s passes",
    (command) => passes(command),
  )

  test.each([["node -e process.exit(0)"], ["sh -c ls"], ["env"], ["printenv"]])("%s asks", (command) => asks(command))
})
