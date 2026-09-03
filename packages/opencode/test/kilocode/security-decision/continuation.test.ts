// kilocode_change - new file
import { describe, expect, test } from "bun:test"
import { SecurityContinuation } from "@/kilocode/security-decision/continuation"
import { SecurityBlocked } from "@/kilocode/security-decision/block"

// A security block stops the *call*, not the turn: the model keeps its turn and may pick another
// allowed path. Repeating the identical blocked call is not another path, so it ends the turn.

describe("SecurityContinuation.after", () => {
  const blocked = () => SecurityBlocked.of("SEC.V1.GIT_HOOK_WRITE", {} as never)

  test("continues the turn after a security block", () => {
    const seen = SecurityContinuation.state()
    expect(
      SecurityContinuation.after(seen, blocked(), { tool: "edit", input: { filePath: ".git/hooks/pre-commit" } }),
    ).toBe("continue")
  })

  test("continues when the next blocked call differs", () => {
    const seen = SecurityContinuation.state()
    SecurityContinuation.after(seen, blocked(), { tool: "edit", input: { filePath: ".git/hooks/pre-commit" } })
    expect(SecurityContinuation.after(seen, blocked(), { tool: "edit", input: { filePath: "src/a.ts" } })).toBe(
      "continue",
    )
    expect(SecurityContinuation.after(seen, blocked(), { tool: "bash", input: { command: "ls" } })).toBe("continue")
  })

  test("stops the turn when the identical blocked call is repeated", () => {
    const seen = SecurityContinuation.state()
    const call = { tool: "edit", input: { filePath: ".git/hooks/pre-commit", content: "x" } }
    expect(SecurityContinuation.after(seen, blocked(), call)).toBe("continue")
    expect(
      SecurityContinuation.after(seen, blocked(), {
        tool: "edit",
        input: { content: "x", filePath: ".git/hooks/pre-commit" },
      }),
    ).toBe("stop")
  })

  test("leaves a non-security failure to the existing rule", () => {
    const seen = SecurityContinuation.state()
    expect(SecurityContinuation.after(seen, new Error("boom"), { tool: "edit", input: {} })).toBeUndefined()
  })
})
