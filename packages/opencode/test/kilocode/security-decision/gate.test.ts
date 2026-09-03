import { test, expect, describe, afterEach } from "bun:test"
import { Effect } from "effect"
import { KiloSecurityGate } from "../../../src/kilocode/security-decision/gate"
import { SecurityReviewer } from "../../../src/kilocode/security-decision/reviewer"

const previous = process.env["KILO_SECURITY_DECISION"]
afterEach(() => {
  if (previous === undefined) delete process.env["KILO_SECURITY_DECISION"]
  else process.env["KILO_SECURITY_DECISION"] = previous
  SecurityReviewer.reset()
})

function on() {
  process.env["KILO_SECURITY_DECISION"] = "1"
}

function config(permission: Record<string, unknown> = {}) {
  return { getGlobal: () => Effect.succeed({ permission } as any) }
}

function run(input: Partial<Parameters<typeof KiloSecurityGate.evaluate>[0]> = {}) {
  return Effect.runPromise(
    KiloSecurityGate.evaluate({
      config: config(),
      workspace: "/repo",
      permission: "edit",
      patterns: [".git/hooks/pre-commit"],
      metadata: { filepath: "x" },
      sessionID: "ses_1",
      callID: "call_1",
      resolved: [{ pattern: ".git/hooks/pre-commit", action: "allow" }],
      humanOnly: false,
      ...input,
    }),
  )
}

describe("KiloSecurityGate", () => {
  test("returns nothing while the feature flag is off", async () => {
    delete process.env["KILO_SECURITY_DECISION"]
    expect(await run()).toBeUndefined()
  })

  test("denies a git hook write once the flag is on", async () => {
    on()
    const out = await run()
    expect(out?.decision).toBe("deny")
    expect(out?.rule_id).toBe("SEC.V1.GIT_HOOK_WRITE")
  })

  test("an xdg ask floor holds the decision at ask instead of denying", async () => {
    on()
    const out = await run({ config: config({ edit: { "*": "ask" } }) })
    expect(out?.decision).toBe("ask")
    expect(out?.audit.authority_level).toBe("xdg_global")
  })

  test("an xdg ask is not weakened by a project or session allow", async () => {
    on()
    const out = await run({
      permission: "read",
      patterns: ["src/a.ts"],
      metadata: {},
      resolved: [{ pattern: "src/a.ts", action: "allow" }],
      config: config({ read: { "*": "ask" } }),
    })
    expect(out?.decision).toBe("ask")
    expect(out?.rule_id).toBe("SEC.V1.AUTHORITY_FLOOR")
  })

  test("an xdg allow does not stop the core from tightening", async () => {
    on()
    const out = await run({ config: config({ edit: { "*": "allow" } }) })
    expect(out?.decision).toBe("deny")
  })

  test("a human-only ask is never turned into a deny", async () => {
    on()
    const out = await run({ humanOnly: true })
    expect(out?.decision).toBe("ask")
  })

  test("takes the strictest floor across a multi-pattern request", async () => {
    on()
    const out = await run({
      permission: "read",
      patterns: ["src/a.ts", "src/b.ts"],
      metadata: {},
      resolved: [
        { pattern: "src/a.ts", action: "allow" },
        { pattern: "src/b.ts", action: "allow" },
      ],
      config: config({ read: { "src/b.ts": "ask" } }),
    })
    expect(out?.decision).toBe("ask")
    expect(out?.rule_id).toBe("SEC.V1.AUTHORITY_FLOOR")
  })

  test("core pass leaves an existing multi-pattern ask to the current pipeline", async () => {
    on()
    const out = await run({
      permission: "read",
      patterns: ["src/a.ts", "src/b.ts"],
      metadata: {},
      resolved: [
        { pattern: "src/a.ts", action: "allow" },
        { pattern: "src/b.ts", action: "ask" },
      ],
    })
    expect(out?.decision).toBe("pass")
  })

  test("an unreadable global config fails closed to ask", async () => {
    on()
    const out = await run({
      permission: "read",
      patterns: ["src/a.ts"],
      metadata: {},
      resolved: [{ pattern: "src/a.ts", action: "allow" }],
      config: { getGlobal: () => Effect.fail(new Error("boom")) as any },
    })
    expect(out?.decision).toBe("ask")
    expect(out?.audit.authority_level).toBe("unknown")
  })

  test("has no opinion on an ordinary allowed read", async () => {
    on()
    const out = await run({
      permission: "read",
      patterns: ["src/a.ts"],
      metadata: {},
      resolved: [{ pattern: "src/a.ts", action: "allow" }],
    })
    expect(out?.decision).toBe("pass")
  })
})

// kilocode_change start - the reviewer stage lives in the gate, after the deterministic decision
const unclassified = {
  permission: "bash",
  patterns: ["sed -i s/a/b/ src/a.ts"],
  metadata: {
    securityFacts: {
      complete: true,
      composed: false,
      executable: "sed",
      argv: ["sed", "-i", "s/a/b/", "src/a.ts"],
      effects: [],
    },
  },
  resolved: [{ pattern: "sed -i s/a/b/ src/a.ts", action: "allow" as const }],
}

describe("KiloSecurityGate reviewer stage", () => {
  test("never offers a deterministic deny to the reviewer", async () => {
    on()
    let called = 0
    SecurityReviewer.bind(() => {
      called++
      return Promise.resolve('{"decision":"allow","reason_code":"OK"}')
    })

    const out = await run()

    expect(out?.decision).toBe("deny")
    expect(called).toBe(0)
    expect(out?.audit.reviewer).toEqual({ state: "not_run" })
  })

  test("routes a fully parsed unclassified command to a reviewable ask", async () => {
    on()
    const out = await run(unclassified)

    expect(out?.decision).toBe("ask")
    expect(out?.rule_id).toBe("SEC.V1.UNCLASSIFIED_EXEC")
    expect(out?.reviewable).toBe(true)
  })

  test("an allow verdict narrows that ask for this call", async () => {
    on()
    SecurityReviewer.bind(() => Promise.resolve('{"decision":"allow","reason_code":"IN_WORKSPACE_EDIT"}'))

    const out = await run(unclassified)

    expect(out?.decision).toBe("allow")
    expect(out?.audit.reviewer).toMatchObject({ state: "allow", reason_code: "IN_WORKSPACE_EDIT" })
    expect(out?.rule_id).toBe("SEC.V1.UNCLASSIFIED_EXEC")
  })

  test("a keep_ask verdict leaves the ask standing", async () => {
    on()
    SecurityReviewer.bind(() => Promise.resolve('{"decision":"keep_ask","reason_code":"UNCLEAR"}'))

    const out = await run(unclassified)

    expect(out?.decision).toBe("ask")
    expect(out?.audit.reviewer).toMatchObject({ state: "keep_ask" })
  })

  test("a failing reviewer leaves the ask standing", async () => {
    on()
    SecurityReviewer.bind(() => Promise.reject(new Error("down")))

    const out = await run(unclassified)

    expect(out?.decision).toBe("ask")
    expect(out?.audit.reviewer.state).toBe("error")
  })

  test("a human-only ask is never narrowed", async () => {
    on()
    let called = 0
    SecurityReviewer.bind(() => {
      called++
      return Promise.resolve('{"decision":"allow","reason_code":"OK"}')
    })

    const out = await run({ ...unclassified, humanOnly: true })

    expect(out?.decision).toBe("ask")
    expect(called).toBe(0)
  })

  test("an ask under a conflicting user-global rule is never narrowed", async () => {
    on()
    let called = 0
    SecurityReviewer.bind(() => {
      called++
      return Promise.resolve('{"decision":"allow","reason_code":"OK"}')
    })

    const out = await run({
      ...unclassified,
      config: config({ bash: { "*": "ask" } }),
      resolved: [{ pattern: "sed -i s/a/b/ src/a.ts", action: "allow" as const }],
    })

    expect(out?.decision).toBe("ask")
    expect(called).toBe(0)
  })

  test("an inert command never reaches the reviewer", async () => {
    on()
    let called = 0
    SecurityReviewer.bind(() => {
      called++
      return Promise.resolve('{"decision":"allow","reason_code":"OK"}')
    })

    const out = await run({
      ...unclassified,
      patterns: ["git status"],
      metadata: {
        securityFacts: { complete: true, composed: false, executable: "git", argv: ["git", "status"], effects: [] },
      },
      resolved: [{ pattern: "git status", action: "allow" as const }],
    })

    expect(out?.decision).toBe("pass")
    expect(called).toBe(0)
  })
})
// kilocode_change end
