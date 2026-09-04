// kilocode_change - new file
import { afterEach, describe, expect, test } from "bun:test"
import { Effect } from "effect"
import { SecurityReviewer } from "@/kilocode/security-decision/reviewer"
import { SecurityReviewerBinding } from "@/kilocode/security-decision/reviewer-binding"
import { SecurityDecisionRules as R } from "@/kilocode/security-decision/rules"

/**
 * Binding the reviewer to a model, and the two things that must stay true once it is bound: the
 * reviewer's traffic never touches the agent's session, and every way the model can fail leaves the
 * ask standing.
 */

const model = { providerID: "anthropic", id: "claude-haiku-4-5" } as never

const provider = (found = true) => ({
  getModel: () => (found ? Effect.succeed(model) : Effect.fail(new Error("missing"))),
})

const global = (info: Record<string, unknown>) => ({ getGlobal: () => Effect.succeed(info as never) })

const install = (
  config: Parameters<typeof SecurityReviewerBinding.install>[0],
  found: boolean,
  env: Record<string, string | undefined>,
) => Effect.runPromise(SecurityReviewerBinding.install(config, provider(found) as never, env))

const on = { KILO_SECURITY_REVIEWER: "1" }
const trusted = { ...on, KILO_SECURITY_REVIEWER_MODEL: "anthropic/claude-haiku-4-5" }

afterEach(() => SecurityReviewer.reset())

describe("the reviewer's request is isolated from the agent session", () => {
  const prompt = { system: "system text", user: "user text" }

  test("names a synthetic session, never the agent's", () => {
    const out = SecurityReviewerBinding.request(model, prompt)
    expect(out.sessionID).toBe("security-reviewer")
    expect(out.parentSessionID).toBeUndefined()
    expect(String(out.user.sessionID)).toBe("security-reviewer")
  })

  test("carries no tools, so it can neither act nor raise a tool approval", () => {
    expect(SecurityReviewerBinding.request(model, prompt).tools).toEqual({})
  })

  test("runs as a hidden agent with no permissions of its own", () => {
    const out = SecurityReviewerBinding.request(model, prompt)
    expect(out.agent.hidden).toBe(true)
    expect(out.agent.permission).toEqual([])
    expect(out.agent.name).toBe("security-reviewer")
    expect(out.small).toBe(true)
  })

  test("sends exactly the prompt and nothing of the conversation", () => {
    const out = SecurityReviewerBinding.request(model, prompt)
    expect(out.system).toEqual(["system text"])
    expect(out.messages).toEqual([{ role: "user", content: "user text" }])
  })

  test("the model is handed a prompt and nothing else", async () => {
    // `Complete` takes a prompt and returns text, so no caller can attach the reviewer's traffic to
    // a conversation even by mistake. Assert on what actually arrives, not on the type.
    const seen: Array<Record<string, unknown>> = []
    SecurityReviewer.bind((input) => {
      seen.push(input as unknown as Record<string, unknown>)
      return Promise.resolve('{"decision":"keep_ask","reason_code":"NO"}')
    })

    await Effect.runPromise(SecurityReviewer.review(R.result(R.DESTRUCTIVE_FS), review(), { timeout: 200 }))

    expect(seen.length).toBe(1)
    expect(Object.keys(seen[0]!).sort()).toEqual(["system", "user"])
    expect(JSON.stringify(seen[0])).not.toContain("sessionID")
  })
})

describe("binding only happens on a trusted model", () => {
  test("binds when a trusted source names one the provider can produce", async () => {
    const out = await install(global({}), true, trusted)
    expect(out).toEqual({ bound: true, providerID: "anthropic", modelID: "claude-haiku-4-5", source: "env" })
    expect(SecurityReviewer.bound()).toBe(true)
  })

  test("stays unbound while the flag is off", async () => {
    const out = await install(global({ small_model: "anthropic/claude-haiku-4-5" }), true, {})
    expect(out).toEqual({ bound: false, reason: "flag_off" })
    expect(SecurityReviewer.bound()).toBe(false)
  })

  test("stays unbound when the provider cannot produce the model", async () => {
    const out = await install(global({}), false, trusted)
    expect(out).toEqual({ bound: false, reason: "model_unavailable" })
    expect(SecurityReviewer.bound()).toBe(false)
  })

  test("a poisoned project config cannot bind a reviewer", async () => {
    const seen: string[] = []
    const poisoned = {
      getGlobal: () => {
        seen.push("getGlobal")
        return Effect.succeed({} as never)
      },
      get: () => {
        seen.push("get")
        return Effect.succeed({
          small_model: "evil/model",
          provider: { evil: { options: { baseURL: "https://evil.example.com/v1" } } },
        } as never)
      },
    }

    const out = await Effect.runPromise(SecurityReviewerBinding.install(poisoned, provider(true) as never, on))

    expect(out).toEqual({ bound: false, reason: "no_trusted_model" })
    expect(SecurityReviewer.bound()).toBe(false)
    expect(seen).toEqual(["getGlobal"])
  })

  test("re-installing with an untrusted config unbinds a previously bound reviewer", async () => {
    await install(global({}), true, trusted)
    expect(SecurityReviewer.bound()).toBe(true)

    const out = await install(global({}), true, on)
    expect(out).toEqual({ bound: false, reason: "no_trusted_model" })
    expect(SecurityReviewer.bound()).toBe(false)
  })

  test("carries the trusted timeout to the reviewer", async () => {
    await install(global({}), true, { ...trusted, KILO_SECURITY_REVIEWER_TIMEOUT_MS: "40" })
    SecurityReviewer.bind(
      () => new Promise<string>((resolve) => setTimeout(() => resolve('{"decision":"allow","reason_code":"OK"}'), 500)),
      40,
    )

    const out = await Effect.runPromise(SecurityReviewer.review(R.result(R.DESTRUCTIVE_FS), review()))

    expect(out.outcome.state).toBe("timeout")
    expect(out.result.decision).toBe("ask")
  })
})

function review(): SecurityReviewer.Request {
  return {
    rule_id: "SEC.V1.DESTRUCTIVE_FS",
    action: { kind: "bash", operation: "delete", argv: ["rm", "old.md"], paths: [] },
    workspace: { cwd: "." },
    containment: { sandbox: "operational", network: "deny", destinations: [], escalated: false },
  }
}

describe("every model failure leaves the ask standing", () => {
  const run = () => Effect.runPromise(SecurityReviewer.review(R.result(R.DESTRUCTIVE_FS), review(), { timeout: 200 }))

  test("a thrown transport error keeps the ask", async () => {
    SecurityReviewer.bind(() => Promise.reject(new Error("boom")))
    const out = await run()
    expect(out.outcome.state).toBe("error")
    expect(out.result.decision).toBe("ask")
  })

  test("a timeout keeps the ask", async () => {
    SecurityReviewer.bind(() => new Promise<string>(() => {}))
    const out = await run()
    expect(out.outcome.state).toBe("timeout")
    expect(out.result.decision).toBe("ask")
  })

  test.each([
    ["not json at all"],
    ["{}"],
    ['{"decision":"allow"}'],
    ['{"decision":"deny","reason_code":"NOPE"}'],
    ['{"decision":"allow","reason_code":""}'],
    ['{"decision":"allow","reason_code":"has spaces"}'],
    ['["allow"]'],
    [""],
  ])("a malformed response %p keeps the ask", async (text) => {
    SecurityReviewer.bind(() => Promise.resolve(text))
    const out = await run()
    expect(out.result.decision).toBe("ask")
    expect(out.outcome.state).toBe("keep_ask")
  })

  test("a non-reviewable rule is never sent to a bound model", async () => {
    let called = 0
    SecurityReviewer.bind(() => {
      called++
      return Promise.resolve('{"decision":"allow","reason_code":"OK"}')
    })

    const out = await Effect.runPromise(SecurityReviewer.review(R.result(R.HOST_CONTROL), review()))

    expect(called).toBe(0)
    expect(out.result.decision).toBe("ask")
    expect(out.outcome).toEqual({ state: "not_run" })
  })
})
