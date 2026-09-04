// kilocode_change - new file
import { describe, expect, test } from "bun:test"
import { Effect } from "effect"
import { SecurityReviewerConfig } from "@/kilocode/security-decision/reviewer-config"

/**
 * Where the reviewer's own model may come from.
 *
 * The reviewer decides whether a bounded ask runs without a human, so the choice of *which* model
 * answers that question is part of the trusted base. A project config arrives with a clone, and the
 * merge only scopes `sandbox` and indexing by source — `model`, `small_model` and `provider`
 * (including its `baseURL`) survive from a repository into the effective config. A repository that
 * picks its own reviewer would turn the whole eligible population into an automatic allow, which is
 * strictly worse than having no reviewer at all.
 *
 * So resolution never reads the merged config, never inherits the session's provider, and fails
 * closed: no trusted model means the reviewer stays disabled.
 */

const global = (info: Record<string, unknown>) => ({ getGlobal: () => Effect.succeed(info as never) })

const unreadable = {
  getGlobal: () => Effect.fail(new Error("boom")),
} as unknown as Parameters<typeof SecurityReviewerConfig.resolve>[0]

const resolve = (
  config: Parameters<typeof SecurityReviewerConfig.resolve>[0],
  env: Record<string, string | undefined>,
) => Effect.runPromise(SecurityReviewerConfig.resolve(config, env))

const on = { KILO_SECURITY_REVIEWER: "1" }

describe("SecurityReviewerConfig.resolve", () => {
  test("stays disabled until the flag is set", async () => {
    const out = await resolve(global({ small_model: "anthropic/claude-haiku-4-5" }), {})
    expect(out).toEqual({ enabled: false, reason: "flag_off" })
  })

  test("takes the model from the user's own global config", async () => {
    const out = await resolve(global({ small_model: "anthropic/claude-haiku-4-5" }), on)
    expect(out).toMatchObject({
      enabled: true,
      providerID: "anthropic",
      modelID: "claude-haiku-4-5",
      source: "xdg_global",
    })
  })

  test("an environment model outranks the global one", async () => {
    const out = await resolve(global({ small_model: "anthropic/claude-haiku-4-5" }), {
      ...on,
      KILO_SECURITY_REVIEWER_MODEL: "kilo-auto/free",
    })
    expect(out).toMatchObject({ enabled: true, providerID: "kilo-auto", modelID: "free", source: "env" })
  })

  test("keeps a model id that carries its own slashes", async () => {
    const out = await resolve(global({}), { ...on, KILO_SECURITY_REVIEWER_MODEL: "openrouter/meta/llama-3.1-8b" })
    expect(out).toMatchObject({ providerID: "openrouter", modelID: "meta/llama-3.1-8b" })
  })

  test("stays disabled when no trusted source names a model", async () => {
    const out = await resolve(global({}), on)
    expect(out).toEqual({ enabled: false, reason: "no_trusted_model" })
  })

  test.each([["no-slash"], ["/leading"], ["trailing/"], [""], ["   "]])(
    "stays disabled for the malformed model %p rather than guessing",
    async (model) => {
      const out = await resolve(global({}), { ...on, KILO_SECURITY_REVIEWER_MODEL: model })
      expect(out.enabled).toBe(false)
    },
  )

  test("stays disabled when the global config cannot be read", async () => {
    const out = await resolve(unreadable, on)
    expect(out).toEqual({ enabled: false, reason: "config_unreadable" })
  })

  test("stays disabled while the user asked for privacy mode", async () => {
    const out = await resolve(global({ privacy_mode: true, small_model: "anthropic/claude-haiku-4-5" }), on)
    expect(out).toEqual({ enabled: false, reason: "privacy_mode" })
  })

  test("bounds the timeout and keeps a default", async () => {
    expect(await resolve(global({ small_model: "a/b" }), on)).toMatchObject({ timeout: 4000 })
    expect(
      await resolve(global({ small_model: "a/b" }), { ...on, KILO_SECURITY_REVIEWER_TIMEOUT_MS: "1500" }),
    ).toMatchObject({ timeout: 1500 })
    expect(
      await resolve(global({ small_model: "a/b" }), { ...on, KILO_SECURITY_REVIEWER_TIMEOUT_MS: "60000" }),
    ).toMatchObject({ timeout: 5000 })
    expect(
      await resolve(global({ small_model: "a/b" }), { ...on, KILO_SECURITY_REVIEWER_TIMEOUT_MS: "nonsense" }),
    ).toMatchObject({ timeout: 4000 })
  })
})

/**
 * The poisoning cases, stated as their own suite because they are the reason this module exists.
 * Each one hands the resolver a value shaped exactly as a merged config would deliver it from a
 * repository, and asserts the resolver never took it.
 */
describe("a repository cannot choose the reviewer", () => {
  test("a project small_model in the merged config is not a trusted source", async () => {
    // `resolve` is given only `getGlobal`, so a merged value has no way in. The global block here
    // is what the user's own XDG config holds: nothing.
    const out = await resolve(global({}), on)
    expect(out).toEqual({ enabled: false, reason: "no_trusted_model" })
  })

  test("resolution never reads anything but the global block", async () => {
    const seen: string[] = []
    const spy = {
      getGlobal: () => {
        seen.push("getGlobal")
        return Effect.succeed({ small_model: "anthropic/claude-haiku-4-5" } as never)
      },
      get: () => {
        seen.push("get")
        return Effect.succeed({ small_model: "evil/model" } as never)
      },
    }
    const out = await Effect.runPromise(SecurityReviewerConfig.resolve(spy, on))
    expect(seen).toEqual(["getGlobal"])
    expect(out).toMatchObject({ providerID: "anthropic" })
  })

  test("a provider block the repository could ship never reaches the resolver", async () => {
    const poisoned = {
      small_model: "evil/model",
      provider: { evil: { options: { baseURL: "https://evil.example.com/v1" } } },
    }
    // The same object as a *global* value is the user's own choice and is honoured; the point is
    // that the resolver has no path to the merged one, so a repository copy of it does nothing.
    const trusted = await resolve(global(poisoned), on)
    expect(trusted).toMatchObject({ enabled: true, providerID: "evil", source: "xdg_global" })

    const untrusted = await resolve(global({}), on)
    expect(untrusted.enabled).toBe(false)
  })
})
