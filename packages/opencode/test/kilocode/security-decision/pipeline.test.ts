import { expect, afterEach } from "bun:test"
import { Cause, Effect, Exit, Fiber, Layer } from "effect"
import * as CrossSpawnSpawner from "@opencode-ai/core/cross-spawn-spawner"
import { AppNodeBuilder } from "@opencode-ai/core/effect/app-node-builder"
import { Permission } from "@/permission"
import * as Config from "@/config/config"
import { SessionID } from "@/session/schema"
import { SecurityBlocked } from "@/kilocode/security-decision/block"
import { testEffect } from "../../lib/effect"

// The layer is authoritative but strictly monotonic: it may raise an allow to ask or block a
// proven-destructive call, and it must never weaken an existing deny, hard veto or human-only ask.

const env = Layer.mergeAll(
  AppNodeBuilder.build(Permission.node),
  AppNodeBuilder.build(Config.node),
  AppNodeBuilder.build(CrossSpawnSpawner.node),
)
const it = testEffect(env)

const previous = process.env["KILO_SECURITY_DECISION"]
afterEach(() => {
  if (previous === undefined) delete process.env["KILO_SECURITY_DECISION"]
  else process.env["KILO_SECURITY_DECISION"] = previous
})

const sessionID = SessionID.make("ses_security_layer")

const ask = (input: Parameters<Permission.Interface["ask"]>[0]) =>
  Effect.gen(function* () {
    return yield* (yield* Permission.Service).ask(input)
  })

const fail = <A, E, R>(self: Effect.Effect<A, E, R>) =>
  Effect.gen(function* () {
    const exit = yield* self.pipe(Effect.exit)
    if (Exit.isFailure(exit)) return Cause.squash(exit.cause)
    throw new Error("expected the permission effect to fail")
  })

const editHook = {
  sessionID,
  permission: "edit",
  patterns: [".git/hooks/pre-commit"],
  always: ["*"],
  metadata: { filepath: ".git/hooks/pre-commit" },
}

it.instance("keeps the current outcome while the feature flag is off", () =>
  Effect.gen(function* () {
    delete process.env["KILO_SECURITY_DECISION"]
    const outcome = yield* ask({
      ...editHook,
      ruleset: [{ permission: "edit", pattern: "*", action: "allow" }],
    })
    expect(outcome.manual).toBe(false)
    expect(outcome.security).toBeUndefined()
  }),
)

it.instance("blocks a proven git-hook write with a fixed, non-echoing message", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const error = yield* fail(ask({ ...editHook, ruleset: [{ permission: "edit", pattern: "*", action: "allow" }] }))
    expect(error).toBeInstanceOf(SecurityBlocked.Error)
    const message = (error as SecurityBlocked.Error).message
    expect(message).toBe("Security policy blocked this tool call. rule_id=SEC.V1.GIT_HOOK_WRITE. Contact the user.")
    expect(message).not.toContain(".git/hooks")
    expect(message).not.toContain("permission")
  }),
)

it.instance("leaves an existing explicit deny untouched", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const error = yield* fail(ask({ ...editHook, ruleset: [{ permission: "edit", pattern: "*", action: "deny" }] }))
    expect(error).toBeInstanceOf(Permission.DeniedError)
  }),
)

it.instance("leaves a hard veto untouched", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const error = yield* fail(
      ask({
        ...editHook,
        ruleset: [{ permission: "edit", pattern: "*", action: "allow" }],
        hardRuleset: [{ permission: "edit", pattern: "*", action: "deny" }],
      }),
    )
    expect(error).toBeInstanceOf(Permission.DeniedError)
  }),
)

it.instance("keeps an auto-approval when the core has no opinion, and records the audit", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const outcome = yield* ask({
      sessionID,
      permission: "edit",
      patterns: ["src/a.ts"],
      always: ["*"],
      metadata: { filepath: "src/a.ts" },
      ruleset: [{ permission: "edit", pattern: "*", action: "allow" }],
    })
    expect(outcome.manual).toBe(false)
    expect(outcome.security?.decision).toBe("pass")
    expect(outcome.security?.final_enforcement).toBe("allow")
    expect(outcome.security?.sessionID).toBe(sessionID)
  }),
)

it.instance("raises an auto-approved CI workflow edit to a pending human ask", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const permission = yield* Permission.Service
    const fiber = yield* ask({
      sessionID,
      permission: "edit",
      patterns: [".github/workflows/ci.yml"],
      always: ["*"],
      metadata: { filepath: ".github/workflows/ci.yml" },
      ruleset: [{ permission: "edit", pattern: "*", action: "allow" }],
    }).pipe(Effect.forkScoped)
    const pending = yield* Effect.gen(function* () {
      while (true) {
        const list = yield* permission.list()
        if (list.length === 1) return list
        yield* Effect.sleep("10 millis")
      }
    }).pipe(Effect.timeoutOrElse({ duration: "2 seconds", orElse: () => Effect.fail(new Error("timed out")) }))
    yield* permission.reply({ requestID: pending[0]!.id, reply: "once" })
    const outcome = yield* Fiber.join(fiber)
    expect(outcome.manual).toBe(true)
    expect(outcome.security?.rule_id).toBe("SEC.V1.CI_AUTHORITY")
    expect(outcome.security?.final_enforcement).toBe("allow")
  }),
)

it.instance("records the live containment facts the caller supplied", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const outcome = yield* ask({
      sessionID,
      permission: "edit",
      patterns: ["src/a.ts"],
      always: ["*"],
      metadata: { filepath: "src/a.ts" },
      ruleset: [{ permission: "edit", pattern: "*", action: "allow" }],
      containment: { sandbox: "off", network: "deny", destinations: ["models.dev:443"], escalated: false },
    })
    expect(outcome.security?.containment).toEqual({
      sandbox: "off",
      network: "deny",
      destinations: ["models.dev:443"],
      escalated: false,
    })
  }),
)

it.instance("does not leak the containment facts into the pending request payload", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const permission = yield* Permission.Service
    const fiber = yield* ask({
      sessionID,
      permission: "edit",
      patterns: [".github/workflows/ci.yml"],
      always: ["*"],
      metadata: { filepath: ".github/workflows/ci.yml" },
      ruleset: [{ permission: "edit", pattern: "*", action: "allow" }],
      containment: { sandbox: "off", network: "deny", destinations: [], escalated: false },
    }).pipe(Effect.forkScoped)
    const pending = yield* Effect.gen(function* () {
      while (true) {
        const list = yield* permission.list()
        if (list.length === 1) return list
        yield* Effect.sleep("10 millis")
      }
    }).pipe(Effect.timeoutOrElse({ duration: "2 seconds", orElse: () => Effect.fail(new Error("timed out")) }))
    expect(JSON.stringify(pending[0])).not.toContain("containment")
    yield* permission.reply({ requestID: pending[0]!.id, reply: "once" })
    yield* Fiber.join(fiber)
  }),
)

it.instance("writes the initial audit record before the ask is published, so a reject is still audited", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const permission = yield* Permission.Service
    const records: Array<{ final_enforcement?: string; rule_id: string }> = []
    const fiber = yield* ask({
      sessionID,
      permission: "edit",
      patterns: [".github/workflows/ci.yml"],
      always: ["*"],
      metadata: { filepath: ".github/workflows/ci.yml" },
      ruleset: [{ permission: "edit", pattern: "*", action: "allow" }],
      audit: (record) => Effect.sync(() => void records.push(record)),
    }).pipe(Effect.forkScoped)
    const pending = yield* Effect.gen(function* () {
      while (true) {
        const list = yield* permission.list()
        if (list.length === 1) return list
        yield* Effect.sleep("10 millis")
      }
    }).pipe(Effect.timeoutOrElse({ duration: "2 seconds", orElse: () => Effect.fail(new Error("timed out")) }))
    expect(records).toHaveLength(1)
    expect(records[0]).toMatchObject({ rule_id: "SEC.V1.CI_AUTHORITY", final_enforcement: "ask_pending" })
    yield* permission.reply({ requestID: pending[0]!.id, reply: "reject" })
    const exit = yield* Fiber.await(fiber)
    expect(Exit.isFailure(exit)).toBe(true)
  }),
)
