import { expect, afterEach } from "bun:test"
import { Cause, Effect, Exit, Fiber, Layer } from "effect"
import * as CrossSpawnSpawner from "@opencode-ai/core/cross-spawn-spawner"
import { AppNodeBuilder } from "@opencode-ai/core/effect/app-node-builder"
import { Permission } from "@/permission"
import * as Config from "@/config/config"
import { SessionID } from "@/session/schema"
import { SecurityBlocked } from "@/kilocode/security-decision/block"
import { SecurityAsk } from "@/kilocode/security-decision/ask"
import type { SecurityDecisionAdapter } from "@/kilocode/security-decision/adapter"
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
    // kilocode_change - a security-raised ask needs a human reply; a machine "once" is refused
    yield* permission.reply({ requestID: pending[0]!.id, reply: "once", interactive: true })
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
    yield* permission.reply({ requestID: pending[0]!.id, reply: "once", interactive: true }) // kilocode_change
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

// kilocode_change start - enforcement semantics: a security deny/reject stops the call, not the turn

const ciEdit = {
  sessionID,
  permission: "edit",
  patterns: [".github/workflows/ci.yml"],
  always: ["*"],
  metadata: { filepath: ".github/workflows/ci.yml" },
  ruleset: [{ permission: "edit", pattern: "*", action: "allow" as const }],
}

const ordinaryAsk = {
  sessionID,
  permission: "edit",
  patterns: ["src/a.ts"],
  always: ["*"],
  metadata: { filepath: "src/a.ts" },
  ruleset: [{ permission: "edit", pattern: "*", action: "ask" as const }],
}

const published = (permission: Permission.Interface) =>
  Effect.gen(function* () {
    while (true) {
      const list = yield* permission.list()
      if (list.length === 1) return list[0]!
      yield* Effect.sleep("10 millis")
    }
  }).pipe(Effect.timeoutOrElse({ duration: "2 seconds", orElse: () => Effect.fail(new Error("timed out")) }))

/** Stands in for the tool body: it only runs when the permission effect succeeds. */
const guarded = <A, E, R>(self: Effect.Effect<A, E, R>, counter: { runs: number }) =>
  self.pipe(Effect.tap(() => Effect.sync(() => void counter.runs++)))

it.instance("a security deny leaves no side effect and reports the rule id", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const counter = { runs: 0 }
    const records: SecurityDecisionAdapter.Audit[] = []
    const error = yield* fail(
      guarded(
        ask({
          ...editHook,
          ruleset: [{ permission: "edit", pattern: "*", action: "allow" }],
          audit: (record) => Effect.sync(() => void records.push(record)),
        }),
        counter,
      ),
    )
    expect(counter.runs).toBe(0)
    expect(error).toBeInstanceOf(SecurityBlocked.Error)
    expect((error as SecurityBlocked.Error).rule_id).toBe("SEC.V1.GIT_HOOK_WRITE")
    expect((error as SecurityBlocked.Error).audit.final_enforcement).toBe("deny")
    expect(records.at(-1)?.final_enforcement).toBe("deny")
  }),
)

it.instance("a different tool call still runs after a security deny", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const counter = { runs: 0 }
    yield* fail(
      guarded(ask({ ...editHook, ruleset: [{ permission: "edit", pattern: "*", action: "allow" }] }), counter),
    )
    const outcome = yield* guarded(
      ask({
        sessionID,
        permission: "edit",
        patterns: ["src/a.ts"],
        always: ["*"],
        metadata: { filepath: "src/a.ts" },
        ruleset: [{ permission: "edit", pattern: "*", action: "allow" }],
      }),
      counter,
    )
    expect(counter.runs).toBe(1)
    expect(outcome.manual).toBe(false)
  }),
)

it.instance("marks a security-raised ask with the typed provenance marker", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const permission = yield* Permission.Service
    const fiber = yield* ask(ciEdit).pipe(Effect.forkScoped)
    const request = yield* published(permission)
    expect(SecurityAsk.is(request.metadata)).toBe(true)
    expect(SecurityAsk.of(request.metadata)?.rule_id).toBe("SEC.V1.CI_AUTHORITY")
    yield* permission.reply({ requestID: request.id, reply: "reject", interactive: true })
    yield* Fiber.await(fiber)
  }),
)

it.instance("leaves an ordinary ask unmarked", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const permission = yield* Permission.Service
    const fiber = yield* ask(ordinaryAsk).pipe(Effect.forkScoped)
    const request = yield* published(permission)
    expect(SecurityAsk.is(request.metadata)).toBe(false)
    yield* permission.reply({ requestID: request.id, reply: "reject", interactive: true })
    yield* Fiber.await(fiber)
  }),
)

it.instance("a rejected security ask blocks the call and audits the reject", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const permission = yield* Permission.Service
    const counter = { runs: 0 }
    const records: SecurityDecisionAdapter.Audit[] = []
    const fiber = yield* guarded(
      ask({ ...ciEdit, audit: (record) => Effect.sync(() => void records.push(record)) }),
      counter,
    ).pipe(Effect.forkScoped)
    const request = yield* published(permission)
    yield* permission.reply({ requestID: request.id, reply: "reject", interactive: true })
    const exit = yield* Fiber.await(fiber)
    expect(Exit.isFailure(exit)).toBe(true)
    const error = Cause.squash((exit as Exit.Failure<never, unknown>).cause)
    expect(error).toBeInstanceOf(SecurityBlocked.Error)
    expect((error as SecurityBlocked.Error).audit.final_enforcement).toBe("reject")
    expect(counter.runs).toBe(0)
    expect(records.at(-1)?.final_enforcement).toBe("reject")
  }),
)

it.instance("an approved security ask runs the call exactly once", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const permission = yield* Permission.Service
    const counter = { runs: 0 }
    const fiber = yield* guarded(ask(ciEdit), counter).pipe(Effect.forkScoped)
    const request = yield* published(permission)
    yield* permission.reply({ requestID: request.id, reply: "once", interactive: true })
    const outcome = yield* Fiber.join(fiber)
    expect(outcome.manual).toBe(true)
    expect(outcome.security?.final_enforcement).toBe("allow")
    expect(counter.runs).toBe(1)
  }),
)

it.instance("a machine reply cannot auto-approve a security ask, and its block is audited", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const permission = yield* Permission.Service
    const counter = { runs: 0 }
    const fiber = yield* guarded(ask(ciEdit), counter).pipe(Effect.forkScoped)
    const request = yield* published(permission)
    yield* permission.reply({ requestID: request.id, reply: "once" })
    expect(yield* permission.list()).toHaveLength(1)
    expect(counter.runs).toBe(0)
    yield* permission.reply({ requestID: request.id, reply: "reject" })
    const exit = yield* Fiber.await(fiber)
    const error = Cause.squash((exit as Exit.Failure<never, unknown>).cause)
    expect(error).toBeInstanceOf(SecurityBlocked.Error)
    expect((error as SecurityBlocked.Error).audit.final_enforcement).toBe("blocked")
    expect(counter.runs).toBe(0)
  }),
)

it.instance("an ordinary ask keeps its auto-approval and its rejection semantics", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const permission = yield* Permission.Service
    const approved = yield* ask(ordinaryAsk).pipe(Effect.forkScoped)
    const first = yield* published(permission)
    yield* permission.reply({ requestID: first.id, reply: "once" })
    expect((yield* Fiber.join(approved)).manual).toBe(true)

    const rejected = yield* ask({ ...ordinaryAsk, patterns: ["src/b.ts"] }).pipe(Effect.forkScoped)
    const second = yield* published(permission)
    yield* permission.reply({ requestID: second.id, reply: "reject", interactive: true })
    const exit = yield* Fiber.await(rejected)
    expect(Cause.squash((exit as Exit.Failure<never, unknown>).cause)).toBeInstanceOf(Permission.RejectedError)
  }),
)
it.instance("auto-approve mode cannot resolve a pending security ask", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const permission = yield* Permission.Service
    const counter = { runs: 0 }
    const fiber = yield* guarded(ask(ciEdit), counter).pipe(Effect.forkScoped)
    const request = yield* published(permission)
    yield* permission.allowEverything({ enable: true, sessionID, requestID: request.id })
    expect(yield* permission.list()).toHaveLength(1)
    expect(counter.runs).toBe(0)
    yield* permission.reply({ requestID: request.id, reply: "reject", interactive: true })
    yield* Fiber.await(fiber)
  }),
)

it.instance("an always-rule from a sibling ask cannot drain a pending security ask", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const permission = yield* Permission.Service
    const counter = { runs: 0 }
    const secured = yield* guarded(ask(ciEdit), counter).pipe(Effect.forkScoped)
    const first = yield* published(permission)
    const sibling = yield* ask(ordinaryAsk).pipe(Effect.forkScoped)
    const both = yield* Effect.gen(function* () {
      while (true) {
        const list = yield* permission.list()
        if (list.length === 2) return list
        yield* Effect.sleep("10 millis")
      }
    }).pipe(Effect.timeoutOrElse({ duration: "2 seconds", orElse: () => Effect.fail(new Error("timed out")) }))
    const second = both.find((item) => item.id !== first.id)!
    yield* permission.reply({ requestID: second.id, reply: "always", interactive: true })
    yield* Fiber.join(sibling)
    expect(yield* permission.list()).toHaveLength(1)
    expect(counter.runs).toBe(0)
    yield* permission.reply({ requestID: first.id, reply: "reject", interactive: true })
    yield* Fiber.await(secured)
  }),
)
// A baseline ask the security core independently also raises is still a security decision: the
// marker is provenance, not "who raised the prompt", so no automated client may approve it.
it.instance("marks a security ask that a baseline ask already required", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const permission = yield* Permission.Service
    const counter = { runs: 0 }
    const fiber = yield* guarded(
      ask({ ...ciEdit, ruleset: [{ permission: "edit", pattern: "*", action: "ask" }] }),
      counter,
    ).pipe(Effect.forkScoped)
    const request = yield* published(permission)
    expect(SecurityAsk.of(request.metadata)?.rule_id).toBe("SEC.V1.CI_AUTHORITY")
    expect(SecurityAsk.autoDecision({ interactive: false, metadata: request.metadata })).toBe("block")
    yield* permission.reply({ requestID: request.id, reply: "once" })
    expect(yield* permission.list()).toHaveLength(1)
    expect(counter.runs).toBe(0)
    yield* permission.reply({ requestID: request.id, reply: "reject", interactive: true })
    const exit = yield* Fiber.await(fiber)
    expect(Exit.isFailure(exit)).toBe(true)
    expect(counter.runs).toBe(0)
  }),
)

it.instance("keeps ordinary reject semantics for a security ask a baseline ask already required", () =>
  Effect.gen(function* () {
    process.env["KILO_SECURITY_DECISION"] = "1"
    const permission = yield* Permission.Service
    const fiber = yield* ask({ ...ciEdit, ruleset: [{ permission: "edit", pattern: "*", action: "ask" }] }).pipe(
      Effect.forkScoped,
    )
    const request = yield* published(permission)
    yield* permission.reply({ requestID: request.id, reply: "reject", interactive: true })
    const exit = yield* Fiber.await(fiber)
    expect(Cause.squash((exit as Exit.Failure<never, unknown>).cause)).toBeInstanceOf(Permission.RejectedError)
  }),
)
// kilocode_change end
