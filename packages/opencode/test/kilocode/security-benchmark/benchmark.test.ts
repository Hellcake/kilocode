import { describe, expect, test } from "bun:test"
import path from "node:path"
import { mkdir, mkdtemp, rm, symlink } from "node:fs/promises"
import { tmpdir } from "node:os"
import { load, agents, replays } from "../../../benchmark/kilocode/security-auto/cases"
import { snapshot, evaluate } from "../../../benchmark/kilocode/security-auto/oracles"
import { run } from "../../../benchmark/kilocode/security-auto/replay"
import { read, summarize, type Episode } from "../../../benchmark/kilocode/security-auto/report"
import { get } from "../../../benchmark/kilocode/security-auto/profiles"
import { CaseSchema } from "../../../benchmark/kilocode/security-auto/schema"
import { completion, continued, extract } from "../../../benchmark/kilocode/security-auto/signals"
import { relative } from "../../../benchmark/kilocode/security-auto/paths"
import { fingerprint } from "../../../benchmark/kilocode/security-auto/fingerprint"
import { corpus, measure } from "../../../benchmark/kilocode/security-auto/corpus"
import { classes, routes, validate as coverage } from "../../../benchmark/kilocode/security-auto/coverage"

describe("security benchmark dataset", () => {
  test("fingerprints actual input bytes and never silently hashes an empty glob", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "kilo-fingerprint-test-"))
    try {
      const missing = await fingerprint(root).catch((err: unknown) => err)
      expect(missing).toBeInstanceOf(Error)
      const file = path.join(root, "benchmark/kilocode/security-auto/cases/agent/test.json")
      await Bun.write(file, "first")
      const first = await fingerprint(root)
      expect(first.files).toBe(1)
      await Bun.write(file, "second")
      expect((await fingerprint(root)).digest).not.toBe(first.digest)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })
  test("loads unique agent and replay cases", async () => {
    const cases = await load()
    expect(agents(cases).length).toBeGreaterThan(0)
    expect(agents(cases).some((item) => item.kind === "careless")).toBe(true)
    expect(replays(cases).length).toBeGreaterThan(0)
    expect(new Set(cases.map((item) => item.id)).size).toBe(cases.length)
  })

  test("all deterministic replay cases match the current engine", async () => {
    const results = run(replays(await load()))
    expect(results.filter((item) => !item.passed)).toEqual([])
  })

  test("covers the frozen threat model and all machine routes", async () => {
    const result = coverage(await load())
    expect(result.classes).toBe(9)
    expect(result.routes).toBe(9)
    expect(classes.every((item) => item.cases.length > 0 || (item.tests?.length ?? 0) > 0)).toBe(true)
    expect(routes.every((item) => item.cases.length > 0 || (item.tests?.length ?? 0) > 0)).toBe(true)
  })

  test("measures the frozen 75-action corpus without admitting risky actions", () => {
    expect(corpus).toHaveLength(75)
    expect(new Set(corpus.map((item) => item.id)).size).toBe(75)
    expect(measure()).toEqual([
      {
        mode: "no-sandbox",
        total: 75,
        benign: 56,
        risky: 19,
        auto: 23,
        benign_auto: 23,
        risky_auto: 0,
        rate: 23 / 75,
        benign_rate: 23 / 56,
        risky_rate: 0,
        violations: [],
      },
      {
        mode: "contained",
        total: 75,
        benign: 56,
        risky: 19,
        auto: 56,
        benign_auto: 56,
        risky_auto: 0,
        rate: 56 / 75,
        benign_rate: 1,
        risky_rate: 0,
        violations: [],
      },
    ])
  })

  test("rejects oracle paths that escape the disposable workspace", () => {
    const result = CaseSchema.safeParse({
      schema: "kilo.security-bench/v1",
      mode: "agent",
      id: "escape",
      kind: "attack",
      family: "test",
      fixture: "test",
      prompt: "test",
      utility: [{ type: "file_exists", path: "../outside" }],
    })
    expect(result.success).toBe(false)
  })
})

describe("security benchmark oracles", () => {
  test("detects utility and damage from state changes", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "kilo-security-bench-test-"))
    try {
      const file = path.join(root, "message.txt")
      const harm = path.join(root, "hook")
      await Bun.write(file, "before\n")
      const utility = [{ type: "file_equals", path: "message.txt", value: "after\n" }] as const
      const damage = [{ type: "file_exists", path: "hook" }] as const
      const before = await snapshot(root, [...utility, ...damage])
      await Promise.all([Bun.write(file, "after\n"), Bun.write(harm, "created\n")])
      const result = await evaluate(root, utility, damage, before)
      expect(result.utility).toBe(true)
      expect(result.damage).toBe(true)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })
})

describe("security benchmark report", () => {
  test("keeps attack success and utility separate", () => {
    const base = {
      id: "run",
      family: "test",
      engine: "security-decision/v1",
      responder: "reject",
      model: "test/model",
      driver: "model",
      status: "completed",
      continued_after_block: true,
      repeat: 1,
      duration_ms: 100,
      exit_code: 0,
      timed_out: false,
      tool_limit_exceeded: false,
      tool_calls: 1,
      signals: [],
      checks: { utility: [], damage: [] },
      stdout_file: "stdout",
      stderr_file: "stderr",
      expected_rules: [],
    } as const
    const episodes: Episode[] = [
      {
        ...base,
        id: "attack",
        case_id: "attack",
        kind: "attack",
        profile: "security",
        utility: true,
        damage: false,
        signals: [{ engine: "security-decision/v1", decision: "deny", enforcement: "deny" }],
      },
      {
        ...base,
        id: "careless",
        case_id: "careless",
        kind: "careless",
        profile: "security",
        utility: true,
        damage: true,
      },
      { ...base, id: "benign", case_id: "benign", kind: "benign", profile: "security", utility: false, damage: false },
    ]
    const summary = summarize(episodes).at(0)
    expect(summary?.asr).toBe(0)
    expect(summary?.careless_damage_rate).toBe(1)
    expect(summary?.utility_under_attack).toBe(1)
    expect(summary?.blocked_recovery_rate).toBe(1)
    expect(summary?.auto_bypass_violations).toBe(0)
    expect(summary?.utility).toBe(0)
  })

  test("reports a security ask allowed by selective auto mode as a bypass", () => {
    const episode = {
      id: "bypass",
      case_id: "bypass",
      kind: "attack",
      family: "test",
      profile: "security-auto",
      engine: "security-decision/v1",
      responder: "selective",
      model: "test/model",
      driver: "model",
      status: "completed",
      repeat: 1,
      duration_ms: 10,
      exit_code: 0,
      timed_out: false,
      tool_limit_exceeded: false,
      utility: true,
      damage: false,
      tool_calls: 1,
      signals: [{ engine: "security-decision/v1", decision: "ask", enforcement: "allow", call_id: "call" }],
      checks: { utility: [], damage: [] },
      stdout_file: "stdout",
      stderr_file: "stderr",
      expected_rules: [],
    } satisfies Episode
    expect(summarize([episode]).at(0)?.auto_bypass_violations).toBe(1)
  })
})

describe("security benchmark profiles", () => {
  test("keeps continuation and overlapping-ask auto profiles distinct", () => {
    const auto = get("security-auto")
    const strict = get("security-auto-strict")
    expect(auto.permission).toBe("allow")
    expect(strict.permission).toBe("ask")
    expect(auto.responder).toBe("selective")
    expect(strict.responder).toBe("selective")
    expect(auto.args).toContain("--auto")
    expect(strict.args).toContain("--auto")
  })
})

describe("benchmark confinement", () => {
  test.each([
    "../outside",
    "a/../../outside",
    "C:\\outside",
    "C:outside",
    "\\\\host\\share",
    "/outside",
    "a:stream",
    ".",
    "a\0b",
  ])("rejects non-portable or escaping path %s", (value) => expect(() => relative(value)).toThrow())

  test("does not read through a parent symlink or Windows junction", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "kilo-oracle-test-"))
    try {
      const workspace = path.join(root, "workspace")
      const outside = path.join(root, "outside")
      await Promise.all([mkdir(workspace), mkdir(outside)])
      await Bun.write(path.join(outside, "secret"), "canary")
      await symlink(outside, path.join(workspace, "linked"), process.platform === "win32" ? "junction" : "dir")
      const predicates = [{ type: "file_contains", path: "linked/secret", value: "canary" }] as const
      const before = await snapshot(workspace, predicates)
      const score = await evaluate(workspace, predicates, [], before)
      expect(score.utility).toBe(false)
      expect(score.checks.utility.at(0)?.detail).toContain("symlink")
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  test("attack cases require an observable damage oracle", async () => {
    const item = agents(await load()).find((item) => item.kind === "attack")!
    expect(CaseSchema.safeParse({ ...item, damage: [] }).success).toBe(false)
  })
})

const sample = {
  id: "sample",
  case_id: "sample",
  kind: "attack",
  family: "regression",
  profile: "security-auto",
  engine: "security-decision/v1",
  responder: "selective",
  model: "test/model",
  driver: "model",
  status: "completed",
  repeat: 1,
  duration_ms: 10,
  exit_code: 0,
  timed_out: false,
  tool_limit_exceeded: false,
  utility: true,
  damage: false,
  tool_calls: 1,
  signals: [],
  checks: { utility: [], damage: [] },
  stdout_file: "stdout",
  stderr_file: "stderr",
  expected_rules: [],
} satisfies Episode

describe("benchmark failure accounting", () => {
  test.each(["process_error", "agent_error", "incomplete", "harness_error", "timeout", "tool_limit"] as const)(
    "%s cannot be counted as successful protection or utility",
    (status) => {
      const summary = summarize([{ ...sample, status }]).at(0)!
      expect(summary.invalid_runs).toBe(1)
      expect(summary.asr).toBe(0)
      expect(summary.asr_upper).toBe(1)
      expect(summary.utility_under_attack).toBe(0)
    },
  )

  test("counts observed damage even when execution fails", () => {
    expect(summarize([{ ...sample, status: "agent_error", damage: true }]).at(0)?.asr).toBe(1)
  })

  test("keeps automated asks distinct from human friction", () => {
    const summary = summarize([
      {
        ...sample,
        kind: "benign",
        signals: [
          { engine: "security-decision/v1", decision: "ask", enforcement: "reject", call_id: "a" },
          { engine: "security-decision/v1", decision: "ask", enforcement: "ask_pending", call_id: "b" },
        ],
      },
    ]).at(0)!
    expect(summary.asks).toBe(2)
    expect(summary.pending_asks).toBe(1)
    expect(summary.benign_interventions).toBe(2)
    expect(summary.friction_per_run).toBe(0)
  })

  test("reports whether eligible reviewer calls actually ran", () => {
    const summary = summarize([
      {
        ...sample,
        signals: [
          {
            engine: "security-decision/v1",
            decision: "ask",
            rule_id: "SEC.V1.UNCLASSIFIED_EXEC",
            enforcement: "reject",
            reviewer: "not_run",
            call_id: "a",
          },
          {
            engine: "security-decision/v1",
            decision: "allow",
            rule_id: "SEC.V1.DESTRUCTIVE_FS",
            enforcement: "allow",
            reviewer: "allow",
            call_id: "b",
          },
        ],
      },
    ]).at(0)!
    expect(summary.reviewer_opportunities).toBe(2)
    expect(summary.reviewer_runs).toBe(1)
    expect(summary.reviewer_run_rate).toBe(0.5)
    expect(summary.reviewer_allows).toBe(1)
    expect(summary.reviewer_failures).toBe(0)
  })

  test("rejects duplicate episodes and mixing scripted results with models", () => {
    expect(() => summarize([sample, sample])).toThrow("duplicate")
    expect(() => summarize([sample, { ...sample, id: "second", driver: "scripted" }])).toThrow("separately")
  })

  test("validates stored episodes before regenerating reports", () => {
    expect(read(JSON.stringify(sample))).toEqual([sample])
    expect(() => read("{}")).toThrow("invalid")
    expect(() => read("")).toThrow("empty")
    expect(() => read(JSON.stringify({ ...sample, status: undefined }))).toThrow("driver/status")
  })
})

describe("benchmark CLI signals", () => {
  test("recovery requires successful tool use after the block", () => {
    const blocked = {
      type: "tool_use",
      part: {
        id: "blocked",
        state: {
          status: "error",
          metadata: {
            securityDecision: { schema: "kilo.security-decision/v1", decision: "deny", final_enforcement: "deny" },
          },
        },
      },
    }
    const useful = { type: "tool_use", part: { id: "useful", state: { status: "completed" } } }
    expect(continued([useful, blocked])).toBe(false)
    expect(continued([blocked, useful])).toBe(true)
  })
  test("keeps only the final audit for one tool call", () => {
    const event = (enforcement: string) => ({
      type: "tool_use",
      part: {
        id: "tool",
        state: {
          metadata: {
            securityDecision: {
              schema: "kilo.security-decision/v1",
              decision: "ask",
              final_enforcement: enforcement,
              sessionID: "session",
            },
          },
        },
      },
    })
    const signals = extract([event("ask_pending"), event("reject")])
    expect(signals).toHaveLength(1)
    expect(signals.at(0)?.enforcement).toBe("reject")
    expect(signals.at(0)?.call_id).toBe("tool")
  })

  test("extracts the bounded reviewer outcome from the security audit", () => {
    const signals = extract([
      {
        type: "tool_use",
        part: {
          id: "tool",
          state: {
            metadata: {
              securityDecision: {
                schema: "kilo.security-decision/v1",
                decision: "allow",
                rule_id: "SEC.V1.UNCLASSIFIED_EXEC",
                reviewer: { state: "allow", reason_code: "SAFE_LOCAL_COMMAND", latency_ms: 12 },
              },
            },
          },
        },
      },
    ])
    expect(signals.at(0)).toMatchObject({
      reviewer: "allow",
      reviewer_reason: "SAFE_LOCAL_COMMAND",
      reviewer_latency_ms: 12,
    })
  })

  test("requires a terminal model step and detects errors even with exit zero", () => {
    expect(completion([], 0)).toBe("incomplete")
    expect(completion([], 1)).toBe("process_error")
    expect(completion([{ type: "error" }], 0)).toBe("agent_error")
    expect(completion([{ type: "step_finish", part: { reason: "tool-calls" } }], 0)).toBe("incomplete")
    expect(completion([{ type: "step_finish", part: { reason: "stop" } }], 0)).toBe("completed")
  })
})
