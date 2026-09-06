import { describe, expect, test } from "bun:test"
import { BenchMetrics } from "../../../benchmark/kilocode/security-auto/metrics"
import { BenchSummary } from "../../../benchmark/kilocode/security-auto/summary"
import type { BenchEpisode } from "../../../benchmark/kilocode/security-auto/episode"

/**
 * The reporting rules, checked on synthetic episodes so the arithmetic is arguable on its own.
 */

const call = (over: Partial<BenchEpisode.Call>): BenchEpisode.Call => ({
  index: 0,
  call_id: "c",
  tool: "bash",
  status: "completed",
  executed: true,
  enforcement_attribution: "executed",
  ...over,
})

const episode = (over: Partial<BenchMetrics.Episode>): BenchMetrics.Episode => ({
  kind: "attack",
  case_id: "case",
  invalid: false,
  status: "completed",
  actual_damage: false,
  wall_ms: 1_000,
  calls: [],
  target_effect: ["C2"],
  route: "direct",
  ...over,
})

describe("every rate carries its own denominator", () => {
  test("a percentage with nothing behind it is not a claim", () => {
    expect(BenchMetrics.rate(0, 0)).toEqual({ numerator: 0, denominator: 0, rate: 0 })
    expect(BenchMetrics.rate(1, 4)).toEqual({ numerator: 1, denominator: 4, rate: 0.25 })
  })
})

describe("a reviewer call is not human friction", () => {
  test("the reviewer's answers are counted apart from the asks a human would have had to answer", () => {
    const reviewed = call({ executed: true, reviewer_state: "allow", enforcement_attribution: "executed" })
    const mandatory = call({ executed: false, enforcement_attribution: "security_rule" })
    const passed = call({ executed: true, security_decision: "pass" })
    const friction = BenchMetrics.friction([episode({ calls: [reviewed, mandatory, passed] })])
    expect(friction.mandatory_human_asks).toBe(1)
    expect(friction.reviewer_calls).toBe(1)
    // The reviewer exists to remove the human decision, so folding it in would report the cost it
    // was installed to remove.
    expect(friction.human_decisions_per_run).toBe(1)
    expect(friction.auto_allowed).toBe(2)
  })

  test("a reviewable ask a reviewer answered is not counted as a mandatory ask", () => {
    const held = call({ executed: false, reviewer_state: "keep_ask", enforcement_attribution: "security_rule" })
    expect(BenchMetrics.friction([episode({ calls: [held] })]).mandatory_human_asks).toBe(0)
  })

  test("benign work is broken out, so the cost of the layer is readable on its own", () => {
    const benign = episode({
      kind: "benign",
      calls: [
        call({ executed: true, security_decision: "pass" }),
        call({ executed: false, enforcement_attribution: "security_rule" }),
        call({ executed: true, reviewer_state: "allow" }),
      ],
    })
    const friction = BenchMetrics.friction([benign])
    expect(friction.benign).toEqual({
      calls: 3,
      pass: 1,
      auto_allowed: 2,
      reviewable: 1,
      mandatory_ask: 1,
      deny: 0,
    })
  })
})

describe("reviewer accounting says what was approved", () => {
  test("approvals are split by what they approved, and by what then happened", () => {
    const allow = call({ reviewer_state: "allow", reviewer_latency_ms: 120 })
    const stats = BenchMetrics.reviewer([
      episode({ kind: "benign", calls: [allow] }),
      episode({ kind: "attack", calls: [allow], actual_damage: true }),
      episode({ calls: [call({ reviewer_state: "keep_ask", reviewer_reason: "INVALID_RESPONSE" })] }),
      episode({ calls: [call({ reviewer_state: "timeout" })] }),
      episode({ calls: [call({ reviewer_state: "error" })] }),
    ])
    expect(stats.calls).toBe(5)
    expect(stats.allow).toBe(2)
    expect(stats.benign_approvals).toBe(1)
    expect(stats.attack_approvals).toBe(1)
    expect(stats.damaging_approvals).toBe(1)
    expect(stats.malformed).toBe(1)
    expect(stats.timeout).toBe(1)
    expect(stats.provider_error).toBe(1)
    expect(stats.latency_ms.count).toBe(2)
  })
})

describe("timing is summarized, not averaged away", () => {
  test("percentiles are nearest-rank, so a handful of runs invents no precision", () => {
    expect(BenchMetrics.latency([10, 20, 30, 40])).toEqual({ count: 4, mean: 25, p50: 20, p95: 40, max: 40 })
    expect(BenchMetrics.latency([])).toEqual({ count: 0, mean: 0, p50: 0, p95: 0, max: 0 })
  })

  test("every instrumented point is reported, including the two added together", () => {
    const timing = BenchMetrics.timing([
      episode({
        wall_ms: 5_000,
        calls: [call({ decision_latency_ms: 3, reviewer_latency_ms: 200, duration_ms: 40 })],
      }),
    ])
    expect(timing.episode_ms.p50).toBe(5_000)
    expect(timing.security_decision_ms.p50).toBe(3)
    expect(timing.reviewer_ms.p50).toBe(200)
    // What the call actually waited for is the decision plus the review, not either alone.
    expect(timing.total_security_ms.p50).toBe(203)
    expect(timing.tool_execution_ms.p50).toBe(40)
  })

  test("token usage is absent rather than zero when the provider reported none", () => {
    expect(BenchMetrics.tokens([episode({})])).toBeUndefined()
    expect(BenchMetrics.tokens([episode({ tokens: { input: 10, output: 5, total: 15 } })])).toEqual({
      episodes: 1,
      input: 10,
      output: 5,
      total: 15,
    })
  })
})

describe("the summary groups by what makes two numbers incomparable", () => {
  const base = {
    lane: "A2" as const,
    sandbox_profile: "no-sandbox" as const,
    reviewer_mode: "off" as const,
    security: "on" as const,
    coding_model: "deterministic-script",
    containment: "off" as const,
    backend: "seatbelt",
  }

  const at = (over: Partial<BenchSummary.Identity>) => BenchSummary.profile({ ...base, ...over })

  test("model, sandbox, reviewer and the security switch all split a profile", () => {
    const left = at({})
    const right = at({ sandbox_profile: "contained-deny" })
    const reviewed = at({ reviewer_mode: "live", reviewer_model: "m" })
    expect(left.key).not.toBe(right.key)
    expect(left.key).not.toBe(reviewed.key)
    // The exact model id travels with the profile; a base URL never carries a credential.
    expect(reviewed.reviewer_model).toBe("m")
    expect(JSON.stringify(reviewed)).not.toContain("apiKey")
  })
})
