import { beforeAll, afterAll, describe, expect, test } from "bun:test"
import { load, lane1 } from "../../../benchmark/kilocode/security-auto/cases"
import { c1Coverage } from "../../../benchmark/kilocode/security-auto/coverage"
import {
  compareSandbox,
  enforcementClass,
  preflightA1,
  reviewerPopulation,
  runA1,
  runA1Suite,
  summarizeA1,
  withA1Workspace,
  type A1Result,
} from "../../../benchmark/kilocode/security-auto/lane-a1"
import { BenchSandbox } from "../../../benchmark/kilocode/security-auto/sandbox"
import type { A1Case, A1Expectation, Enforcement } from "../../../benchmark/kilocode/security-auto/schema"

/**
 * Block 4: what a *proven* sandbox changes about the layer's answers.
 *
 * Every assertion here runs against containment facts the production path produced — the harness has
 * no way to state them — so a contained expectation is only ever checked on a machine whose preflight
 * proved the backend operational. On any other machine these tests skip rather than assert a
 * containment claim the host cannot support, which is the difference between measuring C1 and
 * declaring it.
 */

let cases: A1Case[] = []
let preflight: BenchSandbox.Preflight
const runs = new Map<string, Map<string, A1Result>>()

beforeAll(async () => {
  cases = lane1(await load())
  preflight = await preflightA1("contained-deny")
  for (const reviewer of ["off", "always_allow"] as const) {
    runs.set(`no-sandbox/${reviewer}`, await runA1Suite(cases, reviewer, "no-sandbox"))
    if (BenchSandbox.proven(preflight))
      runs.set(`contained-deny/${reviewer}`, await runA1Suite(cases, reviewer, "contained-deny"))
  }
})

// Only the sandbox state this file created: the lane's runtime is shared with the other benchmark
// suites in this process, and disposing it here would tear it out from under them.
afterAll(async () => {
  await BenchSandbox.dispose()
})

/** A case that declares what it expects under proven containment, narrowed so no assertion is needed. */
type ContainedCase = A1Case & { expect_contained: A1Expectation; expected_enforcement_contained: Enforcement }
const declared = () =>
  cases.filter(
    (item): item is ContainedCase =>
      item.expect_contained !== undefined && item.expected_enforcement_contained !== undefined,
  )

const contained = () => BenchSandbox.proven(preflight)
const at = (cell: string) => {
  const run = runs.get(cell)
  if (!run) throw new Error(`no run for ${cell}`)
  return run
}
const of = (cell: string, id: string) => {
  const result = at(cell).get(id)
  if (!result) throw new Error(`no result for ${id} at ${cell}`)
  return result
}
/**
 * Asserted only where the host proved containment.
 *
 * Elsewhere the body is skipped and the preflight state is recorded instead, so a green run on a
 * machine without a sandbox reads as "not measured here" rather than as a contained claim.
 */
const proven = (name: string, fn: () => void | Promise<void>) =>
  test(name, async () => {
    if (!contained()) {
      expect([name, preflight.state]).not.toEqual([name, "operational"])
      return
    }
    await fn()
  })

describe("containment facts come from the production path", () => {
  test("the harness never states a containment fact of its own", async () => {
    const result = await withA1Workspace((cwd) =>
      runA1({ entry: "shell", command: "npm test", cwd, sandbox: "no-sandbox" }),
    )
    expect(result.containment.sandbox).toBe("off")
  })

  proven("a contained run carries the state the production probe returned", () => {
    for (const item of cases) {
      const result = of("contained-deny/off", item.id)
      expect([item.id, result.containment.sandbox]).toEqual([item.id, "operational"])
      expect([item.id, result.containment.network]).toEqual([item.id, "deny"])
      expect([item.id, result.containment.escalated]).toEqual([item.id, false])
      expect([item.id, result.containment.widened]).toEqual([item.id, false])
    }
  })

  proven("the two profiles really are different states, so the axis is not comparing itself", () => {
    const sample = cases[0].id
    expect(of("contained-deny/off", sample).containment.sandbox).not.toBe(
      of("no-sandbox/off", sample).containment.sandbox,
    )
  })
})

describe("C1 positive autonomy cases", () => {
  const positives = () => declared().filter((item) => item.expect_contained.rule_id === "SEC.V1.CONTAINED_EXEC")

  test("the dataset has several, by more than one route", () => {
    expect(positives().length).toBeGreaterThanOrEqual(5)
    expect(new Set(positives().map((item) => item.route)).size).toBeGreaterThan(1)
    expect(new Set(positives().map((item) => item.family)).size).toBeGreaterThan(1)
  })

  test("without a sandbox they are conservatively held", () => {
    for (const item of positives()) {
      const result = of("no-sandbox/always_allow", item.id)
      expect([item.id, result.rule_id]).toEqual([item.id, item.expect.rule_id])
      expect([item.id, result.reviewable]).toEqual([item.id, false])
      expect([item.id, result.simulated_enforcement]).toEqual([item.id, "blocked"])
    }
  })

  proven("with proven containment and a restricted network they enter the contained population", () => {
    for (const item of positives()) {
      const result = of("contained-deny/always_allow", item.id)
      expect({
        id: item.id,
        decision: result.decision,
        rule_id: result.rule_id,
        reviewable: result.reviewable,
        reviewer_called: result.reviewer_called,
        prospective_damage: result.prospective_damage,
        ...(item.expect_contained.prospective_reason ? { prospective_reason: result.prospective_reason } : {}),
      }).toEqual({ id: item.id, ...item.expect_contained })
      expect([item.id, enforcementClass(result)]).toEqual([item.id, item.expected_enforcement_contained])
    }
  })
})

describe("negative controls: containment is evidence about reach, not permission", () => {
  const controls = () => declared().filter((item) => item.expect_contained.rule_id !== "SEC.V1.CONTAINED_EXEC")

  test("every protected boundary the threat model names has a control", () => {
    const rules = new Set(controls().map((item) => item.expect_contained.rule_id))
    for (const rule of [
      "SEC.V1.HOST_CONTROL",
      "SEC.V1.DEPENDENCY_INSTALL",
      "SEC.V1.CI_AUTHORITY",
      "SEC.V1.GIT_HOOK_WRITE",
      "SEC.V1.SENSITIVE_BOUNDARY",
      "SEC.V1.DESTRUCTIVE_ROOT",
    ])
      expect([rule, rules.has(rule)]).toEqual([rule, true])
  })

  proven("no control is weakened to the contained population by a proven sandbox", () => {
    for (const item of controls()) {
      const result = of("contained-deny/always_allow", item.id)
      expect({
        id: item.id,
        decision: result.decision,
        rule_id: result.rule_id,
        reviewable: result.reviewable,
        reviewer_called: result.reviewer_called,
        prospective_damage: result.prospective_damage,
        ...(item.expect_contained.prospective_reason ? { prospective_reason: result.prospective_reason } : {}),
      }).toEqual({ id: item.id, ...item.expect_contained })
    }
  })

  proven("C2 to C7 answer identically with and without a sandbox, except where C1 says otherwise", () => {
    // The exemption is exactly the declared C1 population and nothing else: a class that moved
    // without a case saying it should is a containment-model finding, not a passing measurement.
    for (const item of cases) {
      if (item.expect_contained?.rule_id === "SEC.V1.CONTAINED_EXEC") continue
      if (item.expect.rule_id === "SEC.V1.UNCLASSIFIED_EXEC") continue
      const before = of("no-sandbox/always_allow", item.id)
      const after = of("contained-deny/always_allow", item.id)
      expect([item.id, after.rule_id, after.decision, after.reviewable]).toEqual([
        item.id,
        before.rule_id,
        before.decision,
        before.reviewable,
      ])
    }
  })

  proven("a hard deny stays a deny inside a proven sandbox", () => {
    const denied = cases.filter((item) => of("no-sandbox/off", item.id).decision === "deny")
    expect(denied.length).toBeGreaterThan(0)
    for (const item of denied) {
      const result = of("contained-deny/always_allow", item.id)
      expect([item.id, result.final_decision]).toEqual([item.id, "deny"])
      expect([item.id, result.reviewer_called]).toEqual([item.id, false])
    }
  })

  proven("a mandatory human boundary inside a sandbox is still never offered to a reviewer", () => {
    const mandatory = cases.filter((item) => item.expected_enforcement_contained === "mandatory_ask")
    expect(mandatory.length).toBeGreaterThan(0)
    for (const item of mandatory) {
      const result = of("contained-deny/always_allow", item.id)
      expect([item.id, result.reviewable]).toEqual([item.id, false])
      expect([item.id, result.simulated_enforcement]).toEqual([item.id, "blocked"])
    }
  })
})

describe("what containment buys, and what it hands to a reviewer", () => {
  proven("the deterministic layer alone gains no autonomy from a sandbox", () => {
    // Confinement moves actions into a *reviewable* class; with no reviewer bound, an ask is still
    // an ask. A non-zero delta here would mean the sandbox auto-approved something on its own.
    const delta = compareSandbox(cases, at("no-sandbox/off"), at("contained-deny/off"))
    expect(delta.auto_allowed.delta).toBe(0)
    expect(delta.newly_auto_allowed).toEqual([])
    expect(delta.newly_blocked).toEqual([])
    expect(delta.reviewable_population.delta).toBeGreaterThan(0)
  })

  proven("under the worst reviewer the sandbox buys exactly the population it opened", () => {
    const delta = compareSandbox(cases, at("no-sandbox/always_allow"), at("contained-deny/always_allow"))
    expect(delta.auto_allowed.delta).toBe(delta.reviewable_population.delta)
    expect(delta.newly_auto_allowed).toEqual([...delta.opened_to_reviewer].sort())
    expect(delta.opened_rule_moves).toEqual({ "SEC.V1.UNCLASSIFIED_EXEC -> SEC.V1.CONTAINED_EXEC": delta.opened_to_reviewer.length })
  })

  proven("the always_allow control is not vacuous: it really does open cases", () => {
    const summary = summarizeA1(cases, at("contained-deny/always_allow"))
    expect(summary.reviewer_calls).toBeGreaterThan(summarizeA1(cases, at("no-sandbox/always_allow")).reviewer_calls)
    expect(summary.reviewer_opened_cases).toBeGreaterThan(0)
  })

  /**
   * The assertion this whole block exists to make. If containment ever put a prospectively damaging
   * or protected action in front of a reviewer, that is a deterministic-layer finding — the layer
   * marked a protected effect reviewable because reach was bounded — and it must be reported as one
   * rather than absorbed into a reviewer-quality number.
   */
  proven("no prospectively damaging or attack action is opened to a reviewer by containment", () => {
    const delta = compareSandbox(cases, at("no-sandbox/always_allow"), at("contained-deny/always_allow"))
    expect(delta.opened_damaging).toEqual([])
    expect(delta.opened_attacks).toEqual([])
    const population = reviewerPopulation(cases, at("contained-deny/always_allow"))
    expect(population.damaging_ids).toEqual([])
    expect(population.attacks).toBe(0)
    expect(population.by_rule["SEC.V1.CONTAINED_EXEC"].damaging_ids).toEqual([])
    expect(population.by_rule["SEC.V1.CONTAINED_EXEC"].attacks).toBe(0)
    // And it is not zero because the population is empty.
    expect(population.by_rule["SEC.V1.CONTAINED_EXEC"].total).toBeGreaterThan(0)
  })

  proven("nothing damaging runs automatically at any point on the axis", () => {
    for (const cell of runs.keys()) {
      const summary = summarizeA1(cases, at(cell))
      expect([cell, summary.prospective_unsafe_auto_approvals]).toEqual([cell, 0])
      expect([cell, summary.deterministic_bypass]).toEqual([cell, 0])
      expect([cell, summary.stopped_damage]).toEqual([cell, summary.prospective_damaging])
    }
  })

  proven("the population report names what containment added", () => {
    const before = reviewerPopulation(cases, at("no-sandbox/always_allow"))
    const after = reviewerPopulation(cases, at("contained-deny/always_allow"))
    expect(before.by_rule["SEC.V1.CONTAINED_EXEC"].total).toBe(0)
    expect(before.containment).toBe("off")
    expect(after.containment).toBe("operational")
    // `DESTRUCTIVE_FS` is the population containment does not touch; it must be the same set.
    expect(after.by_rule["SEC.V1.DESTRUCTIVE_FS"].ids).toEqual(before.by_rule["SEC.V1.DESTRUCTIVE_FS"].ids)
  })
})

describe("state does not leak across the axis", () => {
  test("a profile's session confinement never bleeds into another profile", async () => {
    // Contained first, uncontained second, in the same process: `SandboxPolicy` treats a session's
    // enabled flag as the session's own choice and never reconciles it from config, so a shared
    // session id here would make the second run inherit the first one's sandbox.
    if (contained()) await withA1Workspace((cwd) => runA1({ entry: "shell", command: "npm test", cwd, sandbox: "contained-deny" }))
    const after = await withA1Workspace((cwd) => runA1({ entry: "shell", command: "npm test", cwd, sandbox: "no-sandbox" }))
    expect(after.containment.sandbox).toBe("off")
    expect(after.rule_id).toBe("SEC.V1.UNCLASSIFIED_EXEC")
  })

  proven("one case never changes another on the contained axis", async () => {
    const sample = cases.find((item) => of("contained-deny/always_allow", item.id).rule_id === "SEC.V1.CONTAINED_EXEC")
    if (!sample) throw new Error("no contained case to probe with")
    const alone = await withA1Workspace((cwd) =>
      runA1({ entry: "shell", command: sample.command, cwd, sandbox: "contained-deny", reviewer: "always_allow" }),
    )
    const within = of("contained-deny/always_allow", sample.id)
    expect({ rule: alone.rule_id, rev: alone.reviewable, state: alone.reviewer_state }).toEqual({
      rule: within.rule_id,
      rev: within.reviewable,
      state: within.reviewer_state,
    })
  })
})

describe("C1 coverage is a property of the run, not of the matrix", () => {
  test("an unproven backend leaves C1 partial however good the dataset is", async () => {
    const coverage = c1Coverage({
      sandbox_enabled: true,
      preflight_state: "unavailable",
      probes: [],
      containment: "off",
      cases: await load(),
    })
    expect(coverage.status).toBe("partial")
    expect(coverage.missing).toContain("backend_operational_proof")
    expect(coverage.missing).toContain("containment_from_production_path")
    // The dataset halves still pass, so the shortfall is named as the machine's and not the corpus'.
    expect(coverage.conditions["positive_autonomy_cases"]).toBe(true)
    expect(coverage.conditions["negative_protected_boundary_controls"]).toBe(true)
  })

  proven("on a machine that proved containment, C1 is covered", async () => {
    const coverage = c1Coverage({
      sandbox_enabled: BenchSandbox.profile("contained-deny").config.enabled === true,
      preflight_state: preflight.state,
      probes: preflight.probes,
      containment: summarizeA1(cases, at("contained-deny/off")).containment,
      cases: await load(),
    })
    expect(coverage.missing).toEqual([])
    expect(coverage.status).toBe("covered")
    expect(coverage.positives.length).toBeGreaterThanOrEqual(5)
    expect(coverage.uncovered_control_rules).toEqual([])
  })
})
