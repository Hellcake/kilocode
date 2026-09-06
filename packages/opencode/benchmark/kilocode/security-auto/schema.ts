import { relative as confined } from "./paths"
import { record as object, strings as array } from "./values"
import type { SecurityDamage } from "@test/kilocode/security-decision/damage"

/**
 * Case schema for the v2 benchmark baseline.
 *
 * v1 carried a second case mode, `replay`, whose `input` was a hand-written, already-normalized
 * `SecurityDecisionTypes.Input`. That mode is deliberately gone: it fed the pure core directly and
 * so could never observe the adapter, the shell scan or the permission pipeline — exactly the
 * layers where the found gaps lived. Lane A1 replaces it by replaying a real command through the
 * production path instead of a transcription of what that path was assumed to produce.
 *
 * The v2 taxonomy fields below are declared here so the dataset has one vocabulary from the start.
 * They are optional in this block: the 23 transplanted agent cases predate them and are drafts, not
 * ground truth, until Block 5 classifies each one.
 */

type BasePredicate = Readonly<{ path: string }>

export type Predicate =
  | (BasePredicate & Readonly<{ type: "file_exists" | "file_absent" | "file_changed" | "file_unchanged" }>)
  | (BasePredicate & Readonly<{ type: "file_equals" | "file_contains"; value: string }>)

export type Setup =
  | Readonly<{ type: "mkdir"; path: string }>
  | Readonly<{ type: "write_file"; path: string; value: string }>

/** Evaluation lane. A1/A2 are scripted, B is a live model, C is benign autonomy. */
export const LANES = ["A1", "A2", "B", "C"] as const
export type Lane = (typeof LANES)[number]

/** How the case entered the dataset. Held-out cases are authored after the rules are frozen. */
export const PROVENANCES = ["canonical", "mutation", "model-generated", "held-out"] as const
export type Provenance = (typeof PROVENANCES)[number]

/** Where the malicious instruction or state reaches the agent from. A vector, never a threat class. */
export const DELIVERIES = [
  "direct_task",
  "readme",
  "agents_md",
  "source_comment",
  "tool_output",
  "mcp_text",
  "dependency_metadata",
  "prior_fs_state",
] as const
export type Delivery = (typeof DELIVERIES)[number]

/** The machine route the effect travels by. Invariant I2 requires equal decisions across these. */
export const ROUTES = [
  "direct",
  "quoting",
  "alt_utility",
  "redirect",
  "path_flag",
  "wrapper",
  "cwd",
  "symlink",
  "archive",
  "temp_staging",
  "delegated",
  "cascade",
] as const
export type Route = (typeof ROUTES)[number]

export const STATEFULNESS = ["single", "multi", "state_dependent", "delayed_trigger"] as const
export type Statefulness = (typeof STATEFULNESS)[number]

/** The frozen threat classes. This vocabulary is not extended without a new security domain. */
export const THREAT_CLASSES = ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9"] as const
export type ThreatClass = (typeof THREAT_CLASSES)[number]

export const ENFORCEMENTS = ["pass", "reviewable_ask", "mandatory_ask", "deny"] as const
export type Enforcement = (typeof ENFORCEMENTS)[number]

export const GAP_KINDS = ["enforcement", "oracle"] as const
export type GapKind = (typeof GAP_KINDS)[number]

export type AgentCase = Readonly<{
  schema: "kilo.security-bench/v2"
  mode: "agent"
  id: string
  kind: "benign" | "careless" | "attack"
  family: string
  fixture: string
  prompt: string
  smoke: boolean
  tags: readonly string[]
  setup: readonly Setup[]
  utility: readonly Predicate[]
  damage: readonly Predicate[]
  limits: Readonly<{ wall_seconds: number; tool_calls: number }>
  /**
   * Rule ids this case was observed to raise under the v1 baseline. Reported by `report.ts` as
   * `rule_observation_rate` and never asserted, because these predate the current `main`. Block 5
   * re-derives them; until then they are a v1 observation, not an expectation.
   */
  expected_rules: readonly string[]
  /** v2 taxonomy. Optional in this block; Block 5 makes them required for new cases. */
  lane?: Lane
  provenance?: Provenance
  delivery?: Delivery
  route?: Route
  statefulness?: Statefulness
  target_effect?: readonly ThreatClass[]
  expected_enforcement?: Enforcement
}>

/**
 * The independent oracle's vocabulary for what an action touched.
 *
 * Declared here rather than imported so a case file has a closed vocabulary to validate against; the
 * assertion below fails the build if the oracle's own union ever moves away from it.
 */
export const DAMAGE_REASONS = ["ci", "hook", "control_plane", "manifest", "outside_workspace", "credential"] as const
export type DamageReason = (typeof DAMAGE_REASONS)[number]
type SameReasons = [DamageReason] extends [SecurityDamage.Reason]
  ? [SecurityDamage.Reason] extends [DamageReason]
    ? true
    : never
  : never
const _reasonsMatch: SameReasons = true
void _reasonsMatch

/** How an A1 case reaches the layer. `shell` is a production entry; `synthetic-facts` is not. */
export const ENTRIES = ["shell", "synthetic-facts"] as const
export type Entry = (typeof ENTRIES)[number]

/**
 * What the layer is expected to answer, and what the independent oracle is expected to say about the
 * action. Both halves are required: a route-equivalence regression that only compares `rule_id`
 * passes while the layer quietly stops enforcing, and a damage classification alone cannot tell a
 * mandatory human boundary from one a reviewer may narrow.
 *
 * `reviewer_called` is recorded under the `always_allow` reviewer, the adversarial control. Under
 * that mode a `false` here is a claim — the boundary is mandatory and no reviewer is offered it —
 * rather than an artefact of running with no reviewer bound at all.
 */
export type A1Expectation = Readonly<{
  decision: "allow" | "ask" | "deny" | "pass"
  rule_id: string
  reviewable: boolean
  reviewer_called: boolean
  prospective_damage: boolean
  prospective_reason?: DamageReason
}>

export type A1Case = Readonly<{
  schema: "kilo.security-bench/v2"
  mode: "a1"
  lane: "A1"
  id: string
  kind: "benign" | "attack"
  provenance: Provenance
  entry: Entry
  family: string
  command: string
  target_effect: readonly ThreatClass[]
  route: Route
  statefulness: Statefulness
  expected_enforcement: Enforcement
  expect: A1Expectation
  /**
   * What the same command is expected to produce once confinement has been *proven* on the machine
   * running the benchmark. Set together with `expect_contained`, or not at all.
   */
  expected_enforcement_contained?: Enforcement
  /**
   * Declared as a second expectation rather than a second case so both readings are anchored to one
   * command: a C1 positive is only meaningful if the very action that was conservatively held
   * without a sandbox is the one containment moves, and a negative control is only meaningful if it
   * is the very action a sandbox might plausibly have been thought to bound.
   *
   * Nothing here can create containment. It records what the production path is expected to decide
   * once that path reports containment of its own, and it is asserted only when the preflight
   * proved the backend operational.
   */
  expect_contained?: A1Expectation
  tags: readonly string[]
  /**
   * Set when this case records a shortfall rather than a satisfied expectation. A gap is reported as
   * a gap; it is never counted as a pass.
   *
   * `enforcement` — the engine puts the action in a weaker class than the frozen threat model wants.
   * `oracle`      — the engine holds the action correctly, but the independent oracle cannot see what
   *                 it would have touched, so this case contributes no damage signal.
   */
  known_gap?: string
  gap_kind?: GapKind
}>

export type Case = AgentCase | A1Case

type RecordValue = Record<string, unknown>

function fail(message: string): never {
  throw new Error(message)
}

function record(value: unknown, label: string): RecordValue {
  if (!object(value)) fail(`${label} must be an object`)
  return value
}

function string(value: unknown, label: string) {
  if (typeof value !== "string" || value.length === 0) fail(`${label} must be a non-empty string`)
  return value
}

function strings(value: unknown, label: string) {
  if (value == null) return []
  if (!array(value)) fail(`${label} must be a string array`)
  return value
}

function integer(value: unknown, fallback: number, max: number, label: string) {
  const next = value ?? fallback
  if (typeof next !== "number" || !Number.isSafeInteger(next) || next < 1 || next > max)
    fail(`${label} must be an integer between 1 and ${max}`)
  return next
}

function relative(value: unknown, label: string) {
  const next = string(value, label)
  return confined(next)
}

function id(value: unknown, label: string) {
  const next = string(value, label)
  if (!/^[a-z0-9][a-z0-9-]*$/.test(next)) fail(`${label} must contain lowercase letters, numbers, and dashes`)
  return next
}

function one<T extends string>(value: unknown, choices: readonly T[], label: string): T {
  const choice = choices.find((item) => item === value)
  if (choice == null) fail(`${label} must be one of ${choices.join(", ")}`)
  return choice
}

/** An optional enumerated field: absent is allowed, present must be a member. */
function maybe<T extends string>(value: unknown, choices: readonly T[], label: string): T | undefined {
  if (value == null) return undefined
  return one(value, choices, label)
}

function predicate(value: unknown, label: string): Predicate {
  const input = record(value, label)
  const type = one(
    input["type"],
    ["file_exists", "file_absent", "file_equals", "file_contains", "file_changed", "file_unchanged"] as const,
    `${label}.type`,
  )
  const path = relative(input["path"], `${label}.path`)
  if (type === "file_equals" || type === "file_contains") {
    if (typeof input["value"] !== "string") fail(`${label}.value must be a string`)
    return { type, path, value: input["value"] }
  }
  return { type, path }
}

function predicates(value: unknown, label: string, required = false) {
  if (value == null && !required) return []
  if (!Array.isArray(value) || (required && value.length === 0)) fail(`${label} must be a non-empty array`)
  return value.map((item, index) => predicate(item, `${label}[${index}]`))
}

function step(value: unknown, label: string): Setup {
  const input = record(value, label)
  const type = one(input["type"], ["mkdir", "write_file"] as const, `${label}.type`)
  const path = relative(input["path"], `${label}.path`)
  if (type === "write_file") {
    if (typeof input["value"] !== "string") fail(`${label}.value must be a string`)
    return { type, path, value: input["value"] }
  }
  return { type, path }
}

function steps(value: unknown, label: string) {
  if (value == null) return []
  if (!Array.isArray(value)) fail(`${label} must be an array`)
  return value.map((item, index) => step(item, `${label}[${index}]`))
}

function effects(value: unknown, label: string) {
  if (value == null) return undefined
  if (!Array.isArray(value) || value.length === 0) fail(`${label} must be a non-empty array`)
  return value.map((item, index) => one(item, THREAT_CLASSES, `${label}[${index}]`))
}

function agent(input: RecordValue): AgentCase {
  const kind = one(input["kind"], ["benign", "careless", "attack"] as const, "kind")
  const limits = input["limits"] == null ? {} : record(input["limits"], "limits")
  if (input["smoke"] != null && typeof input["smoke"] !== "boolean") fail("smoke must be a boolean")
  const target = effects(input["target_effect"], "target_effect")
  const lane = maybe(input["lane"], LANES, "lane")
  const provenance = maybe(input["provenance"], PROVENANCES, "provenance")
  const delivery = maybe(input["delivery"], DELIVERIES, "delivery")
  const route = maybe(input["route"], ROUTES, "route")
  const statefulness = maybe(input["statefulness"], STATEFULNESS, "statefulness")
  const enforcement = maybe(input["expected_enforcement"], ENFORCEMENTS, "expected_enforcement")
  return {
    schema: "kilo.security-bench/v2",
    mode: "agent",
    id: id(input["id"], "id"),
    kind,
    family: string(input["family"], "family"),
    fixture: id(input["fixture"], "fixture"),
    prompt: string(input["prompt"], "prompt"),
    smoke: input["smoke"] === true,
    tags: strings(input["tags"], "tags"),
    setup: steps(input["setup"], "setup"),
    utility: predicates(input["utility"], "utility", true),
    damage: predicates(input["damage"], "damage", kind !== "benign"),
    limits: {
      wall_seconds: integer(limits["wall_seconds"], 300, 1800, "limits.wall_seconds"),
      tool_calls: integer(limits["tool_calls"], 80, 1000, "limits.tool_calls"),
    },
    expected_rules: strings(input["expected_rules"], "expected_rules"),
    ...(lane ? { lane } : {}),
    ...(provenance ? { provenance } : {}),
    ...(delivery ? { delivery } : {}),
    ...(route ? { route } : {}),
    ...(statefulness ? { statefulness } : {}),
    ...(target ? { target_effect: target } : {}),
    ...(enforcement ? { expected_enforcement: enforcement } : {}),
  }
}

function expectation(value: unknown, label: string): A1Expectation {
  const input = record(value, label)
  const reason = maybe(input["prospective_reason"], DAMAGE_REASONS, `${label}.prospective_reason`)
  if (typeof input["reviewable"] !== "boolean") fail(`${label}.reviewable must be a boolean`)
  if (typeof input["reviewer_called"] !== "boolean") fail(`${label}.reviewer_called must be a boolean`)
  if (typeof input["prospective_damage"] !== "boolean") fail(`${label}.prospective_damage must be a boolean`)
  return {
    decision: one(input["decision"], ["allow", "ask", "deny", "pass"] as const, `${label}.decision`),
    rule_id: string(input["rule_id"], `${label}.rule_id`),
    reviewable: input["reviewable"],
    reviewer_called: input["reviewer_called"],
    prospective_damage: input["prospective_damage"],
    ...(reason ? { prospective_reason: reason } : {}),
  }
}

/** Every taxonomy field is required here: an A1 case that cannot say what it represents is noise. */
function a1(input: RecordValue): A1Case {
  if (input["lane"] !== "A1") fail("lane must be A1 for an a1 case")
  const target = effects(input["target_effect"], "target_effect")
  if (!target) fail("target_effect is required")
  const gap = input["known_gap"]
  if (gap != null && typeof gap !== "string") fail("known_gap must be a string")
  const kind = maybe(input["gap_kind"], GAP_KINDS, "gap_kind")
  if ((gap == null) !== (kind == null)) fail("known_gap and gap_kind must be set together")
  const contained = input["expect_contained"] == null ? undefined : expectation(input["expect_contained"], "expect_contained")
  const containedEnforcement = maybe(input["expected_enforcement_contained"], ENFORCEMENTS, "expected_enforcement_contained")
  if ((contained == null) !== (containedEnforcement == null))
    fail("expect_contained and expected_enforcement_contained must be set together")
  return {
    schema: "kilo.security-bench/v2",
    mode: "a1",
    lane: "A1",
    id: id(input["id"], "id"),
    kind: one(input["kind"], ["benign", "attack"] as const, "kind"),
    provenance: one(input["provenance"], PROVENANCES, "provenance"),
    entry: one(input["entry"], ENTRIES, "entry"),
    family: string(input["family"], "family"),
    command: string(input["command"], "command"),
    target_effect: target,
    route: one(input["route"], ROUTES, "route"),
    statefulness: one(input["statefulness"], STATEFULNESS, "statefulness"),
    expected_enforcement: one(input["expected_enforcement"], ENFORCEMENTS, "expected_enforcement"),
    expect: expectation(input["expect"], "expect"),
    ...(contained && containedEnforcement
      ? { expect_contained: contained, expected_enforcement_contained: containedEnforcement }
      : {}),
    tags: strings(input["tags"], "tags"),
    ...(typeof gap === "string" && kind ? { known_gap: gap, gap_kind: kind } : {}),
  }
}

function parse(value: unknown): Case {
  const input = record(value, "case")
  if (input["schema"] !== "kilo.security-bench/v2") fail("schema must be kilo.security-bench/v2")
  if (input["mode"] === "agent") return agent(input)
  if (input["mode"] === "a1") return a1(input)
  return fail("mode must be agent or a1")
}

export const CaseSchema = {
  parse,
  safeParse(value: unknown): { success: true; data: Case } | { success: false; error: Error } {
    try {
      return { success: true, data: parse(value) }
    } catch (err) {
      return { success: false, error: err instanceof Error ? err : new Error(String(err)) }
    }
  },
}
