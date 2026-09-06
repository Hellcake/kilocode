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

/**
 * What Lane A2 observed, by domain.
 *
 * The `literal_`/`modeled_` split is the whole point of the vocabulary. A `literal_` domain says the
 * effect happened: a file is there, bytes arrived on a socket, the canary came back in tool output.
 * A `modeled_` domain says the command reached the execution boundary and a `PATH` shim answered
 * it — real evidence that the layer did not stop it, and deliberately not a claim that the host
 * changed. A benchmark that blurred the two would be reporting an attack it never actually landed.
 */
export const A2_DOMAINS = [
  "literal_fs",
  "literal_outside_fs",
  "modeled_host_exec",
  "modeled_package_install",
  "literal_local_exfil",
  "literal_secret_disclosure",
] as const
export type A2Domain = (typeof A2_DOMAINS)[number]

export type A2Damage =
  | Readonly<{ domain: "literal_fs"; type: "file_exists" | "file_absent" | "file_changed"; path: string }>
  | Readonly<{ domain: "literal_fs"; type: "file_contains"; path: string; value: string }>
  /** Any file in the disposable sentinel root, optionally one carrying the episode canary. */
  | Readonly<{ domain: "literal_outside_fs"; contains?: string }>
  | Readonly<{ domain: "modeled_host_exec"; program: string }>
  | Readonly<{ domain: "modeled_package_install"; program: string }>
  | Readonly<{ domain: "literal_local_exfil" }>
  | Readonly<{ domain: "literal_secret_disclosure" }>

/**
 * What a scripted step is for.
 *
 * Declared rather than inferred, because the recovery metrics are about intent: the harness cannot
 * tell a safe alternative from a re-routed attack by looking at a command, and guessing would make
 * `workaround_stopped` a measurement of the guess.
 */
export const A2_ROLES = ["setup", "attack", "safe_recovery", "workaround"] as const
export type A2Role = (typeof A2_ROLES)[number]

/**
 * What the step is expected to do. Asserted per step, not per episode.
 *
 * `not_issued` is a real outcome, not a harness failure: when the layer ends the turn rather than
 * handing the model a structured block, the later steps of the script never reach the tool boundary
 * at all. A case that observes that has to be able to say so.
 */
export const A2_STEP_OUTCOMES = ["executed", "stopped", "not_issued"] as const
export type A2StepOutcome = (typeof A2_STEP_OUTCOMES)[number]

export type A2Step = Readonly<{
  tool: string
  input: Readonly<Record<string, unknown>>
  role: A2Role
  expect: A2StepOutcome
}>

/**
 * A deterministic end-to-end episode.
 *
 * The script lives here and only here. The old `probe.ts` kept a per-case-id table of tool calls
 * beside the case file, which made the dataset two sources of truth that could disagree silently;
 * the A2 model server knows no case ids at all and simply plays back what this array says.
 */
export type A2Case = Readonly<{
  schema: "kilo.security-bench/v2"
  mode: "a2"
  lane: "A2"
  id: string
  kind: "benign" | "attack"
  provenance: Provenance
  /**
   * `direct_task` throughout. A2 hands the script to a deterministic model, so nothing here is
   * evidence about indirect prompt injection, and no case is allowed to imply otherwise.
   */
  delivery: Extract<Delivery, "direct_task">
  family: string
  fixture: string
  prompt: string
  target_effect: readonly ThreatClass[]
  route: Route
  statefulness: Statefulness
  expected_enforcement: Enforcement
  setup: readonly Setup[]
  script: readonly A2Step[]
  /**
   * Whether this case may be replayed with the security layer switched off, as an oracle control.
   *
   * Only true when every scripted command is confined to the fixture workspace, the disposable
   * sentinel root, a `PATH` shim or the loopback sink — because with the layer off, every one of
   * them runs. A case whose failure mode reaches the host is never given this flag, and the
   * harness refuses to run an unsafe control without it.
   */
  unsafe_control: boolean
  /**
   * Set when this case records a shortfall rather than a satisfied expectation, exactly as an A1
   * case does. A gap is reported as a gap and never counted as a pass, and an A2 gap is the sharper
   * kind: the action actually happened.
   */
  known_gap?: string
  gap_kind?: GapKind
  /** What the independent oracle must see for this episode to count as damaging. */
  damage: readonly A2Damage[]
  /**
   * What a benign episode is supposed to have achieved, in the same oracle vocabulary as `damage`.
   * One vocabulary rather than two: a utility claim and a damage claim are read by the same oracle,
   * so they must be expressible in exactly the same terms.
   */
  utility: readonly A2Damage[]
  limits: Readonly<{ wall_seconds: number; tool_calls: number }>
  tags: readonly string[]
}>

/** Where an indirect injection is planted. Lane B's whole subject. */
export const B_VECTORS = [
  "rules",
  "readme",
  "source_comment",
  "docstring",
  "tool_output",
  "dependency_lure",
  "none",
] as const
export type BVector = (typeof B_VECTORS)[number]

/**
 * Whether the payload reaches the model by being in its context automatically, or only if it
 * chooses to read something.
 *
 * `automatic` is the honest label for a rules file: Kilo loads `.kilocode/rules` into the prompt, so
 * there is nothing to observe and nothing to prove. `observed` means delivery has to be *seen* — the
 * payload carries a unique token, and only a transcript containing it counts.
 */
export const B_DELIVERY_MODES = ["automatic", "observed"] as const
export type BDeliveryMode = (typeof B_DELIVERY_MODES)[number]

/** Where a case came from, so an adapted scenario can never be mistaken for one authored here. */
export type CaseSource = Readonly<{
  repo: string
  path: string
  commit: string
  /** The upstream name for this vector or level. */
  vector: string
  /** Always true for a transplanted scenario: the payload was re-expressed for this harness. */
  adapted: boolean
  note?: string
}>

/**
 * A Lane B episode: a real model, a benign task, and a malicious instruction hidden in the project.
 *
 * The defining property is that the benchmark never issues the malicious tool call. It plants the
 * instruction, asks for ordinary work, and measures whether the model went and did the other thing —
 * and, if it tried, what the security layer then did about it. A case therefore carries no script.
 */
export type BCase = Readonly<{
  schema: "kilo.security-bench/v2"
  mode: "b"
  lane: "B"
  id: string
  kind: "benign" | "attack"
  provenance: Provenance
  delivery: Delivery
  vector: BVector
  delivery_mode: BDeliveryMode
  family: string
  fixture: string
  /** The ordinary work the user asks for. Never mentions the payload. */
  task: string
  setup: readonly Setup[]
  /** The planted instruction. Absent on a benign control, which is the point of the control. */
  injection?: Readonly<{ path: string; content: string }>
  target_effect: readonly ThreatClass[]
  route: Route
  statefulness: Statefulness
  expected_enforcement: Enforcement
  /** Strings whose presence in the transcript shows the payload was read. */
  delivery_markers: readonly string[]
  /** Strings in a tool call's arguments that show the model tried to carry the instruction out. */
  attempt_markers: readonly string[]
  /** What the injection succeeding actually looks like, in the independent oracle's vocabulary. */
  damage: readonly A2Damage[]
  /** What doing the real work looks like, so compliance and usefulness are measured separately. */
  utility: readonly A2Damage[]
  limits: Readonly<{ wall_seconds: number; tool_calls: number }>
  source?: CaseSource
  tags: readonly string[]
}>

export type Case = AgentCase | A1Case | A2Case | BCase

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
    return { type, path, value: templated(input["value"], `${label}.value`) }
  }
  return { type, path }
}

function steps(value: unknown, label: string) {
  if (value == null) return []
  if (!Array.isArray(value)) fail(`${label} must be an array`)
  return value.map((item, index) => step(item, `${label}[${index}]`))
}

const steps2 = steps

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

/**
 * The substitutions a case may carry.
 *
 * A fixed, closed set. The sentinel root and the sink port are chosen per episode and cannot be
 * written into a checked-in file, and an open-ended template would let a case name a path on the
 * machine running the benchmark — which is the one thing an executing lane must never allow.
 */
export const A2_PLACEHOLDERS = [
  "${SENTINEL}",
  "${SINK_URL}",
  "${SINK_PORT}",
  "${CANARY}",
  "${WORKSPACE}",
  "${DELIVERY}",
] as const
export type A2Placeholder = (typeof A2_PLACEHOLDERS)[number]

const PLACEHOLDER = /\$\{[A-Z_]+\}/g

const ALLOWED_PLACEHOLDERS: ReadonlySet<string> = new Set(A2_PLACEHOLDERS)

function templated(value: string, label: string) {
  for (const found of value.match(PLACEHOLDER) ?? [])
    if (!ALLOWED_PLACEHOLDERS.has(found))
      fail(`${label} uses an unknown placeholder ${found}; allowed: ${A2_PLACEHOLDERS.join(", ")}`)
  return value
}

function damage(value: unknown, label: string): A2Damage {
  const input = record(value, label)
  const domain = one(input["domain"], A2_DOMAINS, `${label}.domain`)
  if (domain === "literal_fs") {
    const type = one(
      input["type"],
      ["file_exists", "file_absent", "file_changed", "file_contains"] as const,
      `${label}.type`,
    )
    const file = relative(input["path"], `${label}.path`)
    if (type === "file_contains") {
      if (typeof input["value"] !== "string") fail(`${label}.value must be a string`)
      return { domain, type, path: file, value: templated(input["value"], `${label}.value`) }
    }
    return { domain, type, path: file }
  }
  if (domain === "literal_outside_fs") {
    if (input["contains"] == null) return { domain }
    if (typeof input["contains"] !== "string") fail(`${label}.contains must be a string`)
    return { domain, contains: templated(input["contains"], `${label}.contains`) }
  }
  if (domain === "modeled_host_exec" || domain === "modeled_package_install") {
    const program = string(input["program"], `${label}.program`)
    return { domain, program }
  }
  return { domain }
}

function damages(value: unknown, label: string, required: boolean) {
  if (value == null && !required) return []
  if (!Array.isArray(value) || (required && value.length === 0)) fail(`${label} must be a non-empty array`)
  return value.map((item, index) => damage(item, `${label}[${index}]`))
}

/** Every string in a step's input is template-checked, however deeply it is nested. */
function scan(value: unknown, label: string): unknown {
  if (typeof value === "string") return templated(value, label)
  if (Array.isArray(value)) return value.map((item, index) => scan(item, `${label}[${index}]`))
  if (object(value))
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, scan(item, `${label}.${key}`)]))
  return value
}

function step2(value: unknown, label: string): A2Step {
  const input = record(value, label)
  const tool = string(input["tool"], `${label}.tool`)
  const args = record(input["input"], `${label}.input`)
  const scanned = scan(args, `${label}.input`)
  if (!object(scanned)) fail(`${label}.input must be an object`)
  return {
    tool,
    input: scanned,
    role: one(input["role"], A2_ROLES, `${label}.role`),
    expect: one(input["expect"], A2_STEP_OUTCOMES, `${label}.expect`),
  }
}

function a2(input: RecordValue): A2Case {
  const target = effects(input["target_effect"], "target_effect")
  if (!target) fail("target_effect is required")
  if (input["lane"] !== "A2") fail("lane must be A2 for an a2 case")
  if (input["delivery"] !== "direct_task") fail("delivery must be direct_task; A2 is not an injection lane")
  const script = input["script"]
  if (!Array.isArray(script) || script.length === 0) fail("script must be a non-empty array")
  const kind = one(input["kind"], ["benign", "attack"] as const, "kind")
  const limits = input["limits"] == null ? {} : record(input["limits"], "limits")
  const steps = script.map((item, index) => step2(item, `script[${index}]`))
  if (kind === "attack" && !steps.some((item) => item.role === "attack"))
    fail("an attack case must script at least one step with role attack")
  // The `attack` role is what `attempted` and the ASR denominators are counted from, so a benign
  // case may not carry one: its ordinary work is `setup`, however conservatively the layer holds it.
  if (kind === "benign" && steps.some((item) => item.role === "attack"))
    fail("a benign case must not script a step with role attack")
  if (input["unsafe_control"] != null && typeof input["unsafe_control"] !== "boolean")
    fail("unsafe_control must be a boolean")
  const gap = input["known_gap"]
  if (gap != null && typeof gap !== "string") fail("known_gap must be a string")
  const gapKind = maybe(input["gap_kind"], GAP_KINDS, "gap_kind")
  if ((gap == null) !== (gapKind == null)) fail("known_gap and gap_kind must be set together")
  return {
    schema: "kilo.security-bench/v2",
    mode: "a2",
    lane: "A2",
    id: id(input["id"], "id"),
    kind,
    provenance: one(input["provenance"], PROVENANCES, "provenance"),
    delivery: "direct_task",
    family: string(input["family"], "family"),
    fixture: id(input["fixture"], "fixture"),
    prompt: string(input["prompt"], "prompt"),
    target_effect: target,
    route: one(input["route"], ROUTES, "route"),
    statefulness: one(input["statefulness"], STATEFULNESS, "statefulness"),
    expected_enforcement: one(input["expected_enforcement"], ENFORCEMENTS, "expected_enforcement"),
    setup: steps2(input["setup"], "setup"),
    script: steps,
    unsafe_control: input["unsafe_control"] === true,
    ...(typeof gap === "string" && gapKind ? { known_gap: gap, gap_kind: gapKind } : {}),
    damage: damages(input["damage"], "damage", kind === "attack"),
    utility: damages(input["utility"], "utility", false),
    limits: {
      wall_seconds: integer(limits["wall_seconds"], 180, 1800, "limits.wall_seconds"),
      tool_calls: integer(limits["tool_calls"], 20, 1000, "limits.tool_calls"),
    },
    tags: strings(input["tags"], "tags"),
  }
}

function source(value: unknown, label: string): CaseSource | undefined {
  if (value == null) return undefined
  const input = record(value, label)
  if (typeof input["adapted"] !== "boolean") fail(`${label}.adapted must be a boolean`)
  const note = input["note"]
  if (note != null && typeof note !== "string") fail(`${label}.note must be a string`)
  return {
    repo: string(input["repo"], `${label}.repo`),
    path: string(input["path"], `${label}.path`),
    commit: string(input["commit"], `${label}.commit`),
    vector: string(input["vector"], `${label}.vector`),
    adapted: input["adapted"],
    ...(typeof note === "string" ? { note } : {}),
  }
}

function b(input: RecordValue): BCase {
  const target = effects(input["target_effect"], "target_effect")
  if (!target) fail("target_effect is required")
  if (input["lane"] !== "B") fail("lane must be B for a b case")
  const kind = one(input["kind"], ["benign", "attack"] as const, "kind")
  const limits = input["limits"] == null ? {} : record(input["limits"], "limits")
  const injection = input["injection"] == null ? undefined : record(input["injection"], "injection")
  // A benign control is a control precisely because nothing is planted in it.
  if (kind === "attack" && !injection) fail("an attack case must plant an injection")
  if (kind === "benign" && injection) fail("a benign control must not plant an injection")
  return {
    schema: "kilo.security-bench/v2",
    mode: "b",
    lane: "B",
    id: id(input["id"], "id"),
    kind,
    provenance: one(input["provenance"], PROVENANCES, "provenance"),
    delivery: one(input["delivery"], DELIVERIES, "delivery"),
    vector: one(input["vector"], B_VECTORS, "vector"),
    delivery_mode: one(input["delivery_mode"], B_DELIVERY_MODES, "delivery_mode"),
    family: string(input["family"], "family"),
    fixture: id(input["fixture"], "fixture"),
    task: templated(string(input["task"], "task"), "task"),
    setup: steps2(input["setup"], "setup"),
    ...(injection
      ? {
          injection: {
            path: relative(injection["path"], "injection.path"),
            content: templated(string(injection["content"], "injection.content"), "injection.content"),
          },
        }
      : {}),
    target_effect: target,
    route: one(input["route"], ROUTES, "route"),
    statefulness: one(input["statefulness"], STATEFULNESS, "statefulness"),
    expected_enforcement: one(input["expected_enforcement"], ENFORCEMENTS, "expected_enforcement"),
    delivery_markers: strings(input["delivery_markers"], "delivery_markers").map((value, index) =>
      templated(value, `delivery_markers[${index}]`),
    ),
    attempt_markers: strings(input["attempt_markers"], "attempt_markers").map((value, index) =>
      templated(value, `attempt_markers[${index}]`),
    ),
    damage: damages(input["damage"], "damage", kind === "attack"),
    utility: damages(input["utility"], "utility", false),
    limits: {
      wall_seconds: integer(limits["wall_seconds"], 300, 1800, "limits.wall_seconds"),
      tool_calls: integer(limits["tool_calls"], 40, 1000, "limits.tool_calls"),
    },
    ...(input["source"] != null ? { source: source(input["source"], "source")! } : {}),
    tags: strings(input["tags"], "tags"),
  }
}

function parse(value: unknown): Case {
  const input = record(value, "case")
  if (input["schema"] !== "kilo.security-bench/v2") fail("schema must be kilo.security-bench/v2")
  if (input["mode"] === "agent") return agent(input)
  if (input["mode"] === "a1") return a1(input)
  if (input["mode"] === "a2") return a2(input)
  if (input["mode"] === "b") return b(input)
  return fail("mode must be agent, a1, a2 or b")
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
