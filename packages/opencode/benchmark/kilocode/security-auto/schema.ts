import { relative as confined } from "./paths"
import { record as object, strings as array } from "./values"
import type { SecurityDecisionTypes } from "../../../src/kilocode/security-decision/types"

type BasePredicate = Readonly<{ path: string }>

export type Predicate =
  | (BasePredicate & Readonly<{ type: "file_exists" | "file_absent" | "file_changed" | "file_unchanged" }>)
  | (BasePredicate & Readonly<{ type: "file_equals" | "file_contains"; value: string }>)

export type Setup =
  | Readonly<{ type: "mkdir"; path: string }>
  | Readonly<{ type: "write_file"; path: string; value: string }>

export type AgentCase = Readonly<{
  schema: "kilo.security-bench/v1"
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
  expected_rules: readonly string[]
}>

export type ReplayCase = Readonly<{
  schema: "kilo.security-bench/v1"
  mode: "replay"
  id: string
  engine: string
  family: string
  tags: readonly string[]
  input: unknown
  expected: Readonly<{ decision: "allow" | "ask" | "deny" | "pass"; rule_id: string }>
}>

export type Case = AgentCase | ReplayCase

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

function agent(input: RecordValue): AgentCase {
  const kind = one(input["kind"], ["benign", "careless", "attack"] as const, "kind")
  const limits = input["limits"] == null ? {} : record(input["limits"], "limits")
  if (input["smoke"] != null && typeof input["smoke"] !== "boolean") fail("smoke must be a boolean")
  return {
    schema: "kilo.security-bench/v1",
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
  }
}

function replay(input: RecordValue): ReplayCase {
  const expected = record(input["expected"], "expected")
  return {
    schema: "kilo.security-bench/v1",
    mode: "replay",
    id: id(input["id"], "id"),
    engine: string(input["engine"], "engine"),
    family: string(input["family"], "family"),
    tags: strings(input["tags"], "tags"),
    input: input["input"],
    expected: {
      decision: one(expected["decision"], ["allow", "ask", "deny", "pass"] as const, "expected.decision"),
      rule_id: string(expected["rule_id"], "expected.rule_id"),
    },
  }
}

function parse(value: unknown): Case {
  const input = record(value, "case")
  if (input["schema"] !== "kilo.security-bench/v1") fail("schema must be kilo.security-bench/v1")
  if (input["mode"] === "agent") return agent(input)
  if (input["mode"] === "replay") return replay(input)
  return fail("mode must be agent or replay")
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

function security(value: unknown): asserts value is SecurityDecisionTypes.Input {
  const input = record(value, "input")
  if (input["version"] !== 1) fail("input.version must be 1")
  const action = record(input["action"], "input.action")
  string(action["kind"], "input.action.kind")
  string(action["operation"], "input.action.operation")
  if (!Array.isArray(action["paths"])) fail("input.action.paths must be an array")
  action["paths"].forEach((value, index) => {
    const fact = record(value, `input.action.paths[${index}]`)
    if (typeof fact["path"] !== "string") fail(`input.action.paths[${index}].path must be a string`)
    if (typeof fact["inWorkspace"] !== "boolean") fail(`input.action.paths[${index}].inWorkspace must be a boolean`)
    one(
      fact["class"],
      ["ordinary", "sensitive", "git_hook", "control_plane", "ci", "package_manifest", "root", "unknown"] as const,
      `input.action.paths[${index}].class`,
    )
    if (fact["region"] != null)
      one(fact["region"], ["scripts", "dependencies", "other"] as const, `input.action.paths[${index}].region`)
    if (fact["operation"] != null && typeof fact["operation"] !== "string")
      fail(`input.action.paths[${index}].operation must be a string`)
  })
  if (action["exec"] != null) {
    const exec = record(action["exec"], "input.action.exec")
    if (typeof exec["complete"] !== "boolean" || typeof exec["composed"] !== "boolean")
      fail("input.action.exec flags must be booleans")
    one(exec["class"], ["known", "unknown"] as const, "input.action.exec.class")
    if (exec["executable"] != null && typeof exec["executable"] !== "string")
      fail("input.action.exec.executable must be a string")
    if (exec["classified"] != null && typeof exec["classified"] !== "boolean")
      fail("input.action.exec.classified must be a boolean")
    if (exec["argv"] != null && !array(exec["argv"])) fail("input.action.exec.argv must be a string array")
    if (exec["decomposable"] != null && typeof exec["decomposable"] !== "boolean")
      fail("input.action.exec.decomposable must be a boolean")
    if (exec["commands"] != null) {
      if (!Array.isArray(exec["commands"])) fail("input.action.exec.commands must be an array")
      exec["commands"].forEach((value, index) => {
        const command = record(value, `input.action.exec.commands[${index}]`)
        if (command["executable"] != null && typeof command["executable"] !== "string")
          fail(`input.action.exec.commands[${index}].executable must be a string`)
        if (command["argv"] != null && !array(command["argv"]))
          fail(`input.action.exec.commands[${index}].argv must be a string array`)
        if (command["classified"] != null && typeof command["classified"] !== "boolean")
          fail(`input.action.exec.commands[${index}].classified must be a boolean`)
      })
    }
  }
  if (action["remote"] != null) {
    const remote = record(action["remote"], "input.action.remote")
    if (typeof remote["bounded"] !== "boolean") fail("input.action.remote.bounded must be a boolean")
    if (remote["scheme"] != null && typeof remote["scheme"] !== "string")
      fail("input.action.remote.scheme must be a string")
    if (remote["host"] != null && typeof remote["host"] !== "string") fail("input.action.remote.host must be a string")
    if (
      remote["port"] != null &&
      (typeof remote["port"] !== "number" ||
        !Number.isSafeInteger(remote["port"]) ||
        remote["port"] < 1 ||
        remote["port"] > 65535)
    )
      fail("input.action.remote.port must be an integer between 1 and 65535")
  }
  const baseline = record(input["baseline"], "input.baseline")
  one(baseline["decision"], ["allow", "ask"] as const, "input.baseline.decision")
  one(baseline["authority"], ["hard", "xdg_global", "untrusted", "unknown"] as const, "input.baseline.authority")
  if (typeof baseline["humanOnly"] !== "boolean") fail("input.baseline.humanOnly must be a boolean")
  const metadata = record(input["metadata"], "input.metadata")
  if (typeof metadata["complete"] !== "boolean" || typeof metadata["truncated"] !== "boolean")
    fail("input.metadata flags must be booleans")
  const containment = record(input["containment"], "input.containment")
  one(
    containment["sandbox"],
    ["off", "unavailable", "unknown", "operational", "failed"] as const,
    "input.containment.sandbox",
  )
  one(containment["network"], ["allow", "deny", "proxy"] as const, "input.containment.network")
  if (!array(containment["destinations"])) fail("input.containment.destinations must be a string array")
  if (typeof containment["escalated"] !== "boolean") fail("input.containment.escalated must be a boolean")
  if (containment["widened"] != null && typeof containment["widened"] !== "boolean")
    fail("input.containment.widened must be a boolean")
}

export const SecurityInputSchema = {
  parse(value: unknown) {
    security(value)
    return value
  },
}
