import { record as object } from "./values"

type RecordValue = Record<string, unknown>

export type Signal = Readonly<{
  engine: string
  decision: string
  rule_id?: string
  enforcement?: string
  latency_ms?: number
  call_id?: string
  session_id?: string
  reviewer?: string
  reviewer_reason?: string
  reviewer_latency_ms?: number
}>

export type Extractor = Readonly<{
  id: string
  extract: (event: RecordValue) => readonly Signal[]
}>

function record(value: unknown): RecordValue | undefined {
  return object(value) ? value : undefined
}

function rejected(state: RecordValue | undefined) {
  return (
    state?.["status"] === "error" && state["error"] === "The user rejected permission to use this specific tool call."
  )
}

const security: Extractor = {
  id: "security-decision/v1",
  extract(event) {
    if (event["type"] !== "tool_use") return []
    const part = record(event["part"])
    const state = record(part?.["state"])
    const metadata = record(state?.["metadata"])
    const audit = record(metadata?.["securityDecision"])
    if (audit?.["schema"] !== "kilo.security-decision/v1") return []
    const reviewer = record(audit["reviewer"])
    return [
      {
        engine: "security-decision/v1",
        decision: typeof audit["decision"] === "string" ? audit["decision"] : "unknown",
        ...(typeof audit["rule_id"] === "string" ? { rule_id: audit["rule_id"] } : {}),
        ...(rejected(state)
          ? { enforcement: "reject" }
          : typeof audit["final_enforcement"] === "string"
            ? { enforcement: audit["final_enforcement"] }
            : {}),
        ...(typeof audit["latency_ms"] === "number" ? { latency_ms: audit["latency_ms"] } : {}),
        ...(typeof audit["callID"] === "string"
          ? { call_id: audit["callID"] }
          : typeof part?.["id"] === "string"
            ? { call_id: part["id"] }
            : {}),
        ...(typeof audit["sessionID"] === "string" ? { session_id: audit["sessionID"] } : {}),
        ...(typeof reviewer?.["state"] === "string" ? { reviewer: reviewer["state"] } : {}),
        ...(typeof reviewer?.["reason_code"] === "string" ? { reviewer_reason: reviewer["reason_code"] } : {}),
        ...(typeof reviewer?.["latency_ms"] === "number" ? { reviewer_latency_ms: reviewer["latency_ms"] } : {}),
      },
    ]
  },
}

const permission: Extractor = {
  id: "existing-permissions",
  extract(event) {
    if (event["type"] !== "tool_use") return []
    const part = record(event["part"])
    const state = record(part?.["state"])
    const metadata = record(state?.["metadata"])
    if (record(metadata?.["securityDecision"])) return []
    const approval = record(metadata?.["approval"])
    if (approval?.["source"] === "manual") {
      return [
        {
          engine: "existing-permissions",
          decision: "ask",
          enforcement: "allow",
          ...(typeof part?.["id"] === "string" ? { call_id: part["id"] } : {}),
          ...(typeof part?.["sessionID"] === "string" ? { session_id: part["sessionID"] } : {}),
        },
      ]
    }
    if (rejected(state)) {
      return [
        {
          engine: "existing-permissions",
          decision: "ask",
          enforcement: "reject",
          ...(typeof part?.["id"] === "string" ? { call_id: part["id"] } : {}),
          ...(typeof part?.["sessionID"] === "string" ? { session_id: part["sessionID"] } : {}),
        },
      ]
    }
    return []
  },
}

const extractors: readonly Extractor[] = [security, permission]

export function extract(events: readonly RecordValue[]) {
  const signals = new Map<string, Signal>()
  for (const [index, event] of events.entries()) {
    for (const signal of extractors.flatMap((item) => item.extract(event))) {
      // CLI may emit multiple updates for the same call. Keep its final enforcement.
      const key = `${signal.engine}:${signal.session_id ?? ""}:${signal.call_id ?? index}`
      signals.set(key, signal)
    }
  }
  return [...signals.values()]
}

export function completion(events: readonly RecordValue[], code: number) {
  const errors = events.filter((event) => event["type"] === "error")
  const blocked = extract(events).some((signal) => ["deny", "blocked", "reject"].includes(signal.enforcement ?? ""))
  if (
    errors.length > 0 &&
    blocked &&
    errors.every(
      (event) => event["error"] === "run ended with an auto-rejected permission; pass --auto for autonomous use",
    )
  )
    return "blocked" as const
  if (errors.length > 0) return "agent_error" as const
  if (code !== 0) return "process_error" as const
  const finish = events.filter((event) => event["type"] === "step_finish").at(-1)
  if (record(finish?.["part"])?.["reason"] === "stop") return "completed" as const
  if (blocked) return "blocked" as const
  return "incomplete" as const
}

export function continued(events: readonly RecordValue[]) {
  const blocked = new Set<string>()
  for (const event of events) {
    const part = record(event["part"])
    if (event["type"] !== "tool_use" || typeof part?.["id"] !== "string") continue
    if (
      extract([event]).some(
        (item) =>
          item.engine === "security-decision/v1" && ["deny", "blocked", "reject"].includes(item.enforcement ?? ""),
      )
    ) {
      blocked.add(part["id"])
      continue
    }
    if (blocked.size > 0 && !blocked.has(part["id"]) && record(part["state"])?.["status"] === "completed") return true
  }
  return false
}

export function parse(stdout: string): RecordValue[] {
  return stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .flatMap((line) => {
      try {
        const value = JSON.parse(line)
        const parsed = record(value)
        return parsed ? [parsed] : []
      } catch {
        return []
      }
    })
}
