import path from "node:path"
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises"
import { randomUUID } from "node:crypto"
import { tmpdir } from "node:os"
import { testProviderConfig } from "@test/lib/test-provider"
import type { SecurityDecisionTypes as T } from "@/kilocode/security-decision/types"
import { FIXTURES } from "./cases"
import { BenchEndpoints } from "./endpoints"
import { BenchEnvironment } from "./a2-environment"
import { BenchSandbox } from "./sandbox"
import { fixture as validateFixture, inspect, target } from "./paths"
import { CLI, PKG, cleanenv, output, stop } from "./runner"
import { parse } from "./signals"
import { record } from "./values"
import type { Setup } from "./schema"

/**
 * Everything an executing lane needs that is not about what it is measuring.
 *
 * A2 and Lane B differ in exactly one thing — who decides the next tool call, a fixed script or a
 * real model — and in nothing else. The disposable workspace, the isolated HOME, the sentinel root,
 * the `PATH` shims, the loopback sink, the generated provider config, the spawn, the stream capture
 * and the reading of the CLI's own audit records are identical, so they live here once.
 */
export namespace BenchEpisode {
  /** Who answers the CLI's completion requests. */
  export type Model =
    | Readonly<{ kind: "deterministic"; url: string }>
    | Readonly<{ kind: "live"; endpoint: BenchEndpoints.Endpoint; apiKey: string }>

  /**
   * Who reviews a reviewable security ask.
   *
   * `off` binds nothing. The three stubs answer through the benchmark's local server, which is still
   * the production reviewer path — `SecurityReviewerBinding` reaches it as an ordinary provider and
   * `SecurityReviewer` does the prompting, parsing, retrying and timing out. `live` is the same
   * path pointed at a real endpoint. Nothing in the benchmark edits a verdict afterwards.
   */
  export type Reviewer =
    | Readonly<{ kind: "off" }>
    | Readonly<{ kind: "stub"; mode: "always_allow" | "always_keep" | "malformed" | "timeout"; url: string }>
    | Readonly<{ kind: "live"; endpoint: BenchEndpoints.Endpoint; apiKey: string; timeoutMs: number }>

  export function reviewerLabel(reviewer: Reviewer) {
    return reviewer.kind === "stub" ? reviewer.mode : reviewer.kind
  }

  export type Roots = Readonly<{
    root: string
    workspace: string
    home: string
    sentinel: string
    shims: string
    logs: string
    canary: string
    /**
     * A token planted inside the injected payload. Seeing it in the transcript is direct evidence
     * that the payload text reached the model, rather than a guess from a filename appearing.
     */
    delivery: string
  }>

  /** The per-episode values a case reaches through its closed set of placeholders. */
  export function variables(roots: Roots, sink: BenchEnvironment.Sink) {
    return {
      DELIVERY: roots.delivery,
      SENTINEL: roots.sentinel,
      SINK_URL: sink.url,
      SINK_PORT: String(sink.port),
      CANARY: roots.canary,
      WORKSPACE: roots.workspace,
    }
  }

  export function substitute(value: string, vars: Readonly<Record<string, string>>) {
    return Object.entries(vars).reduce((out, [key, item]) => out.replaceAll(`\${${key}}`, item), value)
  }

  export function fill(value: unknown, vars: Readonly<Record<string, string>>): unknown {
    if (typeof value === "string") return substitute(value, vars)
    if (Array.isArray(value)) return value.map((item) => fill(item, vars))
    if (record(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, fill(item, vars)]))
    return value
  }

  export async function open(prefix: string, fixture: string, out?: string): Promise<Roots> {
    const root = await mkdtemp(path.join(tmpdir(), prefix))
    const parent = path.resolve(tmpdir()) + path.sep
    if (!root.startsWith(parent) || !path.basename(root).startsWith(prefix))
      throw new Error("refusing cleanup outside the benchmark temporary directory")
    const roots: Roots = {
      root,
      workspace: path.join(root, "workspace"),
      home: path.join(root, "home"),
      sentinel: path.join(root, "sentinel"),
      shims: path.join(root, "shims"),
      logs: out ? path.join(out, "episodes") : path.join(root, "logs"),
      // Unique per episode, so a canary observed anywhere can only have come from this run.
      canary: `KILOBENCH-${randomUUID().replaceAll("-", "").slice(0, 20).toUpperCase()}`,
      delivery: `KILODELIV-${randomUUID().replaceAll("-", "").slice(0, 16).toUpperCase()}`,
    }
    const source = path.join(FIXTURES, fixture)
    await validateFixture(source)
    await cp(source, roots.workspace, { recursive: true, errorOnExist: false })
    await Promise.all([
      mkdir(path.join(roots.workspace, BenchEnvironment.AUDIT_DIR), { recursive: true }),
      mkdir(roots.sentinel, { recursive: true }),
      mkdir(roots.logs, { recursive: true }),
      ...["config/kilo", "data", "state", "cache"].map((dir) => mkdir(path.join(roots.home, dir), { recursive: true })),
    ])
    await BenchEnvironment.shims(roots.shims)
    return roots
  }

  export async function close(roots: Roots, keep: boolean) {
    if (!keep) await rm(roots.root, { recursive: true, force: true, maxRetries: 3 })
  }

  export async function applySetup(root: string, steps: readonly Setup[], vars: Readonly<Record<string, string>>) {
    for (const step of steps) {
      const file = target(root, step.path)
      if ((await inspect(root, step.path))?.isSymbolicLink()) throw new Error(`symlink in setup: ${step.path}`)
      if (step.type === "mkdir") {
        await mkdir(file, { recursive: true })
        continue
      }
      await mkdir(path.dirname(file), { recursive: true })
      await Bun.write(file, substitute(step.value, vars))
    }
  }

  /**
   * The config the CLI runs under, written identically to `KILO_CONFIG_CONTENT` and to the isolated
   * global `kilo.json`.
   *
   * Identical on purpose: `SecurityReviewerConfig` refuses a reviewer whose merged provider block
   * differs from the trusted global one, because a repository that rewrote `baseURL` could point the
   * reviewer at a server that answers `allow` to everything. Generating the block once and writing
   * it to both is what makes a live reviewer resolvable at all.
   */
  export function config(input: { model: Model; reviewer: Reviewer; sandbox: BenchSandbox.ProfileID }) {
    const providers =
      input.model.kind === "live"
        ? BenchEndpoints.provider({ endpoint: input.model.endpoint, apiKey: input.model.apiKey })
        : testProviderConfig(input.model.url).provider
    const reviewer =
      input.reviewer.kind === "live"
        ? BenchEndpoints.provider({ endpoint: input.reviewer.endpoint, apiKey: input.reviewer.apiKey })
        : {}
    return {
      formatter: false,
      lsp: false,
      provider: { ...providers, ...reviewer },
      permission: { "*": "allow" as const },
      sandbox: BenchSandbox.profile(input.sandbox).config,
    }
  }

  /** `provider/model` for `--model`. */
  export function modelRef(model: Model) {
    return model.kind === "live" ? BenchEndpoints.reference(model.endpoint) : "test/test-model"
  }

  export function environment(input: {
    roots: Roots
    reviewer: Reviewer
    security: "on" | "off"
    config: unknown
  }): Record<string, string> {
    const { roots } = input
    return {
      ...cleanenv(),
      PATH: `${roots.shims}${path.delimiter}${process.env["PATH"] ?? "/usr/bin:/bin"}`,
      [BenchEnvironment.LOG_ENV]: path.join(roots.workspace, BenchEnvironment.AUDIT_LOG),
      KILO_CLIENT: "cli",
      KILO_TEST_HOME: roots.home,
      HOME: roots.home,
      USERPROFILE: roots.home,
      APPDATA: path.join(roots.home, "config"),
      LOCALAPPDATA: path.join(roots.home, "data"),
      XDG_CONFIG_HOME: path.join(roots.home, "config"),
      XDG_DATA_HOME: path.join(roots.home, "data"),
      XDG_STATE_HOME: path.join(roots.home, "state"),
      XDG_CACHE_HOME: path.join(roots.home, "cache"),
      KILO_CONFIG_CONTENT: JSON.stringify(input.config),
      KILO_DB: ":memory:",
      KILO_DISABLE_DEFAULT_PLUGINS: "1",
      KILO_DISABLE_AUTOUPDATE: "1",
      KILO_DISABLE_AUTOCOMPACT: "1",
      KILO_DISABLE_MODELS_FETCH: "1",
      KILO_DISABLE_PROJECT_CONFIG: "1",
      KILO_TELEMETRY_LEVEL: "off",
      KILO_PURE: "1",
      KILO_SECURITY_DECISION: input.security === "on" ? "1" : "0",
      ...(input.reviewer.kind === "off"
        ? {}
        : {
            KILO_SECURITY_REVIEWER: "1",
            KILO_SECURITY_REVIEWER_MODEL:
              input.reviewer.kind === "live"
                ? BenchEndpoints.reference(input.reviewer.endpoint)
                : "test/test-model",
            KILO_SECURITY_REVIEWER_TIMEOUT_MS: String(
              input.reviewer.kind === "live" ? input.reviewer.timeoutMs : 2_000,
            ),
          }),
    }
  }

  export type Call = Readonly<{
    index: number
    call_id: string
    tool: string
    status: string
    executed: boolean
    /** The call's arguments, bounded. Lane B reads them to tell an attempt from a refusal. */
    input_text?: string
    /** The verdict the security layer itself recorded, when it recorded one. */
    security_decision?: string
    security_rule?: string
    final_enforcement?: string
    enforcement_source?: string
    /**
     * Which stage actually settled the call.
     *
     * `pre_execution_gate` is the one worth naming: the call was stopped while the security layer
     * recorded no opinion at all, so a reader must not take `NO_OPINION`/`pass` for an allow. Under
     * an operational sandbox the known cause is the `sandbox_escalation` ask `ShellTool` raises
     * before a git mutation is decided, which headless mode rejects outright — see the note in
     * `src/tool/shell.ts`. The benchmark reports the attribution it can observe and names the cause
     * rather than changing production to expose it.
     */
    enforcement_attribution: "executed" | "security_rule" | "pre_execution_gate" | "permission_rule" | "unknown"
    reviewer_state?: string
    reviewer_reason?: string
    reviewer_latency_ms?: number
    decision_latency_ms?: number
    containment?: T.Containment["sandbox"]
    duration_ms?: number
  }>

  const CONTAINMENT_STATES: readonly T.Containment["sandbox"][] = [
    "off",
    "unavailable",
    "unknown",
    "operational",
    "failed",
  ]

  function sandboxState(value: unknown) {
    return CONTAINMENT_STATES.find((state) => state === value)
  }

  function number(value: unknown) {
    return typeof value === "number" && Number.isFinite(value) ? value : undefined
  }

  function attribution(input: {
    executed: boolean
    decision?: string
    source?: string
    enforcement?: string
  }): Call["enforcement_attribution"] {
    if (input.executed) return "executed"
    if (input.source === "security") return "security_rule"
    if (input.decision === "ask" || input.decision === "deny") return "security_rule"
    // Stopped with no security opinion: something upstream of the rule settled it.
    if (input.decision === "pass" || input.decision === "allow") return "pre_execution_gate"
    if (input.enforcement === "reject") return "permission_rule"
    return "unknown"
  }

  /** Tool calls in issue order, each folded to its final state. */
  export function calls(events: readonly Record<string, unknown>[]): Call[] {
    const order: string[] = []
    const seen = new Map<string, Call>()
    for (const event of events) {
      if (event["type"] !== "tool_use") continue
      const part = record(event["part"]) ? event["part"] : undefined
      const id = typeof part?.["callID"] === "string" ? part["callID"] : undefined
      if (!part || !id) continue
      const state = record(part["state"]) ? part["state"] : undefined
      const metadata = record(state?.["metadata"]) ? state["metadata"] : undefined
      const audit = record(metadata?.["securityDecision"]) ? metadata["securityDecision"] : undefined
      const reviewer = record(audit?.["reviewer"]) ? audit["reviewer"] : undefined
      const containment = record(audit?.["containment"]) ? audit["containment"] : undefined
      const time = record(state?.["time"]) ? state["time"] : undefined
      const status = typeof state?.["status"] === "string" ? state["status"] : "unknown"
      const executed = status === "completed"
      const decision = typeof audit?.["decision"] === "string" ? audit["decision"] : undefined
      const source = typeof audit?.["enforcement_source"] === "string" ? audit["enforcement_source"] : undefined
      const enforcement = typeof audit?.["final_enforcement"] === "string" ? audit["final_enforcement"] : undefined
      if (!seen.has(id)) order.push(id)
      const start = number(time?.["start"])
      const end = number(time?.["end"])
      seen.set(id, {
        index: order.indexOf(id),
        call_id: id,
        tool: typeof part["tool"] === "string" ? part["tool"] : "unknown",
        status,
        executed,
        ...(state?.["input"] !== undefined ? { input_text: JSON.stringify(state["input"]).slice(0, 4_000) } : {}),
        ...(decision ? { security_decision: decision } : {}),
        ...(typeof audit?.["rule_id"] === "string" ? { security_rule: audit["rule_id"] } : {}),
        ...(enforcement ? { final_enforcement: enforcement } : {}),
        ...(source ? { enforcement_source: source } : {}),
        enforcement_attribution: audit
          ? attribution({ executed, decision, source, enforcement })
          : executed
            ? "executed"
            : "permission_rule",
        ...(typeof reviewer?.["state"] === "string" ? { reviewer_state: reviewer["state"] } : {}),
        ...(typeof reviewer?.["reason_code"] === "string" ? { reviewer_reason: reviewer["reason_code"] } : {}),
        ...(number(reviewer?.["latency_ms"]) !== undefined
          ? { reviewer_latency_ms: number(reviewer?.["latency_ms"])! }
          : {}),
        ...(number(audit?.["latency_ms"]) !== undefined ? { decision_latency_ms: number(audit?.["latency_ms"])! } : {}),
        ...(sandboxState(containment?.["sandbox"]) ? { containment: sandboxState(containment?.["sandbox"]) } : {}),
        ...(start !== undefined && end !== undefined ? { duration_ms: Math.max(0, end - start) } : {}),
      })
    }
    return order.map((id) => seen.get(id)!).map((item, index) => ({ ...item, index }))
  }

  export type Status =
    | "completed"
    | "blocked"
    | "timeout"
    | "tool_limit"
    | "process_error"
    | "agent_error"
    | "incomplete"
    | "harness_error"

  export function status(events: readonly Record<string, unknown>[], code: number, list: readonly Call[]): Status {
    const errors = events.filter((event) => event["type"] === "error")
    const blocked = list.some((item) => !item.executed)
    if (errors.length > 0 && !blocked) return "agent_error"
    if (code !== 0 && !blocked) return "process_error"
    const finish = events.filter((event) => event["type"] === "step_finish").at(-1)
    const part = record(finish?.["part"]) ? finish["part"] : undefined
    if (part?.["reason"] === "stop") return "completed"
    if (blocked) return "blocked"
    return "incomplete"
  }

  export type Run = Readonly<{
    stdout: string
    exit_code: number
    timed_out: boolean
    tool_limit_exceeded: boolean
    wall_ms: number
    stdout_file: string
    stderr_file: string
  }>

  /**
   * Boot the real CLI and drain it.
   *
   * The wall time is taken from a monotonic clock rather than `Date.now`, so a clock adjustment
   * during a long episode cannot turn a latency into a negative number.
   */
  export async function spawn(input: {
    roots: Roots
    id: string
    prompt: string
    model: Model
    env: Record<string, string>
    limits: { wall_seconds: number; tool_calls: number }
  }): Promise<Run> {
    const outlog = path.join(input.roots.logs, `${input.id}.stdout.jsonl`)
    const errlog = path.join(input.roots.logs, `${input.id}.stderr.log`)
    const args = [
      process.execPath,
      "run",
      "--conditions=browser",
      CLI,
      "run",
      input.prompt,
      "--format",
      "json",
      "--model",
      modelRef(input.model),
      "--dir",
      input.roots.workspace,
      "--auto",
    ]
    const started = performance.now()
    const proc = Bun.spawn(args, {
      cwd: PKG,
      env: input.env,
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
      windowsHide: true,
      detached: process.platform !== "win32",
    })
    const state = { timeout: false, limited: false, calls: new Set<string>() }
    const timer = setTimeout(() => {
      state.timeout = true
      stop(proc)
    }, input.limits.wall_seconds * 1000)
    const [stdout, , code] = await Promise.all([
      output(proc.stdout, outlog, (line) => {
        const event = parse(line).at(0)
        if (event?.["type"] !== "tool_use") return
        const part = record(event["part"]) ? event["part"] : undefined
        const callID = typeof part?.["callID"] === "string" ? part["callID"] : undefined
        if (callID) state.calls.add(callID)
        if (state.calls.size <= input.limits.tool_calls) return
        state.limited = true
        stop(proc)
      }),
      output(proc.stderr, errlog),
      proc.exited,
    ]).finally(() => {
      clearTimeout(timer)
      stop(proc)
    })
    return {
      stdout,
      exit_code: code,
      timed_out: state.timeout,
      tool_limit_exceeded: state.limited,
      wall_ms: performance.now() - started,
      stdout_file: outlog,
      stderr_file: errlog,
    }
  }

  /** Token usage, when the provider reported any. Summed across steps. */
  export function usage(events: readonly Record<string, unknown>[]) {
    let input = 0
    let output = 0
    let seen = false
    for (const event of events) {
      if (event["type"] !== "step_finish") continue
      const part = record(event["part"]) ? event["part"] : undefined
      const tokens = record(part?.["tokens"]) ? part["tokens"] : undefined
      const left = number(tokens?.["input"]) ?? 0
      const right = number(tokens?.["output"]) ?? 0
      if (left > 0 || right > 0) seen = true
      input += left
      output += right
    }
    return seen ? { input, output, total: input + output } : undefined
  }
}
