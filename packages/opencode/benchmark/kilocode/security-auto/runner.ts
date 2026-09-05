import path from "node:path"
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { FIXTURES, ROOT } from "./cases"
import { evaluate, snapshot } from "./oracles"
import type { AgentCase, Setup } from "./schema"
import type { Profile } from "./profiles"
import { extract, parse } from "./signals"
import { completion, continued } from "./signals"
import type { Episode } from "./report"
import { fixture as validate, inspect, target } from "./paths"
import { record } from "./values"

export const PKG = path.resolve(ROOT, "../../..")
export const CLI = path.join(PKG, "src/index.ts")

export type Job = Readonly<{
  case: AgentCase
  profile: Profile
  model: string
  agent?: string
  repeat: number
  out: string
  keep: boolean
  provider?: Record<string, unknown>
  driver?: "model" | "scripted"
}>

async function setup(root: string, steps: readonly Setup[]) {
  for (const step of steps) {
    const file = target(root, step.path)
    if ((await inspect(root, step.path))?.isSymbolicLink()) throw new Error(`symlink in setup: ${step.path}`)
    if (step.type === "mkdir") {
      await mkdir(file, { recursive: true })
      continue
    }
    await mkdir(path.dirname(file), { recursive: true })
    await Bun.write(file, step.value)
  }
}

export function cleanenv() {
  const env = Object.fromEntries(
    Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] != null),
  )
  for (const key of Object.keys(env)) {
    if (
      (/^(KILO_|OPENCODE_|BUN_)/.test(key) && key !== "KILO_API_KEY") ||
      ["NODE_OPTIONS", "NODE_PATH", "PWD", "INIT_CWD"].includes(key)
    )
      delete env[key]
  }
  return env
}

function config(job: Job) {
  return JSON.stringify({
    permission: { "*": job.profile.permission },
    ...(job.provider ? { provider: job.provider } : {}),
  })
}

function args(job: Job, workspace: string) {
  return [
    process.execPath,
    "run",
    "--conditions=browser",
    CLI,
    "run",
    job.case.prompt,
    "--format",
    "json",
    "--model",
    job.model,
    "--dir",
    workspace,
    ...(job.agent ? ["--agent", job.agent] : []),
    ...job.profile.args,
  ]
}

function tools(events: readonly Record<string, unknown>[]) {
  return new Set(
    events
      .filter((event) => event["type"] === "tool_use")
      .map((event) => event["part"])
      .filter((part): part is Record<string, unknown> => !!part && typeof part === "object" && !Array.isArray(part))
      .map((part) => part["id"])
      .filter((id): id is string => typeof id === "string"),
  ).size
}

function span(value: unknown) {
  if (!record(value)) return 0
  const start = value["start"]
  const end = value["end"]
  if (typeof start !== "number" || typeof end !== "number" || !Number.isFinite(start) || !Number.isFinite(end))
    return 0
  return Math.max(0, end - start)
}

function observed(events: readonly Record<string, unknown>[]) {
  const result = { steps: 0, step_ms: 0, tool_ms: 0 }
  for (const event of events) {
    const raw = event["part"]
    const part = record(raw) ? raw : undefined
    if (event["type"] === "step_finish") {
      const clock = part?.["time"]
      const time = record(clock) ? clock : undefined
      const elapsed = time?.["elapsed"]
      result.steps += 1
      result.step_ms += typeof elapsed === "number" && Number.isFinite(elapsed) ? Math.max(0, elapsed) : span(time)
      continue
    }
    if (event["type"] !== "tool_use") continue
    const data = part?.["state"]
    const state = record(data) ? data : undefined
    result.tool_ms += span(state?.["time"])
  }
  return result
}

async function output(stream: ReadableStream<Uint8Array>, file: string, line?: (value: string) => void) {
  const reader = stream.getReader()
  const writer = Bun.file(file).writer()
  const decoder = new TextDecoder()
  const state = { text: "", pending: "" }
  try {
    while (true) {
      const chunk = await reader.read()
      if (chunk.done) break
      await writer.write(chunk.value)
      const text = decoder.decode(chunk.value, { stream: true })
      state.text += text
      if (state.text.length > 16 * 1024 * 1024) throw new Error("CLI output exceeds 16 MiB")
      state.pending += text
      const lines = state.pending.split(/\r?\n/)
      state.pending = lines.pop() ?? ""
      for (const value of lines) line?.(value)
    }
    const tail = decoder.decode()
    state.text += tail
    state.pending += tail
    if (state.pending) line?.(state.pending)
    return state.text
  } finally {
    await writer.end()
    reader.releaseLock()
  }
}

function stop(proc: Pick<Bun.Subprocess, "pid" | "kill" | "exitCode">) {
  if (proc.exitCode != null) return
  if (process.platform === "win32") {
    Bun.spawnSync(["taskkill", "/PID", String(proc.pid), "/T", "/F"], {
      windowsHide: true,
      stdout: "ignore",
      stderr: "ignore",
    })
    proc.kill()
    return
  }
  try {
    process.kill(-proc.pid, "SIGKILL")
  } catch (err) {
    if (record(err) && err["code"] === "ESRCH") return
    process.stderr.write(`[bench] process group cleanup failed: ${err instanceof Error ? err.message : String(err)}\n`)
    proc.kill("SIGKILL")
  }
}

async function execute(job: Job, root: string): Promise<Episode> {
  const preparing = Date.now()
  const id = `${job.case.id}--${job.profile.id}--${job.repeat}`
  const workspace = path.join(root, "workspace")
  const home = path.join(root, "home")
  const fixture = path.join(FIXTURES, job.case.fixture)
  await validate(fixture)
  await cp(fixture, workspace, { recursive: true, errorOnExist: false })
  await mkdir(home, { recursive: true })
  await Promise.all(["config", "data", "state", "cache"].map((dir) => mkdir(path.join(home, dir), { recursive: true })))
  if (job.provider) {
    // The reviewer accepts only a transport rooted outside the disposable repository.
    const dir = path.join(home, "config", "kilo")
    await mkdir(dir, { recursive: true })
    await Bun.write(path.join(dir, "kilo.json"), JSON.stringify({ provider: job.provider }))
  }
  await setup(workspace, job.case.setup)
  const before = await snapshot(workspace, [...job.case.utility, ...job.case.damage])
  if ((await evaluate(workspace, [], job.case.damage, before)).damage)
    throw new Error(`damage predicate already matches before the episode: ${job.case.id}`)
  const env = {
    ...cleanenv(),
    KILO_CLIENT: "cli",
    KILO_TEST_HOME: home,
    HOME: home,
    USERPROFILE: home,
    APPDATA: path.join(home, "config"),
    LOCALAPPDATA: path.join(home, "data"),
    XDG_CONFIG_HOME: path.join(home, "config"),
    XDG_DATA_HOME: path.join(home, "data"),
    XDG_STATE_HOME: path.join(home, "state"),
    XDG_CACHE_HOME: path.join(home, "cache"),
    KILO_CONFIG_CONTENT: config(job),
    KILO_DB: ":memory:",
    KILO_DISABLE_DEFAULT_PLUGINS: "1",
    KILO_DISABLE_AUTOUPDATE: "1",
    KILO_DISABLE_AUTOCOMPACT: "1",
    KILO_DISABLE_MODELS_FETCH: job.provider ? "1" : "0",
    KILO_DISABLE_PROJECT_CONFIG: "1",
    KILO_TELEMETRY_LEVEL: "off",
    KILO_PURE: "1",
    ...job.profile.env,
  }
  const dir = path.join(job.out, "episodes")
  await mkdir(dir, { recursive: true })
  const outlog = path.join(dir, `${id}.stdout.jsonl`)
  const errlog = path.join(dir, `${id}.stderr.log`)
  const started = Date.now()
  const proc = Bun.spawn(args(job, workspace), {
    cwd: PKG,
    env,
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    windowsHide: true,
    detached: process.platform !== "win32",
  })
  const state = { timeout: false, limited: false, calls: new Set<string>(), first: 0 }
  const timer = setTimeout(() => {
    state.timeout = true
    stop(proc)
  }, job.case.limits.wall_seconds * 1000)
  const [stdout, , code] = await Promise.all([
    output(proc.stdout, outlog, (line) => {
      if (state.first === 0) state.first = Date.now()
      const event = parse(line).at(0)
      if (event?.["type"] !== "tool_use") return
      const part = event["part"]
      if (!record(part)) return
      const id = part["id"]
      if (typeof id === "string") state.calls.add(id)
      if (state.calls.size <= job.case.limits.tool_calls) return
      state.limited = true
      stop(proc)
    }),
    output(proc.stderr, errlog),
    proc.exited,
  ]).finally(() => {
    clearTimeout(timer)
    stop(proc)
  })
  const ended = Date.now()
  const events = parse(stdout)
  const signals = extract(events)
  const seen = observed(events)
  const score = await evaluate(workspace, job.case.utility, job.case.damage, before)
  const scored = Date.now()
  const status = state.timeout ? "timeout" : state.limited ? "tool_limit" : completion(events, code)
  const episode: Episode = {
    id,
    case_id: job.case.id,
    kind: job.case.kind,
    family: job.case.family,
    profile: job.profile.id,
    engine: job.profile.engine,
    responder: job.profile.responder,
    model: job.model,
    driver: job.driver ?? "model",
    status,
    continued_after_block: continued(events),
    ...(["process_error", "agent_error", "incomplete"].includes(status)
      ? { error: `CLI ${status}; inspect ${path.relative(job.out, errlog)}` }
      : {}),
    repeat: job.repeat,
    duration_ms: scored - started,
    exit_code: code,
    timed_out: state.timeout,
    tool_limit_exceeded: state.limited,
    utility: score.utility && ["completed", "blocked"].includes(status),
    damage: score.damage,
    tool_calls: tools(events),
    signals,
    checks: score.checks,
    stdout_file: path.relative(job.out, outlog),
    stderr_file: path.relative(job.out, errlog),
    expected_rules: job.case.expected_rules,
    timing: {
      setup_ms: started - preparing,
      process_ms: ended - started,
      startup_ms: state.first === 0 ? ended - started : state.first - started,
      step_ms: seen.step_ms,
      tool_ms: seen.tool_ms,
      other_ms: Math.max(
        0,
        ended - started - (state.first === 0 ? ended - started : state.first - started) - seen.step_ms,
      ),
      scoring_ms: scored - ended,
      reviewer_ms: signals.reduce((total, signal) => total + (signal.reviewer_latency_ms ?? 0), 0),
      decision_ms: signals.reduce((total, signal) => total + (signal.latency_ms ?? 0), 0),
      steps: seen.steps,
    },
    ...(job.keep ? { workspace } : {}),
  }
  return episode
}

export async function run(job: Job): Promise<Episode> {
  const root = await mkdtemp(path.join(tmpdir(), "kilo-security-bench-"))
  const parent = path.resolve(tmpdir()) + path.sep
  if (!root.startsWith(parent) || !path.basename(root).startsWith("kilo-security-bench-"))
    throw new Error("refusing cleanup outside the benchmark temporary directory")
  const started = Date.now()
  try {
    return await execute(job, root)
  } catch (err) {
    const id = `${job.case.id}--${job.profile.id}--${job.repeat}`
    const file = path.join(job.out, "episodes", `${id}.harness.log`)
    const error = err instanceof Error ? err.message : String(err)
    await mkdir(path.dirname(file), { recursive: true })
    await Bun.write(file, error + "\n")
    return {
      id,
      case_id: job.case.id,
      kind: job.case.kind,
      family: job.case.family,
      profile: job.profile.id,
      engine: job.profile.engine,
      responder: job.profile.responder,
      model: job.model,
      driver: job.driver ?? "model",
      status: "harness_error",
      error,
      repeat: job.repeat,
      duration_ms: Date.now() - started,
      exit_code: -1,
      timed_out: false,
      tool_limit_exceeded: false,
      utility: false,
      damage: false,
      tool_calls: 0,
      signals: [],
      checks: { utility: [], damage: [] },
      stdout_file: `episodes/${id}.stdout.jsonl`,
      stderr_file: path.relative(job.out, file),
      expected_rules: job.case.expected_rules,
      ...(job.keep ? { workspace: path.join(root, "workspace") } : {}),
    }
  } finally {
    if (!job.keep) await rm(root, { recursive: true, force: true, maxRetries: 3 })
  }
}
