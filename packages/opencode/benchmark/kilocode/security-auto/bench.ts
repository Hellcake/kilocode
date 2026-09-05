import path from "node:path"
import { appendFile, mkdir } from "node:fs/promises"
import { parseArgs } from "node:util"
import { agents, load, replays, ROOT } from "./cases"
import { list, get } from "./profiles"
import { run as replay } from "./replay"
import { invalid, markdown, summarize, read, type Episode } from "./report"
import { CLI, PKG, cleanenv, run as episode, type Job } from "./runner"
import { fixture, target } from "./paths"
import { SecurityInputSchema } from "./schema"
import { record } from "./values"
import { start } from "./probe"
import { continued, parse } from "./signals"
import { fingerprint } from "./fingerprint"
import { measure, table, corpus } from "./corpus"
import { markdown as coverage, validate as matrix } from "./coverage"

const parsed = parseArgs({
  allowPositionals: true,
  options: {
    suite: { type: "string", default: "smoke" },
    profiles: { type: "string", default: "unsafe,security-auto" },
    model: { type: "string" },
    agent: { type: "string" },
    repeat: { type: "string", default: "1" },
    workers: { type: "string", default: "1" },
    out: { type: "string" },
    input: { type: "string" },
    case: { type: "string" },
    keep: { type: "boolean", default: false },
    help: { type: "boolean", short: "h", default: false },
    "provider-config": { type: "string" },
    "wall-seconds": { type: "string" },
    "human-seconds": { type: "string", default: "15" },
  },
})

function number(value: string, name: string) {
  const parsed = /^\d+$/.test(value) ? Number(value) : NaN
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`${name} must be a positive integer`)
  return parsed
}

function stamp() {
  return new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-")
}

type Manifest = Readonly<{
  schema: "kilo.security-bench-run/v1"
  created_at: string
  git_sha: string
  bun: string
  platform: string
  arch: string
  model: string
  profiles: readonly string[]
  cases: readonly string[]
  repeat: number
  workers: number
  driver: "model" | "scripted"
  fingerprint: string
  fingerprint_files: number
  dirty: boolean
  human_decision_seconds: number
  provider_config_sha256?: string
}>

async function reports(out: string, episodes: readonly Episode[], human: number) {
  await mkdir(out, { recursive: true })
  const summary = summarize(episodes, human)
  await Promise.all([
    Bun.write(path.join(out, "summary.json"), JSON.stringify(summary, null, 2) + "\n"),
    Bun.write(path.join(out, "report.md"), markdown(summary)),
  ])
}

function sha() {
  const proc = Bun.spawnSync(["git", "rev-parse", "HEAD"], { cwd: PKG, stdout: "pipe", windowsHide: true })
  if (proc.exitCode !== 0) return "unknown"
  return proc.stdout.toString().trim()
}

function dirty() {
  const proc = Bun.spawnSync(
    [
      "git",
      "-c",
      "filter.lfs.process=",
      "-c",
      "filter.lfs.required=false",
      "status",
      "--porcelain",
      "--",
      "packages/opencode",
    ],
    {
      cwd: path.resolve(PKG, "../.."),
      stdout: "pipe",
      stderr: "pipe",
      windowsHide: true,
    },
  )
  return proc.exitCode !== 0 || proc.stdout.toString().trim().length > 0
}

async function pool(jobs: Job[], workers: number, out: string, human: number) {
  const queue = [...jobs]
  const results: Episode[] = []
  const sink = { pending: Promise.resolve() }
  const work = async () => {
    const output: Episode[] = []
    while (true) {
      const job = queue.shift()
      if (!job) return output
      process.stderr.write(`[bench] ${job.case.id} profile=${job.profile.id} repeat=${job.repeat}\n`)
      const result = await episode(job)
      output.push(result)
      sink.pending = sink.pending.then(async () => {
        results.push(result)
        await appendFile(path.join(out, "episodes.jsonl"), JSON.stringify(result) + "\n")
        await reports(out, results, human)
      })
      await sink.pending
      process.stderr.write(
        `[bench] ${result.id}: ${result.status}, utility=${result.utility}, damage=${result.damage}\n`,
      )
    }
  }
  return (await Promise.all(Array.from({ length: Math.min(workers, jobs.length) }, work))).flat()
}

function help() {
  process.stdout.write(`Security auto-mode benchmark\n\n`)
  process.stdout.write(`  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts validate\n`)
  process.stdout.write(`  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts replay\n`)
  process.stdout.write(`  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts corpus\n`)
  process.stdout.write(`  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts coverage [--out dir]\n`)
  process.stdout.write(`  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts profiles\n`)
  process.stdout.write(`  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts doctor\n`)
  process.stdout.write(`  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts selftest [options]\n`)
  process.stdout.write(
    `  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts run --model provider/model [options]\n\n`,
  )
  process.stdout.write(
    `  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts report --input results/episodes.jsonl\n\n`,
  )
  process.stdout.write(`Options: --suite smoke|full --profiles a,b --repeat N --workers N --case id --out dir --keep\n`)
  process.stdout.write(`         --provider-config file.json --wall-seconds N --human-seconds N\n`)
}

async function doctor() {
  process.stdout.write(`[ok] Bun ${Bun.version}\n`)
  const proc = Bun.spawn([process.execPath, "run", "--conditions=browser", CLI, "--help"], {
    cwd: PKG,
    env: { ...cleanenv(), KILO_DISABLE_DEFAULT_PLUGINS: "1", KILO_PURE: "1", KILO_DISABLE_PROJECT_CONFIG: "1" },
    stdin: "ignore",
    windowsHide: true,
    stdout: "pipe",
    stderr: "pipe",
  })
  const timer = setTimeout(() => proc.kill(), 30_000)
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]).finally(() => clearTimeout(timer))
  if (code === 0) {
    process.stdout.write(`[ok] Local Kilo CLI boots from ${CLI}\n`)
    process.stdout.write(`[next] Run a smoke matrix with --model provider/model\n`)
    return
  }
  process.stderr.write(`[fail] Local Kilo CLI did not boot (exit ${code})\n`)
  const detail = (stderr || stdout).trim().split(/\r?\n/).slice(-8).join("\n")
  if (detail) process.stderr.write(`${detail}\n`)
  process.stderr.write(`[fix] Install this worktree's dependencies with: bun install --frozen-lockfile\n`)
  process.exitCode = 1
}

async function main() {
  if (parsed.positionals.length > 1) throw new Error("expected one command; use --help")
  const command = parsed.values.help ? "help" : (parsed.positionals.at(0) ?? "help")
  const human = number(parsed.values["human-seconds"], "human-seconds") * 1_000
  if (command === "help") return help()
  if (command === "doctor") return doctor()
  if (command === "profiles") {
    for (const profile of list()) process.stdout.write(`${profile.id}\t${profile.description}\n`)
    return
  }
  if (command === "report") {
    if (!parsed.values.input) throw new Error("--input episodes.jsonl is required")
    const input = path.resolve(parsed.values.input)
    const episodes = await Promise.all(
      read(await Bun.file(input).text()).map(async (item) => {
        if (item.continued_after_block != null) return item
        const file = Bun.file(target(path.dirname(input), item.stdout_file))
        return { ...item, continued_after_block: (await file.exists()) ? continued(parse(await file.text())) : false }
      }),
    )
    const out = path.resolve(parsed.values.out ?? path.dirname(input))
    await reports(out, episodes, human)
    process.stdout.write(`${path.join(out, "report.md")}\n`)
    return
  }
  const cases = await load()
  if (command === "validate") {
    await Promise.all(agents(cases).map((item) => fixture(path.join(ROOT, "fixtures", item.fixture))))
    for (const item of replays(cases)) SecurityInputSchema.parse(item.input)
    const mapped = matrix(cases)
    if (corpus.length !== 75) throw new Error(`command corpus must contain 75 entries, found ${corpus.length}`)
    const measured = measure()
    if (measured.some((item) => item.violations.length > 0))
      throw new Error(`risky corpus actions auto-passed: ${measured.flatMap((item) => item.violations).join(", ")}`)
    process.stdout.write(
      `validated ${cases.length} cases (${agents(cases).length} agent, ${replays(cases).length} replay), ${corpus.length} corpus actions, ${mapped.classes} threat classes, ${mapped.routes} routes\n`,
    )
    return
  }
  if (command === "corpus") {
    const results = measure()
    process.stdout.write(table(results))
    if (results.some((item) => item.violations.length > 0)) process.exitCode = 1
    return
  }
  if (command === "coverage") {
    const text = coverage(cases)
    if (!parsed.values.out) {
      process.stdout.write(text)
      return
    }
    const out = path.resolve(parsed.values.out)
    await mkdir(out, { recursive: true })
    const file = path.join(out, "coverage.md")
    await Bun.write(file, text)
    process.stdout.write(`${file}\n`)
    return
  }
  if (command === "replay") {
    const results = replay(replays(cases))
    for (const result of results) {
      process.stdout.write(
        `${result.passed ? "PASS" : "FAIL"} ${result.id} ${result.actual.decision} ${result.actual.rule_id}\n`,
      )
    }
    if (results.some((item) => !item.passed)) process.exitCode = 1
    return
  }
  if (command !== "run" && command !== "selftest") throw new Error(`unknown command: ${command}`)
  if (command === "run" && !parsed.values.model) throw new Error("--model provider/model is required for agent runs")
  if (!["smoke", "full"].includes(parsed.values.suite)) throw new Error("suite must be smoke or full")
  const names = parsed.values.profiles.split(",").map((name) => name.trim())
  if (names.some((name) => !name) || new Set(names).size !== names.length)
    throw new Error("profiles must be non-empty and unique")
  const out = path.resolve(parsed.values.out ?? path.join(ROOT, ".artifacts", stamp()))
  const profiles = names.map(get)
  const repeat = number(parsed.values.repeat, "repeat")
  const workers = number(parsed.values.workers, "workers")
  const seconds = parsed.values["wall-seconds"] ? number(parsed.values["wall-seconds"], "wall-seconds") : undefined
  const provider = parsed.values["provider-config"]
    ? ((await Bun.file(path.resolve(parsed.values["provider-config"])).json()) as unknown)
    : undefined
  if (provider != null && (!record(provider) || Object.keys(provider).length === 0))
    throw new Error("provider-config must contain a non-empty provider map (see README)")
  const selected = agents(cases).filter((item) => {
    if (parsed.values["case"]) return item.id === parsed.values["case"]
    if (parsed.values.suite === "smoke") return item.smoke
    if (parsed.values.suite === "full") return true
    throw new Error("suite must be smoke or full")
  })
  if (selected.length === 0) throw new Error("no cases matched")
  const probe = command === "selftest" ? start() : undefined
  const model = probe ? "benchmark/probe" : parsed.values.model!
  const driver = probe ? "scripted" : "model"
  try {
    const jobs: Job[] = selected.flatMap((item) =>
      profiles.flatMap((profile) =>
        Array.from(
          { length: repeat },
          (_, index): Job => ({
            case: seconds ? { ...item, limits: { ...item.limits, wall_seconds: seconds } } : item,
            profile,
            model,
            driver,
            agent: parsed.values.agent,
            repeat: index + 1,
            out,
            keep: parsed.values.keep,
            provider: probe?.provider(item.id) ?? (record(provider) ? provider : undefined),
          }),
        ),
      ),
    )
    if (
      (await Bun.file(path.join(out, "manifest.json")).exists()) ||
      (await Bun.file(path.join(out, "episodes.jsonl")).exists())
    )
      throw new Error(`output already contains a run: ${out}`)
    await mkdir(out, { recursive: true })
    const source = await fingerprint(PKG)
    const manifest: Manifest = {
      schema: "kilo.security-bench-run/v1",
      created_at: new Date().toISOString(),
      git_sha: sha(),
      bun: Bun.version,
      platform: process.platform,
      arch: process.arch,
      model,
      profiles: profiles.map((item) => item.id),
      cases: selected.map((item) => item.id),
      repeat,
      workers,
      driver,
      fingerprint: source.digest,
      fingerprint_files: source.files,
      dirty: dirty(),
      human_decision_seconds: human / 1_000,
      ...(provider
        ? { provider_config_sha256: new Bun.CryptoHasher("sha256").update(JSON.stringify(provider)).digest("hex") }
        : {}),
    }
    await Bun.write(path.join(out, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n")
    await Bun.write(path.join(out, "episodes.jsonl"), "")
    const episodes = await pool(jobs, workers, out, human)
    if (episodes.some(invalid) || summarize(episodes).some((item) => item.auto_bypass_violations > 0))
      process.exitCode = 1
    process.stdout.write(`${path.join(out, "report.md")}\n`)
  } finally {
    await probe?.stop()
  }
}

await main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`)
  process.exitCode = 1
})
