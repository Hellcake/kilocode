import path from "node:path"
import { appendFile, mkdir } from "node:fs/promises"
import { parseArgs } from "node:util"
import { agents, lane1, load, ROOT } from "./cases"
import {
  REVIEWER_MODES,
  compareReviewers,
  reviewerPopulation,
  disposeA1,
  runA1Suite,
  summarizeA1,
  type ReviewerMode,
} from "./lane-a1"
import { list, get } from "./profiles"
import { invalid, markdown, summarize, read, type Episode } from "./report"
import { CLI, PKG, cleanenv, run as episode, type Job } from "./runner"
import { fixture, target } from "./paths"
import { record } from "./values"
import { continued, parse } from "./signals"
import { fingerprint } from "./fingerprint"
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
    // Defaults to the deterministic baseline. A run that did not ask for a reviewer must not get
    // one: standing a permissive reviewer behind the layer by default would report a more
    // autonomous system than the caller asked to measure.
    reviewer: { type: "string", default: "off" },
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
  schema: "kilo.security-bench-run/v2"
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
  process.stdout.write(
    `  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts a1 [--reviewer MODE] [--out dir]\n`,
  )
  process.stdout.write(`  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts coverage [--out dir]\n`)
  process.stdout.write(`  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts profiles\n`)
  process.stdout.write(`  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts doctor\n`)
  process.stdout.write(
    `  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts run --model provider/model [options]\n\n`,
  )
  process.stdout.write(
    `  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts report --input results/episodes.jsonl\n\n`,
  )
  process.stdout.write(
    `Options: --suite smoke|full --profiles a,b --repeat N --workers N --case id[,id...] --out dir --keep\n` +
      `         --reviewer off|always_allow|always_keep|malformed|timeout\n`,
  )
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
    const a1 = lane1(cases)
    // A `synthetic-facts` case bypasses the production normalization path on purpose. It may exist,
    // but it must never be counted as production-path coverage, so it is rejected here for now.
    const synthetic = a1.filter((item) => item.entry !== "shell")
    if (synthetic.length > 0)
      throw new Error(`A1 cases must use a production entry; synthetic-facts found: ${synthetic.map((i) => i.id).join(", ")}`)
    const mapped = matrix(cases)
    process.stdout.write(
      `validated ${agents(cases).length} agent cases, ${a1.length} A1 cases ` +
        `(${a1.filter((item) => item.kind === "attack").length} attack, ${a1.filter((item) => item.kind === "benign").length} benign), ` +
        `${mapped.classes} threat classes, ${mapped.routes} routes, ${mapped.deferred} deferred groups, ${mapped.gaps} known gaps\n`,
    )
    return
  }
  if (command === "a1") {
    const requested = REVIEWER_MODES.find((mode) => mode === parsed.values.reviewer)
    if (!requested) throw new Error(`--reviewer must be one of ${REVIEWER_MODES.join(", ")}`)
    const items = lane1(cases)
    const modes = requested === "off" ? (["off"] as const) : ([("off" as const), requested] as const)
    const runs = new Map<ReviewerMode, Awaited<ReturnType<typeof runA1Suite>>>()
    try {
      for (const mode of modes) runs.set(mode, await runA1Suite(items, mode))
    } finally {
      await disposeA1()
    }
    const summary = summarizeA1(items, runs.get(requested)!)
    const population = reviewerPopulation(items, runs.get(requested)!)
    const report = {
      schema: "kilo.security-bench-a1/v1",
      created_at: new Date().toISOString(),
      git_sha: sha(),
      dirty: dirty(),
      bun: Bun.version,
      platform: process.platform,
      reviewer_mode: requested,
      summary,
      reviewer_population: population,
      ...(requested === "off" ? {} : { delta_from_off: compareReviewers(items, runs.get("off")!, runs.get(requested)!) }),
    }
    // Always a file. The permission scan logs resolved paths to stdout, so a report printed there
    // would arrive interleaved with them and unparseable.
    const out = path.resolve(parsed.values.out ?? path.join(ROOT, ".artifacts", stamp()))
    await mkdir(out, { recursive: true })
    const file = path.join(out, `a1-${requested}.json`)
    await Bun.write(file, JSON.stringify(report, null, 2) + "\n")
    process.stderr.write(`[bench] A1 reviewer=${requested} -> ${file}\n`)
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
  // `selftest` (the scripted driver) returns in Block 5 with the tool script moved into the case
  // file. Until then the only episode driver is a live model, and it has to be named.
  if (command !== "run") throw new Error(`unknown command: ${command}`)
  if (!parsed.values.model) throw new Error("--model provider/model is required for agent runs")
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
  const requested = parsed.values["case"]?.split(",").map((item) => item.trim())
  if (requested?.some((item) => !item) || (requested && new Set(requested).size !== requested.length))
    throw new Error("case ids must be non-empty and unique")
  const selected = agents(cases).filter((item) => {
    if (requested) return requested.includes(item.id)
    if (parsed.values.suite === "smoke") return item.smoke
    if (parsed.values.suite === "full") return true
    throw new Error("suite must be smoke or full")
  })
  const missing = requested?.filter((id) => !selected.some((item) => item.id === id)) ?? []
  if (missing.length > 0) throw new Error(`unknown case ids: ${missing.join(", ")}`)
  if (selected.length === 0) throw new Error("no cases matched")
  const model = parsed.values.model
  const driver = "model" as const
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
          provider: record(provider) ? provider : undefined,
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
    schema: "kilo.security-bench-run/v2",
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
}

await main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`)
  process.exitCode = 1
})
