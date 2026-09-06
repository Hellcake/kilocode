import path from "node:path"
import { appendFile, mkdir } from "node:fs/promises"
import { parseArgs } from "node:util"
import { agents, lane1, load, ROOT } from "./cases"
import {
  REVIEWER_MODES,
  compareReviewers,
  compareSandbox,
  preflightA1,
  reviewerPopulation,
  disposeA1,
  runA1Suite,
  summarizeA1,
  type A1Result,
  type ReviewerMode,
} from "./lane-a1"
import { BenchSandbox } from "./sandbox"
import { list, get } from "./profiles"
import { invalid, markdown, summarize, read, type Episode } from "./report"
import { CLI, PKG, cleanenv, run as episode, type Job } from "./runner"
import { fixture, target } from "./paths"
import { record } from "./values"
import { continued, parse } from "./signals"
import { fingerprint } from "./fingerprint"
import { c1Coverage, markdown as coverage, validate as matrix } from "./coverage"

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
    // Same reasoning: an unstated sandbox axis resolves to the weaker claim. A contained result is
    // only produced when the caller asked for one and the preflight proved it.
    sandbox: { type: "string", default: "no-sandbox" },
  },
})

/** Set by the commands that load an instance context. See the note at the end of this file. */
let exiting = false

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

function sha(paths?: readonly string[]) {
  const args = paths ? ["log", "-1", "--format=%H", "--", ...paths] : ["rev-parse", "HEAD"]
  const proc = Bun.spawnSync(["git", ...args], { cwd: PKG, stdout: "pipe", stderr: "pipe", windowsHide: true })
  if (proc.exitCode !== 0) return "unknown"
  return proc.stdout.toString().trim() || "unknown"
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
    `  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts preflight [--out dir]\n`,
  )
  process.stdout.write(
    `  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts a1 [--sandbox ID] [--reviewer MODE] [--out dir]\n`,
  )
  process.stdout.write(`  bun packages/opencode/benchmark/kilocode/security-auto/bench.ts matrix [--out dir]\n`)
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
      `         --reviewer off|always_allow|always_keep|malformed|timeout --sandbox no-sandbox|contained-deny\n`,
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

/**
 * What a report has to carry to be attributable.
 *
 * Production and benchmark are dated separately on purpose: they live in one repository, so a single
 * HEAD cannot say whether a number moved because the dataset grew or because the security layer did.
 */
function provenanceBase() {
  return {
    created_at: new Date().toISOString(),
    lane: "A1" as const,
    basis: "prospective-simulation" as const,
    git_sha: sha(),
    production_sha: sha(["src/kilocode/security-decision", "src/kilocode/sandbox", "src/permission", "src/kilocode/permission"]),
    benchmark_sha: sha(["benchmark/kilocode/security-auto", "test/kilocode/security-benchmark"]),
    dirty: dirty(),
    bun: Bun.version,
    platform: process.platform,
    backend: BenchSandbox.backend(),
  }
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
        `${mapped.classes} threat classes, ${mapped.routes} routes, ` +
        `${mapped.deferred} deferred and ${mapped.conditional} conditional groups, ${mapped.gaps} known gaps\n`,
    )
    return
  }
  if (command === "a1" || command === "matrix" || command === "preflight") {
    exiting = true
    const items = lane1(cases)
    if (command === "preflight") {
      const reports = await Promise.all(BenchSandbox.PROFILE_IDS.map(preflightA1)).finally(disposeA1)
      const out = path.resolve(parsed.values.out ?? path.join(ROOT, ".artifacts", stamp()))
      await mkdir(out, { recursive: true })
      const file = path.join(out, "preflight.json")
      await Bun.write(file, JSON.stringify({ schema: "kilo.security-bench-preflight/v1", ...provenanceBase(), reports }, null, 2) + "\n")
      for (const report of reports)
        process.stderr.write(
          `[bench] ${report.profile}: ${report.state} (${report.backend}, network=${report.network})` +
            report.probes.map((probe) => `\n         ${probe.ok ? "ok  " : "FAIL"} ${probe.id}${probe.detail ? ` — ${probe.detail}` : ""}`).join("") +
            `\n`,
        )
      process.stderr.write(`[bench] preflight -> ${file}\n`)
      return
    }
    const requestedReviewer = REVIEWER_MODES.find((mode) => mode === parsed.values.reviewer)
    if (!requestedReviewer) throw new Error(`--reviewer must be one of ${REVIEWER_MODES.join(", ")}`)
    const requestedSandbox = BenchSandbox.PROFILE_IDS.find((id) => id === parsed.values.sandbox)
    if (!requestedSandbox) throw new Error(`--sandbox must be one of ${BenchSandbox.PROFILE_IDS.join(", ")}`)
    // The matrix is fixed rather than a cross product: `off` needs only the two reviewer modes that
    // bracket it, while every reviewer mode is worth running against a proven sandbox because that
    // is where a reviewer is handed a population it did not have before.
    const cells: ReadonlyArray<{ sandbox: BenchSandbox.ProfileID; reviewer: ReviewerMode }> =
      command === "matrix"
        ? [
            { sandbox: "no-sandbox", reviewer: "off" },
            { sandbox: "no-sandbox", reviewer: "always_allow" },
            { sandbox: "contained-deny", reviewer: "off" },
            { sandbox: "contained-deny", reviewer: "always_allow" },
            { sandbox: "contained-deny", reviewer: "always_keep" },
            { sandbox: "contained-deny", reviewer: "malformed" },
            { sandbox: "contained-deny", reviewer: "timeout" },
          ]
        : // The baselines a single run needs to mean anything: `off` on the same sandbox, so the
          // reviewer delta is available, and `no-sandbox` on the same reviewer, so the sandbox
          // delta is. A cell reported without the row it is a delta against is just a number.
          [...new Set<BenchSandbox.ProfileID>(["no-sandbox", requestedSandbox])].flatMap<{
            sandbox: BenchSandbox.ProfileID
            reviewer: ReviewerMode
          }>((sandbox) =>
            [...new Set<ReviewerMode>(["off", requestedReviewer])].map((reviewer) => ({ sandbox, reviewer })),
          )
    const key = (cell: { sandbox: BenchSandbox.ProfileID; reviewer: ReviewerMode }) => `${cell.sandbox}/${cell.reviewer}`
    const runs = new Map<string, Map<string, A1Result>>()
    const preflights = new Map<BenchSandbox.ProfileID, BenchSandbox.Preflight>()
    const skipped: Array<{ cell: string; reason: string }> = []
    try {
      for (const id of new Set(cells.map((cell) => cell.sandbox))) preflights.set(id, await preflightA1(id))
      for (const cell of cells) {
        const preflight = preflights.get(cell.sandbox)!
        // A contained cell is only run on proven confinement. `failed` aborts the whole run rather
        // than the cell: a machine whose sandbox is configured and broken is not a machine whose
        // uncontained numbers should be published as if nothing were wrong.
        if (preflight.state === "failed")
          throw new Error(`sandbox preflight failed for ${cell.sandbox}; refusing to report a contained run`)
        if (cell.sandbox !== "no-sandbox" && !BenchSandbox.proven(preflight)) {
          skipped.push({ cell: key(cell), reason: `containment is ${preflight.state}, not operational` })
          continue
        }
        runs.set(key(cell), await runA1Suite(items, cell.reviewer, cell.sandbox))
      }
    } finally {
      await disposeA1()
    }
    const executed = cells.filter((cell) => runs.has(key(cell)))
    const summaries = executed.map((cell) => ({ cell: key(cell), ...summarizeA1(items, runs.get(key(cell))!) }))
    const populations = executed.map((cell) => ({ cell: key(cell), ...reviewerPopulation(items, runs.get(key(cell))!) }))
    // Same reviewer on both sides of the comparison: a delta that also moved the reviewer would not
    // say which axis produced it.
    const sandboxDeltas = executed
      .filter((cell) => cell.sandbox === "contained-deny" && runs.has(`no-sandbox/${cell.reviewer}`))
      .map((cell) =>
        compareSandbox(items, runs.get(`no-sandbox/${cell.reviewer}`)!, runs.get(key(cell))!),
      )
    const reviewerDeltas = executed
      .filter((cell) => cell.reviewer !== "off" && runs.has(`${cell.sandbox}/off`))
      .map((cell) => ({
        sandbox: cell.sandbox,
        ...compareReviewers(items, runs.get(`${cell.sandbox}/off`)!, runs.get(key(cell))!),
      }))
    const contained = summaries.find((item) => item.sandbox_profile === "contained-deny")
    const coverage = c1Coverage({
      sandbox_enabled: BenchSandbox.profile("contained-deny").config.enabled === true,
      preflight_state: preflights.get("contained-deny")?.state ?? "unavailable",
      probes: preflights.get("contained-deny")?.probes ?? [],
      containment: contained?.containment ?? "off",
      cases,
    })
    const report = {
      schema: "kilo.security-bench-a1/v2",
      ...provenanceBase(),
      preflight: [...preflights.values()],
      skipped,
      summaries,
      reviewer_populations: populations,
      sandbox_deltas: sandboxDeltas,
      reviewer_deltas: reviewerDeltas,
      c1_coverage: coverage,
    }
    const out = path.resolve(parsed.values.out ?? path.join(ROOT, ".artifacts", stamp()))
    await mkdir(out, { recursive: true })
    // Always a file. The permission scan logs resolved paths to stdout, so a report printed there
    // would arrive interleaved with them and unparseable.
    const file = path.join(out, command === "matrix" ? "a1-matrix.json" : `a1-${requestedSandbox}-${requestedReviewer}.json`)
    await Bun.write(file, JSON.stringify(report, null, 2) + "\n")
    for (const item of summaries)
      process.stderr.write(
        `[bench] ${item.cell.padEnd(28)} containment=${item.containment.padEnd(12)} auto_allowed=${item.auto_allowed} ` +
          `reviewable=${item.reviewer_exposure} reviewer_calls=${item.reviewer_calls} ` +
          `unsafe_auto_approvals=${item.prospective_unsafe_auto_approvals}\n`,
      )
    for (const item of skipped) process.stderr.write(`[bench] skipped ${item.cell}: ${item.reason}\n`)
    process.stderr.write(`[bench] C1 ${coverage.status}${coverage.missing.length ? ` (missing: ${coverage.missing.join(", ")})` : ""}\n`)
    process.stderr.write(`[bench] -> ${file}\n`)
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

// The lane's disposal releases everything it owns — `process.getActiveResourcesInfo()` is empty
// here — and the process still does not return, because loading an instance context leaves a native
// handle Bun does not surface. Every artifact is written and awaited before this point, and Bun
// flushes its standard streams on exit, so ending explicitly costs nothing and is the difference
// between a CLI and a command that has to be killed.
if (exiting) process.exit(process.exitCode ?? 0)
