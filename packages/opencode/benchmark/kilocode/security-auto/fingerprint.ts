import path from "node:path"

// Scan each pattern separately: Bun's Windows glob did not expand the original brace union.
const BENCHMARK = [
  "benchmark/kilocode/security-auto/*.ts",
  "benchmark/kilocode/security-auto/cases/**/*.json",
  "benchmark/kilocode/security-auto/fixtures/**/*",
]

/**
 * The production code a result may be attributed to.
 *
 * Kept apart from the benchmark's own sources so a report can say which half moved: a number that
 * changed because the dataset grew is a different fact from one that changed because the security
 * layer did, and a single combined digest cannot tell them apart.
 */
const PRODUCTION = [
  "src/kilocode/security-decision/*.ts",
  "src/kilocode/sandbox/*.ts",
  "src/kilocode/permission/*.ts",
  "src/permission/**/*.ts",
  "src/cli/cmd/run.ts",
  "src/kilocode/tool/shell-security-facts.ts",
]

async function digest(root: string, patterns: readonly string[]) {
  const matches = await Promise.all(
    patterns.map((pattern) => Array.fromAsync(new Bun.Glob(pattern).scan({ cwd: root, onlyFiles: true }))),
  )
  const files = [...new Set(matches.flat())].sort()
  if (files.length === 0) throw new Error("no sources found for fingerprint")
  const hash = new Bun.CryptoHasher("sha256")
  for (const file of files)
    hash.update(file.replaceAll("\\", "/") + "\0").update(await Bun.file(path.join(root, file)).arrayBuffer())
  return { digest: hash.digest("hex"), files: files.length }
}

export async function fingerprint(root: string) {
  const [benchmark, production] = await Promise.all([digest(root, BENCHMARK), digest(root, PRODUCTION)])
  const combined = new Bun.CryptoHasher("sha256").update(benchmark.digest).update(production.digest).digest("hex")
  return {
    digest: combined,
    files: benchmark.files + production.files,
    benchmark: benchmark.digest,
    benchmark_files: benchmark.files,
    production: production.digest,
    production_files: production.files,
  }
}

/** Repository-relative paths the two fingerprints cover, for a report that has to name its subject. */
export const SOURCES = { benchmark: BENCHMARK, production: PRODUCTION }
