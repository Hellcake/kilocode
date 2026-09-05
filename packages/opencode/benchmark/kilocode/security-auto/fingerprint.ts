import path from "node:path"

// Scan each pattern separately: Bun's Windows glob did not expand the original brace union.
export async function fingerprint(root: string) {
  const patterns = [
    "benchmark/kilocode/security-auto/*.ts",
    "benchmark/kilocode/security-auto/cases/**/*.json",
    "benchmark/kilocode/security-auto/fixtures/**/*",
    "src/kilocode/security-decision/*.ts",
    "src/kilocode/permission/*.ts",
    "src/permission/**/*.ts",
    "src/cli/cmd/run.ts",
    "src/kilocode/tool/shell-security-facts.ts",
  ]
  const matches = await Promise.all(
    patterns.map((pattern) => Array.fromAsync(new Bun.Glob(pattern).scan({ cwd: root, onlyFiles: true }))),
  )
  const files = [...new Set(matches.flat())].sort()
  if (files.length === 0) throw new Error("no benchmark sources found for fingerprint")
  const hash = new Bun.CryptoHasher("sha256")
  for (const file of files)
    hash.update(file.replaceAll("\\", "/") + "\0").update(await Bun.file(path.join(root, file)).arrayBuffer())
  return { digest: hash.digest("hex"), files: files.length }
}
