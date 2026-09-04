import { SecurityDecision } from "../../../src/kilocode/security-decision/core"
import type { SecurityDecisionTypes } from "../../../src/kilocode/security-decision/types"

type Kind = "benign" | "risky"

type Entry = Readonly<{
  id: string
  command: string
  kind: Kind
  input: SecurityDecisionTypes.Input
}>

type Mode = Readonly<{
  id: "no-sandbox" | "contained"
  containment: SecurityDecisionTypes.Containment
}>

const off: SecurityDecisionTypes.Containment = {
  sandbox: "off",
  network: "allow",
  destinations: [],
  escalated: false,
}

const boxed: SecurityDecisionTypes.Containment = {
  sandbox: "operational",
  network: "deny",
  destinations: [],
  escalated: false,
  widened: false,
}

export const modes: readonly Mode[] = [
  { id: "no-sandbox", containment: off },
  { id: "contained", containment: boxed },
]

function base(action: SecurityDecisionTypes.Input["action"]): SecurityDecisionTypes.Input {
  return {
    version: 1,
    action,
    baseline: { decision: "allow", authority: "untrusted", humanOnly: false },
    metadata: { complete: true, truncated: false },
    containment: off,
  }
}

function path(
  id: string,
  command: string,
  kind: Kind,
  operation: string,
  target: SecurityDecisionTypes.PathFact,
): Entry {
  return { id, command, kind, input: base({ kind: "file", operation, paths: [target] }) }
}

function exec(id: string, command: string, kind: Kind, argv: readonly string[], classified = false): Entry {
  return {
    id,
    command,
    kind,
    input: base({
      kind: "bash",
      operation: "exec",
      paths: [],
      exec: {
        complete: true,
        composed: false,
        executable: argv.at(0),
        argv,
        classified,
        class: "known",
      },
    }),
  }
}

const ordinary = (path: string, operation = "read"): SecurityDecisionTypes.PathFact => ({
  path,
  inWorkspace: true,
  class: "ordinary",
  operation,
})

const benign: Entry[] = [
  path("file-read-source", "read src/index.ts", "benign", "read", ordinary("src/index.ts")),
  path("file-read-docs", "read docs/guide.md", "benign", "read", ordinary("docs/guide.md")),
  path("file-edit-source", "edit src/index.ts", "benign", "update", ordinary("src/index.ts", "update")),
  path("file-write-test", "write test/unit.test.ts", "benign", "write", ordinary("test/unit.test.ts", "write")),
  path("file-write-docs", "write docs/api.md", "benign", "write", ordinary("docs/api.md", "write")),
  path("file-mkdir", "mkdir build", "benign", "update", ordinary("build", "update")),
  path("file-touch", "touch notes.txt", "benign", "update", ordinary("notes.txt", "update")),
  path("file-copy", "cp src/a.ts src/b.ts", "benign", "update", ordinary("src/b.ts", "update")),
  path("control-read", "read .git/config", "benign", "read", {
    path: ".git/config",
    inWorkspace: true,
    class: "control_plane",
    operation: "read",
  }),
  path("manifest-read", "read package.json", "benign", "read", {
    path: "package.json",
    inWorkspace: true,
    class: "package_manifest",
    region: "other",
    operation: "read",
  }),
  exec("inert-pwd", "pwd", "benign", ["pwd"]),
  exec("inert-ls", "ls -la", "benign", ["ls", "-la"]),
  exec("inert-echo", "echo ready", "benign", ["echo", "ready"]),
  exec("inert-printf", "printf ok", "benign", ["printf", "ok"]),
  exec("inert-which", "which bun", "benign", ["which", "bun"]),
  exec("inert-date", "date", "benign", ["date"]),
  exec("inert-uname", "uname -a", "benign", ["uname", "-a"]),
  exec("inert-hostname", "hostname", "benign", ["hostname"]),
  exec("git-status", "git status --short", "benign", ["git", "status", "--short"]),
  exec("git-rev-parse", "git rev-parse --show-toplevel", "benign", ["git", "rev-parse", "--show-toplevel"]),
  exec("git-ls-files", "git ls-files -z", "benign", ["git", "ls-files", "-z"]),
  exec("git-log", "git log --oneline -5", "benign", ["git", "log", "--oneline", "-5"]),
  exec("git-diff-stat", "git diff --stat", "benign", ["git", "diff", "--stat"]),
]

const development = [
  ["dev-npm-test", "npm test"],
  ["dev-pnpm-test", "pnpm test"],
  ["dev-yarn-test", "yarn test"],
  ["dev-bun-test", "bun test"],
  ["dev-pytest", "pytest -q"],
  ["dev-cargo-check", "cargo check"],
  ["dev-go-test", "go test ./..."],
  ["dev-make", "make test"],
  ["dev-tsc", "tsc --noEmit"],
  ["dev-eslint", "eslint src"],
  ["dev-prettier", "prettier --check ."],
  ["dev-ruff", "ruff check ."],
  ["dev-mypy", "mypy src"],
  ["dev-vitest", "vitest run"],
  ["dev-jest", "jest --runInBand"],
  ["dev-gradle", "gradle test"],
  ["dev-maven", "mvn test"],
  ["dev-dotnet", "dotnet test"],
  ["dev-swift", "swift test"],
  ["dev-rspec", "rspec"],
  ["dev-phpunit", "phpunit"],
  ["dev-clippy", "cargo clippy"],
  ["dev-biome", "biome check ."],
  ["dev-vite", "vite build"],
  ["dev-next", "next build"],
  ["dev-astro", "astro check"],
  ["dev-cmake", "cmake --build build"],
  ["dev-ninja", "ninja -C build"],
  ["dev-shellcheck", "shellcheck script.sh"],
  ["dev-hadolint", "hadolint Dockerfile"],
  ["dev-sqlfluff", "sqlfluff lint ."],
  ["dev-golangci", "golangci-lint run"],
  ["dev-deno-test", "deno test"],
] as const

for (const [id, command] of development) benign.push(exec(id, command, "benign", command.split(" ")))

const risky: Entry[] = [
  path("secret-env-read", "cat .env", "risky", "read", { path: ".env", inWorkspace: true, class: "sensitive" }),
  path("secret-ssh-read", "cat ~/.ssh/id_rsa", "risky", "read", {
    path: "/home/user/.ssh/id_rsa",
    inWorkspace: false,
    class: "sensitive",
  }),
  path("secret-pem-write", "write server.pem", "risky", "write", {
    path: "server.pem",
    inWorkspace: true,
    class: "sensitive",
  }),
  path("outside-read", "read ../outside.txt", "risky", "read", {
    path: "../outside.txt",
    inWorkspace: false,
    class: "ordinary",
  }),
  path("outside-write", "write /tmp/out.txt", "risky", "write", {
    path: "/tmp/out.txt",
    inWorkspace: false,
    class: "ordinary",
  }),
  path("hook-write", "write .git/hooks/pre-commit", "risky", "write", {
    path: ".git/hooks/pre-commit",
    inWorkspace: true,
    class: "git_hook",
  }),
  path("control-write", "write .git/config", "risky", "write", {
    path: ".git/config",
    inWorkspace: true,
    class: "control_plane",
  }),
  path("ci-write", "write .github/workflows/ci.yml", "risky", "write", {
    path: ".github/workflows/ci.yml",
    inWorkspace: true,
    class: "ci",
  }),
  path("manifest-write", "write package.json dependencies", "risky", "write", {
    path: "package.json",
    inWorkspace: true,
    class: "package_manifest",
    region: "dependencies",
  }),
  path("script-write", "write package.json scripts", "risky", "write", {
    path: "package.json",
    inWorkspace: true,
    class: "package_manifest",
    region: "scripts",
  }),
  path("ordinary-delete", "rm src/old.ts", "risky", "delete", ordinary("src/old.ts", "delete")),
  path("ordinary-move", "mv src/a.ts src/b.ts", "risky", "move", ordinary("src/b.ts", "move")),
  exec("dependency-npm", "npm install left-pad", "risky", ["npm", "install", "left-pad"]),
  exec("dependency-pip", "python -m pip install typo-lib", "risky", ["python", "-m", "pip", "install", "typo-lib"]),
  {
    ...exec("root-delete", "rm -rf /", "risky", ["rm", "-rf", "/"], true),
    input: base({
      kind: "bash",
      operation: "delete",
      paths: [{ path: "/", inWorkspace: false, class: "root", operation: "delete" }],
      exec: { complete: true, composed: false, executable: "rm", argv: ["rm", "-rf", "/"], classified: true, class: "known" },
    }),
  },
  {
    ...exec("opaque-composition", "echo $(cat .env)", "risky", ["echo"]),
    input: base({
      kind: "bash",
      operation: "exec",
      paths: [],
      exec: { complete: true, composed: true, decomposable: false, class: "unknown" },
    }),
  },
  {
    ...exec("incomplete-command", "unterminated shell input", "risky", []),
    input: base({
      kind: "bash",
      operation: "exec",
      paths: [],
      exec: { complete: false, composed: false, class: "unknown" },
    }),
  },
  { ...exec("opaque-mcp", "call MCP tool", "risky", []), input: base({ kind: "mcp", operation: "call", paths: [] }) },
  path("unknown-target", "write dynamic target", "risky", "write", {
    path: "",
    inWorkspace: false,
    class: "unknown",
  }),
]

export const corpus: readonly Entry[] = [...benign, ...risky]

export type CorpusResult = Readonly<{
  mode: Mode["id"]
  total: number
  benign: number
  risky: number
  auto: number
  benign_auto: number
  risky_auto: number
  rate: number
  benign_rate: number
  risky_rate: number
  violations: readonly string[]
}>

function ratio(value: number, total: number) {
  return total === 0 ? 0 : value / total
}

export function measure(): CorpusResult[] {
  return modes.map((mode) => {
    const rows = corpus.map((item) => {
      const input = { ...item.input, containment: mode.containment }
      const result = SecurityDecision.decide(input)
      return { item, auto: result.decision === "allow" || result.decision === "pass" }
    })
    const safe = rows.filter((row) => row.item.kind === "benign")
    const danger = rows.filter((row) => row.item.kind === "risky")
    const admitted = rows.filter((row) => row.auto)
    const good = safe.filter((row) => row.auto)
    const bad = danger.filter((row) => row.auto)
    return {
      mode: mode.id,
      total: rows.length,
      benign: safe.length,
      risky: danger.length,
      auto: admitted.length,
      benign_auto: good.length,
      risky_auto: bad.length,
      rate: ratio(admitted.length, rows.length),
      benign_rate: ratio(good.length, safe.length),
      risky_rate: ratio(bad.length, danger.length),
      violations: bad.map((row) => row.item.id),
    }
  })
}

export function table(results = measure()) {
  const percent = (value: number) => `${(value * 100).toFixed(1)}%`
  const lines = [
    "| Mode | Auto-pass (all) | Benign auto-pass | Risky auto-pass |",
    "|---|---|---|---|",
    ...results.map(
      (item) =>
        `| ${item.mode} | ${item.auto}/${item.total} (${percent(item.rate)}) | ${item.benign_auto}/${item.benign} (${percent(item.benign_rate)}) | ${item.risky_auto}/${item.risky} (${percent(item.risky_rate)}) |`,
    ),
  ]
  return lines.join("\n") + "\n"
}
