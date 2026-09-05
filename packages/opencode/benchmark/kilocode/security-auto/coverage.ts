import type { Case } from "./schema"

type Group = Readonly<{
  id: string
  title: string
  cases: readonly string[]
  tests?: readonly string[]
}>

export const classes: readonly Group[] = [
  { id: "C1", title: "Contained execution remains an ask, optionally reviewable", cases: ["contained-exec", "contained-exec-widened", "contained-exec-open-network", "contained-exec-proxy"] },
  { id: "C2", title: "Destructive filesystem", cases: ["root-delete", "ordinary-delete", "ordinary-file-move"] },
  { id: "C3", title: "Repository execution persistence", cases: ["git-hook-write", "shell-hook-redirect", "control-plane-write", "control-plane-read"] },
  { id: "C4", title: "CI authority", cases: ["ci-write", "shell-ci-redirect", "ci-read"] },
  { id: "C5", title: "Dependency boundary", cases: ["dependency-install", "wrapped-dependency-install", "package-dependencies", "package-script-write"] },
  { id: "C6", title: "Sensitive and outside paths", cases: ["sensitive-read", "npmrc-sensitive-read", "shell-sensitive-read", "outside-workspace", "chmod-parent-boundary"] },
  { id: "C7", title: "Unknown or incomplete execution", cases: ["unclassified-exec", "version-only-exec", "incomplete-shell", "composed-shell", "background-shell"] },
  { id: "C8", title: "Delegated and MCP operations", cases: ["opaque-mcp"] },
  { id: "C9", title: "Authority and provenance", cases: ["hook-human-only", "hook-trusted-authority", "hook-unknown-authority", "hook-untrusted-authority"] },
]

export const routes: readonly Group[] = [
  { id: "R1", title: "Structured file tools", cases: ["git-hook-write", "ci-write", "ordinary-edit"] },
  { id: "R2", title: "Shell commands", cases: ["shell-sensitive-read", "dependency-install", "root-delete"] },
  { id: "R3", title: "Shell redirects", cases: ["shell-hook-redirect", "shell-ci-redirect"] },
  { id: "R4", title: "Sequences and composition", cases: ["decomposed-dependency-install", "composed-shell"] },
  { id: "R5", title: "Wrappers and prefixes", cases: ["wrapped-dependency-install", "git-reprogram"] },
  { id: "R6", title: "Symlink and realpath", cases: [], tests: ["benchmark confinement / parent symlink", "security-decision / realpath"] },
  { id: "R7", title: "External directory", cases: ["outside-workspace", "chmod-parent-boundary"] },
  { id: "R8", title: "Background process", cases: ["background-shell"] },
  { id: "R9", title: "MCP", cases: ["opaque-mcp"] },
]

export const invariants: readonly Group[] = [
  { id: "I1", title: "Fail closed on missing or ambiguous facts", cases: ["metadata-missing", "metadata-truncated", "unknown-target", "incomplete-shell"] },
  { id: "I2", title: "Equivalent effects get equivalent decisions", cases: ["sensitive-read", "shell-sensitive-read", "git-hook-write", "shell-hook-redirect", "ci-write", "shell-ci-redirect"] },
]

export const gaps: readonly Group[] = [
  { id: "G1", title: "Executable repository configs not classified", cases: ["vscode-task-write-known-gap"] },
  { id: "G2", title: "Web tools have no destination policy", cases: ["webfetch-open-known-gap"] },
  { id: "G3", title: "Git branch positional create is admitted", cases: ["git-branch-create-known-gap"] },
  { id: "G4", title: "CI reads are conservatively held", cases: ["ci-read"] },
]

export function validate(cases: readonly Case[]) {
  const ids = new Set(cases.map((item) => item.id))
  const groups = [...classes, ...routes, ...invariants, ...gaps]
  const missing = groups.flatMap((group) => group.cases.filter((id) => !ids.has(id)).map((id) => `${group.id}:${id}`))
  if (missing.length > 0) throw new Error(`coverage references missing cases: ${missing.join(", ")}`)
  if (classes.some((group) => group.cases.length === 0 && (group.tests?.length ?? 0) === 0))
    throw new Error("every threat class needs benchmark evidence")
  if (routes.some((group) => group.cases.length === 0 && (group.tests?.length ?? 0) === 0))
    throw new Error("every route needs benchmark evidence")
  return { classes: classes.length, routes: routes.length, invariants: invariants.length, gaps: gaps.length }
}

export function markdown(cases: readonly Case[]) {
  validate(cases)
  const section = (title: string, groups: readonly Group[]) => [
    `## ${title}`,
    "",
    "| ID | Meaning | Evidence |",
    "|---|---|---|",
    ...groups.map((group) => {
      const evidence = [...group.cases.map((id) => `\`${id}\``), ...(group.tests ?? []).map((id) => `test: ${id}`)]
      return `| ${group.id} | ${group.title} | ${evidence.join(", ")} |`
    }),
    "",
  ]
  return [
    "# Security benchmark coverage",
    "",
    "This matrix is generated from checked-in benchmark metadata. Known gaps are evidence of current behavior, not passing security claims.",
    "",
    ...section("Threat classes", classes),
    ...section("Machine routes", routes),
    ...section("Invariants", invariants),
    ...section("Known gaps and conservative holds", gaps),
  ].join("\n")
}
