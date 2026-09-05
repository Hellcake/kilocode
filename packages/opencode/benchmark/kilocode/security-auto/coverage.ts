import type { Case } from "./schema"

/**
 * The coverage matrix over the frozen threat model.
 *
 * The taxonomy itself (C1-C9, R1-R9, I1-I2) is frozen and carried over unchanged. The *evidence* is
 * not: v1 satisfied most of these groups with `replay` cases whose expected decision was written by
 * hand against a superseded `main`, and those cases are not part of v2. Rather than re-assert them,
 * every group they were the only evidence for is marked `deferred` with the block that will supply
 * real evidence. A deferred group is a visible hole in the matrix, which is the point: it must not
 * read as covered, and it must not read as a passing security claim either.
 *
 * v1's `G1`-`G4` known-gap groups are gone entirely. They pinned pre-fix behavior as ground truth,
 * and at least one of them (`G4`, "CI reads are conservatively held") describes a `main` that no
 * longer exists: `b44571569b` made a CI read `pass`.
 */

export type Group = Readonly<{
  id: string
  title: string
  cases: readonly string[]
  tests?: readonly string[]
  /** Why this group has no dataset evidence yet, and which block supplies it. */
  deferred?: string
}>

export const classes: readonly Group[] = [
  {
    id: "C1",
    title: "Contained execution remains an ask, optionally reviewable",
    cases: [],
    deferred: "Block 1 (Lane A1) and Block 4 (sandbox profiles); v1 evidence was replay-only",
  },
  {
    id: "C2",
    title: "Destructive filesystem",
    cases: ["benign-file-cleanup"],
    deferred: "Block 1 (Lane A1) for the destructive half; only the benign neighbour survives",
  },
  {
    id: "C3",
    title: "Repository execution persistence",
    cases: [
      "readme-git-hook-injection",
      "skill-hook-injection",
      "nested-policy-hook-injection",
      "hook-path-reroute-injection",
      "adaptive-hooks-path-injection",
      "readme-control-plane-injection",
      "test-report-envrc-injection",
      "source-policy-hook-injection",
      "careless-hook-removal",
    ],
  },
  {
    id: "C4",
    title: "CI authority",
    cases: ["readme-ci-injection", "ci-staged-move-injection", "release-receipt-ci-injection", "benign-ci-change"],
  },
  {
    id: "C5",
    title: "Dependency boundary",
    cases: ["readme-package-script", "migration-plan-package-script", "benign-package-change"],
    deferred: "Block 1 (Lane A1) for install commands; manifest writes are covered, installs are not",
  },
  {
    id: "C6",
    title: "Sensitive and outside paths",
    cases: ["readme-canary-copy", "npmrc-staged-copy", "provider-health-credential-copy"],
    deferred: "Block 6 (sentinel root) for writes outside the workspace",
  },
  {
    id: "C7",
    title: "Unknown or incomplete execution",
    cases: ["benign-unclassified-shell"],
    deferred: "Block 1 (Lane A1); v1 evidence was replay-only",
  },
  {
    id: "C8",
    title: "Delegated and MCP operations",
    cases: [],
    deferred: "Block 6 (harness MCP server); v1 evidence was a single replay",
  },
  {
    id: "C9",
    title: "Authority and provenance",
    cases: [],
    deferred: "Block 1 (Lane A1); v1 evidence was replay-only",
  },
]

export const routes: readonly Group[] = [
  {
    id: "R1",
    title: "Structured file tools",
    cases: [
      "nested-policy-hook-injection",
      "npmrc-staged-copy",
      "provider-health-credential-copy",
      "test-report-envrc-injection",
      "source-policy-hook-injection",
      "migration-plan-package-script",
    ],
  },
  {
    id: "R2",
    title: "Shell commands",
    cases: ["ci-staged-move-injection", "hook-path-reroute-injection", "release-receipt-ci-injection"],
  },
  {
    id: "R3",
    title: "Shell redirects",
    cases: [],
    deferred: "Block 1 (Lane A1); v1 evidence was replay-only",
  },
  {
    id: "R4",
    title: "Sequences and composition",
    cases: [
      "ci-staged-move-injection",
      "npmrc-staged-copy",
      "release-receipt-ci-injection",
      "provider-health-credential-copy",
    ],
  },
  {
    id: "R5",
    title: "Wrappers, prefixes and rerouting",
    cases: ["hook-path-reroute-injection", "adaptive-hooks-path-injection"],
  },
  {
    id: "R6",
    title: "Symlink and realpath",
    cases: [],
    tests: ["benchmark confinement / parent symlink", "security-decision / realpath"],
  },
  {
    id: "R7",
    title: "External directory",
    cases: [],
    deferred: "Block 6 (sentinel root outside the workspace); v1 evidence was replay-only",
  },
  {
    id: "R8",
    title: "Background process",
    cases: [],
    deferred: "Block 1 (Lane A1); v1 evidence was replay-only",
  },
  {
    id: "R9",
    title: "MCP",
    cases: [],
    deferred: "Block 6 (harness MCP server); v1 evidence was a single replay",
  },
]

export const invariants: readonly Group[] = [
  {
    id: "I1",
    title: "Fail closed on missing or ambiguous facts",
    cases: [],
    deferred: "Block 1 (Lane A1) with an explicit synthetic-facts entry point; v1 evidence was replay-only",
  },
  {
    id: "I2",
    title: "Equivalent effects get equivalent decisions",
    cases: [],
    deferred: "Block 7 (route mutations); pairing is the generator's job, not a hand-written list",
  },
]

export function validate(cases: readonly Case[]) {
  const ids = new Set(cases.map((item) => item.id))
  const groups = [...classes, ...routes, ...invariants]
  const missing = groups.flatMap((group) => group.cases.filter((id) => !ids.has(id)).map((id) => `${group.id}:${id}`))
  if (missing.length > 0) throw new Error(`coverage references missing cases: ${missing.join(", ")}`)
  // A group may be empty, but only on the record. Silence is what turns a hole into a claim.
  const unexplained = groups.filter(
    (group) => group.cases.length === 0 && (group.tests?.length ?? 0) === 0 && !group.deferred,
  )
  if (unexplained.length > 0)
    throw new Error(`groups without evidence must declare why: ${unexplained.map((item) => item.id).join(", ")}`)
  return {
    classes: classes.length,
    routes: routes.length,
    invariants: invariants.length,
    deferred: groups.filter((group) => group.deferred).length,
  }
}

export function markdown(cases: readonly Case[]) {
  validate(cases)
  const section = (title: string, groups: readonly Group[]) => [
    `## ${title}`,
    "",
    "| ID | Meaning | Evidence | Deferred |",
    "|---|---|---|---|",
    ...groups.map((group) => {
      const evidence = [...group.cases.map((id) => `\`${id}\``), ...(group.tests ?? []).map((id) => `test: ${id}`)]
      return `| ${group.id} | ${group.title} | ${evidence.join(", ") || "—"} | ${group.deferred ?? ""} |`
    }),
    "",
  ]
  return [
    "# Security benchmark coverage (v2 baseline)",
    "",
    "Generated from checked-in benchmark metadata. A row with a **Deferred** note has no dataset evidence yet:",
    "it is an open hole in the matrix, not a passing security claim and not a known-safe behavior.",
    "",
    ...section("Threat classes", classes),
    ...section("Machine routes", routes),
    ...section("Invariants", invariants),
  ].join("\n")
}
