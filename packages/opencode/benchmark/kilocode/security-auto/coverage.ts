import type { A1Case, Case } from "./schema"

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
  /** Cases in this group where the engine is weaker than the frozen threat model wants. */
  gaps?: readonly string[]
  /** Evidence that exists in the dataset but only counts on a run that met a runtime condition. */
  conditional?: string
}>

export const classes: readonly Group[] = [
  {
    id: "C1",
    title: "Contained execution remains an ask, optionally reviewable",
    cases: [
      "a1-c1-contained-unit-tests",
      "a1-c1-contained-typecheck",
      "a1-c1-contained-lint-fix",
      "a1-c1-contained-prefixed-test",
      "a1-c1-contained-sequenced-build",
      "a1-c1-contained-label-build",
      "a1-c7-host-daemon",
      "a1-c5-install-direct",
      "a1-c4-workflow-redirect",
      "a1-c3-hook-redirect",
      "a1-c6-secret-read-direct",
      "a1-c6-outside-workspace-write",
      "a1-c2-root-delete",
    ],
    // The dataset alone is not the claim. C1 is only covered on a run whose preflight proved the
    // backend operational, which is a property of the machine and not of these files, so the
    // condition is evaluated per run by `c1Coverage` and reported with the result.
    conditional:
      "covered only on a run whose sandbox preflight proved the backend operational; otherwise partial (see c1Coverage)",
  },
  {
    id: "C2",
    title: "Destructive filesystem",
    cases: [
      "a1-c2-root-delete",
      "a1-c2-expanded-target",
      "a1-c2-benign-build-output",
      "a1-c2-benign-source-move",
      "benign-file-cleanup",
    ],
  },
  {
    id: "C3",
    title: "Repository execution persistence",
    gaps: ["a1-c3-hooks-path-reroute"],
    cases: [
      "a1-c3-hook-redirect",
      "a1-c3-hook-staged-copy",
      "a1-c3-hooks-path-reroute",
      "a1-c3-envrc-redirect",
      "a1-c3-benign-source-write",
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
    cases: [
      "a1-c4-workflow-redirect",
      "a1-c4-workflow-staged-copy",
      "a1-c4-workflow-parent-delete",
      "a1-c4-benign-workflow-read",
      "readme-ci-injection",
      "ci-staged-move-injection",
      "release-receipt-ci-injection",
      "benign-ci-change",
    ],
  },
  {
    id: "C5",
    title: "Dependency boundary",
    cases: [
      "a1-c5-install-direct",
      "a1-c5-install-cwd",
      "a1-c5-install-interpreter",
      "a1-c5-manifest-redirect",
      "a1-c5-benign-test-run",
      "readme-package-script",
      "migration-plan-package-script",
      "benign-package-change",
    ],
  },
  {
    id: "C6",
    title: "Sensitive and outside paths",
    cases: [
      "a1-c6-secret-read-direct",
      "a1-c6-secret-read-alt-utility",
      "a1-c6-registry-credential-read",
      "a1-c6-outside-workspace-write",
      "a1-c6-outside-workspace-redirect",
      "a1-c6-benign-source-read",
      "a1-c6-benign-doc-read",
      "readme-canary-copy",
      "npmrc-staged-copy",
      "provider-health-credential-copy",
    ],
  },
  {
    id: "C7",
    title: "Unknown or incomplete execution",
    cases: [
      "a1-c7-inplace-edit",
      "a1-c7-command-substitution",
      "a1-c7-wrapper-hides-secret-read",
      "a1-c7-ambient-environment",
      "a1-c7-host-daemon",
      "a1-c7-delegated-container",
      "a1-c7-benign-known-inert",
      "a1-c7-benign-listing",
      "benign-unclassified-shell",
    ],
    gaps: ["a1-c7-wrapper-hides-secret-read"],
  },
  {
    id: "C8",
    title: "Delegated and MCP operations",
    cases: [],
    deferred:
      "Block 6 (harness MCP server): a shell command cannot stand in for MCP provenance, and no A1 case claims to",
  },
  {
    id: "C9",
    title: "Authority and provenance",
    cases: [],
    deferred:
      "A1 calls the adapter with a fixed untrusted floor and never traverses KiloSecurityGate or SecurityAuthority, so it cannot be evidence about who may weaken a decision",
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
    deferred: "A2: A1 is shell-only, so the read/edit/write entry has no production-path evidence yet",
  },
  {
    id: "R2",
    title: "Shell commands",
    cases: [
      "a1-c2-root-delete",
      "a1-c5-install-direct",
      "a1-c6-secret-read-direct",
      "a1-c7-inplace-edit",
      "ci-staged-move-injection",
      "hook-path-reroute-injection",
      "release-receipt-ci-injection",
    ],
  },
  {
    id: "R3",
    title: "Shell redirects",
    cases: [
      "a1-c3-hook-redirect",
      "a1-c3-envrc-redirect",
      "a1-c4-workflow-redirect",
      "a1-c5-manifest-redirect",
      "a1-c6-outside-workspace-redirect",
    ],
  },
  {
    id: "R4",
    title: "Sequences and composition",
    cases: [
      "a1-c5-install-cwd",
      "a1-c7-command-substitution",
      "ci-staged-move-injection",
      "npmrc-staged-copy",
      "release-receipt-ci-injection",
      "provider-health-credential-copy",
    ],
  },
  {
    id: "R5",
    title: "Wrappers, prefixes and rerouting",
    cases: [
      "a1-c5-install-interpreter",
      "a1-c7-ambient-environment",
      "a1-c7-wrapper-hides-secret-read",
      "a1-c3-hooks-path-reroute",
      "hook-path-reroute-injection",
      "adaptive-hooks-path-injection",
    ],
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
    cases: ["a1-c6-outside-workspace-write", "a1-c6-outside-workspace-redirect"],
  },
  {
    id: "R8",
    title: "Background process",
    cases: [],
    deferred: "A1 drives the bash permission only; the background-process ask has no facts and needs its own entry",
  },
  {
    id: "R9",
    title: "MCP",
    cases: [],
    deferred: "Block 6 (harness MCP server)",
  },
]

export const invariants: readonly Group[] = [
  {
    id: "I1",
    title: "Fail closed on missing or ambiguous facts",
    cases: ["a1-c2-expanded-target"],
    deferred:
      "The metadata-incomplete and truncated halves need the synthetic-facts entry, which is kept out of production-path coverage on purpose",
  },
  {
    id: "I2",
    title: "Equivalent effects get equivalent decisions",
    cases: [
      "a1-c3-hook-redirect",
      "a1-c3-hook-staged-copy",
      "a1-c4-workflow-redirect",
      "a1-c4-workflow-staged-copy",
      "a1-c6-secret-read-direct",
      "a1-c6-secret-read-alt-utility",
      "a1-c5-install-direct",
      "a1-c5-install-cwd",
      "a1-c5-install-interpreter",
    ],
  },
]

/** The protected boundaries a contained run must be shown *not* to weaken. */
export const C1_CONTROL_RULES = [
  "SEC.V1.HOST_CONTROL",
  "SEC.V1.DEPENDENCY_INSTALL",
  "SEC.V1.CI_AUTHORITY",
  "SEC.V1.GIT_HOOK_WRITE",
  "SEC.V1.SENSITIVE_BOUNDARY",
  "SEC.V1.DESTRUCTIVE_ROOT",
] as const

export type C1Coverage = Readonly<{
  status: "covered" | "partial"
  conditions: Readonly<Record<string, boolean>>
  missing: readonly string[]
  positives: readonly string[]
  controls: readonly string[]
  uncovered_control_rules: readonly string[]
}>

/**
 * Whether C1 is actually covered by this run, rather than merely referenced by the matrix.
 *
 * Five things have to hold at once, and only two of them are properties of the dataset. The other
 * three are properties of the machine and of the path the facts came from, which is why this is a
 * per-run function rather than a static row: a C1 claim on a host where the backend never confined
 * anything would be the benchmark asserting the feature it was built to measure.
 *
 * `containment` is the state the production path reported for the run. Nothing in the harness can
 * produce `operational` — only `ContainmentMacos.probe` can — so its presence here *is* the evidence
 * that the facts travelled the production path.
 */
export function c1Coverage(input: {
  sandbox_enabled: boolean
  preflight_state: "off" | "operational" | "unavailable" | "failed"
  probes: readonly { id: string; ok: boolean }[]
  containment: string
  cases: readonly Case[]
}): C1Coverage {
  const a1 = input.cases.filter((item): item is A1Case => item.mode === "a1" && item.expect_contained !== undefined)
  const positives = a1.filter(
    (item) =>
      item.expect_contained!.rule_id === "SEC.V1.CONTAINED_EXEC" &&
      item.expect.rule_id !== "SEC.V1.CONTAINED_EXEC" &&
      item.expected_enforcement === "mandatory_ask",
  )
  const controls = a1.filter(
    (item) =>
      item.expect_contained!.rule_id !== "SEC.V1.CONTAINED_EXEC" &&
      item.expect_contained!.rule_id === item.expect.rule_id &&
      item.expected_enforcement_contained === item.expected_enforcement,
  )
  const covered = new Set(controls.map((item) => item.expect_contained!.rule_id))
  const uncovered = C1_CONTROL_RULES.filter((rule) => !covered.has(rule))
  const conditions = {
    sandbox_enabled_by_real_config: input.sandbox_enabled,
    backend_operational_proof: input.preflight_state === "operational" && input.probes.every((probe) => probe.ok),
    containment_from_production_path: input.containment === "operational",
    positive_autonomy_cases: positives.length > 0,
    negative_protected_boundary_controls: uncovered.length === 0,
  }
  const missing = Object.entries(conditions)
    .filter(([, ok]) => !ok)
    .map(([name]) => name)
  return {
    status: missing.length === 0 ? "covered" : "partial",
    conditions,
    missing,
    positives: positives.map((item) => item.id),
    controls: controls.map((item) => item.id),
    uncovered_control_rules: uncovered,
  }
}

export function validate(cases: readonly Case[]) {
  const ids = new Set(cases.map((item) => item.id))
  const groups = [...classes, ...routes, ...invariants]
  const missing = groups.flatMap((group) => group.cases.filter((id) => !ids.has(id)).map((id) => `${group.id}:${id}`))
  if (missing.length > 0) throw new Error(`coverage references missing cases: ${missing.join(", ")}`)
  // A group may be empty, but only on the record. Silence is what turns a hole into a claim.
  const unexplained = groups.filter(
    (group) => group.cases.length === 0 && (group.tests?.length ?? 0) === 0 && !group.deferred && !group.conditional,
  )
  if (unexplained.length > 0)
    throw new Error(`groups without evidence must declare why: ${unexplained.map((item) => item.id).join(", ")}`)
  const gaps = groups.flatMap((group) => group.gaps ?? [])
  const unknown = gaps.filter((id) => !ids.has(id))
  if (unknown.length > 0) throw new Error(`coverage references missing gap cases: ${unknown.join(", ")}`)
  // A gap the matrix advertises but the dataset does not declare is a claim with nothing behind it.
  const declared = new Set(cases.filter((item) => item.mode === "a1" && item.known_gap).map((item) => item.id))
  const undeclared = gaps.filter((id) => !declared.has(id))
  if (undeclared.length > 0)
    throw new Error(`coverage lists gaps the dataset does not declare: ${undeclared.join(", ")}`)
  return {
    classes: classes.length,
    routes: routes.length,
    invariants: invariants.length,
    deferred: groups.filter((group) => group.deferred).length,
    conditional: groups.filter((group) => group.conditional).length,
    gaps: gaps.length,
  }
}

export function markdown(cases: readonly Case[]) {
  validate(cases)
  const section = (title: string, groups: readonly Group[]) => [
    `## ${title}`,
    "",
    "| ID | Meaning | Evidence | Known gaps | Deferred or conditional |",
    "|---|---|---|---|---|",
    ...groups.map((group) => {
      const evidence = [...group.cases.map((id) => `\`${id}\``), ...(group.tests ?? []).map((id) => `test: ${id}`)]
      const gaps = (group.gaps ?? []).map((id) => `\`${id}\``).join(", ")
      const note = group.deferred ?? (group.conditional ? `conditional: ${group.conditional}` : "")
      return `| ${group.id} | ${group.title} | ${evidence.join(", ") || "—"} | ${gaps || "—"} | ${note} |`
    }),
    "",
  ]
  return [
    "# Security benchmark coverage (v2 baseline)",
    "",
    "Generated from checked-in benchmark metadata. A row with a **Deferred** note is an open hole in the",
    "matrix, not a passing security claim and not a known-safe behavior. A **conditional** row has the",
    "cases but not automatically the claim: its evidence only counts on a run that met the stated",
    "runtime condition, which for C1 is a sandbox preflight that proved the backend operational.",
    "A **Known gap** is a case where the engine is weaker than the frozen threat model wants; it is",
    "recorded, never counted as a pass.",
    "",
    "All `a1-*` evidence is decision-level: Lane A1 scans a real command and never executes it, so it",
    "establishes what the layer decides and what the action *would* have touched, not a final effect.",
    "Observing the effect is A2's job.",
    "",
    ...section("Threat classes", classes),
    ...section("Machine routes", routes),
    ...section("Invariants", invariants),
  ].join("\n")
}
