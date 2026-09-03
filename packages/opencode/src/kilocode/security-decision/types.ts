/**
 * Portable types for the deterministic security decision layer (Hackathon V1).
 *
 * This module and its siblings `rules.ts`/`core.ts` are the *pure* half of the layer: no IO,
 * no clock, no randomness, no Effect and no Kilo imports. Everything Kilo-specific lives in
 * `adapter.ts`, which normalizes permission metadata into these facts.
 */
export namespace SecurityDecisionTypes {
  /** `pass` means "no opinion" — it is not a strictness level. */
  export type Decision = "allow" | "ask" | "deny" | "pass"

  /** Authority backing the baseline decision. Undeterminable provenance is `unknown`, run as untrusted. */
  export type Authority = "hard" | "xdg_global" | "untrusted" | "unknown"

  /** Sensitivity class of a normalized path. `unknown` blocks any multi-target allow. */
  export type PathClass =
    | "ordinary"
    | "sensitive"
    | "git_hook"
    | "control_plane"
    | "ci"
    | "package_manifest"
    | "root"
    | "unknown"

  export type PathFact = Readonly<{
    path: string
    inWorkspace: boolean
    class: PathClass
    /** Which region of a structured file the change touches, when the adapter could determine it. */
    region?: "scripts" | "dependencies" | "other"
    /**
     * Operation for this target specifically. One shell command can read one file and write another,
     * so a fact may override the action-wide operation. Structured file tools leave it unset.
     */
    operation?: string
  }>

  export type ExecFact = Readonly<{
    /** Whether the shell scan recovered the full AST (fail-closed to false). */
    complete: boolean
    /** Pipelines, substitutions, heredocs and other composition the scan observed. */
    composed: boolean
    executable?: string
    /** The parsed command line, bounded. Present only for a single, fully recovered command. */
    argv?: readonly string[]
    /** Whether the executable's own file semantics are known to the scan. */
    classified?: boolean
    class: "known" | "unknown"
  }>

  export type RemoteFact = Readonly<{
    scheme?: string
    host?: string
    port?: number
    /** Whether the destination is an exact, bounded, public host. */
    bounded: boolean
  }>

  export type Containment = Readonly<{
    sandbox: "off" | "unavailable" | "unknown" | "operational" | "failed"
    network: "allow" | "deny" | "proxy"
    destinations: readonly string[]
    escalated: boolean
  }>

  export type Requirement = "sandbox" | "restricted_network"

  export type Input = Readonly<{
    version: 1
    action: Readonly<{
      kind: string
      operation: string
      paths: readonly PathFact[]
      exec?: ExecFact
      remote?: RemoteFact
    }>
    baseline: Readonly<{ decision: "allow" | "ask"; authority: Authority; humanOnly: boolean }>
    metadata: Readonly<{ complete: boolean; truncated: boolean }>
    containment: Containment
  }>

  export type Result = Readonly<{
    decision: Decision
    reason: string
    rule_id: string
    requirements: readonly Requirement[]
    reviewable: boolean
  }>
}
