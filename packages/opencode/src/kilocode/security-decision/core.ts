import type { SecurityDecisionTypes } from "./types"
import { SecurityDecisionRules as R } from "./rules"

/**
 * The pure decision core. No IO, no clock, no randomness, no Effect, no Kilo imports.
 *
 * It returns a *recommendation*; `Permission.ask` stays the enforcement point. `deny` is reserved
 * for a fully recognized, exact signal on the untrusted soft path — every ambiguity degrades to
 * `ask`, and `pass` means the layer has no opinion at all.
 */
export namespace SecurityDecision {
  /** Operations that unambiguously write to their target. */
  const WRITES = new Set(["add", "create", "update", "write", "move", "delete"])
  /** Operations that unambiguously destroy or relocate their target. */
  const DESTRUCTIVE = new Set(["delete", "move"])

  /**
   * Executables that can neither mutate state nor reveal file contents, whatever their arguments.
   * Deliberately tiny: this is an allowlist of proven-inert commands, not a catalog of safe tools.
   * Anything not here is unclassified, which is an ask, not a refusal.
   */
  const INERT = new Set([
    "basename",
    "date",
    "dirname",
    "echo",
    "false",
    "hostname",
    "ls",
    "printf",
    "pwd",
    "sleep",
    "true",
    "uname",
    "which",
    "whoami",
  ])

  /**
   * git is allowlisted by verb *and* arguments, never by verb alone.
   *
   * A read-only sounding verb is not evidence of anything: `show`, `diff`, `log` and `blame` all
   * print file contents, so `git show HEAD:.env` would read a secret that a direct `read` asks for.
   * Git also reprograms itself from its arguments — `--git-dir` and `--work-tree` move the operation
   * to another repository, `-C` moves the working directory, and `-c` sets configuration that can
   * name a program to run (pager, external diff, textconv filter). So only verbs that emit names and
   * metadata are listed, every global flag but two is refused, and any argument the verb does not
   * explicitly allow fails closed.
   */
  const GIT_GLOBALS = new Set(["--no-pager", "--no-optional-locks"])

  type GitVerb = Readonly<{ flags: ReadonlySet<string>; short: ReadonlySet<string> }>

  const GIT_VERBS: Record<string, GitVerb> = {
    /** Names, branch and working-tree state. No file contents. */
    status: {
      flags: new Set([
        "--",
        "--branch",
        "--ignore-submodules",
        "--long",
        "--no-renames",
        "--porcelain",
        "--short",
        "--untracked-files",
        "-b",
        "-s",
        "-u",
        "-uall",
        "-uno",
        "-unormal",
        "-z",
      ]),
      short: new Set(["b", "s", "z"]),
    },
    /** Revision and repository-layout resolution. Prints refs and paths. */
    "rev-parse": {
      flags: new Set([
        "--",
        "--abbrev-ref",
        "--git-common-dir",
        "--git-dir",
        "--is-bare-repository",
        "--is-inside-work-tree",
        "--quiet",
        "--short",
        "--show-cdup",
        "--show-prefix",
        "--show-toplevel",
        "--symbolic",
        "--symbolic-full-name",
        "--verify",
        "-q",
      ]),
      short: new Set(["q"]),
    },
    /** Tracked path names. */
    "ls-files": {
      flags: new Set([
        "--",
        "--cached",
        "--deleted",
        "--exclude-standard",
        "--full-name",
        "--modified",
        "--others",
        "--stage",
        "-c",
        "-d",
        "-m",
        "-o",
        "-s",
        "-z",
      ]),
      short: new Set(["c", "d", "m", "o", "s", "z"]),
    },
  }

  /** A token is acceptable when it is not a flag, or is a flag the verb explicitly allows. */
  function acceptable(token: string, verb: GitVerb) {
    if (!token.startsWith("-")) return true
    const head = token.includes("=") ? token.slice(0, token.indexOf("=")) : token
    if (verb.flags.has(head)) return true
    // Clustered short flags such as `-sb`, drawn only from the verb's own letters.
    if (/^-[a-zA-Z]{2,}$/.test(token)) return [...token.slice(1)].every((letter) => verb.short.has(letter))
    return false
  }

  function inertGit(argv: readonly string[]) {
    let index = 1
    // Global flags sit before the verb, and almost all of them can redirect or reprogram the run.
    while (index < argv.length && argv[index]!.startsWith("-")) {
      if (!GIT_GLOBALS.has(argv[index]!)) return false
      index++
    }
    const name = argv[index]
    if (name === undefined) return false
    const verb = GIT_VERBS[name]
    if (!verb) return false
    return argv.slice(index + 1).every((token) => acceptable(token, verb))
  }

  /** True only for a command proven inert here. An unnamed executable is never inert. */
  function inert(exec: SecurityDecisionTypes.ExecFact) {
    const name = exec.executable
    if (!name) return false
    if (INERT.has(name)) return true
    if (name !== "git") return false
    // Without the parsed command line there is nothing to prove anything against.
    return exec.argv !== undefined && exec.argv.length > 0 && inertGit(exec.argv)
  }

  function target(input: SecurityDecisionTypes.Input, fact: SecurityDecisionTypes.PathFact): R.Entry {
    // A shell command can read one target and write another, so a fact's own operation wins.
    const op = fact.operation ?? input.action.operation
    const exec = input.action.exec

    // Exact, fully parsed destruction of a root/device target — the narrow soft-path deny.
    if (fact.class === "root") {
      if (op === "delete" && exec?.complete && !exec.composed) return R.DESTRUCTIVE_ROOT
      return R.DESTRUCTIVE_FS
    }

    if (fact.class === "git_hook") {
      if (WRITES.has(op)) return R.GIT_HOOK_WRITE
      return R.AMBIGUOUS_OPERATION
    }

    // Reading the control plane is ordinary; installing into it is not.
    if (fact.class === "control_plane") {
      if (WRITES.has(op)) return R.CONTROL_PLANE_WRITE
      if (op === "read") return R.NO_OPINION
      return R.AMBIGUOUS_OPERATION
    }

    if (fact.class === "unknown") return R.UNKNOWN_TARGET
    if (fact.class === "sensitive" || !fact.inWorkspace) return R.SENSITIVE_BOUNDARY
    if (fact.class === "ci") return R.CI_AUTHORITY
    // Dependency and lockfile edits are ordinary in V1; only the executable region is authority.
    if (fact.class === "package_manifest" && fact.region === "scripts") return R.PACKAGE_EXECUTION
    if (DESTRUCTIVE.has(op)) return R.DESTRUCTIVE_FS
    return R.NO_OPINION
  }

  /** `deny > ask > allow`; `pass` carries no strictness. */
  function strictness(decision: SecurityDecisionTypes.Decision) {
    return decision === "deny" ? 3 : decision === "ask" ? 2 : decision === "allow" ? 1 : 0
  }

  export function decide(input: SecurityDecisionTypes.Input): SecurityDecisionTypes.Result {
    const rule = evaluate(input)
    // The soft-path deny is only available against untrusted authority, and never against an
    // existing human-only guard: those stay at ask so a human still resolves them.
    if (rule.decision === "deny" && (input.baseline.humanOnly || input.baseline.authority !== "untrusted")) {
      return { ...R.result(rule), decision: "ask", reviewable: false }
    }
    const result = R.result(rule)
    // An existing human-only guard is never narrowed by a reviewer: a human has to answer it.
    if (input.baseline.humanOnly && result.decision === "ask") return { ...result, reviewable: false }
    return result
  }

  function evaluate(input: SecurityDecisionTypes.Input): R.Entry {
    // Opaque delegated actions stay opaque in V1: no semantic classification, and their empty
    // metadata must not be reported as a generic metadata gap.
    if (input.action.kind === "mcp") return R.DELEGATED_OPAQUE

    if (!input.metadata.complete || input.metadata.truncated) return R.METADATA_INCOMPLETE

    const exec = input.action.exec
    if (exec) {
      if (!exec.complete) return R.EXEC_INCOMPLETE
      if (exec.composed) return R.EXEC_COMPOSED
    }

    let winner: R.Entry = R.NO_OPINION
    for (const fact of input.action.paths) {
      const rule = target(input, fact)
      if (strictness(rule.decision) > strictness(winner.decision)) winner = rule
    }
    // Only once every deterministic path rule has had its say. A complete parse is not proof of
    // safety: unless the scan knows what this executable does to files, or the command is proven
    // inert, the action is unclassified rather than harmless.
    if (winner.decision === "pass" && exec && exec.complete && !exec.composed && !exec.classified && !inert(exec))
      return R.UNCLASSIFIED_EXEC
    return winner
  }
}
