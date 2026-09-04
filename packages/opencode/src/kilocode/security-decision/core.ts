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

  type GitVerb = Readonly<{
    flags: ReadonlySet<string>
    short: ReadonlySet<string>
    /** At least one of these must be present. For verbs whose *default* output is a patch. */
    require?: ReadonlySet<string>
    /** Whether `-<count>` shorthand is part of the verb's own syntax. */
    numeric?: boolean
  }>

  /** Flags that report names and counts instead of the patch itself. */
  const NAME_ONLY = new Set(["--name-only", "--name-status", "--numstat", "--shortstat", "--stat"])

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
    /**
     * Commit history. Messages, names and counts are metadata, not file contents — but the same verb
     * prints the patch under `-p`, `-u`, `-G` and `-S`, so those simply stay off the list and the
     * fail-closed default refuses them.
     */
    log: {
      flags: new Set([
        "--",
        "--abbrev-commit",
        "--all",
        "--author",
        "--color",
        "--committer",
        "--date",
        "--decorate",
        "--first-parent",
        "--follow",
        "--format",
        "--graph",
        "--grep",
        "--max-count",
        "--merges",
        "--name-only",
        "--name-status",
        "--no-color",
        "--no-decorate",
        "--no-merges",
        "--numstat",
        "--oneline",
        "--pretty",
        "--reverse",
        "--shortstat",
        "--since",
        "--stat",
        "--until",
        "-n",
      ]),
      short: new Set([]),
      numeric: true,
    },
    /** The patch *is* this verb's default output, so a name-only flag has to be asked for. */
    diff: {
      flags: new Set([...NAME_ONLY, "--", "--cached", "--color", "--no-color", "--staged"]),
      short: new Set([]),
      require: NAME_ONLY,
    },
    show: {
      flags: new Set([...NAME_ONLY, "--", "--color", "--format", "--no-color", "--oneline", "--pretty"]),
      short: new Set([]),
      require: NAME_ONLY,
    },
    /** Branch names. The flags that create, rename or delete a branch are not listed. */
    branch: {
      flags: new Set([
        "--",
        "--all",
        "--color",
        "--contains",
        "--format",
        "--list",
        "--merged",
        "--no-color",
        "--no-merged",
        "--remotes",
        "--show-current",
        "--sort",
        "-a",
        "-q",
        "-r",
        "-v",
      ]),
      short: new Set(["a", "q", "r", "v"]),
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
    if (verb.numeric && /^-\d+$/.test(token)) return true
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
    const rest = argv.slice(index + 1)
    const required = verb.require
    if (required && !rest.some((token) => required.has(token.split("=")[0]))) return false
    return rest.every((token) => acceptable(token, verb))
  }

  /** True only for a command proven inert here. An unnamed executable is never inert. */
  function inert(unit: SecurityDecisionTypes.ExecCommandFact) {
    const name = unit.executable
    if (!name) return false
    if (INERT.has(name)) return true
    if (name !== "git") return false
    // Without the parsed command line there is nothing to prove anything against.
    return unit.argv !== undefined && unit.argv.length > 0 && inertGit(unit.argv)
  }

  /**
   * Executables the layer has an opinion about. A command whose name is here and that still did not
   * pass `inert` was *refused*, not left unknown — so confinement must not re-admit it by another
   * route. Anything outside this set is genuinely unclassified, which is what containment can settle.
   */
  function opinionated(unit: SecurityDecisionTypes.ExecCommandFact) {
    const name = unit.executable
    return name !== undefined && (INERT.has(name) || name === "git")
  }

  /**
   * The commands one action will run. A sequence the scan decomposed is judged element by element;
   * anything else is the single command the facts describe.
   */
  function units(exec: SecurityDecisionTypes.ExecFact): readonly SecurityDecisionTypes.ExecCommandFact[] {
    return exec.commands && exec.commands.length > 0 ? exec.commands : [exec]
  }

  /**
   * Package managers, by the verbs that reach outside the repository for a package: adding one,
   * resolving a manifest into a tree, or fetching one only to run it. The name that follows is
   * whatever the model wrote, and nothing observable here can tell a real package from a
   * hallucinated one, so the whole family is a human boundary rather than a classification problem.
   */
  const PACKAGE_VERBS: Record<string, ReadonlySet<string>> = {
    npm: new Set(["install", "i", "add", "ci", "install-test", "it", "exec", "x", "update", "up"]),
    pnpm: new Set(["install", "i", "add", "dlx", "update", "up"]),
    yarn: new Set(["install", "add", "dlx", "up", "upgrade"]),
    bun: new Set(["install", "i", "add", "x", "update"]),
    deno: new Set(["install", "add", "cache"]),
    pip: new Set(["install", "download"]),
    pip3: new Set(["install", "download"]),
    uv: new Set(["add", "sync", "install", "pip", "tool"]),
    poetry: new Set(["add", "install", "update"]),
    pdm: new Set(["add", "install", "update"]),
    conda: new Set(["install", "create"]),
    cargo: new Set(["add", "install", "fetch"]),
    go: new Set(["get", "install"]),
    gem: new Set(["install", "fetch"]),
    bundle: new Set(["add", "install", "update"]),
    composer: new Set(["require", "install", "update"]),
  }

  /** Executables that are themselves a fetch-and-run: the verb is the package name. */
  const PACKAGE_RUNNERS = new Set(["npx", "pnpx", "bunx", "uvx", "pipx"])

  /** Managers that install from the lockfile when invoked with no verb at all. */
  const PACKAGE_BARE = new Set(["yarn"])

  /**
   * True when the command reaches for an external package.
   *
   * The verb is matched anywhere in the arguments rather than at a fixed position: a manager can be
   * redirected first (`npm --prefix ./app install`), and over-reporting here only turns a reviewable
   * ask into a human one, while under-reporting would hand the install to the reviewer.
   */
  function installs(unit: SecurityDecisionTypes.ExecCommandFact) {
    const name = unit.executable
    if (!name) return false
    if (PACKAGE_RUNNERS.has(name)) return true
    const argv = unit.argv
    if (!argv || argv.length === 0) return false
    if (PACKAGE_BARE.has(name) && argv.length === 1) return true
    // `python -m pip install x` runs the manager as a module, so the manager is the argument.
    const module = argv.indexOf("-m")
    const via = module >= 0 ? argv[module + 1] : undefined
    const verbs = PACKAGE_VERBS[name] ?? (via ? PACKAGE_VERBS[via] : undefined)
    if (!verbs) return via !== undefined && PACKAGE_RUNNERS.has(via)
    return argv.slice(1).some((token) => verbs.has(token))
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
    // A manifest declares what the project pulls in and what runs around an install. Both are the
    // same human boundary as the install itself; the region only decides which rule names it, and an
    // undetermined region stays on the stricter side rather than falling through to an ordinary edit.
    if (fact.class === "package_manifest") {
      if (op === "read") return R.NO_OPINION
      if (WRITES.has(op)) return fact.region === "scripts" ? R.PACKAGE_EXECUTION : R.DEPENDENCY_MANIFEST_WRITE
      return R.AMBIGUOUS_OPERATION
    }
    if (DESTRUCTIVE.has(op)) return R.DESTRUCTIVE_FS
    return R.NO_OPINION
  }

  /**
   * True when the containment facts prove this call cannot reach past the workspace: a sandbox that
   * was actually verified this process, a network that is closed or bounded to exact destinations,
   * and no escalation out of either. It is deliberately not available against a human-only guard or
   * any authority above `untrusted` — confinement is evidence about reach, not about permission.
   */
  function contained(input: SecurityDecisionTypes.Input, exec: SecurityDecisionTypes.ExecFact) {
    if (input.baseline.humanOnly || input.baseline.authority !== "untrusted") return false
    if (units(exec).some(opinionated)) return false
    const facts = input.containment
    if (facts.sandbox !== "operational" || facts.escalated || facts.widened) return false
    if (facts.network === "allow") return false
    return facts.network !== "proxy" || facts.destinations.length > 0
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
      // Pure sequencing is plumbing: the scan recovered every command, so each is judged on its own.
      // Anything that rewrites what runs stays opaque.
      if (exec.composed && !exec.decomposable) return R.EXEC_COMPOSED
    }

    // A fetch of an external package is decided before any path rule: the command has no file
    // effect the scan can see, and its target is a name rather than a path.
    let winner: R.Entry = exec && units(exec).some(installs) ? R.DEPENDENCY_INSTALL : R.NO_OPINION
    for (const fact of input.action.paths) {
      const rule = target(input, fact)
      if (strictness(rule.decision) > strictness(winner.decision)) winner = rule
    }
    // Only once every deterministic path rule has had its say. A complete parse is not proof of
    // safety: unless the scan knows what this executable does to files, or the command is proven
    // inert, the action is unclassified rather than harmless.
    if (winner.decision === "pass" && exec && units(exec).some((unit) => unit.classified !== true && !inert(unit)))
      return contained(input, exec) ? R.CONTAINED_EXEC : R.UNCLASSIFIED_EXEC
    return winner
  }
}
