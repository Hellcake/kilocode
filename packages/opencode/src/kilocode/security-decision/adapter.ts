import path from "path"
import { SecurityDecision } from "./core"
import { SecurityDecisionRules as R } from "./rules"
import { SecurityReviewer } from "./reviewer"
import type { SecurityAuthority } from "./authority"
import type { SecurityDecisionTypes as T } from "./types"

/**
 * Kilo-side normalization for the deterministic security layer.
 *
 * Everything Kilo-specific happens here: reading the existing per-permission metadata, canonicalizing
 * paths without touching the filesystem, assembling the authority and containment facts, calling the
 * pure core and shaping the audit record. Raw chat, README text, tool output and MCP arguments never
 * reach this function, and nothing it produces echoes a command, path or diff.
 */
export namespace SecurityDecisionAdapter {
  /** Built-in permission names. Anything else asking for `*` is an opaque delegated (MCP) action. */
  const KNOWN = new Set([
    "agent_manager",
    "bash",
    "board_post",
    "board_read",
    "browser_open",
    "doom_loop",
    "edit",
    "external_directory",
    "glob",
    "grep",
    "interactive_terminal",
    "lsp",
    "notebook_edit",
    "notebook_execute",
    "notebook_read",
    "plan_enter",
    "plan_exit",
    "question",
    "read",
    "recall",
    "repo_clone",
    "repo_overview",
    "sandbox_escalation",
    "semantic_search",
    "skill",
    "suggest",
    "task",
    "todowrite",
    "webfetch",
    "websearch",
    "workflow_tool_approval",
    "write",
  ])

  const READS = new Set(["read", "grep", "glob", "notebook_read", "semantic_search", "repo_overview"])
  const EXECS = new Set(["bash", "interactive_terminal"])

  export type Request = Readonly<{
    permission: string
    patterns: readonly string[]
    metadata?: Record<string, unknown>
    sessionID: string
    callID?: string
  }>

  export type Context = Readonly<{
    workspace: string
    effective: "allow" | "ask" | "deny"
    humanOnly: boolean
    floor: SecurityAuthority.Floor
    containment: T.Containment & { probe_id?: string; checked_at?: number }
  }>

  export type Enforcement = "allow" | "ask_pending" | "reject" | "deny" | "blocked" | "error"

  export type Audit = {
    schema: "kilo.security-decision/v1"
    policy_version: string
    rule_id: string
    reason: string
    decision: T.Decision
    reviewer: SecurityReviewer.Outcome
    final_enforcement?: Enforcement
    enforcement_source?: string
    authority_level: T.Authority
    authority_basis: "none" | "xdg_scope" | "hard_product"
    authority_conflict: boolean
    metadata_complete: boolean
    metadata_truncated: boolean
    containment: T.Containment & { probe_id?: string; checked_at?: number }
    requirements: readonly T.Requirement[]
    latency_ms: number
    callID?: string
    sessionID: string
  }

  export type Directive = Readonly<{ decision: T.Decision; rule_id: string; reviewable: boolean; audit: Audit }>

  /**
   * Server-side feature flag. It lives in the process environment precisely so a project config,
   * which can arrive with a clone, cannot turn the layer off.
   */
  export function enabled(env: Record<string, string | undefined> = process.env) {
    const value = env["KILO_SECURITY_DECISION"]
    return value === "1" || value === "true"
  }

  /** Device nodes that discard or echo output rather than persisting a file. */
  const SINKS = new Set(["/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero"])

  const OPERATIONS = new Set(["read", "update", "delete", "move"])

  function posix(value: string) {
    return value.replaceAll("\\", "/")
  }

  /** Canonicalize a permission pattern into a path fact. No IO: the workspace is compared textually. */
  function classify(pattern: string, workspace: string): T.PathFact {
    if (!pattern || pattern === "*") return { path: pattern, inWorkspace: true, class: "unknown" }
    const raw = posix(pattern)
    const normalized = path.posix.normalize(raw)
    const absolute = path.posix.isAbsolute(normalized)
    const relative = absolute ? path.posix.relative(posix(workspace), normalized) : normalized
    const inWorkspace = !relative.startsWith("../") && relative !== ".." && !(absolute && relative === normalized)

    // `> /dev/null` is the canonical discard, not a device write, and nothing persists past the
    // process — so it is neither a root target nor a boundary crossing. Other device nodes stay root.
    if (SINKS.has(normalized)) return { path: normalized, inWorkspace: true, class: "ordinary" }
    if (normalized === "/" || normalized.startsWith("/dev/"))
      return { path: normalized, inWorkspace: false, class: "root" }

    const target = inWorkspace ? relative : normalized
    const cls = pathClass(target)
    return {
      path: target,
      inWorkspace,
      class: cls,
      ...(cls === "package_manifest" ? { region: "other" as const } : {}),
    }
  }

  function pathClass(target: string): T.PathClass {
    const base = path.posix.basename(target)
    if (/(^|\/)\.git\/hooks\//.test(target)) return "git_hook"
    if (/(^|\/)\.github\/workflows\//.test(target) || base === ".gitlab-ci.yml" || /(^|\/)\.circleci\//.test(target))
      return "ci"
    if (base === "package.json") return "package_manifest"
    if (
      base === ".env" ||
      base.startsWith(".env.") ||
      /(^|\/)\.ssh\//.test(target) ||
      /(^|\/)\.aws\//.test(target) ||
      base.endsWith(".pem") ||
      base.endsWith(".key") ||
      base === "credentials" ||
      base === ".netrc"
    )
      return "sensitive"
    return "ordinary"
  }

  /** apply-patch reports a per-file operation; edit/write always write, reads always read. */
  function operation(request: Request): string {
    if (READS.has(request.permission)) return "read"
    if (EXECS.has(request.permission)) return "exec"
    if (request.permission === "external_directory") {
      return request.metadata?.["access"] === "read" ? "read" : "unknown"
    }
    const files = request.metadata?.["files"]
    if (Array.isArray(files)) {
      const types = files.map((file) => (file as { type?: unknown }).type).filter((t) => typeof t === "string")
      if (types.includes("delete")) return "delete"
      if (types.includes("move")) return "move"
      if (types.length > 0) return "update"
    }
    if (request.permission === "edit" || request.permission === "write" || request.permission === "notebook_edit")
      return "update"
    return "unknown"
  }

  function exec(request: Request): T.ExecFact | undefined {
    if (!EXECS.has(request.permission)) return undefined
    const facts = request.metadata?.["securityFacts"]
    // No facts at all is a plumbing gap, not an unparsed command: report it as missing metadata.
    if (!facts || typeof facts !== "object") return undefined
    const value = facts as { complete?: unknown; composed?: unknown; executable?: unknown }
    return {
      complete: value.complete === true,
      composed: value.composed === true,
      ...(typeof value.executable === "string"
        ? { executable: value.executable, class: "known" as const }
        : { class: "unknown" as const }),
    }
  }

  /**
   * File effects the shell scan extracted, normalized into path facts so a shell route reaches the
   * same rules as `edit`/`write`/`read`. An effect without a path is a target the scan could not
   * determine: it becomes an `unknown` fact, which the core holds at ask.
   */
  function effects(request: Request, workspace: string): T.PathFact[] {
    const facts = request.metadata?.["securityFacts"]
    if (!facts || typeof facts !== "object") return []
    const list = (facts as { effects?: unknown }).effects
    if (!Array.isArray(list)) return []
    const out: T.PathFact[] = []
    for (const item of list) {
      if (!item || typeof item !== "object") continue
      const value = item as { operation?: unknown; path?: unknown }
      if (typeof value.operation !== "string" || !OPERATIONS.has(value.operation)) continue
      if (typeof value.path !== "string" || value.path.length === 0) {
        out.push({ path: "", inWorkspace: false, class: "unknown", operation: value.operation })
        continue
      }
      out.push({ ...classify(value.path, workspace), operation: value.operation })
    }
    return out
  }

  /** MCP asks arrive as an unregistered permission name with a `*` pattern and empty metadata. */
  function delegated(request: Request) {
    return !KNOWN.has(request.permission)
  }

  function toInput(request: Request, ctx: Context): T.Input {
    const kind = delegated(request) ? "mcp" : request.permission
    // Shell patterns are commands, not paths: its targets come from the scan's structured effects.
    const paths =
      kind === "mcp"
        ? []
        : EXECS.has(request.permission)
          ? effects(request, ctx.workspace)
          : request.patterns.map((pattern) => classify(pattern, ctx.workspace))
    const facts = exec(request)
    const complete = !EXECS.has(request.permission) || facts !== undefined
    return {
      version: 1,
      action: { kind, operation: operation(request), paths, ...(facts ? { exec: facts } : {}) },
      baseline: {
        decision: ctx.floor.action === "deny" ? "ask" : ctx.floor.action,
        authority: ctx.floor.authority,
        humanOnly: ctx.humanOnly,
      },
      metadata: { complete, truncated: false },
      containment: ctx.containment,
    }
  }

  function audit(request: Request, ctx: Context, result: T.Result, started: number): Audit {
    return {
      schema: "kilo.security-decision/v1",
      policy_version: R.POLICY_VERSION,
      rule_id: result.rule_id,
      reason: result.reason,
      decision: result.decision,
      reviewer: SecurityReviewer.SKIPPED,
      authority_level: ctx.floor.authority,
      authority_basis:
        ctx.floor.authority === "xdg_global" ? "xdg_scope" : ctx.floor.authority === "hard" ? "hard_product" : "none",
      authority_conflict: ctx.floor.conflict,
      metadata_complete: result.rule_id !== R.METADATA_INCOMPLETE.id,
      metadata_truncated: false,
      containment: ctx.containment,
      requirements: result.requirements,
      latency_ms: Date.now() - started,
      ...(request.callID ? { callID: request.callID } : {}),
      sessionID: request.sessionID,
    }
  }

  export function evaluate(request: Request, ctx: Context): Directive {
    const started = Date.now()
    try {
      const result = SecurityDecision.decide(toInput(request, ctx))
      const reviewed = SecurityReviewer.review(result)
      return {
        decision: reviewed.result.decision,
        rule_id: reviewed.result.rule_id,
        reviewable: reviewed.result.reviewable,
        audit: { ...audit(request, ctx, reviewed.result, started), reviewer: reviewed.outcome },
      }
    } catch {
      // Anything unexpected in normalization, the core or the reviewer fails closed to ask.
      const result = R.result(R.INTERNAL_ERROR)
      return {
        decision: result.decision,
        rule_id: result.rule_id,
        reviewable: false,
        audit: {
          ...audit(
            { permission: "", patterns: [], sessionID: request.sessionID, callID: request.callID },
            ctx,
            result,
            started,
          ),
          metadata_complete: false,
        },
      }
    }
  }

  export function finalize(record: Audit, enforcement: Enforcement, source: string): Audit {
    return { ...record, final_enforcement: enforcement, enforcement_source: source }
  }
}
