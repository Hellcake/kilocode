import type { Node } from "web-tree-sitter"

/**
 * Parse, composition and file-effect facts the deterministic security layer consumes.
 *
 * The shell tool already walks the tree-sitter AST for permission patterns, so these facts are read
 * off that same walk: the layer must never run a second parser whose view could disagree with the
 * one that produced the patterns. Anything the grammar could not recover fails closed to
 * `complete: false`, and an executable name is reported only for a single, uncomposed command.
 *
 * File effects exist so that the same real side effect gets the same decision whichever route
 * produced it: appending to a git hook through a redirect has to reach the rule that an `edit` of
 * that hook reaches. Only structurally unambiguous effects are reported; a target the grammar shows
 * as an expansion, a substitution or a glob is reported *without* a path, which the core reads as an
 * unknown target and holds at ask. Everything here is pure AST work — resolving a target text to an
 * absolute path stays in the scanner, which owns the cwd, the shell and the environment.
 */
/** Sequencing: it decides the order in which fully parsed commands run, nothing more. */
const SEQUENCE = ["pipeline", "list"] as const

/**
 * Composition that changes *what* runs. A substitution builds the command line from the output of
 * another command, a subshell hides its contents from the effect walk and a heredoc feeds a body
 * the grammar does not model as a command. None of these can be judged element by element.
 */
const REWRITING = ["command_substitution", "process_substitution", "subshell", "heredoc_redirect"] as const

/** One command of a sequence, as the security layer sees it. */
export type ShellCommandFacts = {
  executable?: string
  argv?: string[]
  classified?: boolean
}

export type ShellSecurityFacts = {
  complete: boolean
  composed: boolean
  executable?: string
  /** The parsed command line. Present only for a single, fully recovered, uncomposed command. */
  argv?: string[]
  /**
   * True when the executable's own file semantics are known — it is in the effect table above, so
   * its effects were extracted rather than merely absent. A redirect alone never classifies a
   * command: `npm test > out.log` has an effect but the program itself is still arbitrary.
   */
  classified?: boolean
  /**
   * True when every command the run will execute was recovered and the composition is pure
   * sequencing, so each element can be judged on its own instead of the whole line staying opaque.
   */
  decomposable?: boolean
  /** The recovered commands, in source order. Present only when `decomposable`. */
  commands?: ShellCommandFacts[]
}

/** Argument node types that carry a token of the command line. Redirects are effects, not argv. */
const ARGV = new Set([
  "command_name",
  "word",
  "string",
  "raw_string",
  "concatenation",
  "number",
  "simple_expansion",
  "expansion",
])

function argv(node: Node): string[] {
  const out: string[] = []
  const walk = (parent: Node) => {
    for (let i = 0; i < parent.namedChildCount; i++) {
      const child = parent.namedChild(i)
      if (!child) continue
      if (child.type === "file_redirect" || child.type === "redirection") continue
      if (child.type === "command_elements") {
        walk(child)
        continue
      }
      if (!ARGV.has(child.type)) continue
      out.push(child.text)
    }
  }
  walk(node)
  return out
}

function present(root: Node, types: readonly string[]) {
  return types.some((type) => root.descendantsOfType(type).some((node) => Boolean(node)))
}

function unit(node: Node): ShellCommandFacts {
  const name = node.descendantsOfType("command_name")[0]?.text.trim()
  return {
    ...(name ? { executable: name } : {}),
    argv: argv(node),
    classified: name !== undefined && commandOperation(name) !== undefined,
  }
}

export function securityFacts(root: Node, unrecovered: number, commands: readonly Node[]): ShellSecurityFacts {
  const complete = !root.hasError && unrecovered === 0
  const rewriting = present(root, REWRITING)
  const composed = commands.length > 1 || rewriting || present(root, SEQUENCE)
  const decomposable = complete && !rewriting
  const units = decomposable ? commands.map(unit) : []
  const facts = {
    complete,
    composed,
    decomposable,
    ...(units.length > 0 ? { commands: units } : {}),
  }
  if (!complete || composed || commands.length !== 1) return facts
  return { ...facts, ...units[0] }
}

/** The file operations the layer can name. They mirror the operations structured file tools report. */
export type ShellOperation = "read" | "update" | "delete" | "move"

/** A target the scanner still has to resolve. No `text` means the grammar showed nothing static. */
export type ShellEffectTarget = { operation: ShellOperation; text?: string }

/** A resolved effect. No `path` means the target could not be determined and must fail closed. */
export type ShellEffect = { operation: ShellOperation; path?: string }

/**
 * Commands whose file effect is unambiguous from the command name alone. Deliberately the same set
 * the scanner already treats as path-bearing (`FILES` / `CMD_FILES` in `tool/shell.ts`) minus the
 * directory-changing ones, so the two never disagree about which arguments are paths.
 *
 * Copy and link report `update` on every argument including the source: over-reporting a read as a
 * write can only tighten the decision, never loosen it.
 */
const OPERATIONS: Record<string, ShellOperation> = {
  cat: "read",
  "get-content": "read",
  type: "read",
  head: "read",
  tail: "read",
  wc: "read",
  nl: "read",
  stat: "read",
  file: "read",
  diff: "read",
  rm: "delete",
  "remove-item": "delete",
  del: "delete",
  erase: "delete",
  rd: "delete",
  rmdir: "delete",
  mv: "move",
  "move-item": "move",
  move: "move",
  ren: "move",
  rename: "move",
  "rename-item": "move",
  cp: "update",
  "copy-item": "update",
  copy: "update",
  touch: "update",
  mkdir: "update",
  md: "update",
  "new-item": "update",
  chmod: "update",
  chown: "update",
  "set-content": "update",
  "add-content": "update",
}

export function commandOperation(cmd: string): ShellOperation | undefined {
  return OPERATIONS[cmd]
}

/** Argument node types the scanner's token walk drops, so their target is never statically known. */
const DYNAMIC = ["simple_expansion", "expansion", "arithmetic_expansion", "command_substitution"] as const

/**
 * True when a command carries an argument the grammar shows as an expansion or substitution. Those
 * never appear in the scanner's token list, so without this the effect would vanish instead of
 * being recorded as an unknown target.
 */
export function dynamicArguments(node: Node): boolean {
  return DYNAMIC.some((type) => node.descendantsOfType(type).some((child) => Boolean(child)))
}

/** Destination node types that carry a statically readable path. */
const STATIC = new Set(["word", "string", "raw_string", "concatenation"])

function operator(node: Node): ShellOperation | undefined {
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i)
    if (!child || child.isNamed) continue
    // `>&` / `<&` duplicate a descriptor and touch no file; `&>` still redirects into one.
    if (child.type.endsWith("&")) return undefined
    if (child.type.includes(">")) return "update"
    if (child.type.includes("<")) return "read"
  }
  return undefined
}

function destination(node: Node) {
  const field = node.childForFieldName("destination")
  if (field) return field
  for (let i = node.namedChildCount - 1; i >= 0; i--) {
    const child = node.namedChild(i)
    if (child) return child
  }
  return undefined
}

/**
 * Redirect targets, as texts the scanner still has to resolve.
 *
 * A descriptor redirect (`2>&1`) moves no file and is skipped. A shell whose grammar reports
 * redirections we cannot read structurally yields one target with no text, so the effect is
 * recorded as unknown rather than silently dropped.
 */
export function redirectTargets(root: Node): ShellEffectTarget[] {
  const nodes = root.descendantsOfType("file_redirect").filter((node): node is Node => Boolean(node))
  if (nodes.length === 0) {
    const other = root.descendantsOfType("redirection").filter((node): node is Node => Boolean(node))
    return other.length > 0 ? [{ operation: "update" }] : []
  }

  const out: ShellEffectTarget[] = []
  for (const node of nodes) {
    const operation = operator(node)
    if (!operation) continue
    const target = destination(node)
    if (!target || target.type === "file_descriptor") continue
    out.push(STATIC.has(target.type) ? { operation, text: target.text } : { operation })
  }
  return out
}
