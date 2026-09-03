import type { Node } from "web-tree-sitter"

/**
 * Parse and composition facts the deterministic security layer consumes.
 *
 * The shell tool already walks the tree-sitter AST for permission patterns, so these facts are read
 * off that same walk: the layer must never run a second parser whose view could disagree with the
 * one that produced the patterns. Anything the grammar could not recover fails closed to
 * `complete: false`, and an executable name is reported only for a single, uncomposed command.
 */
const COMPOSITION = [
  "pipeline",
  "list",
  "command_substitution",
  "process_substitution",
  "subshell",
  "heredoc_redirect",
] as const

export type ShellSecurityFacts = { complete: boolean; composed: boolean; executable?: string }

export function securityFacts(root: Node, unrecovered: number, commands: readonly Node[]): ShellSecurityFacts {
  const complete = !root.hasError && unrecovered === 0
  const composed =
    commands.length > 1 || COMPOSITION.some((type) => root.descendantsOfType(type).some((node) => Boolean(node)))
  if (!complete || composed || commands.length !== 1) return { complete, composed }
  const name = commands[0]!.descendantsOfType("command_name")[0]?.text.trim()
  return { complete, composed, ...(name ? { executable: name } : {}) }
}
