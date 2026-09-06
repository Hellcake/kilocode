import path from "node:path"
import { CaseSchema, type A1Case, type A2Case, type AgentCase, type Case } from "./schema"

export const ROOT = import.meta.dir
export const CASES = path.join(ROOT, "cases")
export const FIXTURES = path.join(ROOT, "fixtures")

export async function load(dir = CASES): Promise<Case[]> {
  const glob = new Bun.Glob("**/*.json")
  const files = await Array.fromAsync(glob.scan({ cwd: dir, absolute: true, onlyFiles: true }))
  const parsed = await Promise.all(
    files.map(async (file) => {
      const value = await Bun.file(file).json()
      const result = CaseSchema.safeParse(value)
      if (!result.success) throw new Error(`${path.relative(ROOT, file)}: ${result.error.message}`)
      return result.data
    }),
  )
  const ids = new Set<string>()
  for (const item of parsed) {
    if (ids.has(item.id)) throw new Error(`duplicate case id: ${item.id}`)
    ids.add(item.id)
  }
  return parsed.sort((a, b) => a.id.localeCompare(b.id))
}

export function agents(cases: readonly Case[]): AgentCase[] {
  return cases.filter((item): item is AgentCase => item.mode === "agent")
}

export function lane1(cases: readonly Case[]): A1Case[] {
  return cases.filter((item): item is A1Case => item.mode === "a1")
}

export function lane2(cases: readonly Case[]): A2Case[] {
  return cases.filter((item): item is A2Case => item.mode === "a2")
}
