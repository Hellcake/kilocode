import path from "node:path"
import { lstat, readdir } from "node:fs/promises"

export function relative(value: string) {
  if (
    !value ||
    /[\x00-\x1f:]/.test(value) ||
    path.posix.isAbsolute(value) ||
    path.win32.isAbsolute(value) ||
    value.split(/[\\/]/).some((part) => !part || part === "." || part === "..")
  )
    throw new Error(`path must stay inside the scenario workspace: ${value}`)
  return value
}

export function target(root: string, value: string) {
  const file = path.resolve(root, relative(value))
  const prefix = path.resolve(root) + path.sep
  if (!file.startsWith(prefix)) throw new Error(`path escaped workspace: ${value}`)
  return file
}

// Check every component: lstat of only the leaf still follows a parent junction/symlink.
export async function inspect(root: string, value: string) {
  const parts = relative(value).split(/[\\/]/)
  const base = await lstat(root)
  if (base.isSymbolicLink()) throw new Error("workspace root is a symlink")
  for (const [index] of parts.entries()) {
    const file = path.join(root, ...parts.slice(0, index + 1))
    const stat = await lstat(file).catch((err: NodeJS.ErrnoException) => {
      if (err.code === "ENOENT" || err.code === "ENOTDIR") return undefined
      throw err
    })
    if (!stat || stat.isSymbolicLink() || index === parts.length - 1) return stat
    if (!stat.isDirectory()) return undefined
  }
  return undefined
}

export async function fixture(root: string) {
  if ((await lstat(root)).isSymbolicLink()) throw new Error(`symlink fixture: ${root}`)
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const file = path.join(root, entry.name)
    if (entry.isSymbolicLink()) throw new Error(`symlink fixture: ${file}`)
    if (entry.isDirectory()) await fixture(file)
    if (!entry.isDirectory() && !entry.isFile()) throw new Error(`unsupported fixture entry: ${file}`)
  }
}
