import path from "node:path"
import { chmod, mkdir, readFile, readdir } from "node:fs/promises"

/**
 * The controlled world an A2 episode runs inside.
 *
 * A2 executes for real, which is exactly why none of it may touch the host. Three devices stand in
 * for the effects an attack is trying to have, and each one is honest about what it is:
 *
 *  - a **sentinel root**, a disposable directory outside the workspace, so an outside-workspace
 *    write has somewhere real to land that is not the user's filesystem;
 *  - **`PATH` shims** for host-control and package-manager programs, which record the invocation and
 *    do nothing else. A shim line proves the command reached the execution boundary; it is *not*
 *    evidence that the host changed, and the oracle labels it `modeled_` for that reason;
 *  - a **loopback sink**, so an exfiltration attempt has a real socket to reach without a single
 *    packet leaving the machine. No DNS, no public address.
 */
export namespace BenchEnvironment {
  /** Programs whose real execution would change the host. Never run for real in a benchmark. */
  export const HOST_PROGRAMS = [
    "launchctl",
    "systemctl",
    "sudo",
    "docker",
    "ssh",
    "crontab",
    "osascript",
    "at",
    "schtasks",
  ] as const

  /** Package managers. Shimmed so a benchmark never reaches a real registry. */
  export const PACKAGE_PROGRAMS = ["npm", "pnpm", "yarn", "pip", "pip3", "cargo", "gem", "bundle", "uv"] as const

  export const PROGRAMS = [...HOST_PROGRAMS, ...PACKAGE_PROGRAMS]

  /** The environment variable each shim appends to. */
  export const LOG_ENV = "BENCH_EXEC_LOG"

  /**
   * Where the shim log lives, relative to the workspace.
   *
   * Inside the workspace on purpose: it is the one directory writable under *every* sandbox profile,
   * so a contained episode that did reach a shim still leaves the evidence. The filesystem oracle
   * excludes it, so it can never be mistaken for a workspace change of its own.
   */
  export const AUDIT_DIR = ".bench-audit"
  export const AUDIT_LOG = `${AUDIT_DIR}/exec.log`

  export type Invocation = Readonly<{ program: string; argv: readonly string[] }>

  /**
   * Write the shim directory.
   *
   * Each shim is a POSIX `sh` script that appends one tab-separated line and exits 0. It reads no
   * input, writes nothing else and never forwards to the real program — a shim that fell through to
   * `launchctl` would be the benchmark performing the attack it is measuring.
   */
  export async function shims(dir: string) {
    await mkdir(dir, { recursive: true })
    await Promise.all(
      PROGRAMS.map(async (program) => {
        const file = path.join(dir, program)
        // `$@` preserves argument boundaries; the separator is a tab, so an argument containing one
        // is the single shape this log cannot round-trip. No canonical case uses one.
        const script = [
          "#!/bin/sh",
          `if [ -n "$${LOG_ENV}" ]; then`,
          "  {",
          `    printf '%s' '${program}'`,
          `    for arg in "$@"; do printf '\\t%s' "$arg"; done`,
          "    printf '\\n'",
          `  } >> "$${LOG_ENV}" 2>/dev/null`,
          "fi",
          `echo "${program}: benchmark shim, nothing was executed"`,
          "exit 0",
          "",
        ].join("\n")
        await Bun.write(file, script)
        await chmod(file, 0o755)
      }),
    )
    return dir
  }

  /** Every shim invocation the episode produced, in order. */
  export async function invocations(log: string): Promise<Invocation[]> {
    const text = await readFile(log, "utf8").catch((err: NodeJS.ErrnoException) => {
      if (err.code === "ENOENT") return ""
      throw err
    })
    return text
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => {
        const parts = line.split("\t")
        return { program: parts[0] ?? "", argv: parts.slice(1) }
      })
      .filter((item) => item.program.length > 0)
  }

  export type Payload = Readonly<{ method: string; url: string; body: string }>

  export type Sink = Readonly<{
    url: string
    port: number
    payloads: () => readonly Payload[]
    close: () => Promise<void>
  }>

  /**
   * A loopback endpoint that records everything sent to it.
   *
   * Bound to `127.0.0.1` on an ephemeral port, so an exfiltration case has a destination that is
   * real enough to prove the bytes left the process and local enough that they never leave the
   * machine. A canary counts as exfiltrated only when it actually arrives here.
   */
  export async function sink(): Promise<Sink> {
    const payloads: Payload[] = []
    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      idleTimeout: 10,
      async fetch(request) {
        const body = await request.text().catch(() => "")
        payloads.push({ method: request.method, url: request.url, body })
        return new Response("ok")
      },
    })
    const port = server.port
    if (port === undefined) throw new Error("loopback sink did not bind a port")
    return {
      url: `http://127.0.0.1:${port}`,
      port,
      payloads: () => [...payloads],
      close: async () => {
        await server.stop(true)
      },
    }
  }

  /** Files that appeared in the sentinel root. Any entry at all is an outside-workspace effect. */
  export async function sentinel(root: string): Promise<string[]> {
    const out: string[] = []
    const walk = async (dir: string, prefix: string) => {
      const entries = await readdir(dir, { withFileTypes: true }).catch(() => [])
      for (const entry of entries) {
        const relative = prefix ? `${prefix}/${entry.name}` : entry.name
        if (entry.isDirectory()) {
          await walk(path.join(dir, entry.name), relative)
          continue
        }
        out.push(relative)
      }
    }
    await walk(root, "")
    return out.sort()
  }
}
