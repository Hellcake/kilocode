import { afterAll, describe, expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { Effect } from "effect"
import { ChildProcess } from "effect/unstable/process"
import { prepareCommand, run as runSandbox } from "@kilocode/sandbox"
import * as SandboxPolicy from "@/kilocode/sandbox/policy"
import { BenchSandbox } from "../../../benchmark/kilocode/security-auto/sandbox"
import { runA1, withA1Workspace } from "../../../benchmark/kilocode/security-auto/lane-a1"
import type { InstanceContext } from "@/project/instance-context"

/**
 * Block 3: the preflight that decides whether a contained measurement may be reported at all.
 *
 * Everything here is about the difference between a sandbox being *configured* and a sandbox being
 * *proven*. The benchmark is allowed to say `operational` only after a confined child on this
 * machine has been observed obeying the profile, so these tests check both that the proof runs and
 * that every way of not having one lands somewhere other than `operational`.
 */

const darwin = process.platform === "darwin" ? test : test.skip

// Only the sandbox state this file created: the lane's runtime is shared with the other benchmark
// suites in this process, and disposing it here would tear it out from under them.
afterAll(async () => {
  await BenchSandbox.dispose()
})

/** Launch a script under the production session profile and report its exit code. */
async function confined(ctx: InstanceContext, script: string, env: Record<string, string>) {
  const launch = await Effect.runPromise(
    Effect.scoped(
      runSandbox(
        SandboxPolicy.profile(ctx, "deny"),
        prepareCommand(ChildProcess.make("/bin/sh", ["-c", script], { shell: false }), ctx.directory, {
          PATH: "/usr/bin:/bin",
          ...env,
        }),
      ),
    ),
  )
  const child = Bun.spawn([launch.command, ...launch.args], {
    cwd: launch.options.cwd,
    env: launch.options.env,
    stdout: "ignore",
    stderr: "ignore",
  })
  return child.exited
}

describe("sandbox preflight states", () => {
  test("a disabled sandbox is off, and off is not a containment claim", async () => {
    const report = await withA1Workspace((_cwd, ctx) => BenchSandbox.preflight("no-sandbox", ctx))
    expect(report.state).toBe("off")
    expect(report.network).toBe("off")
    // Nothing was measured, so nothing may be reported as measured.
    expect(report.probes).toEqual([])
    expect(BenchSandbox.proven(report)).toBe(false)
  })

  test("a disabled sandbox reports no containment through the production path either", async () => {
    const facts = await withA1Workspace((cwd) => BenchSandbox.containment("no-sandbox", cwd))
    expect(facts.sandbox).toBe("off")
    expect(facts.escalated).toBe(false)
    expect(facts.widened).toBe(false)
  })

  test("enabled on a platform that cannot confine is unavailable, never operational", async () => {
    const report = await withA1Workspace((_cwd, ctx) =>
      BenchSandbox.preflight("contained-deny", ctx, { platform: "linux" }),
    )
    expect(report.state).toBe("unavailable")
    expect(BenchSandbox.proven(report)).toBe(false)
    // An unavailable backend has nothing to show, so it must not present a passing probe list.
    expect(report.probes).toEqual([])
  })

  test("a probe that comes back unavailable is reported as unavailable, not failed", async () => {
    const report = await withA1Workspace((_cwd, ctx) =>
      BenchSandbox.preflight("contained-deny", ctx, { probe: async () => "unavailable" }),
    )
    expect(report.state).toBe("unavailable")
    expect(report.probes.map((probe) => [probe.id, probe.ok])).toEqual([[BenchSandbox.FILESYSTEM_PROBE, false]])
  })

  test("a probe that comes back failed is a finding, and the run may not claim containment", async () => {
    const report = await withA1Workspace((_cwd, ctx) =>
      BenchSandbox.preflight("contained-deny", ctx, { probe: async () => "failed" }),
    )
    expect(report.state).toBe("failed")
    expect(BenchSandbox.proven(report)).toBe(false)
  })

  test("a failed preflight aborts a contained run instead of downgrading it", async () => {
    await withA1Workspace(async (cwd, ctx) => {
      const failed = await BenchSandbox.preflight("contained-deny", ctx, { probe: async () => "failed" })
      BenchSandbox.seedPreflight("contained-deny", ctx.directory, failed)
      // The point is that it throws rather than quietly reporting an uncontained measurement under
      // a contained label: a broken sandbox is a reason to stop, not a reason to report `off`.
      const thrown = await runA1({ entry: "shell", command: "npm test", cwd, sandbox: "contained-deny" }).then(
        () => undefined,
        (err: unknown) => err,
      )
      expect(thrown).toBeInstanceOf(Error)
      expect(String(thrown)).toMatch(/preflight failed/)
    })
  })

  darwin("the real backend proves containment, and says which probes proved it", async () => {
    const report = await withA1Workspace((_cwd, ctx) => BenchSandbox.preflight("contained-deny", ctx))
    expect([report.state, report.backend, report.network]).toEqual(["operational", "seatbelt", "deny"])
    expect(report.backend_available).toBe(true)
    expect(BenchSandbox.proven(report)).toBe(true)
    expect(report.probes.map((probe) => probe.id)).toEqual([
      BenchSandbox.FILESYSTEM_PROBE,
      BenchSandbox.NETWORK_PROBE,
    ])
    for (const probe of report.probes) expect([probe.id, probe.ok]).toEqual([probe.id, true])
  })
})

/**
 * The four assertions the production containment check makes, re-run against the *session* profile.
 *
 * `ContainmentMacos` proves them against a scratch profile it builds itself; these run the same
 * assertions against `SandboxPolicy.profile`, the profile a real tool call executes under, so a
 * change that loosened the session profile alone could not pass unnoticed.
 */
describe("the production session profile confines what it claims to", () => {
  darwin("a write inside the workspace is allowed", async () => {
    const code = await withA1Workspace((_cwd, ctx) => confined(ctx, 'printf ok > "$PWD/inside"', {}))
    expect(code).toBe(0)
  })

  darwin("a write outside the workspace is denied", async () => {
    const outside = await mkdtemp(path.join(os.tmpdir(), "kilo-bench-outside-"))
    try {
      const code = await withA1Workspace((_cwd, ctx) =>
        confined(ctx, 'printf no > "$PROBE_OUTSIDE/escaped"', { PROBE_OUTSIDE: outside }),
      )
      expect(code).not.toBe(0)
    } finally {
      await rm(outside, { recursive: true, force: true })
    }
  })

  darwin("a write to a .git name is denied even inside the workspace", async () => {
    const code = await withA1Workspace((_cwd, ctx) =>
      confined(ctx, 'mkdir -p "$PWD/.git" 2>/dev/null; printf no > "$PWD/.git/hook"', {}),
    )
    expect(code).not.toBe(0)
  })

  darwin("a denied environment variable does not reach the child", async () => {
    const code = await withA1Workspace((_cwd, ctx) =>
      confined(ctx, '[ -z "$KILO_SERVER_PASSWORD" ] || exit 14', { KILO_SERVER_PASSWORD: "leaked" }),
    )
    expect(code).toBe(0)
  })
})

/**
 * The half the production check does not cover.
 *
 * No DNS and no public address: a loopback server on an ephemeral port, and the same command run
 * twice. The unconfined run must connect — otherwise a probe that simply could not run would read as
 * a passing denial — and the confined run must not.
 */
describe("outbound network is actually denied", () => {
  darwin("the loopback proof is two-sided and lands on the deny side", async () => {
    const report = await withA1Workspace((_cwd, ctx) => BenchSandbox.preflight("contained-deny", ctx))
    const probe = report.probes.find((item) => item.id === BenchSandbox.NETWORK_PROBE)
    expect(probe).toBeDefined()
    expect(probe!.ok).toBe(true)
    // The detail distinguishes "refused" from "the control never connected", which are the two ways
    // this probe can end without the confined child reaching the server.
    expect(probe!.detail).toMatch(/confined connect refused/)
  })
})
