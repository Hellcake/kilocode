import net from "node:net"
import { Effect, Layer } from "effect"
import { ChildProcess } from "effect/unstable/process"
import { AppNodeBuilder } from "@opencode-ai/core/effect/app-node-builder"
import { Database } from "@opencode-ai/core/database/database"
import { backendSupport, prepareCommand, run as runSandbox } from "@kilocode/sandbox"
import { Config } from "@/config/config"
import type { SandboxConfig } from "@/kilocode/sandbox/config"
import * as SandboxPolicy from "@/kilocode/sandbox/policy"
import { SandboxStore } from "@/kilocode/sandbox/store"
import { ContainmentMacos } from "@/kilocode/security-decision/containment-macos"
import type { SecurityDecisionTypes as T } from "@/kilocode/security-decision/types"
import type { InstanceContext } from "@/project/instance-context"
import { SessionID } from "@/session/schema"

/**
 * The sandbox axis: what confinement a benchmark run was actually decided against.
 *
 * The whole point of this module is that the benchmark never states a containment fact of its own.
 * `sandbox: "operational"` is not a value the harness may write; it is a value the production
 * containment path returns after a real confined child has been observed obeying the profile. A
 * dataset that asserted containment would be measuring its own opinion, which is the mistake v1's
 * `replay` mode made about every other fact.
 */
export namespace BenchSandbox {
  /**
   * What the run may claim about confinement.
   *
   * `off`         — the sandbox is deliberately disabled; there is nothing to prove.
   * `operational` — the backend is available *and* every mandatory probe passed on this machine.
   * `unavailable` — the platform or backend cannot confine at all, so no contained claim is possible.
   * `failed`      — confinement was configured and claimed available, and the proof did not hold.
   *
   * The distinction between the last two is the reason this is a four-state machine rather than a
   * boolean: an unavailable backend is a limit of the host, while a failed proof is a finding.
   */
  export type State = "off" | "operational" | "unavailable" | "failed"

  export type ProfileID = "no-sandbox" | "contained-deny"

  export const PROFILE_IDS = ["no-sandbox", "contained-deny"] as const satisfies readonly ProfileID[]

  export type Profile = Readonly<{
    id: ProfileID
    description: string
    /**
     * Exactly the production `kilocode.sandbox` config schema, handed to the production
     * `Config.Service` unchanged. Nothing here is a benchmark-shaped stand-in for it.
     */
    config: SandboxConfig.Info
  }>

  /**
   * `contained-proxy` and `contained-widened` are deliberately absent. A proxy profile needs exact
   * allowed destinations and a running relay, and a widened profile only demonstrates that
   * `containment.widened` disables the contained population — both are Block 5 work, and declaring
   * them here without the probes to back them would put two unproven rows in every report.
   */
  const PROFILES: Readonly<Record<ProfileID, Profile>> = {
    "no-sandbox": {
      id: "no-sandbox",
      description: "Sandbox disabled: the state a developer without an operational backend has",
      config: { enabled: false },
    },
    "contained-deny": {
      id: "contained-deny",
      description: "Sandbox enabled, outbound network denied, no widened writable or network capability",
      config: { enabled: true, network: "deny" },
    },
  }

  export function profile(id: ProfileID): Profile {
    const found = PROFILES[id]
    if (!found) throw new Error(`unknown sandbox profile ${id}; choose: ${PROFILE_IDS.join(", ")}`)
    return found
  }

  export function profiles(): readonly Profile[] {
    return PROFILE_IDS.map(profile)
  }

  /** The backend the platform would actually select. Reported, never assumed. */
  export function backend(platform: NodeJS.Platform = process.platform) {
    if (platform === "darwin") return "seatbelt" as const
    if (platform === "linux") return "bubblewrap" as const
    return "none" as const
  }

  export type Probe = Readonly<{
    id: string
    /** The assertions this probe stands for, so a passing id is not an unexamined claim. */
    covers: readonly string[]
    ok: boolean
    detail?: string
  }>

  /**
   * The production containment check, reused rather than reimplemented.
   *
   * `ContainmentMacos.probe()` launches a confined child through the same public sandbox launch
   * abstraction production uses and observes that a write inside its scratch root succeeds while a
   * write outside it, a write to a `.git` name and a denied environment variable all fail. The
   * benchmark adds nothing to it and second-guesses none of it.
   */
  export const FILESYSTEM_PROBE = "kilo.containment.macos/v1"

  /** The one thing the production check does not assert. See `loopback`. */
  export const NETWORK_PROBE = "bench.network.loopback-deny/v1"

  export type Preflight = Readonly<{
    profile: ProfileID
    platform: NodeJS.Platform
    backend: ReturnType<typeof backend>
    backend_available: boolean
    backend_reason?: string
    /** The configured network policy, or `off` when the profile runs no sandbox at all. */
    network: "off" | "allow" | "deny" | "proxy"
    state: State
    probes: readonly Probe[]
    checked_at: number
  }>

  /** Whether a contained run may be treated as a full contained security result. */
  export function proven(preflight: Preflight) {
    return preflight.state === "operational"
  }

  /**
   * A local, deterministic proof that outbound network is actually denied.
   *
   * The production containment check proves filesystem and environment confinement and says nothing
   * about sockets, so this probe supplies the missing half. It never touches DNS or a public
   * address: a loopback server is started on an ephemeral port and a confined child is asked to
   * connect to it. Seatbelt's `deny` policy is a blanket `(deny network-outbound)` with no loopback
   * exception, so the expected reading is unambiguous.
   *
   * It is a two-sided measurement on purpose. The same command is run unconfined first and must
   * connect; without that control a probe that could not connect for any reason at all — a missing
   * `nc`, a server that never bound — would read as a passing denial.
   */
  async function loopback(ctx: InstanceContext, network: "deny"): Promise<Probe> {
    const covers = ["outbound loopback connect refused under the production profile"]
    const server = net.createServer((socket) => socket.end())
    const listening = new Promise<void>((resolve, reject) => {
      server.once("error", reject)
      server.listen(0, "127.0.0.1", resolve)
    })
    try {
      await listening
      const address = server.address()
      if (!address || typeof address === "string") throw new Error("loopback probe did not bind a port")
      const env = { PATH: "/usr/bin:/bin", PROBE_PORT: String(address.port) }
      const script = 'exec /usr/bin/nc -z -w 2 127.0.0.1 "$PROBE_PORT"'
      const control = Bun.spawn(["/bin/sh", "-c", script], {
        cwd: ctx.directory,
        env,
        stdout: "ignore",
        stderr: "ignore",
      })
      if ((await control.exited) !== 0)
        return { id: NETWORK_PROBE, covers, ok: false, detail: "unconfined control could not reach the loopback server" }
      const launch = await Effect.runPromise(
        Effect.scoped(
          runSandbox(
            SandboxPolicy.profile(ctx, network),
            prepareCommand(ChildProcess.make("/bin/sh", ["-c", script], { shell: false }), ctx.directory, env),
          ),
        ),
      )
      const child = Bun.spawn([launch.command, ...launch.args], {
        cwd: launch.options.cwd,
        env: launch.options.env,
        stdout: "ignore",
        stderr: "ignore",
      })
      const code = await child.exited
      if (code === 0)
        return { id: NETWORK_PROBE, covers, ok: false, detail: "confined child reached the loopback server" }
      return { id: NETWORK_PROBE, covers, ok: true, detail: `confined connect refused (exit ${code})` }
    } catch (err) {
      return { id: NETWORK_PROBE, covers, ok: false, detail: err instanceof Error ? err.message : String(err) }
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
    }
  }

  /**
   * Decide what this machine may claim about the requested profile, before any case is measured.
   *
   * Nothing here is cached across profiles: the answer for `no-sandbox` is `off` by construction and
   * says nothing about whether the backend works, which is exactly why a run must not infer one from
   * the other.
   */
  const preflights = new Map<string, Promise<Preflight>>()

  /**
   * Test seams. Present so the three states this machine cannot produce on its own — an unsupported
   * platform, an unavailable backend, a probe that came back failed — are still exercised, and
   * deliberately routed around `ContainmentMacos`'s own cache: poisoning a process-lifetime
   * containment result from a test is exactly the thing that must never be possible.
   */
  export type Overrides = Readonly<{
    platform?: NodeJS.Platform
    probe?: () => Promise<"operational" | "failed" | "unavailable">
  }>

  /** Memoized per profile and workspace. Overridden probes are never cached. */
  export function preflight(id: ProfileID, ctx: InstanceContext, overrides?: Overrides): Promise<Preflight> {
    if (overrides) return check(id, ctx, overrides)
    const key = `${id}\0${ctx.directory}`
    const existing = preflights.get(key)
    if (existing) return existing
    const next = check(id, ctx, {})
    preflights.set(key, next)
    return next
  }

  /** Test seam only: install a preflight so the abort path can be exercised end to end. */
  export function seedPreflight(id: ProfileID, directory: string, value: Preflight) {
    preflights.set(`${id}\0${directory}`, Promise.resolve(value))
  }

  async function check(id: ProfileID, ctx: InstanceContext, overrides: Overrides): Promise<Preflight> {
    const config = profile(id).config
    const platform = overrides.platform ?? process.platform
    const checked_at = Date.now()
    const base = { profile: id, platform, backend: backend(platform), checked_at }
    const network = config.network === "allow" ? "allow" : (config.allowed_hosts?.length ?? 0) > 0 ? "proxy" : "deny"
    const support = backendSupport({ mode: network, allowedHosts: [...(config.allowed_hosts ?? [])] })
    // Reported even for a disabled profile, because whether the host *could* confine and whether
    // this run was confined are different facts, and a reader comparing two rows needs both.
    if (config.enabled !== true)
      return { ...base, backend_available: support.available, network: "off", state: "off", probes: [] }

    const available = support.available && ContainmentMacos.supported(platform)
    if (!available)
      return {
        ...base,
        backend_available: support.available,
        ...(support.reason ? { backend_reason: support.reason } : {}),
        network,
        state: "unavailable",
        probes: [],
      }

    const filesystem = await (overrides.probe ? overrides.probe() : ContainmentMacos.probe())
    const probes: Probe[] = [
      {
        id: FILESYSTEM_PROBE,
        covers: ["write inside scratch allowed", "write outside scratch denied", ".git denied", "environment denied"],
        ok: filesystem === "operational",
        detail: filesystem,
      },
    ]
    if (filesystem === "unavailable") return { ...base, backend_available: true, network, state: "unavailable", probes }
    if (filesystem !== "operational") return { ...base, backend_available: true, network, state: "failed", probes }
    // A proxy profile's network claim is about exact destinations, not about loopback, so the
    // loopback proof is only meaningful — and only mandatory — for a denying profile.
    if (network === "deny") probes.push(await loopback(ctx, network))
    const state: State = probes.every((probe) => probe.ok) ? "operational" : "failed"
    return { ...base, backend_available: true, network, state, probes }
  }

  /**
   * The session id a profile's confinement state is persisted under.
   *
   * Per profile, because `SandboxPolicy` treats the per-session `enabled` flag as the session's own
   * choice and never reconciles it back from config: two profiles sharing a session id would make
   * the second run inherit the first one's sandbox.
   */
  export function session(id: ProfileID) {
    return SessionID.make(`ses_a1_${id.replaceAll("-", "_")}`)
  }

  const resolved = new Map<string, Promise<T.Containment>>()

  /**
   * The containment facts, taken from the production path and from nowhere else.
   *
   * This is the same two steps `session/tools.ts` performs before every real tool call:
   * `SandboxPolicy.containment` reads the live per-session snapshot the call would execute under,
   * and `ContainmentMacos.facts` turns it into the backend-neutral facts the core consumes —
   * running the production probe itself when, and only when, the session is enabled. There is
   * deliberately no parameter here that could carry a containment state in from a case file.
   */
  export function containment(id: ProfileID, directory: string): Promise<T.Containment> {
    const key = `${id}\0${directory}`
    const existing = resolved.get(key)
    if (existing) return existing
    const sessionID = session(id)
    const config: Config.Info = { sandbox: profile(id).config }
    const next = Effect.runPromise(
      SandboxPolicy.containment(sessionID).pipe(
        Effect.provide(Layer.mock(Config.Service, { get: () => Effect.succeed(config) })),
        Effect.provide(AppNodeBuilder.build(Database.node)),
      ),
    ).then((snapshot) => ContainmentMacos.facts({ ...snapshot, escalated: false }))
    resolved.set(key, next)
    return next
  }

  /** Drop the per-run confinement state this module created. Session state must not outlive a run. */
  export async function dispose() {
    resolved.clear()
    preflights.clear()
    await Promise.all(PROFILE_IDS.map((id) => SandboxStore.dispose(session(id))))
  }
}
