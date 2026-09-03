// kilocode_change - new file
import { AppNodeBuilder } from "@opencode-ai/core/effect/app-node-builder"
import { describe, expect, test } from "bun:test"
import { Effect, Layer, ManagedRuntime } from "effect"
import path from "path"
import * as CrossSpawnSpawner from "@opencode-ai/core/cross-spawn-spawner"
import { FSUtil } from "@opencode-ai/core/fs-util"
import { ShellPermission } from "@/tool/shell"
import type { Permission } from "@/permission"
import { SessionID, MessageID } from "@/session/schema"
import { provideTestInstance, tmpdir } from "../../fixture/fixture"

/**
 * File effects are read off the same tree-sitter scan that produces the permission patterns, so the
 * security layer never runs a second parser. These tests only scan — `ShellPermission.ask` never
 * executes the command, which is what makes `rm -rf /` safe to assert on.
 */

const runtime = ManagedRuntime.make(
  Layer.mergeAll(AppNodeBuilder.build(CrossSpawnSpawner.node), AppNodeBuilder.build(FSUtil.node)),
)

type Effects = Array<{ operation: string; path?: string }>

const facts = async (command: string, cwd: string) => {
  const permission = await runtime.runPromise(ShellPermission)
  const requests: Array<Omit<Permission.Request, "id" | "sessionID" | "tool">> = []
  const ctx = {
    sessionID: SessionID.make("ses_effects"),
    messageID: MessageID.make("msg_effects"),
    callID: "",
    agent: "code",
    abort: AbortSignal.any([]),
    messages: [],
    metadata: () => Effect.void,
    ask: (req: Omit<Permission.Request, "id" | "sessionID" | "tool">) =>
      Effect.sync(() => {
        requests.push(req)
      }),
  }
  await Effect.runPromise(permission.ask(ctx as never, { command, cwd, shell: "/bin/bash" }))
  const bash = requests.find((item) => item.permission === "bash")
  return (bash?.metadata?.["securityFacts"] ?? {}) as {
    effects?: Effects
    argv?: string[]
    executable?: string
    classified?: boolean
    complete?: boolean
    composed?: boolean
  }
}

const scan = async (command: string, cwd: string) => (await facts(command, cwd)).effects ?? []

const withTmp = (fn: (cwd: string) => Promise<void>) => async () => {
  await using tmp = await tmpdir()
  await provideTestInstance({ directory: tmp.path, fn: () => fn(tmp.path) })
}

describe.skipIf(process.platform === "win32")("shell file effects", () => {
  test(
    "an append redirect into a git hook is an update of that hook",
    withTmp(async (cwd) => {
      expect(await scan("echo hi >> .git/hooks/pre-commit", cwd)).toEqual([
        { operation: "update", path: path.join(cwd, ".git/hooks/pre-commit") },
      ])
    }),
  )

  test(
    "a truncating redirect is an update of its destination",
    withTmp(async (cwd) => {
      expect(await scan("echo hi > .github/workflows/ci.yml", cwd)).toEqual([
        { operation: "update", path: path.join(cwd, ".github/workflows/ci.yml") },
      ])
    }),
  )

  test(
    "an input redirect is a read",
    withTmp(async (cwd) => {
      expect(await scan("wc -l < .env", cwd)).toEqual([{ operation: "read", path: path.join(cwd, ".env") }])
    }),
  )

  test(
    "cat reports a read of its argument",
    withTmp(async (cwd) => {
      expect(await scan("cat .env", cwd)).toEqual([{ operation: "read", path: path.join(cwd, ".env") }])
    }),
  )

  test(
    "rm reports a delete and mv reports a move",
    withTmp(async (cwd) => {
      expect(await scan("rm -rf build", cwd)).toEqual([{ operation: "delete", path: path.join(cwd, "build") }])
      expect(await scan("mv src/a.ts src/b.ts", cwd)).toEqual([
        { operation: "move", path: path.join(cwd, "src/a.ts") },
        { operation: "move", path: path.join(cwd, "src/b.ts") },
      ])
    }),
  )

  test(
    "an absolute root target survives resolution",
    withTmp(async (cwd) => {
      expect(await scan("rm -rf /", cwd)).toEqual([{ operation: "delete", path: "/" }])
    }),
  )

  test(
    "a dynamic target is reported without a path",
    withTmp(async (cwd) => {
      expect(await scan("rm -rf $TARGET", cwd)).toEqual([{ operation: "delete" }])
      expect(await scan("echo hi > $OUT", cwd)).toEqual([{ operation: "update" }])
    }),
  )

  test(
    "a glob target is reported without a path",
    withTmp(async (cwd) => {
      expect(await scan("rm -rf *", cwd)).toEqual([{ operation: "delete" }])
    }),
  )

  test(
    "commands outside the effect table report nothing",
    withTmp(async (cwd) => {
      expect(await scan("git status", cwd)).toEqual([])
      expect(await scan("npm test", cwd)).toEqual([])
    }),
  )

  test(
    "a descriptor redirect is not a file effect",
    withTmp(async (cwd) => {
      expect(await scan("npm test 2>&1", cwd)).toEqual([])
    }),
  )
})

describe.skipIf(process.platform === "win32")("shell exec facts", () => {
  test(
    "the parsed command line travels with the facts",
    withTmp(async (cwd) => {
      expect(await facts("sed -i s/a/b/ src/a.ts", cwd)).toMatchObject({
        executable: "sed",
        argv: ["sed", "-i", "s/a/b/", "src/a.ts"],
        classified: false,
      })
    }),
  )

  test(
    "an executable whose file effects the scan knows is reported as classified",
    withTmp(async (cwd) => {
      expect(await facts("cat README.md", cwd)).toMatchObject({ executable: "cat", classified: true })
      expect(await facts("git status", cwd)).toMatchObject({ executable: "git", classified: false })
    }),
  )

  test(
    "redirect targets are effects, not argv",
    withTmp(async (cwd) => {
      expect((await facts("echo hi > out.txt", cwd)).argv).toEqual(["echo", "hi"])
    }),
  )

  test(
    "a composed command reports no command line to reason about",
    withTmp(async (cwd) => {
      const out = await facts("echo a && echo b", cwd)
      expect(out.composed).toBe(true)
      expect(out.argv).toBeUndefined()
    }),
  )
})
