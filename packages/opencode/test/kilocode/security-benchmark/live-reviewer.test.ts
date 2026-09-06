import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { load, lane2 } from "../../../benchmark/kilocode/security-auto/cases"
import { BenchEndpoints } from "../../../benchmark/kilocode/security-auto/endpoints"
import { LaneA2 } from "../../../benchmark/kilocode/security-auto/lane-a2"
import type { A2Case } from "../../../benchmark/kilocode/security-auto/schema"

/**
 * The `live` reviewer, exercised against a local OpenAI-compatible server.
 *
 * Nothing external is contacted: the point of the test is the *path*, not the model. A separate
 * endpoint is registered as its own provider, `SecurityReviewerConfig` resolves it from the process
 * environment and the trusted global config, `SecurityReviewerBinding` reaches it through the real
 * provider and LLM services, and `SecurityReviewer` does the prompting, parsing and fail-closed
 * handling. The benchmark never edits the verdict, so what is asserted here is what the layer did
 * with the answer — including the answers a layer must refuse to trust.
 */

const posix = process.platform === "win32" ? test.skip : test

type Reply = { status: number; body: string }

let server: ReturnType<typeof Bun.serve> | undefined
let reply: Reply = { status: 200, body: '{"decision":"allow","reason_code":"LOOKS_ROUTINE"}' }
let prompts: string[] = []
let endpoint: BenchEndpoints.Resolved
let cases = new Map<string, A2Case>()

function sse(text: string) {
  const chunk = (delta: Record<string, unknown>, finish?: string) => ({
    id: "chatcmpl-mock",
    object: "chat.completion.chunk",
    choices: [{ delta, ...(finish ? { finish_reason: finish } : {}) }],
  })
  return (
    [chunk({ role: "assistant" }), chunk({ content: text }), chunk({}, "stop")]
      .map((line) => `data: ${JSON.stringify(line)}\n\n`)
      .join("") + "data: [DONE]\n\n"
  )
}

beforeAll(async () => {
  cases = new Map(lane2(await load()).map((item) => [item.id, item]))
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    idleTimeout: 0,
    async fetch(request) {
      const body: unknown = await request.json().catch(() => ({}))
      prompts.push(JSON.stringify(body))
      if (reply.status !== 200) return new Response(reply.body, { status: reply.status })
      return new Response(sse(reply.body), { headers: { "content-type": "text/event-stream" } })
    },
  })
  endpoint = {
    apiKey: "mock-key-0123456789",
    endpoint: {
      provider: BenchEndpoints.REVIEWER_PROVIDER,
      base_url: `http://127.0.0.1:${server.port}/v1`,
      model: "mock/reviewer",
      max_output_tokens: 256,
      context_tokens: 128_000,
    },
  }
})

afterAll(async () => {
  await server?.stop(true)
})

/** The first tool call an episode made. */
function first(episode: LaneA2.Episode) {
  const call = episode.calls.at(0)
  if (!call) throw new Error(`episode ${episode.id} made no tool call`)
  return call
}

/** A reviewable ask the layer will actually offer: an in-workspace destructive delete. */
function reviewable() {
  const item = cases.get("a2-c2-build-cleanup")
  if (!item) throw new Error("missing a2-c2-build-cleanup")
  return item
}

async function run(answer: Reply) {
  reply = answer
  prompts = []
  return LaneA2.run({
    case: reviewable(),
    sandbox: "no-sandbox",
    reviewer: "live",
    reviewerEndpoint: endpoint,
  })
}

describe("the live reviewer is the production reviewer, pointed elsewhere", () => {
  posix("a valid allow reaches the layer and narrows the ask", async () => {
    const episode = await run({ status: 200, body: '{"decision":"allow","reason_code":"LOOKS_ROUTINE"}' })
    expect(episode.status).toBe("completed")
    expect(episode.reviewer_mode).toBe("live")
    expect(episode.reviewer_model).toBe("mock/reviewer")
    expect(episode.reviewer_base_url).toContain("127.0.0.1")
    expect(episode.reviewer_allowed).toBe(1)
    expect(first(episode).reviewer_state).toBe("allow")
    expect(first(episode).executed).toBe(true)
    // Resolved through the trusted config path, so the request really was made by the layer.
    expect(prompts.length).toBeGreaterThan(0)
    expect(prompts.join("\n")).toContain("Action under review")
  }, 180_000)

  posix("the reviewer sees the action, and never the agent's session", async () => {
    await run({ status: 200, body: '{"decision":"keep_ask","reason_code":"NEEDS_HUMAN"}' })
    const sent = prompts.join("\n")
    expect(sent).toContain("Action under review")
    // The reviewer's `Complete` contract carries no session; nothing in the request can name one.
    expect(sent).not.toContain("ses_")
  }, 180_000)

  posix("a keep_ask holds the call", async () => {
    const episode = await run({ status: 200, body: '{"decision":"keep_ask","reason_code":"NEEDS_HUMAN"}' })
    expect(episode.reviewer_allowed).toBe(0)
    expect(first(episode).reviewer_state).toBe("keep_ask")
    expect(first(episode).executed).toBe(false)
  }, 180_000)

  posix("a verdict the parser cannot read is not an allow", async () => {
    const episode = await run({ status: 200, body: "Looks fine to me, go ahead." })
    expect(episode.reviewer_allowed).toBe(0)
    expect(first(episode).executed).toBe(false)
    expect(first(episode).reviewer_reason).toBe("INVALID_RESPONSE")
  }, 180_000)

  posix("a provider error is not an allow", async () => {
    const episode = await run({ status: 500, body: '{"error":"upstream exploded"}' })
    expect(episode.reviewer_allowed).toBe(0)
    expect(first(episode).executed).toBe(false)
    expect(episode.actual_damage).toBe(false)
  }, 180_000)
})

describe("what a live reviewer may never do", () => {
  posix("a mandatory ask is not offered to it, whatever it would have said", async () => {
    reply = { status: 200, body: '{"decision":"allow","reason_code":"LOOKS_ROUTINE"}' }
    prompts = []
    const item = cases.get("a2-c6-secret-read")
    if (!item) throw new Error("missing a2-c6-secret-read")
    const episode = await LaneA2.run({
      case: item,
      sandbox: "no-sandbox",
      reviewer: "live",
      reviewerEndpoint: endpoint,
    })
    expect(first(episode).security_rule).toBe("SEC.V1.SENSITIVE_BOUNDARY")
    expect(first(episode).reviewer_state ?? "not_run").toBe("not_run")
    expect(first(episode).executed).toBe(false)
    expect(episode.actual_damage).toBe(false)
  }, 180_000)

  posix("a hard deny is not offered to it either", async () => {
    reply = { status: 200, body: '{"decision":"allow","reason_code":"LOOKS_ROUTINE"}' }
    const item = cases.get("a2-c3-hook-direct")
    if (!item) throw new Error("missing a2-c3-hook-direct")
    const episode = await LaneA2.run({
      case: item,
      sandbox: "no-sandbox",
      reviewer: "live",
      reviewerEndpoint: endpoint,
    })
    expect(first(episode).security_decision).toBe("deny")
    expect(first(episode).reviewer_state ?? "not_run").toBe("not_run")
    expect(episode.actual_damage).toBe(false)
  }, 180_000)

  test("asking for a live reviewer without an endpoint is an error, not a silent stub", () => {
    expect(() => LaneA2.reviewerFor("live", "http://127.0.0.1:1/v1")).toThrow(/BENCH_REVIEWER_BASE_URL/)
    expect(LaneA2.reviewerFor("off", "http://127.0.0.1:1/v1")).toEqual({ kind: "off" })
  })
})
