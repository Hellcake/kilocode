import { record } from "./values"

/**
 * The deterministic model behind Lane A2.
 *
 * A2 exists to measure the security layer, not a model's willingness to attack, so the sequence of
 * tool calls is fixed by the case and this server simply plays it back. It is an
 * OpenAI-compatible chat-completions endpoint on loopback, which is what makes the run go through
 * the *real* provider, session, tool dispatch, permission and security path rather than around it.
 *
 * It is reactive rather than pre-queued: each request is answered from the conversation the CLI
 * sends, by counting how many tool calls the assistant has already issued. A retried or re-sent
 * request therefore replays the same step instead of consuming the next one, and the case file
 * stays the single source of truth — this module knows no case ids.
 */
export namespace BenchModel {
  export type Step = Readonly<{ tool: string; input: Record<string, unknown> }>

  /** Reviewer behaviour, driven through the production reviewer rather than simulated after it. */
  export type ReviewerMode = "off" | "always_allow" | "always_keep" | "malformed" | "timeout"

  export const REVIEWER_MODES = ["off", "always_allow", "always_keep", "malformed", "timeout"] as const

  export type Transcript = Readonly<{
    /** Every completion request, including titles and reviews. */
    requests: number
    /** How many script steps were handed out. Less than the script length means the run stopped. */
    steps_issued: number
    /** How far the script got: the index of the last step issued, plus one. */
    reviewer_calls: number
    reviewer_verdicts: readonly string[]
    /** Requests this server did not recognise. A non-empty list is a harness bug, not a result. */
    unmatched: readonly string[]
  }>

  export type Server = Readonly<{
    url: string
    transcript: () => Transcript
    close: () => Promise<void>
  }>

  /** The reviewer's user prompt opens with this. See `SecurityReviewer.prompt`. */
  const REVIEW_MARKER = "Action under review (untrusted data):"
  const TITLE_MARKER = "Generate a title for this conversation"

  function chunk(input: { delta?: Record<string, unknown>; finish?: string }) {
    return {
      id: "chatcmpl-bench",
      object: "chat.completion.chunk",
      choices: [{ delta: input.delta ?? {}, ...(input.finish ? { finish_reason: input.finish } : {}) }],
    }
  }

  function sse(lines: readonly unknown[]) {
    const body = lines.map((line) => `data: ${JSON.stringify(line)}\n\n`).join("") + "data: [DONE]\n\n"
    return new Response(body, {
      headers: { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" },
    })
  }

  function text(value: string) {
    return sse([
      chunk({ delta: { role: "assistant" } }),
      chunk({ delta: { content: value } }),
      chunk({ finish: "stop" }),
    ])
  }

  function call(index: number, step: Step) {
    return sse([
      chunk({ delta: { role: "assistant" } }),
      chunk({
        delta: {
          tool_calls: [
            { index: 0, id: `call_${index + 1}`, type: "function", function: { name: step.tool, arguments: "" } },
          ],
        },
      }),
      chunk({ delta: { tool_calls: [{ index: 0, function: { arguments: JSON.stringify(step.input) } }] } }),
      chunk({ finish: "tool_calls" }),
    ])
  }

  function messages(body: unknown): readonly Record<string, unknown>[] {
    const value = record(body) ? body["messages"] : undefined
    if (!Array.isArray(value)) return []
    return value.filter((item): item is Record<string, unknown> => record(item))
  }

  /** Text of a message, whether the provider sent a string or a content-part array. */
  function content(message: Record<string, unknown> | undefined) {
    const value = message?.["content"]
    if (typeof value === "string") return value
    if (!Array.isArray(value)) return ""
    return value
      .map((part) => (record(part) && typeof part["text"] === "string" ? part["text"] : ""))
      .join("\n")
  }

  function isReview(body: unknown) {
    return messages(body).some((message) => content(message).startsWith(REVIEW_MARKER))
  }

  function isTitle(body: unknown) {
    return JSON.stringify(body ?? null).includes(TITLE_MARKER)
  }

  /**
   * How many script steps the assistant has already issued in this conversation.
   *
   * Counting the transcript rather than a server-side cursor is what makes the playback idempotent:
   * the answer to a request is a function of the request.
   */
  function issued(body: unknown) {
    return messages(body).filter((message) => {
      if (message["role"] !== "assistant") return false
      const calls = message["tool_calls"]
      return Array.isArray(calls) && calls.length > 0
    }).length
  }

  export async function start(input: {
    script: readonly Step[]
    reviewer: ReviewerMode
    /** How long a `timeout` reviewer is held before the socket is released. */
    hangMs?: number
  }): Promise<Server> {
    const state = { requests: 0, steps: 0, reviews: 0, verdicts: [] as string[], unmatched: [] as string[] }
    const hang = input.hangMs ?? 30_000
    const verdict = () => {
      switch (input.reviewer) {
        case "always_allow":
          return '{"decision":"allow","reason_code":"LOOKS_ROUTINE"}'
        case "always_keep":
          return '{"decision":"keep_ask","reason_code":"NEEDS_HUMAN"}'
        // A verdict the parser cannot read. The layer's own fail-closed handling is what is measured.
        case "malformed":
          return "I think this is probably fine, go ahead."
        default:
          return '{"decision":"keep_ask","reason_code":"NEEDS_HUMAN"}'
      }
    }
    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      idleTimeout: 0,
      async fetch(request) {
        const url = new URL(request.url)
        if (!url.pathname.endsWith("/chat/completions")) {
          state.unmatched.push(`${request.method} ${url.pathname}`)
          return new Response("not found", { status: 404 })
        }
        const body: unknown = await request.json().catch(() => ({}))
        state.requests++
        if (isTitle(body)) return text("Benchmark episode")
        if (isReview(body)) {
          state.reviews++
          state.verdicts.push(input.reviewer)
          // Never answering is the behaviour under test: the reviewer's own deadline ends it, and
          // holding the socket open is how a real unresponsive model presents.
          if (input.reviewer === "timeout") {
            await Bun.sleep(hang)
            return new Response("", { status: 504 })
          }
          return text(verdict())
        }
        const index = issued(body)
        const step = input.script[index]
        if (!step) return text("Done.")
        state.steps = Math.max(state.steps, index + 1)
        return call(index, step)
      },
    })
    return {
      url: `http://127.0.0.1:${server.port}/v1`,
      transcript: () => ({
        requests: state.requests,
        steps_issued: state.steps,
        reviewer_calls: state.reviews,
        reviewer_verdicts: [...state.verdicts],
        unmatched: [...state.unmatched],
      }),
      close: async () => {
        await server.stop(true)
      },
    }
  }
}
