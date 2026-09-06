import { describe, expect, test } from "bun:test"
import { BenchEndpoints } from "../../../benchmark/kilocode/security-auto/endpoints"

/**
 * The configuration surface a colleague has to get right, and the one place a credential could
 * escape. Both are pure functions, so both are checked here rather than in a run.
 */

const CODING = {
  BENCH_MODEL_BASE_URL: "https://openrouter.ai/api/v1/",
  BENCH_MODEL_API_KEY: "sk-coding-0123456789",
  BENCH_MODEL_ID: "anthropic/claude-sonnet-4",
}
const REVIEWER = {
  BENCH_REVIEWER_BASE_URL: "http://127.0.0.1:8000/v1",
  BENCH_REVIEWER_API_KEY: "",
  BENCH_REVIEWER_MODEL: "qwen/qwen3-8b",
}

describe("the two endpoints are configured independently", () => {
  test("neither is read when its own variables are unset", () => {
    expect(BenchEndpoints.coding({})).toBeUndefined()
    expect(BenchEndpoints.reviewer({})).toBeUndefined()
    // Naming one must never supply the other: the reviewer is part of the system under test, and
    // silently reusing the agent's endpoint would report one model's behaviour as two.
    expect(BenchEndpoints.reviewer(CODING)).toBeUndefined()
    expect(BenchEndpoints.coding(REVIEWER)).toBeUndefined()
  })

  test("a half-configured endpoint is an error, not a default", () => {
    expect(() => BenchEndpoints.coding({ BENCH_MODEL_BASE_URL: "https://example.com/v1" })).toThrow(/incomplete/)
    expect(() =>
      BenchEndpoints.reviewer({ BENCH_REVIEWER_BASE_URL: "https://example.com/v1", BENCH_REVIEWER_API_KEY: "k" }),
    ).toThrow(/BENCH_REVIEWER_MODEL/)
  })

  test("a local endpoint may have an empty key, but the variable still has to be present", () => {
    const local = BenchEndpoints.reviewer(REVIEWER)
    expect(local?.apiKey).toBe("")
    expect(local?.endpoint.base_url).toBe("http://127.0.0.1:8000/v1")
    expect(() =>
      BenchEndpoints.reviewer({ BENCH_REVIEWER_BASE_URL: "http://127.0.0.1:8000/v1", BENCH_REVIEWER_MODEL: "m" }),
    ).toThrow(/BENCH_REVIEWER_API_KEY/)
  })

  test("a base URL has to be one, and keeps no trailing slash", () => {
    expect(BenchEndpoints.coding(CODING)?.endpoint.base_url).toBe("https://openrouter.ai/api/v1")
    expect(() => BenchEndpoints.coding({ ...CODING, BENCH_MODEL_BASE_URL: "openrouter.ai" })).toThrow(/absolute URL/)
  })

  test("a model id keeping its own slashes still resolves to one provider", () => {
    const coding = BenchEndpoints.coding(CODING)
    if (!coding) throw new Error("coding endpoint did not resolve")
    // `provider/model` splits on the first slash, so an OpenRouter id survives intact.
    expect(BenchEndpoints.reference(coding.endpoint)).toBe("bench-coding/anthropic/claude-sonnet-4")
    expect(coding.endpoint.provider).toBe(BenchEndpoints.CODING_PROVIDER)
  })

  test("the provider block is the plain OpenAI-compatible shape Kilo already supports", () => {
    const resolved = BenchEndpoints.coding(CODING)
    if (!resolved) throw new Error("coding endpoint did not resolve")
    const block = BenchEndpoints.provider(resolved)
    expect(JSON.parse(JSON.stringify(block))).toMatchObject({
      [BenchEndpoints.CODING_PROVIDER]: {
        npm: "@ai-sdk/openai-compatible",
        options: { apiKey: CODING.BENCH_MODEL_API_KEY, baseURL: "https://openrouter.ai/api/v1" },
        models: { "anthropic/claude-sonnet-4": { tool_call: true } },
      },
    })
  })

  test("the reviewer timeout is passed through, and the production cap stays production's", () => {
    expect(BenchEndpoints.reviewerTimeout({})).toBe(4_000)
    expect(BenchEndpoints.reviewerTimeout({ BENCH_REVIEWER_TIMEOUT_MS: "9000" })).toBe(9_000)
    expect(BenchEndpoints.reviewerTimeout({ BENCH_REVIEWER_TIMEOUT_MS: "nonsense" })).toBe(4_000)
  })
})

describe("credentials do not reach disk", () => {
  test("a key anywhere in a serialized report is replaced", () => {
    const report = JSON.stringify({ env: { key: "sk-coding-0123456789" }, note: "sk-coding-0123456789 trailing" })
    const clean = BenchEndpoints.redact(report, ["sk-coding-0123456789", undefined])
    expect(clean).not.toContain("sk-coding-0123456789")
    expect(clean).toContain("[redacted]")
  })

  test("a short or empty key cannot blank out unrelated text", () => {
    // An empty `BENCH_REVIEWER_API_KEY` is normal for a local server; treating it as a secret would
    // rewrite the whole document.
    expect(BenchEndpoints.redact("nothing to hide", ["", "abc"])).toBe("nothing to hide")
  })
})
