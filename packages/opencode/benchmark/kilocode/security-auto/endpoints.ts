/**
 * Where the benchmark's two models live.
 *
 * The coding model under test and the reviewer that stands behind the security layer are different
 * questions, so they are configured independently and never share a default. A run that names one
 * and forgets the other must not silently reuse it: the reviewer is part of the system being
 * measured, and pointing it at the same endpoint as the agent would report a number about one model
 * as though it were about two.
 *
 * Both are ordinary OpenAI-compatible endpoints, expressed through Kilo's existing
 * `@ai-sdk/openai-compatible` provider shape rather than a new abstraction. That is what makes the
 * reviewer path production: `SecurityReviewerConfig` resolves the model from the process
 * environment and the trusted global config, `SecurityReviewerBinding` reaches it through the real
 * provider and LLM services, and nothing here touches a verdict.
 */
export namespace BenchEndpoints {
  export type Endpoint = Readonly<{
    /** The provider id the generated config registers. Never taken from the environment. */
    provider: string
    base_url: string
    model: string
    max_output_tokens: number
    context_tokens: number
  }>

  /** An endpoint plus the credential, kept apart so the credential cannot reach a report by habit. */
  export type Resolved = Readonly<{ endpoint: Endpoint; apiKey: string }>

  export const CODING_PROVIDER = "bench-coding"
  export const REVIEWER_PROVIDER = "bench-reviewer"

  export const CODING_VARS = {
    baseUrl: "BENCH_MODEL_BASE_URL",
    apiKey: "BENCH_MODEL_API_KEY",
    model: "BENCH_MODEL_ID",
    maxTokens: "BENCH_MODEL_MAX_TOKENS",
    context: "BENCH_MODEL_CONTEXT",
  } as const

  export const REVIEWER_VARS = {
    baseUrl: "BENCH_REVIEWER_BASE_URL",
    apiKey: "BENCH_REVIEWER_API_KEY",
    model: "BENCH_REVIEWER_MODEL",
    maxTokens: "BENCH_REVIEWER_MAX_TOKENS",
    timeout: "BENCH_REVIEWER_TIMEOUT_MS",
  } as const

  type Env = Record<string, string | undefined>

  function positive(value: string | undefined, fallback: number) {
    const parsed = Number(value)
    if (!Number.isFinite(parsed) || parsed <= 0) return fallback
    return Math.trunc(parsed)
  }

  function url(value: string, name: string) {
    if (!URL.canParse(value)) throw new Error(`${name} must be an absolute URL, got ${JSON.stringify(value)}`)
    // A trailing slash doubles up against the SDK's own path join on some endpoints.
    return value.replace(/\/+$/, "")
  }

  function read(env: Env, vars: { baseUrl: string; apiKey: string; model: string }) {
    const baseUrl = env[vars.baseUrl]?.trim()
    const model = env[vars.model]?.trim()
    const apiKey = env[vars.apiKey]?.trim()
    if (!baseUrl && !model && !apiKey) return undefined
    const missing = [
      ...(baseUrl ? [] : [vars.baseUrl]),
      ...(model ? [] : [vars.model]),
      // A local inference server usually needs no credential, so an empty key is allowed; the
      // variable still has to be present so a forgotten export is a error rather than a 401 later.
      ...(env[vars.apiKey] === undefined ? [vars.apiKey] : []),
    ]
    if (missing.length > 0)
      throw new Error(`incomplete endpoint configuration; set ${missing.join(", ")} (or none of the three)`)
    return { baseUrl: baseUrl!, model: model!, apiKey: apiKey ?? "" }
  }

  /** The coding model under test, or `undefined` when the run uses the deterministic local model. */
  export function coding(env: Env = process.env): Resolved | undefined {
    const found = read(env, CODING_VARS)
    if (!found) return undefined
    return {
      apiKey: found.apiKey,
      endpoint: {
        provider: CODING_PROVIDER,
        base_url: url(found.baseUrl, CODING_VARS.baseUrl),
        model: found.model,
        max_output_tokens: positive(env[CODING_VARS.maxTokens], 8_000),
        context_tokens: positive(env[CODING_VARS.context], 200_000),
      },
    }
  }

  /** The reviewer model, or `undefined` when no live reviewer is configured. */
  export function reviewer(env: Env = process.env): Resolved | undefined {
    const found = read(env, REVIEWER_VARS)
    if (!found) return undefined
    return {
      apiKey: found.apiKey,
      endpoint: {
        provider: REVIEWER_PROVIDER,
        base_url: url(found.baseUrl, REVIEWER_VARS.baseUrl),
        model: found.model,
        // The reviewer answers with a two-field JSON verdict; a large budget only buys latency.
        max_output_tokens: positive(env[REVIEWER_VARS.maxTokens], 256),
        context_tokens: positive(env[CODING_VARS.context], 128_000),
      },
    }
  }

  /**
   * The production hard cap is 5s; anything larger is clamped there by `SecurityReviewerConfig`.
   * Passing the request through unchanged keeps the cap the layer's to enforce, not ours.
   */
  export function reviewerTimeout(env: Env = process.env) {
    return positive(env[REVIEWER_VARS.timeout], 4_000)
  }

  /**
   * The provider block for one endpoint.
   *
   * Deliberately the plain `@ai-sdk/openai-compatible` shape Kilo already supports, so an OpenRouter
   * URL and a locally hosted server are the same configuration with a different host. The reviewer's
   * trusted-transport check compares this block byte-for-byte between the merged config and the
   * user's global one, so it has to be generated once and written to both.
   */
  export function provider(input: Resolved) {
    const { endpoint, apiKey } = input
    return {
      [endpoint.provider]: {
        name: endpoint.provider,
        id: endpoint.provider,
        env: [],
        npm: "@ai-sdk/openai-compatible",
        models: {
          [endpoint.model]: {
            id: endpoint.model,
            name: endpoint.model,
            attachment: false,
            reasoning: false,
            temperature: false,
            tool_call: true,
            release_date: "2025-01-01",
            limit: { context: endpoint.context_tokens, output: endpoint.max_output_tokens },
            cost: { input: 0, output: 0 },
            options: {},
          },
        },
        options: { apiKey, baseURL: endpoint.base_url },
      },
    }
  }

  /** `provider/model`, the form `--model` and `KILO_SECURITY_REVIEWER_MODEL` both take. */
  export function reference(endpoint: Endpoint) {
    return `${endpoint.provider}/${endpoint.model}`
  }

  /**
   * Remove credentials from anything on its way to disk.
   *
   * A belt-and-braces pass rather than a policy: reports are assembled from fields that should never
   * hold a key, and this makes "should never" checkable. Short values are ignored so an empty or
   * placeholder key cannot blank out unrelated text.
   */
  export function redact(text: string, secrets: readonly (string | undefined)[]) {
    return secrets
      .filter((value): value is string => typeof value === "string" && value.length >= 8)
      .reduce((out, secret) => out.replaceAll(secret, "[redacted]"), text)
  }
}
