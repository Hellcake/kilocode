import { A2Report } from "./a2-report"
import { BenchMetrics } from "./metrics"
import { record } from "./values"
import type { LaneA2 } from "./lane-a2"
import type { LaneB } from "./lane-b"
import type { A2Case } from "./schema"

/**
 * One report for a whole sweep.
 *
 * Runs are grouped by *profile* — lane, sandbox, reviewer, security switch and the exact model ids —
 * because those are the things that make two numbers incomparable. Everything is keyed off the
 * episodes themselves rather than off what a command was asked to do, so a report assembled from
 * several separate runs says the same thing as one assembled from a single sweep.
 */
export namespace BenchSummary {
  export type Profile = Readonly<{
    key: string
    lane: "A2" | "B"
    sandbox: string
    reviewer: string
    security: string
    containment: string
    backend: string
    coding_model: string
    coding_base_url?: string
    reviewer_model?: string
    reviewer_base_url?: string
  }>

  export type Episode = LaneA2.Episode | LaneB.Episode

  /**
   * Just enough of an episode to say which profile it belongs to.
   *
   * Both lanes satisfy it structurally, and a test can name one without building a whole episode.
   */
  export type Identity = Readonly<{
    lane: "A2" | "B"
    sandbox_profile: string
    reviewer_mode: string
    security: string
    containment: string
    backend: string
    coding_model: string
    coding_base_url?: string
    reviewer_model?: string
    reviewer_base_url?: string
  }>

  const KEYS = ["lane", "case_id", "kind", "sandbox_profile", "reviewer_mode", "security", "calls"] as const

  /**
   * Read one episode back off disk.
   *
   * A report file is a record of what a run produced, but it is still a file: the discriminating
   * fields are checked before it is treated as an episode, so a stray JSON in the results directory
   * is skipped rather than counted.
   */
  export function isEpisode(value: unknown): value is Episode {
    if (!record(value)) return false
    if (!KEYS.every((key) => key in value)) return false
    return (value["lane"] === "A2" || value["lane"] === "B") && Array.isArray(value["calls"])
  }

  function isB(episode: Episode): episode is LaneB.Episode {
    return episode.lane === "B"
  }

  export function profile(episode: Identity): Profile {
    const reviewer = episode.reviewer_model ? `${episode.reviewer_mode}:${episode.reviewer_model}` : episode.reviewer_mode
    const key = [
      episode.lane,
      episode.sandbox_profile,
      reviewer,
      episode.security,
      episode.coding_model,
    ].join(" | ")
    return {
      key,
      lane: episode.lane,
      sandbox: episode.sandbox_profile,
      reviewer: episode.reviewer_mode,
      security: episode.security,
      containment: episode.containment,
      backend: episode.backend,
      coding_model: episode.coding_model,
      ...(episode.coding_base_url ? { coding_base_url: episode.coding_base_url } : {}),
      ...(episode.reviewer_model ? { reviewer_model: episode.reviewer_model } : {}),
      ...(episode.reviewer_base_url ? { reviewer_base_url: episode.reviewer_base_url } : {}),
    }
  }

  export type Group = Readonly<{
    profile: Profile
    episodes: number
    safety: A2Report.Safety | undefined
    lane_b: BenchMetrics.LaneBStats | undefined
    by_vector: ReturnType<typeof BenchMetrics.byVector> | undefined
    reviewer: BenchMetrics.Reviewer
    friction: BenchMetrics.Friction
    timing: BenchMetrics.Timing
    coverage: BenchMetrics.Coverage
    tokens?: BenchMetrics.Tokens
    harness: Readonly<{ invalid: number; timeout: number; tool_limit: number; process_error: number; harness_error: number }>
    damaging_ids: readonly string[]
    bypass_ids: readonly string[]
  }>

  export function group(episodes: readonly Episode[], cases: readonly A2Case[] = []): Group[] {
    const keys = [...new Set(episodes.map((episode) => profile(episode).key))].sort()
    return keys.map((key) => {
      const mine = episodes.filter((episode) => profile(episode).key === key)
      const a2 = mine.filter((episode): episode is LaneA2.Episode => episode.lane === "A2")
      const b = mine.filter(isB)
      const metrics = mine.map((episode) => episode as BenchMetrics.Episode)
      return {
        profile: profile(mine[0]),
        episodes: mine.length,
        safety: a2.length > 0 ? A2Report.summarize(cases, a2).safety : undefined,
        lane_b: b.length > 0 ? BenchMetrics.laneB(b) : undefined,
        by_vector: b.length > 0 ? BenchMetrics.byVector(b) : undefined,
        reviewer: BenchMetrics.reviewer(metrics),
        friction: BenchMetrics.friction(metrics),
        timing: BenchMetrics.timing(metrics),
        coverage: BenchMetrics.coverage(metrics),
        ...(BenchMetrics.tokens(metrics) ? { tokens: BenchMetrics.tokens(metrics)! } : {}),
        harness: {
          invalid: mine.filter((episode) => episode.invalid).length,
          timeout: mine.filter((episode) => episode.status === "timeout").length,
          tool_limit: mine.filter((episode) => episode.status === "tool_limit").length,
          process_error: mine.filter((episode) => episode.status === "process_error").length,
          harness_error: mine.filter((episode) => episode.status === "harness_error").length,
        },
        damaging_ids: [...new Set(mine.filter((episode) => episode.actual_damage).map((episode) => episode.case_id))].sort(),
        bypass_ids: [
          ...new Set(
            mine
              .filter((episode) => episode.deterministic_bypass || episode.reviewer_bypass)
              .map((episode) => `${episode.case_id}:${episode.reviewer_bypass ? "reviewer" : "deterministic"}`),
          ),
        ].sort(),
      }
    })
  }

  function pct(value: BenchMetrics.Rate | number) {
    const ratio = typeof value === "number" ? value : value.rate
    const suffix = typeof value === "number" ? "" : ` (${value.numerator}/${value.denominator})`
    return `${(ratio * 100).toFixed(1)}%${suffix}`
  }

  function table(header: readonly string[], rows: readonly (readonly (string | number)[])[]) {
    if (rows.length === 0) return ""
    return [
      `| ${header.join(" | ")} |`,
      `|${header.map(() => "---").join("|")}|`,
      ...rows.map((row) => `| ${row.join(" | ")} |`),
      "",
    ].join("\n")
  }

  export function markdown(groups: readonly Group[], provenance: Record<string, unknown>) {
    const label = (item: Group) => `\`${item.profile.sandbox}/${item.profile.reviewer}\``
    const safety = groups.flatMap((item) =>
      item.safety
        ? [
            [
              label(item),
              item.safety.attack_cases,
              item.safety.actual_damage,
              item.safety.deterministic_bypass,
              item.safety.reviewer_bypass,
              pct(item.safety.asr_total),
            ],
          ]
        : [],
    )
    const injection = groups.flatMap((item) =>
      (item.by_vector ?? []).map((vector) => [
        label(item),
        vector.vector,
        vector.runs,
        vector.delivered,
        vector.attempted,
        vector.blocked,
        vector.actual_damage,
        pct(vector.asr_total),
      ]),
    )
    const reviewer = groups.map((item) => [
      label(item),
      item.reviewer.calls,
      item.reviewer.allow,
      item.reviewer.damaging_approvals,
      item.reviewer.latency_ms.p50,
      item.reviewer.latency_ms.p95,
    ])
    const friction = groups.map((item) => [
      label(item),
      item.friction.auto_allowed,
      item.friction.mandatory_human_asks,
      item.friction.human_decisions_per_run.toFixed(2),
      item.friction.benign.mandatory_ask + item.friction.benign.reviewable,
    ])
    const timing = groups.map((item) => [
      label(item),
      item.timing.episode_ms.p50,
      item.timing.episode_ms.p95,
      item.timing.security_decision_ms.p50,
      item.timing.reviewer_ms.p50,
      item.timing.reviewer_ms.p95,
    ])
    const models = groups.map((item) => [
      label(item),
      item.profile.lane,
      `\`${item.profile.coding_model}\``,
      item.profile.reviewer_model ? `\`${item.profile.reviewer_model}\`` : "—",
      item.profile.containment,
      item.profile.security,
    ])
    const harness = groups.map((item) => [
      label(item),
      item.episodes,
      item.harness.invalid,
      item.harness.timeout,
      item.harness.process_error,
      item.harness.harness_error,
    ])
    const findings = groups.flatMap((item) =>
      item.damaging_ids.length > 0 || item.bypass_ids.length > 0
        ? [
            `- ${label(item)} damage: ${item.damaging_ids.join(", ") || "none"}`,
            `- ${label(item)} bypass: ${item.bypass_ids.join(", ") || "none"}`,
          ]
        : [`- ${label(item)}: no damage, no bypass`],
    )
    const classes = groups.flatMap((item) =>
      Object.entries(item.coverage.threat_classes).map(([name, count]) => [label(item), name, count]),
    )
    return [
      "# Security benchmark summary",
      "",
      "```json",
      JSON.stringify(provenance, null, 2),
      "```",
      "",
      "## Models and profile",
      "",
      table(["profile", "lane", "coding model", "reviewer model", "containment", "security"], models),
      "## Safety (Lane A2)",
      "",
      table(["profile", "attacks", "damage", "det bypass", "reviewer bypass", "ASR"], safety) ||
        "_no A2 episodes in this report._\n",
      "## Prompt injection (Lane B)",
      "",
      table(
        ["profile", "vector", "runs", "delivered", "attempted", "blocked", "damage", "ASR"],
        injection,
      ) || "_no Lane B episodes in this report._\n",
      "## Reviewer",
      "",
      table(["profile", "calls", "allow", "damaging approvals", "latency p50", "latency p95"], reviewer),
      "## Autonomy and friction",
      "",
      "A reviewer call is not human friction: it is the cost the reviewer exists to remove.",
      "",
      table(
        ["profile", "auto allowed", "mandatory asks", "human decisions/run", "benign escalations"],
        friction,
      ),
      "## Timing (ms)",
      "",
      table(["profile", "episode p50", "episode p95", "security p50", "reviewer p50", "reviewer p95"], timing),
      "## Harness",
      "",
      table(["profile", "episodes", "invalid", "timeout", "process error", "harness error"], harness),
      "## Coverage",
      "",
      table(["profile", "threat class", "episodes"], classes),
      "## Findings",
      "",
      ...findings,
      "",
    ].join("\n")
  }
}
