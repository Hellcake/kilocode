# Security auto-mode benchmark — v2 baseline

This directory is the **Block 0 baseline** of the v2 benchmark: the infrastructure from the v1
branch (`security-auto-benchmark`), transplanted onto the current frozen `main`, with everything
that encoded a superseded security model deliberately left behind.

It does not yet measure anything new. No evaluation lane is implemented, no results are claimed,
and the numbers from v1 are not carried over.

## What this baseline is for

v1's dataset asserted, as ground truth, decisions taken by a `main` that has since changed
(`e134081f19`, `6cc34853e3`, `401181fc29`, `b44571569b`). Rebasing it would have carried those
assertions forward looking reviewed. So the transplant is by file, not by history: the harness came
across, the assumptions did not.

## What runs today

```sh
bun install --frozen-lockfile
bun packages/opencode/benchmark/kilocode/security-auto/bench.ts doctor      # CLI boots
bun packages/opencode/benchmark/kilocode/security-auto/bench.ts validate    # dataset + coverage
bun packages/opencode/benchmark/kilocode/security-auto/bench.ts coverage    # matrix, with holes
bun packages/opencode/benchmark/kilocode/security-auto/bench.ts profiles
bun packages/opencode/benchmark/kilocode/security-auto/bench.ts run --model provider/model ...
bun packages/opencode/benchmark/kilocode/security-auto/bench.ts report --input .../episodes.jsonl
```

`run` launches the real local Kilo CLI against a live model, one disposable workspace per episode,
and scores the resulting filesystem state. It is v1 machinery and it works, but it is **not** yet a
methodologically separated lane: a model that simply declines to attack is scored the same as a
layer that blocked the attack. Block 8 fixes that; until then, treat `run` as an integration check.

`doctor` checks CLI startup, not model access. On Windows, `run.ps1` finds the task-local Bun.

## Preserved properties

These are the reason the harness was worth keeping, and they must not regress:

- one `mkdtemp` workspace per episode, from a checked-in fixture copy, with symlinked fixtures
  rejected before the copy;
- isolated `HOME`/`USERPROFILE`/`APPDATA`/`LOCALAPPDATA` and `XDG_{CONFIG,DATA,STATE,CACHE}_HOME`;
- `KILO_DB=:memory:`, plugins, autoupdate, autocompact and **project config** disabled;
- process-group teardown (`taskkill /T` on Windows), wall-clock timeout, observed tool budget;
- 16 MiB bound per output stream and per oracle file;
- an FS oracle that shares no code with the security classifier it scores, checking every path
  component with `lstat` so a parent symlink or junction cannot redirect a predicate;
- a damage predicate must not already match before the episode starts;
- `fingerprint.ts` hashes benchmark inputs **together with** `src/kilocode/security-decision/*`,
  `src/permission/**`, `src/cli/cmd/run.ts` and `src/kilocode/tool/shell-security-facts.ts`, so a
  result cannot be attributed to code it was not produced by;
- invalid episodes are counted, and `asr_upper` treats every one of them as potentially damaging.

## Dataset status

23 agent cases (6 benign, 16 attack, 1 careless) and 20 fixtures, carried over as **drafts**. They
are marked `kilo.security-bench/v2` because the schema changed, not because they were re-validated.
In particular `expected_rules` is a v1 observation: `report.ts` reports `rule_observation_rate` from
it and nothing asserts it.

`schema.ts` declares the v2 taxonomy — `lane`, `provenance`, `delivery`, `route`, `statefulness`,
`target_effect`, `expected_enforcement` — as optional fields. No transplanted case carries them yet.

`coverage.ts` keeps the frozen C1-C9 / R1-R9 / I1-I2 taxonomy. Groups whose only v1 evidence was a
replay case are marked **deferred** with the block that will supply real evidence. A deferred group
is an open hole, not a passing claim and not a known-safe behavior. v1's `G1`-`G4` known-gap groups
were dropped: they pinned pre-fix behavior, and `G4` ("CI reads are conservatively held") describes
a `main` that no longer exists.

## Deliberately not transplanted

| Left behind | Why |
|---|---|
| `cases/replay/*.json`, `replay.ts` | Fed hand-written, already-normalized facts to `SecurityDecision.decide`, bypassing the adapter, the shell scan and the permission pipeline — the layers where the found gaps actually lived. Lane A1 (Block 1) replays real commands through the production path instead. |
| `corpus.ts` | Duplicates `test/kilocode/security-decision/corpus.ts` on `main`, and pinned auto-pass counts against the old engine. |
| `probe.ts` | Hardcoded each case's tool-call script by case id, a second source of truth beside the case file. Returns in Block 5 as a generic player of a `script` field. |
| `run-openrouter.sh`, `run-kilo.sh` | The OpenRouter launcher defaulted to `openrouter/openrouter/free`, a router that picks a **random** free model per request, and it exported `OPENROUTER_API_KEY` straight into the environment of the agent under test. Block 8 replaces both with pinned model ids and a loopback relay that keeps the key out of the child process. |
| `RESULTS.md` | Measured against the old baseline. |

## Known limitation carried over unchanged

**Temporary state isolation is not an OS sandbox.** No profile configures `sandbox`, so every
episode runs with `containment.sandbox: "off"`: C1 is not exercised end to end, and the CLI runs as
your OS user with full network access. Adversarial model episodes belong in a disposable VM or
container. Do not add real destructive commands, real credentials or production remotes.

Credentials are **not** stripped from tools the model runs: `src/kilocode/process/env.ts` removes
only `KILO_CONFIG*`, `KILO_SERVER_*` and `KILO_BROWSER_BROKER_*`, and the sandbox profile's
`environment.deny` list is the same set. An agent under test can read any `*_API_KEY` in the
environment. Use a disposable, budget-limited key until Block 8 lands the relay.

## v2-deferred

| Block | Work |
|---|---|
| 1 | Lane A1: replay real commands through `ShellPermission` → adapter → core → `SecurityDamage` |
| 2 | Reviewer stubs as an axis: `off`, `always_allow`, `always_keep`, `malformed`, `timeout` |
| 3 | `bench preflight`: FS positive/negative, `.git`, env and loopback network probes |
| 4 | Sandbox profiles; C1 becomes measurable |
| 5 | Lane A2: tool script moves from `probe.ts` into the case file |
| 6 | Oracle reach: sentinel root outside the workspace, loopback sink, `PATH` shims, canary grep |
| 7 | Route and delivery mutation generator; metrics grouped by `(class, route)` |
| 8 | Lane B: outcome ladder, pinned OpenRouter model ids, API-key relay |
| 9 | Lane C benign autonomy, and the metric formulas themselves |
| 10 | Held-out scenarios authored after the rules froze |

## Development checks

From the repository root:

```sh
bun run lint --deny-warnings packages/opencode/benchmark/kilocode/security-auto packages/opencode/test/kilocode/security-benchmark
bun run script/check-opencode-annotations.ts --worktree
```

From `packages/opencode/`:

```sh
bun run typecheck
bun test ./test/kilocode/security-benchmark/benchmark.test.ts --timeout 60000
bun test ./test/kilocode/security-decision --timeout 60000
```

Never run a root `bun test`.
