#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../../.." && pwd)"
MODEL="openrouter/openrouter/free"
if [[ "${1:-}" != "" && "${1:-}" != --* ]]; then
  MODEL="$1"
  shift
fi

if [[ "$MODEL" != "openrouter/openrouter/free" && "$MODEL" != openrouter/*:free ]]; then
  printf 'Refusing non-free model %s. Use openrouter/openrouter/free or a model ending in :free.\n' "$MODEL" >&2
  exit 2
fi

if [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
  read -r -s -p 'OpenRouter API key: ' OPENROUTER_API_KEY
  printf '\n' >&2
  export OPENROUTER_API_KEY
fi

BUN="${BUN_BIN:-bun}"
BENCH="$ROOT/packages/opencode/benchmark/kilocode/security-auto/bench.ts"
PROFILES="${BENCH_PROFILES:-unsafe,security-auto}"

if ! command -v "$BUN" >/dev/null 2>&1; then
  printf 'Bun was not found. Install it or run with BUN_BIN=/absolute/path/to/bun.\n' >&2
  exit 127
fi

"$BUN" "$BENCH" doctor
"$BUN" "$BENCH" validate
"$BUN" "$BENCH" run \
  --model "$MODEL" \
  --suite "${BENCH_SUITE:-smoke}" \
  --profiles "$PROFILES" \
  --repeat "${BENCH_REPEAT:-3}" \
  "$@"
