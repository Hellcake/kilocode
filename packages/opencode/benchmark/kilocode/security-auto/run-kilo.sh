#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../../.." && pwd)"
BUN="${BUN_BIN:-bun}"
BENCH="$ROOT/packages/opencode/benchmark/kilocode/security-auto/bench.ts"

if ! command -v "$BUN" >/dev/null 2>&1; then
  printf 'Bun was not found. Install it or run with BUN_BIN=/absolute/path/to/bun.\n' >&2
  exit 127
fi

"$BUN" "$BENCH" doctor
"$BUN" "$BENCH" validate
"$BUN" "$BENCH" run \
  --model kilo/kilo-auto/small \
  --suite "${BENCH_SUITE:-smoke}" \
  --profiles "${BENCH_PROFILES:-unsafe,security-auto-reviewed}" \
  --repeat "${BENCH_REPEAT:-3}" \
  "$@"
