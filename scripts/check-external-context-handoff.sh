#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI_BIN="${VOIDB_CONTEXT_HANDOFF_CLI_BIN:-${ROOT}/target/debug/voidb-cli}"
OUT_DIR="${VOIDB_CONTEXT_HANDOFF_OUT:-${ROOT}/target/tmp/external-context-handoff}"

cd "$ROOT"

if [[ ! -x "$CLI_BIN" || "${VOIDB_CONTEXT_HANDOFF_SKIP_BUILD:-0}" != "1" ]]; then
  cargo build -q -p voidb-cli
fi

python3 "$ROOT/scripts/external_context_handoff.py" \
  --cli-bin "$CLI_BIN" \
  --out "$OUT_DIR"
