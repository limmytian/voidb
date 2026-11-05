#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
matrix_path="$repo_root/docs/agent-capability-matrix.md"
generated_path="$(mktemp "${TMPDIR:-/tmp}/voidb-agent-capability-matrix.XXXXXX")"
trap 'rm -f "$generated_path"' EXIT

cd "$repo_root"

cargo run --quiet -p voidb-cli --features full -- invoke matrix --format markdown >"$generated_path"

if ! diff -u "$matrix_path" "$generated_path"; then
    echo >&2
    echo "Agent capability matrix is stale." >&2
    echo "Regenerate it with:" >&2
    echo "  cargo run --quiet -p voidb-cli --features full -- invoke matrix --format markdown > docs/agent-capability-matrix.md" >&2
    exit 1
fi

echo "Agent capability matrix is current."
