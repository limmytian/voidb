#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo test -p voidb-core live_session_buffer --quiet -- --test-threads=1
cargo test -p voidb-cli infrastructure_live_session --quiet -- --test-threads=1

for plugin in docker kubernetes jenkins; do
  cargo test -p "voidb-plugin-${plugin}" --quiet -- --test-threads=1
done

printf 'infrastructure live-session conformance checks passed\n'
