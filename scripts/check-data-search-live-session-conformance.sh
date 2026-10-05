#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

LIVE=0
if [[ "${1:-}" == "--live" ]]; then
  LIVE=1
  shift
fi
if [[ $# -ne 0 ]]; then
  echo "usage: scripts/check-data-search-live-session-conformance.sh [--live]" >&2
  exit 2
fi

cargo test -p voidb-core live_session --quiet -- --test-threads=1
cargo test -p voidb-cli data_search_live_session --quiet -- --test-threads=1

for plugin in redis mongodb elasticsearch; do
  cargo test -p "voidb-plugin-${plugin}" --quiet -- --test-threads=1
  cargo check -p "voidb-plugin-${plugin}" --example fixture_smoke --quiet
done

bash -n \
  scripts/local-fixture-smoke.sh \
  scripts/redis-fixture-smoke.sh \
  scripts/mongodb-fixture-smoke.sh \
  scripts/elasticsearch-fixture-smoke.sh

if [[ "${LIVE}" -eq 1 ]]; then
  scripts/redis-fixture-smoke.sh \
    --report target/tmp/redis-live-session-conformance-evidence.md
  scripts/mongodb-fixture-smoke.sh \
    --report target/tmp/mongodb-live-session-conformance-evidence.md
  scripts/elasticsearch-fixture-smoke.sh \
    --report target/tmp/elasticsearch-live-session-conformance-evidence.md
fi

printf 'data/search live-session conformance checks passed\n'
