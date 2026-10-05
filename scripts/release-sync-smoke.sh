#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

MODE="all"
DIFF_CHECK=1
RUN_HOSTED=0

usage() {
  cat <<'EOF'
Usage: scripts/release-sync-smoke.sh [--client-only|--server-only] [--hosted] [--no-diff-check]

Runs local, secret-free sync release smoke checks.

Options:
  --client-only       Run only voidb-plugin-sync tests.
  --server-only       Run only voidb-sync-server tests.
  --hosted            Also run a real local voidb-sync-server process smoke.
  --no-diff-check     Skip git diff --check.
  -h, --help          Show this help.

See docs/release-sync-smoke.md for release boundaries and optional manual
server execution notes.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --client-only)
      MODE="client"
      shift
      ;;
    --server-only)
      MODE="server"
      shift
      ;;
    --hosted)
      RUN_HOSTED=1
      shift
      ;;
    --no-diff-check)
      DIFF_CHECK=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

cd "${REPO_ROOT}"

run() {
  printf '\n==> '
  printf '%q ' "$@"
  printf '\n'
  "$@"
}

smoke_core() {
  run cargo test -p voidb-core object_sync --quiet
}

smoke_client() {
  run cargo test -p voidb-plugin-sync --quiet
}

smoke_server() {
  run cargo test --manifest-path voidb-sync-server/Cargo.toml --quiet
}

smoke_hosted() {
  run scripts/hosted-sync-smoke.sh
}

case "${MODE}" in
  all)
    smoke_core
    smoke_client
    smoke_server
    ;;
  client)
    smoke_core
    smoke_client
    ;;
  server)
    smoke_server
    ;;
  *)
    echo "unsupported mode: ${MODE}" >&2
    usage >&2
    exit 2
    ;;
esac

if [[ "${RUN_HOSTED}" -eq 1 ]]; then
  smoke_hosted
fi

if [[ "${DIFF_CHECK}" -eq 1 ]]; then
  run git diff --check
fi
