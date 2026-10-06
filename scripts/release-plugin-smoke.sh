#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PLUGIN="all"
DIFF_CHECK=1
INVOKE_SMOKE=0

usage() {
  cat <<'EOF'
Usage: scripts/release-plugin-smoke.sh [--plugin all|ssh|s3] [--no-diff-check]

Runs focused, secret-free plugin smoke checks for release-candidate preparation.
External service smoke is intentionally documented, not run here.

Options:
  --plugin <name>      Limit checks to one promoted plugin. Default: all.
  --no-diff-check      Skip git diff --check.
  -h, --help           Show this help.

See docs/release-plugin-smoke.md for fixture-backed live smoke commands.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plugin)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --plugin" >&2
        exit 2
      fi
      PLUGIN="$2"
      shift 2
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

smoke_ssh() {
  run cargo test -p voidb-plugin-ssh capabilities --quiet
  run cargo test -p voidb-plugin-ssh service --quiet
  run cargo test -p voidb-plugin-ssh --quiet
  run cargo test -p voidb-core profile_adapter --quiet
  run cargo test -p voidb-core profile_store --quiet
  INVOKE_SMOKE=1
}

smoke_s3() {
  run cargo test -p voidb-plugin-s3 --quiet
  INVOKE_SMOKE=1
}

case "${PLUGIN}" in
  all)
    smoke_ssh
    smoke_s3
    ;;
  ssh)
    smoke_ssh
    ;;
  s3)
    smoke_s3
    ;;
  *)
    echo "unsupported plugin: ${PLUGIN}" >&2
    usage >&2
    exit 2
    ;;
esac

if [[ "${INVOKE_SMOKE}" -eq 1 ]]; then
  run cargo test -p voidb-cli invoke --quiet
fi

if [[ "${DIFF_CHECK}" -eq 1 ]]; then
  run git diff --check
fi
