#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PORT="${VOIDB_SYNC_SMOKE_PORT:-18080}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RUN_ROOT="${REPO_ROOT}/target/tmp/voidb-sync-hosted-smoke/${RUN_ID}"
DATA_DIR="${RUN_ROOT}/server-data"
CLIENT_DIR="${RUN_ROOT}/client-config"
AUDIT_PATH="${RUN_ROOT}/audit/events.jsonl"
CONFIG_PATH="${RUN_ROOT}/server.toml"
SERVER_LOG="${RUN_ROOT}/server.log"
CLIENT_LOG="${RUN_ROOT}/client.log"
EVIDENCE_PATH="${RUN_ROOT}/evidence.md"
SERVER_PID=""

usage() {
  cat <<'EOF'
Usage: scripts/hosted-sync-smoke.sh [--port <port>]

Starts a real local voidb-sync-server process with disposable storage, then
runs the voidb-plugin-sync hosted_smoke example against it over HTTP.

Environment:
  VOIDB_SYNC_SMOKE_PORT      Override the local port. Default: 18080.
  VOIDB_SYNC_SMOKE_PASSWORD  Override the disposable account password.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)
      PORT="${2:?missing port}"
      shift 2
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
mkdir -p "${DATA_DIR}" "${CLIENT_DIR}" "$(dirname "${AUDIT_PATH}")"

cleanup() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

run() {
  printf '\n==> '
  printf '%q ' "$@"
  printf '\n'
  "$@"
}

cat >"${CONFIG_PATH}" <<EOF
bind = "127.0.0.1:${PORT}"
data_dir = "${DATA_DIR}"
max_blob_bytes = 1048576
history_keep = 5
registration = "open"
log_level = "error"
EOF

BASE_URL="http://127.0.0.1:${PORT}"
SERVER_BIN="${REPO_ROOT}/voidb-sync-server/target/debug/voidb-sync-server"

run cargo build --manifest-path voidb-sync-server/Cargo.toml --quiet
"${SERVER_BIN}" --config "${CONFIG_PATH}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID="$!"

ready=0
for _ in {1..100}; do
  if curl -fsS "${BASE_URL}/v1/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "voidb-sync-server exited before readiness" >&2
    tail -80 "${SERVER_LOG}" >&2 || true
    exit 1
  fi
  sleep 0.1
done

if [[ "${ready}" -ne 1 ]]; then
  echo "voidb-sync-server did not become ready at ${BASE_URL}" >&2
  tail -80 "${SERVER_LOG}" >&2 || true
  exit 1
fi

export VOIDB_CONFIG_DIR="${CLIENT_DIR}"
export VOIDB_AUDIT_PATH="${AUDIT_PATH}"

run cargo run -p voidb-plugin-sync --example hosted_smoke -- \
  --server "${BASE_URL}" \
  --email "hosted-smoke-${RUN_ID}@example.invalid" \
  --device "hosted-smoke-${RUN_ID}" | tee "${CLIENT_LOG}"

for needle in \
  "hosted-super-secret-password" \
  "${VOIDB_SYNC_SMOKE_PASSWORD:-hosted-correcthorsebatterystaple}" \
  "hosted-db.internal.example" \
  "hosted_user" \
  "hosted-prod-db" \
  "Hosted Production DB" \
  "hosted login password" \
  "mysql::hosted-prod-db"; do
  if grep -R -a -F -- "${needle}" "${DATA_DIR}" >/dev/null 2>&1; then
    echo "server data leaked forbidden sample: ${needle}" >&2
    exit 1
  fi
done

cat >"${EVIDENCE_PATH}" <<EOF
# Hosted Sync Smoke Evidence

- Command: \`scripts/hosted-sync-smoke.sh --port ${PORT}\`
- Server URL: \`${BASE_URL}\`
- Run root: \`${RUN_ROOT}\`
- Server config: \`${CONFIG_PATH}\`
- Server log: \`${SERVER_LOG}\`
- Client log: \`${CLIENT_LOG}\`
- Client config dir: \`${CLIENT_DIR}\`
- Audit path: \`${AUDIT_PATH}\`
- Result: passed
- Skipped conditions: none
- Residual risk: local process smoke only; no external hosted deployment,
  TLS termination, production storage, or multi-node NFS behavior was exercised.
EOF

echo "hosted sync smoke evidence: ${EVIDENCE_PATH}"
