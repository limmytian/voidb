#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUN_ID="${1:-req85-postgres-session}"
IMAGE="postgres:15-alpine"
CONTAINER="voidb-fixture-postgres-${RUN_ID}"
REPORT="${REPO_ROOT}/target/tmp/postgres-session-fixture-evidence.md"
LOG="${REPO_ROOT}/target/tmp/postgres-session-fixture.log"
PASSWORD="voidb-postgres-${RUN_ID}-secret"

[[ "${RUN_ID}" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "error: invalid run id" >&2; exit 2; }

cleanup() {
  docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM ERR
cleanup

docker image inspect "${IMAGE}" >/dev/null 2>&1 || docker pull "${IMAGE}" >/dev/null
docker run -d \
  --name "${CONTAINER}" \
  --label voidb.fixture=true \
  --label "voidb.fixture.run_id=${RUN_ID}" \
  -e POSTGRES_USER=voidb \
  -e "POSTGRES_PASSWORD=${PASSWORD}" \
  -e POSTGRES_DB=voidb_fixture \
  -p '127.0.0.1::5432' \
  "${IMAGE}" >/dev/null

for _ in {1..90}; do
  if docker exec "${CONTAINER}" pg_isready -U voidb -d voidb_fixture >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "${CONTAINER}" pg_isready -U voidb -d voidb_fixture >/dev/null
PORT="$(docker port "${CONTAINER}" 5432/tcp | sed 's/.*://')"
(
  cd "${REPO_ROOT}"
  VOIDB_POSTGRES_SESSION_HOST=127.0.0.1 \
  VOIDB_POSTGRES_SESSION_PORT="${PORT}" \
  VOIDB_POSTGRES_SESSION_USER=voidb \
  VOIDB_POSTGRES_SESSION_PASSWORD="${PASSWORD}" \
  VOIDB_POSTGRES_SESSION_DATABASE=voidb_fixture \
    cargo run -p voidb-plugin-postgres --example session_fixture --quiet
) > "${LOG}" 2>&1

if rg -F "${PASSWORD}" "${LOG}" >/dev/null; then
  echo "error: PostgreSQL fixture log exposed credential material" >&2
  exit 1
fi

mkdir -p "$(dirname "${REPORT}")"
{
  echo "# PostgreSQL Persistent Agent Session Fixture Evidence"
  echo
  echo "- Run id: ${RUN_ID}"
  echo "- Image: ${IMAGE}"
  echo "- Status: passed"
  echo "- Coverage: transaction state, temporary objects, session variables, failed-transaction recovery, advisory lock lifecycle, close cleanup, credential scan"
  echo "- Cleanup: disposable container removed"
} > "${REPORT}"

cleanup
trap - EXIT INT TERM ERR
echo "report: ${REPORT}"
