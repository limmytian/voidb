#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RUN_ID=""
ROOT="${REPO_ROOT}/target/fixtures"
REPORT_PATH="${REPO_ROOT}/target/tmp/elasticsearch-fixture-smoke-evidence.md"
IMAGE="docker.elastic.co/elasticsearch/elasticsearch:8.15.3"
TIMEOUT=240
TAIL_LINES=120
PULL=0

usage() {
  cat <<'EOF'
Usage: scripts/elasticsearch-fixture-smoke.sh [options]

Starts a disposable local Elasticsearch fixture, exercises Elasticsearch
plugin capabilities, writes redacted evidence, and tears the fixture down.

Options:
  --run-id <id>         Stable run id. Generated when omitted.
  --root <dir>          Fixture state root. Default: target/fixtures.
  --report <path>       Evidence report path. Default: target/tmp/elasticsearch-fixture-smoke-evidence.md.
  --image <image>       Docker image for the fixture. Default: docker.elastic.co/elasticsearch/elasticsearch:8.15.3.
  --timeout <seconds>   Health wait timeout. Default: 240.
  --tail <lines>        Log lines to keep. Default: 120.
  --pull                Pull the fixture image when it is missing.
  -h, --help            Show this help.

The script prints resource names and variable names only. It does not print
fixture URLs, indexes, document IDs, auth material, document bodies, or raw
target diagnostics.
EOF
}

die() {
  echo "error: $*" >&2
  exit 2
}

generate_run_id() {
  printf 'elasticsearch-cap-%s-%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$$"
}

sanitize_id() {
  local value="$1"
  [[ "${value}" =~ ^[A-Za-z0-9_.-]+$ ]] || die "invalid id: ${value}"
}

fixture_dir() {
  printf '%s/%s\n' "${ROOT}" "${RUN_ID}"
}

env_path() {
  printf '%s/elasticsearch.env\n' "$(fixture_dir)"
}

log_path() {
  printf '%s/elasticsearch.log\n' "$(fixture_dir)"
}

container_name() {
  printf 'voidb-fixture-elasticsearch-%s-main\n' "${RUN_ID}"
}

network_name() {
  printf 'voidb-fixture-elasticsearch-%s\n' "${RUN_ID}"
}

cleanup_fixture() {
  "${SCRIPT_DIR}/local-fixture-smoke.sh" teardown \
    --fixture elasticsearch \
    --run-id "${RUN_ID}" \
    --root "${ROOT}" >/dev/null 2>&1 || true
}

write_evidence() {
  local status="$1"
  local cleanup_status="$2"
  local smoke_log="$3"
  local commit
  commit="$(/usr/bin/git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo "unknown")"
  local docker_version
  docker_version="$(docker version --format 'client={{.Client.Version}} server={{.Server.Version}}' 2>/dev/null || echo "unknown")"

  mkdir -p "$(dirname "${REPORT_PATH}")"
  cat > "${REPORT_PATH}" <<EOF
# Elasticsearch Fixture Capability Smoke Evidence

- Requirement: 69 - Promote Elasticsearch fixture-backed readiness
- Fixture: elasticsearch
- Run id: ${RUN_ID}
- Commit: ${commit}
- Status: ${status}
- Platform: $(uname -s)-$(uname -m)
- Docker: ${docker_version}
- Image: ${IMAGE}
- Container: $(container_name)
- Network: $(network_name)
- Health: Elasticsearch HTTP port accepted local connections, cluster reached yellow/green health, and seeded index count query succeeded
- Capabilities exercised: elasticsearch.diagnostics, elasticsearch.health, elasticsearch.nodes, elasticsearch.indices, elasticsearch.search, elasticsearch.get, elasticsearch.count, elasticsearch.mapping, elasticsearch.raw_api dry-run, elasticsearch.raw_api acknowledged put/delete, elasticsearch.search_stream_read, elasticsearch.bulk
- Live-session coverage: PIT checkpoint/resume and expiry rejection, scroll context cleanup, source-paced delivery, target-material redaction, and bulk partial failure
- Destructive policy: raw_api dry-run succeeded without a live target; acknowledged raw_api PUT/DELETE touched only a generated scratch document inside the fixture index
- Document coverage: paged index search with next cursor, get, count, mapping raw omission, root version compatibility check, missing-index target error, unavailable-target redaction, and scratch document cleanup
- Redaction: diagnostics, target errors, dry-run summaries, fixture logs, and wrapper output omit withheld endpoint, index, document IDs, auth material, document bodies, and target diagnostics
- Variables present by name: VOIDB_FIXTURE_RUN_ID, VOIDB_FIXTURE_NAME, VOIDB_FIXTURE_CONTAINER, VOIDB_FIXTURE_NETWORK, VOIDB_FIXTURE_IMAGE, VOIDB_FIXTURE_HOST, VOIDB_FIXTURE_PORT, VOIDB_ES_SMOKE_PROFILE, VOIDB_ES_SMOKE_CONNECTION, VOIDB_ES_SMOKE_URL, VOIDB_ES_SMOKE_ENDPOINT, VOIDB_ES_SMOKE_HOST, VOIDB_ES_SMOKE_PORT, VOIDB_ES_SMOKE_INDEX, VOIDB_ES_SMOKE_DOCUMENT_ID, VOIDB_ES_SMOKE_VERIFY_SSL
- Log capture: $(log_path)
- Capability log: ${smoke_log}
- Cleanup: ${cleanup_status}
- Release decision: capability and live-session conformance smoke passed
EOF

  echo "report: ${REPORT_PATH}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)
      [[ $# -ge 2 ]] || die "missing value for --run-id"
      RUN_ID="$2"
      shift 2
      ;;
    --root)
      [[ $# -ge 2 ]] || die "missing value for --root"
      ROOT="$2"
      shift 2
      ;;
    --report)
      [[ $# -ge 2 ]] || die "missing value for --report"
      REPORT_PATH="$2"
      shift 2
      ;;
    --image)
      [[ $# -ge 2 ]] || die "missing value for --image"
      IMAGE="$2"
      shift 2
      ;;
    --timeout)
      [[ $# -ge 2 ]] || die "missing value for --timeout"
      TIMEOUT="$2"
      [[ "${TIMEOUT}" =~ ^[0-9]+$ ]] || die "timeout must be numeric"
      shift 2
      ;;
    --tail)
      [[ $# -ge 2 ]] || die "missing value for --tail"
      TAIL_LINES="$2"
      [[ "${TAIL_LINES}" =~ ^[0-9]+$ ]] || die "tail must be numeric"
      shift 2
      ;;
    --pull)
      PULL=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

if [[ -z "${RUN_ID}" ]]; then
  RUN_ID="$(generate_run_id)"
fi
sanitize_id "${RUN_ID}"

START_ARGS=(
  --fixture elasticsearch
  --run-id "${RUN_ID}"
  --root "${ROOT}"
  --image "${IMAGE}"
  --timeout "${TIMEOUT}"
  --tail "${TAIL_LINES}"
)
if [[ "${PULL}" -eq 1 ]]; then
  START_ARGS+=(--pull)
fi

mkdir -p "$(fixture_dir)"
cleanup_status="not_run"
smoke_log="$(fixture_dir)/elasticsearch-capability-smoke.log"
trap 'cleanup_fixture' EXIT INT TERM ERR

"${SCRIPT_DIR}/local-fixture-smoke.sh" start "${START_ARGS[@]}"
"${SCRIPT_DIR}/local-fixture-smoke.sh" wait "${START_ARGS[@]}"

set -a
# shellcheck disable=SC1090
source "$(env_path)"
set +a

(
  cd "${REPO_ROOT}"
  cargo run -p voidb-plugin-elasticsearch --example fixture_smoke --quiet
) > "${smoke_log}" 2>&1

"${SCRIPT_DIR}/local-fixture-smoke.sh" logs "${START_ARGS[@]}"
cleanup_fixture
cleanup_status="removed container, network, and generated env file"
trap - EXIT INT TERM ERR

write_evidence "passed" "${cleanup_status}" "${smoke_log}"
