#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RUN_ID=""
ROOT="${REPO_ROOT}/target/fixtures"
REPORT_PATH="${REPO_ROOT}/target/tmp/jenkins-fixture-smoke-evidence.md"
IMAGE="jenkins/jenkins:lts-jdk17"
TIMEOUT=300
TAIL_LINES=120
PULL=0

usage() {
  cat <<'EOF'
Usage: scripts/jenkins-fixture-smoke.sh [options]

Starts a disposable local Jenkins fixture, exercises Jenkins plugin
capabilities, writes redacted evidence, and tears the fixture down.

Options:
  --run-id <id>         Stable run id. Generated when omitted.
  --root <dir>          Fixture state root. Default: target/fixtures.
  --report <path>       Evidence report path. Default: target/tmp/jenkins-fixture-smoke-evidence.md.
  --image <image>       Docker image for the fixture. Default: jenkins/jenkins:lts-jdk17.
  --timeout <seconds>   Health wait timeout. Default: 300.
  --tail <lines>        Log lines to keep. Default: 120.
  --pull                Pull the fixture image when it is missing.
  -h, --help            Show this help.

The script prints resource names and variable names only. It does not print
fixture URLs, users, tokens, job names, console bodies, or raw target
diagnostics.
EOF
}

die() {
  echo "error: $*" >&2
  exit 2
}

generate_run_id() {
  printf 'jenkins-cap-%s-%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$$"
}

sanitize_id() {
  local value="$1"
  [[ "${value}" =~ ^[A-Za-z0-9_.-]+$ ]] || die "invalid id: ${value}"
}

fixture_dir() {
  printf '%s/%s\n' "${ROOT}" "${RUN_ID}"
}

env_path() {
  printf '%s/jenkins.env\n' "$(fixture_dir)"
}

log_path() {
  printf '%s/jenkins.log\n' "$(fixture_dir)"
}

container_name() {
  printf 'voidb-fixture-jenkins-%s-main\n' "${RUN_ID}"
}

network_name() {
  printf 'voidb-fixture-jenkins-%s\n' "${RUN_ID}"
}

cleanup_fixture() {
  "${SCRIPT_DIR}/local-fixture-smoke.sh" teardown \
    --fixture jenkins \
    --run-id "${RUN_ID}" \
    --root "${ROOT}" >/dev/null 2>&1 || true
}

write_evidence() {
  local status="$1"
  local cleanup_status="$2"
  local smoke_log="$3"
  local commit
  commit="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo "unknown")"
  local docker_version
  docker_version="$(docker version --format 'client={{.Client.Version}} server={{.Server.Version}}' 2>/dev/null || echo "unknown")"

  mkdir -p "$(dirname "${REPORT_PATH}")"
  cat > "${REPORT_PATH}" <<EOF
# Jenkins Fixture Capability Smoke Evidence

- Requirement: 70 - Promote Jenkins fixture-backed readiness
- Fixture: jenkins
- Run id: ${RUN_ID}
- Commit: ${commit}
- Status: ${status}
- Platform: $(uname -s)-$(uname -m)
- Docker: ${docker_version}
- Image: ${IMAGE}
- Container: $(container_name)
- Network: $(network_name)
- Health: Jenkins HTTP port accepted local connections, authenticated API ping succeeded, seeded job exists, and build 1 completed successfully
- Capabilities exercised: jenkins.diagnostics, jenkins.jobs, jenkins.job_detail, jenkins.activity, jenkins.console, jenkins.trigger_build dry-run, jenkins.trigger_build acknowledged, jenkins.abort_build dry-run, jenkins.cancel_queue_item dry-run
- Destructive policy: trigger_build, abort_build, and cancel_queue_item dry-runs succeeded without a live target; acknowledged trigger_build touched only the generated fixture job and waited for the triggered build to complete
- Job coverage: root job discovery, job detail, seeded build status, bounded console output, generated trigger build status, missing-job target error, bad-auth target error, unavailable-target redaction, and fixture cleanup
- Redaction: diagnostics, target errors, dry-run summaries, fixture logs, and wrapper output omit withheld endpoint, user, token, job name, console body, and target diagnostics
- Variables present by name: VOIDB_FIXTURE_RUN_ID, VOIDB_FIXTURE_NAME, VOIDB_FIXTURE_CONTAINER, VOIDB_FIXTURE_NETWORK, VOIDB_FIXTURE_IMAGE, VOIDB_FIXTURE_HOST, VOIDB_FIXTURE_PORT, VOIDB_JENKINS_SMOKE_PROFILE, VOIDB_JENKINS_SMOKE_CONNECTION, VOIDB_JENKINS_SMOKE_URL, VOIDB_JENKINS_SMOKE_HOST, VOIDB_JENKINS_SMOKE_PORT, VOIDB_JENKINS_SMOKE_USER, VOIDB_JENKINS_SMOKE_TOKEN, VOIDB_JENKINS_SMOKE_JOB, VOIDB_JENKINS_SMOKE_BUILD, VOIDB_JENKINS_SMOKE_VERIFY_SSL
- Log capture: $(log_path)
- Capability log: ${smoke_log}
- Cleanup: ${cleanup_status}
- Release decision: capability smoke passed; readiness docs pending
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
  --fixture jenkins
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
smoke_log="$(fixture_dir)/jenkins-capability-smoke.log"
trap 'cleanup_fixture' EXIT INT TERM ERR

"${SCRIPT_DIR}/local-fixture-smoke.sh" start "${START_ARGS[@]}"
"${SCRIPT_DIR}/local-fixture-smoke.sh" wait "${START_ARGS[@]}"

set -a
# shellcheck disable=SC1090
source "$(env_path)"
set +a

(
  cd "${REPO_ROOT}"
  cargo run -p voidb-plugin-jenkins --example jenkins_fixture_smoke --quiet
) > "${smoke_log}" 2>&1

"${SCRIPT_DIR}/local-fixture-smoke.sh" logs "${START_ARGS[@]}"
cleanup_fixture
cleanup_status="removed container, network, generated env file, init Groovy, and build marker"
trap - EXIT INT TERM ERR

write_evidence "passed" "${cleanup_status}" "${smoke_log}"
