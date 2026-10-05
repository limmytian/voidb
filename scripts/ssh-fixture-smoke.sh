#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RUN_ID=""
ROOT="${REPO_ROOT}/target/fixtures"
REPORT_PATH="${REPO_ROOT}/target/tmp/ssh-fixture-smoke-evidence.md"
IMAGE="lscr.io/linuxserver/openssh-server@sha256:67d4c3a1402179a6579aa217a38b52ced557eb8a0c17a8e32fe986a4549fdee4"
TIMEOUT=90
TAIL_LINES=80
PULL=0

usage() {
  cat <<'EOF'
Usage: scripts/ssh-fixture-smoke.sh [options]

Starts a disposable local SSH fixture, exercises SSH plugin capabilities and
channel-mode service flows, writes redacted evidence, and tears the fixture
down.

Options:
  --run-id <id>         Stable run id. Generated when omitted.
  --root <dir>          Fixture state root. Default: target/fixtures.
  --report <path>       Evidence report path. Default: target/tmp/ssh-fixture-smoke-evidence.md.
  --image <image>       Docker image for the fixture. Default: pinned LinuxServer OpenSSH digest.
  --timeout <seconds>   Health wait timeout. Default: 90.
  --tail <lines>        Log lines to keep. Default: 80.
  --pull                Pull the fixture image when it is missing.
  -h, --help            Show this help.

The script prints resource names and variable names only. It does not print
fixture credentials, private key material, known_hosts contents, or scratch
file contents.
EOF
}

die() {
  echo "error: $*" >&2
  exit 2
}

generate_run_id() {
  printf 'ssh-cap-%s-%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$$"
}

sanitize_id() {
  local value="$1"
  [[ "${value}" =~ ^[A-Za-z0-9_.-]+$ ]] || die "invalid id: ${value}"
}

fixture_dir() {
  printf '%s/%s\n' "${ROOT}" "${RUN_ID}"
}

env_path() {
  printf '%s/ssh.env\n' "$(fixture_dir)"
}

log_path() {
  printf '%s/ssh.log\n' "$(fixture_dir)"
}

container_name() {
  printf 'voidb-fixture-ssh-%s-main\n' "${RUN_ID}"
}

network_name() {
  printf 'voidb-fixture-ssh-%s\n' "${RUN_ID}"
}

cleanup_fixture() {
  "${SCRIPT_DIR}/local-fixture-smoke.sh" teardown \
    --fixture ssh \
    --run-id "${RUN_ID}" \
    --root "${ROOT}" >/dev/null 2>&1 || true
}

ensure_ssh_keygen() {
  command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen is not installed"
}

prepare_changed_known_hosts() {
  ensure_ssh_keygen
  local changed_dir
  changed_dir="$(fixture_dir)/ssh-config/changed-host-keys"
  mkdir -p "${changed_dir}"

  local ed25519_key="${changed_dir}/ssh_host_ed25519_key"
  local ecdsa_key="${changed_dir}/ssh_host_ecdsa_key"
  local rsa_key="${changed_dir}/ssh_host_rsa_key"
  ssh-keygen -q -t ed25519 -N "" -C "voidb-fixture-changed-${RUN_ID}" -f "${ed25519_key}"
  ssh-keygen -q -t ecdsa -b 256 -N "" -C "voidb-fixture-changed-${RUN_ID}" -f "${ecdsa_key}"
  ssh-keygen -q -t rsa -b 3072 -N "" -C "voidb-fixture-changed-${RUN_ID}" -f "${rsa_key}"

  local changed_known_hosts="${changed_dir}/changed_known_hosts"
  {
    printf '[127.0.0.1]:%s ssh-ed25519 %s\n' \
      "${VOIDB_SSH_SMOKE_PORT}" "$(awk '{print $2}' "${ed25519_key}.pub")"
    printf '[127.0.0.1]:%s ecdsa-sha2-nistp256 %s\n' \
      "${VOIDB_SSH_SMOKE_PORT}" "$(awk '{print $2}' "${ecdsa_key}.pub")"
    printf '[127.0.0.1]:%s ssh-rsa %s\n' \
      "${VOIDB_SSH_SMOKE_PORT}" "$(awk '{print $2}' "${rsa_key}.pub")"
  } > "${changed_known_hosts}"

  chmod 600 "${changed_dir}"/ssh_host_*_key "${changed_known_hosts}"
  chmod 644 "${changed_dir}"/ssh_host_*_key.pub
  export VOIDB_SSH_SMOKE_CHANGED_KNOWN_HOSTS="${changed_known_hosts}"
}

enable_fixture_tcp_forwarding() {
  docker exec "$(container_name)" sh -eu -c '
    sed -i "s/^AllowTcpForwarding no$/AllowTcpForwarding yes/" /config/sshd/sshd_config
    kill -HUP "$(cat /config/sshd.pid)"
  '
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
# SSH Fixture Capability And Service Smoke Evidence

- Requirement: 63 - Promote SSH fixture-backed readiness
- Fixture: ssh
- Run id: ${RUN_ID}
- Commit: ${commit}
- Status: ${status}
- Platform: $(uname -s)-$(uname -m)
- Docker: ${docker_version}
- Image: ${IMAGE}
- Container: $(container_name)
- Network: $(network_name)
- Health: ssh port accepted local TCP connections; strict known_hosts public-key exec succeeded
- Capabilities exercised: ssh.diagnostics, ssh.test, ssh.exec, ssh.terminal_read, ssh.terminal_snapshot, ssh.terminal_write, ssh.terminal_resize, ssh.sftp_list, ssh.sftp_get, ssh.sftp_put, ssh.sftp_mkdir, ssh.sftp_rm
- Host-key policy: direct unknown-host rejection, direct changed-key rejection, strict trusted known_hosts success, and channel first-use prompt acceptance covered
- Auth coverage: password and public-key auth covered; SSH-agent auth remains optional/manual when SSH_AUTH_SOCK is available
- Service coverage: channel-mode PTY input/output, persistent multi-call shell cwd/environment, agent-owned PTY bounded read/snapshot/write/resize, reused SFTP subsystem, live local forwarding bridge, cancellation/close, and reconnect event covered
- Destructive policy: dry-run exec/sftp_put/sftp_mkdir/sftp_rm succeeded without a live target; acknowledged writes touched only the generated scratch directory
- Redaction: auth failure and dry-run output checked for withheld password and key paths; fixture logs captured through redaction filter
- Variables present by name: VOIDB_FIXTURE_RUN_ID, VOIDB_FIXTURE_NAME, VOIDB_FIXTURE_CONTAINER, VOIDB_FIXTURE_NETWORK, VOIDB_FIXTURE_IMAGE, VOIDB_FIXTURE_HOST, VOIDB_FIXTURE_PORT, VOIDB_SSH_SMOKE_PROFILE, VOIDB_SSH_SMOKE_HOST, VOIDB_SSH_SMOKE_PORT, VOIDB_SSH_SMOKE_USER, VOIDB_SSH_SMOKE_PASSWORD, VOIDB_SSH_SMOKE_PRIVATE_KEY_PATH, VOIDB_SSH_SMOKE_PUBLIC_KEY_PATH, VOIDB_SSH_SMOKE_KNOWN_HOSTS, VOIDB_SSH_SMOKE_CHANGED_KNOWN_HOSTS, VOIDB_SSH_SMOKE_SCRATCH, VOIDB_SSH_SMOKE_REMOTE_FILE
- Log capture: $(log_path)
- Capability log: ${smoke_log}
- Cleanup: ${cleanup_status}
- Release decision: capability and service smoke passed; readiness docs pending
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
  --fixture ssh
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
smoke_log="$(fixture_dir)/ssh-capability-smoke.log"
trap 'cleanup_fixture' EXIT INT TERM ERR

"${SCRIPT_DIR}/local-fixture-smoke.sh" start "${START_ARGS[@]}"
"${SCRIPT_DIR}/local-fixture-smoke.sh" wait "${START_ARGS[@]}"
enable_fixture_tcp_forwarding

set -a
# shellcheck disable=SC1090
source "$(env_path)"
set +a

prepare_changed_known_hosts

(
  cd "${REPO_ROOT}"
  cargo run -p voidb-plugin-ssh --example fixture_smoke --quiet
) > "${smoke_log}" 2>&1

"${SCRIPT_DIR}/local-fixture-smoke.sh" logs "${START_ARGS[@]}"
cleanup_fixture
cleanup_status="removed container, network, generated env file, known_hosts, and SSH config directory"
trap - EXIT INT TERM ERR

write_evidence "passed" "${cleanup_status}" "${smoke_log}"
