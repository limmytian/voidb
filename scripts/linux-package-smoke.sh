#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMAGE="${VOIDB_LINUX_PACKAGE_IMAGE:-rust:1-bookworm}"
DOCKER_PLATFORM="${VOIDB_LINUX_DOCKER_PLATFORM:-linux/amd64}"
PACKAGE_PLATFORM="${VOIDB_LINUX_PACKAGE_PLATFORM:-linux-x64}"
VERSION=""
OUT_DIR="target/package-linux"
TARGET_DIR="target/linux-package-smoke/target"
CARGO_HOME_DIR="target/linux-package-smoke/cargo"
REPORT=""
INSTALL_DEPS=1
BUILD=1

usage() {
  cat <<'EOF'
Usage: scripts/linux-package-smoke.sh [options]

Builds and smokes Linux package artifacts inside a Docker Linux container. The
script stages artifacts with scripts/stage-release-artifacts.sh, verifies
SHA256SUMS and artifact-manifest.json with scripts/package-smoke.sh, and writes
optional evidence for release-owner review. It does not publish artifacts.

Options:
  --image IMAGE              Docker image. Default: rust:1-bookworm.
  --docker-platform NAME     Docker platform. Default: linux/amd64.
  --package-platform NAME    Artifact platform label. Default: linux-x64.
  --version VERSION          Package version. Defaults to voidb-tui Cargo.toml.
  --out DIR                  Repo-relative package output root.
                             Default: target/package-linux.
  --target-dir DIR           Repo-relative Cargo target dir used in Docker.
                             Default: target/linux-package-smoke/target.
  --cargo-home DIR           Repo-relative Cargo home/cache used in Docker.
                             Default: target/linux-package-smoke/cargo.
  --report PATH              Write a Markdown evidence report.
  --skip-build               Regenerate manifest and smoke existing staged
                             Linux artifacts without recompiling.
  --no-install-deps          Skip apt package installation in the container.
  -h, --help                 Show this help.
EOF
}

die() {
  echo "error: $*" >&2
  exit 2
}

read_package_version() {
  local manifest="$1"
  awk '
    /^\[package\]/ { in_package = 1; next }
    /^\[/ { if (in_package) exit }
    in_package && $1 == "version" {
      value = $3
      gsub(/"/, "", value)
      print value
      exit
    }
  ' "${manifest}"
}

repo_relative_path() {
  local path="$1"

  if [[ "${path}" = /* ]]; then
    case "${path}" in
      "${REPO_ROOT}"/*)
        path="${path#"${REPO_ROOT}/"}"
        ;;
      *)
        die "path must be inside the repository: ${path}"
        ;;
    esac
  fi

  path="${path#./}"
  [[ -n "${path}" ]] || die "path must not be empty"
  case "${path}" in
    ../*|*/../*|..)
      die "path must stay inside the repository: ${path}"
      ;;
  esac

  printf '%s\n' "${path}"
}

write_report() {
  local status="$1"
  local report_path="$2"
  local artifact_root="${REPO_ROOT}/${OUT_DIR}/voidb-${VERSION}-${PACKAGE_PLATFORM}"
  local generated_at
  local git_commit

  [[ -n "${report_path}" ]] || return 0

  mkdir -p "$(dirname "${report_path}")"
  generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  git_commit="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true)"

  {
    printf '# Linux Package Smoke Evidence\n\n'
    printf '| Field | Value |\n'
    printf '|---|---|\n'
    printf '| Generated at | `%s` |\n' "${generated_at}"
    printf '| Status | `%s` |\n' "${status}"
    printf '| Git commit | `%s` |\n' "${git_commit:-unknown}"
    printf '| Docker image | `%s` |\n' "${IMAGE}"
    printf '| Docker platform | `%s` |\n' "${DOCKER_PLATFORM}"
    printf '| Package platform label | `%s` |\n' "${PACKAGE_PLATFORM}"
    printf '| Version | `%s` |\n' "${VERSION}"
    printf '| Artifact root | `%s` |\n' "${artifact_root#${REPO_ROOT}/}"
    printf '| Cargo target dir | `%s` |\n' "${TARGET_DIR}"
    printf '| Cargo home | `%s` |\n' "${CARGO_HOME_DIR}"
    printf '\n'
    printf '## Commands\n\n'
    printf '```bash\n'
    if [[ "${BUILD}" -eq 1 ]]; then
      printf 'scripts/stage-release-artifacts.sh --build --out %q --version %q --platform %q --target-dir %q\n' \
        "/work/${OUT_DIR}" "${VERSION}" "${PACKAGE_PLATFORM}" "/work/${TARGET_DIR}"
    else
      printf 'scripts/generate-release-manifest.sh --artifact-root %q --version %q --platform %q\n' \
        "/work/${OUT_DIR}/voidb-${VERSION}-${PACKAGE_PLATFORM}" "${VERSION}" "${PACKAGE_PLATFORM}"
    fi
    printf 'scripts/package-smoke.sh --artifact-root %q\n' \
      "/work/${OUT_DIR}/voidb-${VERSION}-${PACKAGE_PLATFORM}"
    printf '```\n\n'
    printf '## Native Runner Boundary\n\n'
    printf 'This smoke runs inside Docker using the requested Linux container platform. '
    printf 'It verifies container-built Linux artifacts, checksums, manifest metadata, '
    printf 'CLI entry points, sync-server entry points, and staged TUI executability. '
    printf 'If the container platform is emulated by Docker Desktop, record that as '
    printf 'Docker-based evidence rather than native runner evidence. Release notes '
    printf 'must not claim a platform whose native or accepted Docker package smoke '
    printf 'was skipped or failed.\n\n'
    if [[ -f "${artifact_root}/SHA256SUMS" ]]; then
      printf '## SHA256SUMS\n\n'
      printf '```text\n'
      sed -n '1,120p' "${artifact_root}/SHA256SUMS"
      printf '```\n'
    fi
  } > "${report_path}"

  echo "wrote ${report_path}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      [[ $# -ge 2 ]] || die "missing value for --image"
      IMAGE="$2"
      shift 2
      ;;
    --docker-platform)
      [[ $# -ge 2 ]] || die "missing value for --docker-platform"
      DOCKER_PLATFORM="$2"
      shift 2
      ;;
    --package-platform)
      [[ $# -ge 2 ]] || die "missing value for --package-platform"
      PACKAGE_PLATFORM="$2"
      shift 2
      ;;
    --version)
      [[ $# -ge 2 ]] || die "missing value for --version"
      VERSION="$2"
      shift 2
      ;;
    --out)
      [[ $# -ge 2 ]] || die "missing value for --out"
      OUT_DIR="$2"
      shift 2
      ;;
    --target-dir)
      [[ $# -ge 2 ]] || die "missing value for --target-dir"
      TARGET_DIR="$2"
      shift 2
      ;;
    --cargo-home)
      [[ $# -ge 2 ]] || die "missing value for --cargo-home"
      CARGO_HOME_DIR="$2"
      shift 2
      ;;
    --report)
      [[ $# -ge 2 ]] || die "missing value for --report"
      REPORT="$2"
      shift 2
      ;;
    --skip-build)
      BUILD=0
      shift
      ;;
    --no-install-deps)
      INSTALL_DEPS=0
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

command -v docker >/dev/null 2>&1 || die "docker is required"
docker info >/dev/null 2>&1 || die "docker daemon is not available"

VERSION="${VERSION:-$(read_package_version "${REPO_ROOT}/crates/voidb-tui/Cargo.toml")}"
OUT_DIR="$(repo_relative_path "${OUT_DIR}")"
TARGET_DIR="$(repo_relative_path "${TARGET_DIR}")"
CARGO_HOME_DIR="$(repo_relative_path "${CARGO_HOME_DIR}")"
[[ -z "${REPORT}" ]] || REPORT="$(repo_relative_path "${REPORT}")"

mkdir -p \
  "${REPO_ROOT}/${OUT_DIR}" \
  "${REPO_ROOT}/${TARGET_DIR}" \
  "${REPO_ROOT}/${CARGO_HOME_DIR}"

container_script='
set -euo pipefail
export PATH="/usr/local/cargo/bin:${CARGO_HOME}/bin:${PATH}"

cleanup_permissions() {
  if command -v chown >/dev/null 2>&1 && [[ -n "${HOST_UID:-}" && -n "${HOST_GID:-}" ]]; then
    chown -R "${HOST_UID}:${HOST_GID}" "${VOIDB_PACKAGE_OUT}" "${CARGO_TARGET_DIR}" "${CARGO_HOME}" 2>/dev/null || true
  fi
}
trap cleanup_permissions EXIT

if [[ "${VOIDB_INSTALL_DEPS}" -eq 1 ]]; then
  apt-get update
  apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    libdbus-1-dev \
    libssl-dev \
    pkg-config
  rm -rf /var/lib/apt/lists/*
fi

rustc --version
cargo --version
uname -a

scripts/stage-release-artifacts.sh \
  --build \
  --out "${VOIDB_PACKAGE_OUT}" \
  --version "${VOIDB_PACKAGE_VERSION}" \
  --platform "${VOIDB_PACKAGE_PLATFORM}" \
  --target-dir "${CARGO_TARGET_DIR}"

if [[ "${VOIDB_PACKAGE_BUILD}" -eq 0 ]]; then
  artifact_root="${VOIDB_PACKAGE_OUT}/voidb-${VOIDB_PACKAGE_VERSION}-${VOIDB_PACKAGE_PLATFORM}"
  [[ -d "${artifact_root}" ]] || {
    echo "error: existing staged artifact root is missing: ${artifact_root}" >&2
    exit 2
  }
  scripts/generate-release-manifest.sh \
    --artifact-root "${artifact_root}" \
    --version "${VOIDB_PACKAGE_VERSION}" \
    --platform "${VOIDB_PACKAGE_PLATFORM}"
fi

scripts/package-smoke.sh \
  --artifact-root "${VOIDB_PACKAGE_OUT}/voidb-${VOIDB_PACKAGE_VERSION}-${VOIDB_PACKAGE_PLATFORM}"
'

if [[ "${BUILD}" -eq 0 ]]; then
  container_script="set -euo pipefail
export PATH=\"/usr/local/cargo/bin:\${CARGO_HOME}/bin:\${PATH}\"

cleanup_permissions() {
  if command -v chown >/dev/null 2>&1 && [[ -n \"\${HOST_UID:-}\" && -n \"\${HOST_GID:-}\" ]]; then
    chown -R \"\${HOST_UID}:\${HOST_GID}\" \"\${VOIDB_PACKAGE_OUT}\" \"\${CARGO_TARGET_DIR}\" \"\${CARGO_HOME}\" 2>/dev/null || true
  fi
}
trap cleanup_permissions EXIT

if [[ \"\${VOIDB_INSTALL_DEPS}\" -eq 1 ]]; then
  apt-get update
  apt-get install -y --no-install-recommends \\
    build-essential \\
    ca-certificates \\
    clang \\
    cmake \\
    libdbus-1-dev \\
    libssl-dev \\
    pkg-config
  rm -rf /var/lib/apt/lists/*
fi

rustc --version
cargo --version
uname -a

artifact_root=\"\${VOIDB_PACKAGE_OUT}/voidb-\${VOIDB_PACKAGE_VERSION}-\${VOIDB_PACKAGE_PLATFORM}\"
[[ -d \"\${artifact_root}\" ]] || {
  echo \"error: existing staged artifact root is missing: \${artifact_root}\" >&2
  exit 2
}
scripts/generate-release-manifest.sh \\
  --artifact-root \"\${artifact_root}\" \\
  --version \"\${VOIDB_PACKAGE_VERSION}\" \\
  --platform \"\${VOIDB_PACKAGE_PLATFORM}\"

scripts/package-smoke.sh \\
  --artifact-root \"\${artifact_root}\"
"
fi

set +e
docker run --rm \
  --platform "${DOCKER_PLATFORM}" \
  -v "${REPO_ROOT}:/work" \
  -w /work \
  -e CARGO_HOME="/work/${CARGO_HOME_DIR}" \
  -e CARGO_TARGET_DIR="/work/${TARGET_DIR}" \
  -e DEBIAN_FRONTEND=noninteractive \
  -e HOST_GID="$(id -g)" \
  -e HOST_UID="$(id -u)" \
  -e VOIDB_INSTALL_DEPS="${INSTALL_DEPS}" \
  -e VOIDB_PACKAGE_OUT="/work/${OUT_DIR}" \
  -e VOIDB_PACKAGE_PLATFORM="${PACKAGE_PLATFORM}" \
  -e VOIDB_PACKAGE_VERSION="${VERSION}" \
  -e VOIDB_PACKAGE_BUILD="${BUILD}" \
  "${IMAGE}" \
  bash -lc "${container_script}"
status=$?
set -e

if [[ "${status}" -eq 0 ]]; then
  write_report "passed" "${REPORT}"
  echo "linux package smoke passed: ${REPO_ROOT}/${OUT_DIR}/voidb-${VERSION}-${PACKAGE_PLATFORM}"
else
  write_report "failed" "${REPORT}"
  exit "${status}"
fi
