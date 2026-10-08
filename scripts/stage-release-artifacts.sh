#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUT_DIR="${REPO_ROOT}/target/package"
PROFILE="release"
BUILD=0
GENERATE_MANIFEST=1
VERSION=""
PLATFORM=""
TARGET_DIR="${CARGO_TARGET_DIR:-}"
CUSTOM_TARGET_DIR=0
TUI_BIN="${VOIDB_TUI_BIN:-}"
CLI_BIN="${VOIDB_CLI_BIN:-}"
SYNC_SERVER_BIN="${VOIDB_SYNC_SERVER_BIN:-}"

if [[ -n "${TARGET_DIR}" ]]; then
  CUSTOM_TARGET_DIR=1
fi

usage() {
  cat <<'EOF'
Usage: scripts/stage-release-artifacts.sh [options]

Stages VoidB release artifacts into a repeatable platform-qualified package
directory. By default the script copies existing binaries; pass --build for a
fresh local release build.

Options:
  --build                    Build artifacts before staging.
  --skip-build               Copy existing artifacts. This is the default.
  --profile PROFILE          Cargo profile or output dir. Default: release.
  --out DIR                  Package output root. Default: target/package.
  --version VERSION          Package version. Defaults to voidb-tui Cargo.toml.
  --platform NAME            Platform label. Defaults to the current OS/arch.
  --target-dir DIR           Override Cargo target dir for all build outputs.
                             Defaults to Cargo's package/workspace target dirs,
                             or CARGO_TARGET_DIR when set.
  --tui-bin PATH             Existing default TUI binary to stage.
  --cli-bin PATH             Existing voidb-cli binary to stage.
  --sync-server-bin PATH     Existing voidb-sync-server binary to stage.
  --no-manifest              Do not generate SHA256SUMS and artifact manifest.
  -h, --help                 Show this help.

Environment overrides:
  VOIDB_TUI_BIN, VOIDB_CLI_BIN, VOIDB_SYNC_SERVER_BIN
EOF
}

die() {
  echo "error: $*" >&2
  exit 2
}

run() {
  printf '\n==> '
  printf '%q ' "$@"
  printf '\n'
  "$@"
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

detect_platform() {
  local os
  local arch

  case "$(uname -s)" in
    Darwin) os="darwin" ;;
    Linux) os="linux" ;;
    MINGW*|MSYS*|CYGWIN*) os="windows" ;;
    *) os="$(uname -s | tr '[:upper:]' '[:lower:]')" ;;
  esac

  case "$(uname -m)" in
    arm64|aarch64) arch="arm64" ;;
    x86_64|amd64) arch="x64" ;;
    *) arch="$(uname -m | tr '[:upper:]' '[:lower:]')" ;;
  esac

  printf '%s-%s\n' "${os}" "${arch}"
}

profile_dir() {
  case "${PROFILE}" in
    release) printf 'release\n' ;;
    debug) printf 'debug\n' ;;
    *) printf '%s\n' "${PROFILE}" ;;
  esac
}

binary_name() {
  local name="$1"

  if [[ "${PLATFORM}" == windows-* ]]; then
    printf '%s.exe\n' "${name}"
  else
    printf '%s\n' "${name}"
  fi
}

cargo_profile_args() {
  case "${PROFILE}" in
    release) printf '%s\n' "--release" ;;
    debug) ;;
    *) printf '%s\n%s\n' "--profile" "${PROFILE}" ;;
  esac
}

cargo_profile_label() {
  case "${PROFILE}" in
    release) printf ' --release' ;;
    debug) ;;
    *) printf ' --profile %s' "${PROFILE}" ;;
  esac
}

stage_file() {
  local component="$1"
  local package="$2"
  local cargo_manifest="$3"
  local binary="$4"
  local artifact_version="$5"
  local features="$6"
  local source_path="$7"
  local cargo_command="$8"
  local dest_rel="$9"
  local dest_path="${ARTIFACT_ROOT}/${dest_rel}"

  [[ -f "${source_path}" ]] || die "missing ${component} artifact: ${source_path}"

  mkdir -p "$(dirname "${dest_path}")"
  install -m 0755 "${source_path}" "${dest_path}"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${component}" \
    "${package}" \
    "${cargo_manifest}" \
    "${binary}" \
    "${artifact_version}" \
    "${PROFILE}" \
    "${features}" \
    "${source_path#${REPO_ROOT}/}" \
    "${cargo_command}" >> "${BUILD_INPUTS}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build)
      BUILD=1
      shift
      ;;
    --skip-build)
      BUILD=0
      shift
      ;;
    --profile)
      [[ $# -ge 2 ]] || die "missing value for --profile"
      PROFILE="$2"
      shift 2
      ;;
    --out)
      [[ $# -ge 2 ]] || die "missing value for --out"
      OUT_DIR="$2"
      shift 2
      ;;
    --version)
      [[ $# -ge 2 ]] || die "missing value for --version"
      VERSION="$2"
      shift 2
      ;;
    --platform)
      [[ $# -ge 2 ]] || die "missing value for --platform"
      PLATFORM="$2"
      shift 2
      ;;
    --target-dir)
      [[ $# -ge 2 ]] || die "missing value for --target-dir"
      TARGET_DIR="$2"
      CUSTOM_TARGET_DIR=1
      shift 2
      ;;
    --tui-bin)
      [[ $# -ge 2 ]] || die "missing value for --tui-bin"
      TUI_BIN="$2"
      shift 2
      ;;
    --cli-bin)
      [[ $# -ge 2 ]] || die "missing value for --cli-bin"
      CLI_BIN="$2"
      shift 2
      ;;
    --sync-server-bin)
      [[ $# -ge 2 ]] || die "missing value for --sync-server-bin"
      SYNC_SERVER_BIN="$2"
      shift 2
      ;;
    --no-manifest)
      GENERATE_MANIFEST=0
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

cd "${REPO_ROOT}"

VERSION="${VERSION:-$(read_package_version "${REPO_ROOT}/crates/voidb-tui/Cargo.toml")}"
PLATFORM="${PLATFORM:-$(detect_platform)}"
OUT_DIR="$(mkdir -p "${OUT_DIR}" && cd "${OUT_DIR}" && pwd)"
if [[ "${CUSTOM_TARGET_DIR}" -eq 1 ]]; then
  TARGET_DIR="$(mkdir -p "${TARGET_DIR}" && cd "${TARGET_DIR}" && pwd)"
  export CARGO_TARGET_DIR="${TARGET_DIR}"
else
  TARGET_DIR="${REPO_ROOT}/target"
fi
SYNC_TARGET_DIR="${REPO_ROOT}/voidb-sync-server/target"
if [[ "${CUSTOM_TARGET_DIR}" -eq 1 ]]; then
  SYNC_TARGET_DIR="${TARGET_DIR}"
fi
ARTIFACT_ROOT="${OUT_DIR}/voidb-${VERSION}-${PLATFORM}"
BUILD_INPUTS="${ARTIFACT_ROOT}/.build-inputs.tsv"
PROFILE_DIR="$(profile_dir)"
PROFILE_LABEL="$(cargo_profile_label)"
TUI_NAME="$(binary_name voidb)"
CLI_NAME="$(binary_name voidb-cli)"
SYNC_SERVER_NAME="$(binary_name voidb-sync-server)"

rm -rf "${ARTIFACT_ROOT}"
mkdir -p "${ARTIFACT_ROOT}"
: > "${BUILD_INPUTS}"

if [[ "${BUILD}" -eq 1 ]]; then
  profile_args=()
  while IFS= read -r arg; do
    [[ -n "${arg}" ]] && profile_args+=("${arg}")
  done < <(cargo_profile_args)

  run cargo build "${profile_args[@]}"
  stage_file \
    "voidb-default" \
    "voidb-tui" \
    "crates/voidb-tui/Cargo.toml" \
    "${TUI_NAME}" \
    "${VERSION}" \
    "default" \
    "${TARGET_DIR}/${PROFILE_DIR}/${TUI_NAME}" \
    "cargo build${PROFILE_LABEL}" \
    "voidb-default/${TUI_NAME}"

  run cargo build "${profile_args[@]}" -p voidb-cli
  stage_file \
    "cli" \
    "voidb-cli" \
    "crates/voidb-cli/Cargo.toml" \
    "${CLI_NAME}" \
    "${VERSION}" \
    "default" \
    "${TARGET_DIR}/${PROFILE_DIR}/${CLI_NAME}" \
    "cargo build${PROFILE_LABEL} -p voidb-cli" \
    "cli/${CLI_NAME}"

  run cargo build "${profile_args[@]}" --manifest-path voidb-sync-server/Cargo.toml
  stage_file \
    "sync-server" \
    "voidb-sync-server" \
    "voidb-sync-server/Cargo.toml" \
    "${SYNC_SERVER_NAME}" \
    "${VERSION}" \
    "default" \
    "${SYNC_TARGET_DIR}/${PROFILE_DIR}/${SYNC_SERVER_NAME}" \
    "cargo build${PROFILE_LABEL} --manifest-path voidb-sync-server/Cargo.toml" \
    "sync-server/${SYNC_SERVER_NAME}"
else
  TUI_BIN="${TUI_BIN:-${TARGET_DIR}/${PROFILE_DIR}/${TUI_NAME}}"
  CLI_BIN="${CLI_BIN:-${TARGET_DIR}/${PROFILE_DIR}/${CLI_NAME}}"
  SYNC_SERVER_BIN="${SYNC_SERVER_BIN:-${SYNC_TARGET_DIR}/${PROFILE_DIR}/${SYNC_SERVER_NAME}}"

  stage_file \
    "voidb-default" \
    "voidb-tui" \
    "crates/voidb-tui/Cargo.toml" \
    "${TUI_NAME}" \
    "${VERSION}" \
    "default" \
    "${TUI_BIN}" \
    "prebuilt artifact copied by scripts/stage-release-artifacts.sh --skip-build" \
    "voidb-default/${TUI_NAME}"

  stage_file \
    "cli" \
    "voidb-cli" \
    "crates/voidb-cli/Cargo.toml" \
    "${CLI_NAME}" \
    "${VERSION}" \
    "default" \
    "${CLI_BIN}" \
    "prebuilt artifact copied by scripts/stage-release-artifacts.sh --skip-build" \
    "cli/${CLI_NAME}"

  stage_file \
    "sync-server" \
    "voidb-sync-server" \
    "voidb-sync-server/Cargo.toml" \
    "${SYNC_SERVER_NAME}" \
    "${VERSION}" \
    "default" \
    "${SYNC_SERVER_BIN}" \
    "prebuilt artifact copied by scripts/stage-release-artifacts.sh --skip-build" \
    "sync-server/${SYNC_SERVER_NAME}"
fi

# Stage official default plugins if available
DEFAULT_PLUGINS=("mysql" "postgres" "sqlite" "redis" "ssh" "duckdb")
for plugin in "${DEFAULT_PLUGINS[@]}"; do
  plugin_repo="${REPO_ROOT}/../voidb-plugin-${plugin}"
  if [[ -d "${plugin_repo}" && -f "${plugin_repo}/plugin.toml" ]]; then
    plugin_stage="${ARTIFACT_ROOT}/plugins/${plugin}"
    mkdir -p "${plugin_stage}/bin"
    cp "${plugin_repo}/plugin.toml" "${plugin_stage}/"
    if [[ -d "${plugin_repo}/schemas" ]]; then
      cp -r "${plugin_repo}/schemas" "${plugin_stage}/"
    fi
    if [[ -f "${plugin_repo}/target/${PROFILE_DIR}/${plugin}" ]]; then
      cp "${plugin_repo}/target/${PROFILE_DIR}/${plugin}" "${plugin_stage}/bin/voidb-plugin-${plugin}"
      chmod +x "${plugin_stage}/bin/voidb-plugin-${plugin}"
    elif [[ -f "${plugin_repo}/target/${PROFILE_DIR}/voidb-plugin-${plugin}" ]]; then
      cp "${plugin_repo}/target/${PROFILE_DIR}/voidb-plugin-${plugin}" "${plugin_stage}/bin/voidb-plugin-${plugin}"
      chmod +x "${plugin_stage}/bin/voidb-plugin-${plugin}"
    elif [[ -f "${plugin_repo}/bin/voidb-plugin-${plugin}" ]]; then
      cp "${plugin_repo}/bin/voidb-plugin-${plugin}" "${plugin_stage}/bin/voidb-plugin-${plugin}"
      chmod +x "${plugin_stage}/bin/voidb-plugin-${plugin}"
    fi
  fi
done

if [[ "${GENERATE_MANIFEST}" -eq 1 ]]; then
  run "${SCRIPT_DIR}/generate-release-manifest.sh" \
    --artifact-root "${ARTIFACT_ROOT}" \
    --version "${VERSION}" \
    --platform "${PLATFORM}"
fi

echo "staged release artifacts: ${ARTIFACT_ROOT}"
