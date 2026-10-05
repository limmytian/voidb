#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ARTIFACT_ROOT=""
VERSION=""
PLATFORM=""
MANIFEST_PATH=""
CHECKSUMS_PATH=""

usage() {
  cat <<'EOF'
Usage: scripts/generate-release-manifest.sh --artifact-root DIR [options]

Generates SHA-256 checksums and a machine-readable artifact manifest for a
staged VoidB package directory.

Options:
  --artifact-root DIR     Staged package directory to inspect.
  --version VERSION       Package version. Defaults to voidb-tui Cargo.toml.
  --platform NAME         Platform label. Defaults to the current OS/arch.
  --manifest PATH         Manifest output path. Default: DIR/artifact-manifest.json.
  --checksums PATH        Checksum output path. Default: DIR/SHA256SUMS.
  -h, --help              Show this help.
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

sha256_file() {
  local path="$1"

  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${path}" | awk '{ print $1 }'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${path}" | awk '{ print $1 }'
  else
    die "missing shasum or sha256sum"
  fi
}

file_size() {
  local path="$1"

  if stat -f%z "${path}" >/dev/null 2>&1; then
    stat -f%z "${path}"
  else
    stat -c%s "${path}"
  fi
}

json_string() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '"%s"' "${value}"
}

build_input_field() {
  local component="$1"
  local field_index="$2"
  local file="${ARTIFACT_ROOT}/.build-inputs.tsv"

  if [[ -f "${file}" ]]; then
    awk -F '\t' -v component="${component}" -v field_index="${field_index}" \
      '$1 == component { print $field_index; exit }' "${file}"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact-root)
      [[ $# -ge 2 ]] || die "missing value for --artifact-root"
      ARTIFACT_ROOT="$2"
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
    --manifest)
      [[ $# -ge 2 ]] || die "missing value for --manifest"
      MANIFEST_PATH="$2"
      shift 2
      ;;
    --checksums)
      [[ $# -ge 2 ]] || die "missing value for --checksums"
      CHECKSUMS_PATH="$2"
      shift 2
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

[[ -n "${ARTIFACT_ROOT}" ]] || die "--artifact-root is required"
ARTIFACT_ROOT="$(cd "${ARTIFACT_ROOT}" && pwd)"
[[ -d "${ARTIFACT_ROOT}" ]] || die "artifact root does not exist: ${ARTIFACT_ROOT}"

VERSION="${VERSION:-$(read_package_version "${REPO_ROOT}/crates/voidb-tui/Cargo.toml")}"
PLATFORM="${PLATFORM:-$(detect_platform)}"
MANIFEST_PATH="${MANIFEST_PATH:-${ARTIFACT_ROOT}/artifact-manifest.json}"
CHECKSUMS_PATH="${CHECKSUMS_PATH:-${ARTIFACT_ROOT}/SHA256SUMS}"

FILES_LIST="$(mktemp)"
trap 'rm -f "${FILES_LIST}"' EXIT

find "${ARTIFACT_ROOT}" -type f \
  ! -name 'artifact-manifest.json' \
  ! -name 'SHA256SUMS' \
  ! -name '.build-inputs.tsv' \
  -print | LC_ALL=C sort > "${FILES_LIST}"

: > "${CHECKSUMS_PATH}"
while IFS= read -r file; do
  rel="${file#${ARTIFACT_ROOT}/}"
  printf '%s  %s\n' "$(sha256_file "${file}")" "${rel}" >> "${CHECKSUMS_PATH}"
done < "${FILES_LIST}"

generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
artifact_root_name="$(basename "${ARTIFACT_ROOT}")"
git_commit=""
git_dirty="false"

if git -C "${REPO_ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git_commit="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
  if ! git -C "${REPO_ROOT}" diff --quiet || ! git -C "${REPO_ROOT}" diff --cached --quiet; then
    git_dirty="true"
  fi
fi

{
  printf '{\n'
  printf '  "schema_version": 1,\n'
  printf '  "generated_at": %s,\n' "$(json_string "${generated_at}")"
  printf '  "package": "voidb",\n'
  printf '  "version": %s,\n' "$(json_string "${VERSION}")"
  printf '  "platform": %s,\n' "$(json_string "${PLATFORM}")"
  printf '  "artifact_root": %s,\n' "$(json_string "${artifact_root_name}")"
  printf '  "git": {\n'
  if [[ -n "${git_commit}" ]]; then
    printf '    "commit": %s,\n' "$(json_string "${git_commit}")"
  else
    printf '    "commit": null,\n'
  fi
  printf '    "dirty": %s\n' "${git_dirty}"
  printf '  },\n'
  printf '  "artifacts": [\n'

  first=1
  while IFS= read -r file; do
    rel="${file#${ARTIFACT_ROOT}/}"
    component="${rel%%/*}"
    sha="$(sha256_file "${file}")"
    size="$(file_size "${file}")"
    executable="false"
    [[ -x "${file}" ]] && executable="true"

    package="$(build_input_field "${component}" 2)"
    cargo_manifest="$(build_input_field "${component}" 3)"
    binary="$(build_input_field "${component}" 4)"
    artifact_version="$(build_input_field "${component}" 5)"
    profile="$(build_input_field "${component}" 6)"
    features="$(build_input_field "${component}" 7)"
    source_path="$(build_input_field "${component}" 8)"
    cargo_command="$(build_input_field "${component}" 9)"

    [[ -n "${artifact_version}" ]] || artifact_version="${VERSION}"

    if [[ "${first}" -eq 0 ]]; then
      printf ',\n'
    fi
    first=0

    printf '    {\n'
    printf '      "component": %s,\n' "$(json_string "${component}")"
    printf '      "path": %s,\n' "$(json_string "${rel}")"
    printf '      "size_bytes": %s,\n' "${size}"
    printf '      "sha256": %s,\n' "$(json_string "${sha}")"
    printf '      "executable": %s,\n' "${executable}"
    printf '      "package": %s,\n' "$(json_string "${package}")"
    printf '      "binary": %s,\n' "$(json_string "${binary}")"
    printf '      "version": %s,\n' "$(json_string "${artifact_version}")"
    printf '      "build_inputs": {\n'
    printf '        "cargo_manifest": %s,\n' "$(json_string "${cargo_manifest}")"
    printf '        "cargo_command": %s,\n' "$(json_string "${cargo_command}")"
    printf '        "profile": %s,\n' "$(json_string "${profile}")"
    printf '        "features": %s,\n' "$(json_string "${features}")"
    printf '        "source_path": %s\n' "$(json_string "${source_path}")"
    printf '      }\n'
    printf '    }'
  done < "${FILES_LIST}"

  printf '\n'
  printf '  ]\n'
  printf '}\n'
} > "${MANIFEST_PATH}"

echo "wrote ${CHECKSUMS_PATH}"
echo "wrote ${MANIFEST_PATH}"
