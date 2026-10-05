#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ARTIFACT_ROOT=""
CHECKSUMS=1
MANIFEST=1
CLI=1
SYNC_SERVER=1
TUI=1

usage() {
  cat <<'EOF'
Usage: scripts/package-smoke.sh --artifact-root DIR [options]

Runs local, secret-free smoke checks against staged VoidB release artifacts.
This does not replace manual real-terminal TUI smoke.

Options:
  --artifact-root DIR     Staged package directory to verify.
  --no-checksums          Skip SHA256SUMS verification.
  --no-manifest           Skip artifact-manifest.json consistency checks.
  --no-cli                Skip voidb-cli help/version smoke.
  --no-sync-server        Skip voidb-sync-server help/version smoke.
  --no-tui                Skip TUI executable prerequisite checks.
  -h, --help              Show this help.
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

find_binary() {
  local first="$1"
  local second="$2"

  if [[ -e "${first}" ]]; then
    printf '%s\n' "${first}"
  elif [[ -e "${second}" ]]; then
    printf '%s\n' "${second}"
  else
    return 1
  fi
}

check_executable() {
  local label="$1"
  local path="$2"

  [[ -f "${path}" ]] || die "${label} is missing: ${path}"
  [[ -x "${path}" ]] || die "${label} is not executable: ${path}"
}

verify_checksums() {
  local checksums="${ARTIFACT_ROOT}/SHA256SUMS"
  local line
  local expected
  local rel
  local path
  local actual

  [[ -f "${checksums}" ]] || die "missing checksums file: ${checksums}"

  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    expected="${line%%  *}"
    rel="${line#*  }"
    [[ -n "${expected}" && -n "${rel}" && "${expected}" != "${rel}" ]] \
      || die "invalid checksum line: ${line}"
    path="${ARTIFACT_ROOT}/${rel}"
    [[ -f "${path}" ]] || die "checksum references missing file: ${rel}"
    actual="$(sha256_file "${path}")"
    [[ "${actual}" == "${expected}" ]] \
      || die "checksum mismatch for ${rel}: expected ${expected}, got ${actual}"
  done < "${checksums}"
}

verify_manifest() {
  local manifest="${ARTIFACT_ROOT}/artifact-manifest.json"
  local expected_count
  local manifest_count

  [[ -f "${manifest}" ]] || die "missing manifest file: ${manifest}"

  if command -v python3 >/dev/null 2>&1; then
    python3 - "${ARTIFACT_ROOT}" <<'PY'
import hashlib
import json
import os
import stat
import sys

root = sys.argv[1]
manifest_path = os.path.join(root, "artifact-manifest.json")

with open(manifest_path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)

actual_paths = []
for dirpath, _, filenames in os.walk(root):
    for filename in filenames:
        if filename in {"artifact-manifest.json", "SHA256SUMS", ".build-inputs.tsv"}:
            continue
        path = os.path.join(dirpath, filename)
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        actual_paths.append(rel)

actual_paths.sort()
manifest_paths = sorted(artifact["path"] for artifact in manifest.get("artifacts", []))
if actual_paths != manifest_paths:
    missing = sorted(set(actual_paths) - set(manifest_paths))
    extra = sorted(set(manifest_paths) - set(actual_paths))
    raise SystemExit(f"manifest path mismatch; missing={missing}, extra={extra}")

for artifact in manifest.get("artifacts", []):
    rel = artifact["path"]
    path = os.path.join(root, rel)
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    size = os.path.getsize(path)
    executable = bool(os.stat(path).st_mode & stat.S_IXUSR)

    if artifact.get("sha256") != digest:
        raise SystemExit(f"manifest sha256 mismatch for {rel}")
    if artifact.get("size_bytes") != size:
        raise SystemExit(f"manifest size mismatch for {rel}")
    if artifact.get("executable") != executable:
        raise SystemExit(f"manifest executable flag mismatch for {rel}")
PY
  else
    expected_count="$(find "${ARTIFACT_ROOT}" -type f \
      ! -name 'artifact-manifest.json' \
      ! -name 'SHA256SUMS' \
      ! -name '.build-inputs.tsv' \
      -print | wc -l | tr -d ' ')"
    manifest_count="$(grep -c '"path":' "${manifest}")"
    [[ "${expected_count}" == "${manifest_count}" ]] \
      || die "manifest artifact count mismatch: expected ${expected_count}, got ${manifest_count}"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact-root)
      [[ $# -ge 2 ]] || die "missing value for --artifact-root"
      ARTIFACT_ROOT="$2"
      shift 2
      ;;
    --no-checksums)
      CHECKSUMS=0
      shift
      ;;
    --no-manifest)
      MANIFEST=0
      shift
      ;;
    --no-cli)
      CLI=0
      shift
      ;;
    --no-sync-server)
      SYNC_SERVER=0
      shift
      ;;
    --no-tui)
      TUI=0
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

[[ -n "${ARTIFACT_ROOT}" ]] || die "--artifact-root is required"
ARTIFACT_ROOT="$(cd "${ARTIFACT_ROOT}" && pwd)"
[[ -d "${ARTIFACT_ROOT}" ]] || die "artifact root does not exist: ${ARTIFACT_ROOT}"

if [[ "${CHECKSUMS}" -eq 1 ]]; then
  run verify_checksums
fi

if [[ "${MANIFEST}" -eq 1 ]]; then
  run verify_manifest
fi

if [[ "${CLI}" -eq 1 ]]; then
  cli_bin="$(find_binary \
    "${ARTIFACT_ROOT}/cli/voidb-cli" \
    "${ARTIFACT_ROOT}/cli/voidb-cli.exe")" || die "missing voidb-cli artifact"
  check_executable "voidb-cli" "${cli_bin}"
  run "${cli_bin}" --version >/dev/null
  run "${cli_bin}" --help >/dev/null
  run "${cli_bin}" profile --help >/dev/null
  run "${cli_bin}" plugin --help >/dev/null
  run "${cli_bin}" invoke --help >/dev/null
  run "${cli_bin}" credential master --help >/dev/null
fi

if [[ "${SYNC_SERVER}" -eq 1 ]]; then
  sync_bin="$(find_binary \
    "${ARTIFACT_ROOT}/sync-server/voidb-sync-server" \
    "${ARTIFACT_ROOT}/sync-server/voidb-sync-server.exe")" || die "missing voidb-sync-server artifact"
  check_executable "voidb-sync-server" "${sync_bin}"
  run "${sync_bin}" --version >/dev/null
  run "${sync_bin}" --help >/dev/null
fi

if [[ "${TUI}" -eq 1 ]]; then
  default_tui="$(find_binary \
    "${ARTIFACT_ROOT}/voidb-default/voidb" \
    "${ARTIFACT_ROOT}/voidb-default/voidb.exe")" || die "missing default TUI artifact"

  check_executable "default TUI" "${default_tui}"

  if [[ -t 0 && -t 1 ]]; then
    echo "TUI artifacts are staged and executable. Run manual real-terminal smoke before promotion."
  else
    echo "TUI artifacts are staged and executable. Manual real-terminal smoke still requires an interactive terminal."
  fi
fi

echo "package smoke passed: ${ARTIFACT_ROOT}"
