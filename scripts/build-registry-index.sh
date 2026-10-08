#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUTPUT_FILE="${1:-${REPO_ROOT}/registry/index.json}"
BASE_URL="${2:-}"
REGISTRY_NAME="VoidB Official Plugin Registry"

PLUGINS=(
  "mysql"
  "postgres"
  "sqlite"
  "redis"
  "ssh"
  "duckdb"
  "s3"
  "email"
  "docker"
  "kubernetes"
  "elasticsearch"
  "mongodb"
  "jenkins"
  "webdav"
)

echo "==> Building official VoidB Plugin Registry index manifest"
echo "Target output: ${OUTPUT_FILE}"

INPUT_PATHS=()
for plugin in "${PLUGINS[@]}"; do
  plugin_repo="${REPO_ROOT}/../voidb-plugin-${plugin}"
  if [ ! -d "${plugin_repo}" ]; then
    echo "Warning: Plugin repository not found at ${plugin_repo}, skipping." >&2
    continue
  fi

  # Prefer actual packaged distribution archive in dist/ if available
  pkg_archive="$(ls -t "${plugin_repo}"/dist/${plugin}-*.tar.gz 2>/dev/null | head -n 1 || true)"
  if [ -n "${pkg_archive}" ] && [ -f "${pkg_archive}" ]; then
    INPUT_PATHS+=("${pkg_archive}")
  else
    INPUT_PATHS+=("${plugin_repo}")
  fi
done

if [ ${#INPUT_PATHS[@]} -eq 0 ]; then
  echo "Error: No plugin source directories found to index." >&2
  exit 1
fi

mkdir -p "$(dirname "${OUTPUT_FILE}")"

CMD=(
  cargo run -p voidb-cli --
  plugin registry-index
  "${INPUT_PATHS[@]}"
  --output "${OUTPUT_FILE}"
  --registry-name "${REGISTRY_NAME}"
  --format json
)

if [ -n "${BASE_URL}" ]; then
  CMD+=(--base-url "${BASE_URL}")
fi

"${CMD[@]}"

echo "==> Generated registry index successfully:"
ls -lh "${OUTPUT_FILE}"
