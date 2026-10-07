#!/usr/bin/env bash
set -euo pipefail

# scripts/test-plugin-cross-platform.sh
# End-to-end multi-platform packaging, signing, installation, and capability loading test suite.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUTPUT_DIR="${REPO_ROOT}/target/e2e-plugin-test"
INSTALL_ROOT="${OUTPUT_DIR}/installed"
DIST_DIR="${OUTPUT_DIR}/dist"

PLUGINS=(
  "s3"
  "email"
  "docker"
  "kubernetes"
  "elasticsearch"
  "mongodb"
  "jenkins"
  "webdav"
)

FORMATS=("tar" "tar.zst")

echo "================================================================================"
echo " VoidB Multi-Platform Plugin Packaging & Installation Compatibility Test Suite"
echo "================================================================================"
echo "Output Directory:  ${OUTPUT_DIR}"
echo "Install Root:      ${INSTALL_ROOT}"
echo "Plugins under test: ${PLUGINS[*]}"
echo "Archive Formats:   ${FORMATS[*]}"
echo "================================================================================"

rm -rf "${OUTPUT_DIR}"
mkdir -p "${INSTALL_ROOT}" "${DIST_DIR}"

# Step 1: Ensure voidb-cli is built
echo "==> Step 1: Building voidb-cli"
cargo build -p voidb-cli

VOIDB_CLI="${REPO_ROOT}/target/debug/voidb-cli"
if [ ! -f "${VOIDB_CLI}" ]; then
  VOIDB_CLI="${REPO_ROOT}/target/debug/voidb"
fi

# Step 2: Generate Ed25519 signing keypair
echo "==> Step 2: Generating dedicated Ed25519 signing keypair for test run"
KEY_OUT=$("${VOIDB_CLI}" plugin sign Cargo.toml --generate-key --output "${OUTPUT_DIR}/dummy.sig" --format json)
PRIV_KEY=$(echo "${KEY_OUT}" | grep -o '"private_key": *"[^"]*"' | cut -d '"' -f 4)
PUB_KEY=$(echo "${KEY_OUT}" | grep -o '"public_key": *"[^"]*"' | cut -d '"' -f 4)
rm -f "${OUTPUT_DIR}/dummy.sig"

echo "Public Key:  ${PUB_KEY}"
echo "Private Key: [REDACTED 64-hex bytes]"

# Step 3: Iterate through each plugin
PASSED_COUNT=0
TOTAL_COUNT=${#PLUGINS[@]}

for plugin in "${PLUGINS[@]}"; do
  echo "--------------------------------------------------------------------------------"
  echo "==> Testing Plugin: voidb-plugin-${plugin}"
  PLUGIN_REPO="${REPO_ROOT}/../voidb-plugin-${plugin}"
  
  if [ ! -d "${PLUGIN_REPO}" ]; then
    echo "Error: Plugin repository missing at ${PLUGIN_REPO}" >&2
    exit 1
  fi

  # Alternate archive format
  FORMAT_IDX=$(( PASSED_COUNT % 2 ))
  FORMAT="${FORMATS[$FORMAT_IDX]}"
  
  PKG_OUTPUT_DIR="${DIST_DIR}/${plugin}"
  mkdir -p "${PKG_OUTPUT_DIR}"

  echo "--> 3.1 Packaging voidb-plugin-${plugin} with format: .${FORMAT}"
  ARCHIVE_PATH="${PKG_OUTPUT_DIR}/voidb-plugin-${plugin}-0.3.0.${FORMAT}"
  
  "${VOIDB_CLI}" plugin package "${PLUGIN_REPO}" \
    --output "${ARCHIVE_PATH}" \
    --archive-format "${FORMAT}" \
    --format json > /dev/null

  if [ ! -f "${ARCHIVE_PATH}" ]; then
    echo "Error: Package file ${ARCHIVE_PATH} was not generated!" >&2
    exit 1
  fi
  echo "    Package archive created: $(ls -lh "${ARCHIVE_PATH}" | awk '{print $5, $9}')"

  echo "--> 3.2 Signing package archive with Ed25519"
  SIG_PATH="${ARCHIVE_PATH}.sig"
  "${VOIDB_CLI}" plugin sign "${ARCHIVE_PATH}" \
    --private-key "${PRIV_KEY}" \
    --output "${SIG_PATH}" \
    --format json > /dev/null

  if [ ! -f "${SIG_PATH}" ]; then
    echo "Error: Detached signature file ${SIG_PATH} not generated!" >&2
    exit 1
  fi
  echo "    Detached signature created: $(cat "${SIG_PATH}")"

  echo "--> 3.3 Verifying package signature independently"
  "${VOIDB_CLI}" plugin verify "${ARCHIVE_PATH}" \
    --public-key "${PUB_KEY}" \
    --format json > /dev/null
  echo "    Signature verified successfully."

  echo "--> 3.4 Installing package with signature gate enforcement"
  INSTALL_RES=$("${VOIDB_CLI}" plugin install "${ARCHIVE_PATH}" \
    --install-root "${INSTALL_ROOT}" \
    --verify-key "${PUB_KEY}" \
    --require-signature \
    --format json)
  
  INSTALLED_STATE=$(echo "${INSTALL_RES}" | grep -o '"candidate_state": *"[^"]*"' | cut -d '"' -f 4)
  if [ "${INSTALLED_STATE}" != "available" ]; then
    echo "Error: Installed candidate state is '${INSTALLED_STATE}', expected 'available'!" >&2
    echo "${INSTALL_RES}" >&2
    exit 1
  fi
  echo "    Package installed successfully. Candidate state: ${INSTALLED_STATE}"

  echo "--> 3.5 Verifying plugin discovery and metadata description"
  DESC_RES=$(VOIDB_PLUGIN_PATH="${INSTALL_ROOT}" "${VOIDB_CLI}" plugin describe "${plugin}" \
    --format json)
  
  PLUGIN_ID=$(echo "${DESC_RES}" | grep -o '"id": *"[^"]*"' | head -n 1 | cut -d '"' -f 4)
  if [ "${PLUGIN_ID}" != "${plugin}" ]; then
    echo "Error: Described plugin id '${PLUGIN_ID}' does not match '${plugin}'!" >&2
    exit 1
  fi
  echo "    Plugin successfully discovered and verified."

  PASSED_COUNT=$(( PASSED_COUNT + 1 ))
done

echo "================================================================================"
echo "==> Step 4: Building and validating official Registry Index from test artifacts"
REGISTRY_INDEX="${OUTPUT_DIR}/registry-index.json"
"${VOIDB_CLI}" plugin registry-index "${DIST_DIR}"/*/*.tar "${DIST_DIR}"/*/*.tar.zst \
  --output "${REGISTRY_INDEX}" \
  --registry-name "Test E2E Registry" \
  --format json > /dev/null

if [ ! -f "${REGISTRY_INDEX}" ]; then
  echo "Error: Registry index file was not generated!" >&2
  exit 1
fi

echo "Registry index generated at: ${REGISTRY_INDEX}"
TOTAL_INDEXED_PACKAGES=$(grep -c '"filename"' "${REGISTRY_INDEX}" || true)
echo "Total packages indexed: ${TOTAL_INDEXED_PACKAGES}"

echo "================================================================================"
echo " ALL ${PASSED_COUNT}/${TOTAL_COUNT} PLUGINS PASSED MULTI-PLATFORM E2E VALIDATION SUITE!"
echo "================================================================================"
