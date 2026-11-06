#!/usr/bin/env bash
# MCP fixture smoke: drives the real `vb mcp serve` binary over stdio against
# a development fixture plugin in an isolated HOME state, proving the
# initialize handshake, the tools/list shape, a granted tool call, a
# policy-denied tool call, and secret hygiene of every emitted frame.
#
# Isolation: the whole run redirects $HOME into a temp directory, so profiles,
# credentials, config, and agent grants never touch the real user state.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN="${REPO_ROOT}/target/debug/vb"
SMOKE_PASSWORD="mcp-smoke-$$-secret"

if [[ ! -x "${BIN}" ]]; then
  echo "building vb (debug)..."
  (cd "${REPO_ROOT}" && cargo build -q -p voidb-cli)
fi

TMP="$(mktemp -d)"
cleanup() {
  if [[ "${MCP_SMOKE_KEEP:-0}" == "1" ]]; then
    echo "smoke state kept at ${TMP}"
    return
  fi
  rm -rf "${TMP}"
}
trap cleanup EXIT INT TERM

export HOME="${TMP}/home"
export VOIDB_PLUGIN_PATH="${TMP}/plugins"
export VOIDB_ALLOW_UNSIGNED_PLUGINS=1
export VOIDB_MASTER_PASSWORD="${SMOKE_PASSWORD}"
mkdir -p "${HOME}" "${VOIDB_PLUGIN_PATH}/fixture/bin" "${VOIDB_PLUGIN_PATH}/fixture/schemas"

echo "== stage the fixture plugin =="
cat > "${VOIDB_PLUGIN_PATH}/fixture/schemas/profile.schema.json" <<'EOF'
{"type":"object"}
EOF
cat > "${VOIDB_PLUGIN_PATH}/fixture/schemas/io.schema.json" <<'EOF'
{"type":"object"}
EOF
cat > "${VOIDB_PLUGIN_PATH}/fixture/bin/fixture-runtime" <<'EOF'
#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *voidb.initialize*)
      echo '{"jsonrpc":"2.0","id":"initialize","result":{"plugin_id":"fixture","protocol_version":"1.1","status":"ready"}}'
      ;;
    *voidb.health*)
      echo '{"jsonrpc":"2.0","id":"health","result":{"status":"ready","active_invocations":0}}'
      ;;
    *voidb.invoke*)
      inv_id=$(printf '%s' "$line" | sed -n 's/.*"id":"\(invoke-[^"]*\)".*/\1/p')
      echo "{\"jsonrpc\":\"2.0\",\"id\":\"invoke\",\"result\":{\"invocation_id\":\"$inv_id\",\"status\":\"succeeded\",\"output\":{\"echo\":true},\"output_summary\":{\"echo\":true}}}"
      ;;
  esac
done
EOF
chmod +x "${VOIDB_PLUGIN_PATH}/fixture/bin/fixture-runtime"
cat > "${VOIDB_PLUGIN_PATH}/fixture/plugin.toml" <<'EOF'
id = "fixture"
name = "MCP Smoke Fixture"
version = "0.1.0"
protocol_version = "1"

[runtime]
command = "fixture-runtime"
args = []
transport = "stdio-jsonrpc"

[connections]
profile_schema = "schemas/profile.schema.json"
secret_classes = []

[[capabilities]]
id = "echo"
description = "Echo a value back."
input_schema = "schemas/io.schema.json"
output_schema = "schemas/io.schema.json"
permissions = ["fixture.echo"]
destructive = false
streaming = false
connection_required = true
required_secret_classes = []
supports_dry_run = false
default_timeout_ms = 2000

[[capabilities]]
id = "mutate"
description = "A destructive operation used to prove the denial path."
input_schema = "schemas/io.schema.json"
output_schema = "schemas/io.schema.json"
permissions = ["fixture.mutate"]
destructive = true
streaming = false
connection_required = false
required_secret_classes = []
supports_dry_run = false
default_timeout_ms = 2000
EOF

echo "== stage a legacy connection and migrate it into a native profile =="
mkdir -p "${HOME}/Library/Application Support/voidb"
cat > "${HOME}/Library/Application Support/voidb/config.toml" <<'EOF'
[[connections]]
name = "fixture-local"
db_type = "Plugin"
plugin_id = "fixture"

[connections.plugin_config]
host = "fixture.internal"
EOF
"${BIN}" profile migrate apply >/dev/null

echo "== protect the isolated config with the smoke password =="
"${BIN}" credential master reencrypt --new-password-env VOIDB_MASTER_PASSWORD --yes >/dev/null


echo "== authorize the echo capability (read-only, 5m) =="
DIAG="${TMPDIR:-/tmp}/mcp-smoke-diag"
mkdir -p "${DIAG}"
if ! "${BIN}" agent authorize \
  --profile fixture-local \
  --plugin fixture \
  --capability fixture.echo \
  --ttl-minutes 5 \
  --yes > "${DIAG}/auth.out" 2> "${DIAG}/auth.err"; then
  echo "authorize FAILED (exit $?); diag kept at ${DIAG}"
  cat "${DIAG}/auth.err" | head -5
  head -5 "${DIAG}/auth.out"
  ls -la "${HOME}/Library/Application Support/voidb/" >&2
  exit 1
fi

echo "== drive vb mcp serve over stdio =="
FRAMES_FILE="${TMP}/frames"
{
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"voidb-smoke","version":"0.0.1"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
  printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fixture.echo","arguments":{"ping":1,"voidb_profile":"fixture-local"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fixture.mutate","arguments":{"voidb_profile":"fixture-local"}}}'
} > "${FRAMES_FILE}"

OUT_FILE="${TMP}/mcp-out"
"${BIN}" mcp serve --quiet < "${FRAMES_FILE}" > "${OUT_FILE}"

echo "== assertions =="
assert_contains() {
  grep -q "$1" "${OUT_FILE}" || { echo "FAIL: expected frame to contain: $1"; exit 1; }
}

assert_contains '"protocolVersion":"2025-06-18"'
assert_contains '"serverInfo"'
assert_contains '"name":"fixture.echo"'
assert_contains '"name":"fixture.mutate"'
assert_contains '"readOnlyHint":true'
assert_contains '"destructiveHint":true'

python3 - "${OUT_FILE}" <<'EOF'
import json, sys

frames = {}
for line in open(sys.argv[1]):
    message = json.loads(line)
    frames[message.get("id")] = message

granted = frames[3]["result"]
assert granted["isError"] is False, granted
assert granted["structuredContent"]["output"] == {"echo": True}, granted

denied = frames[4]["result"]
assert denied["isError"] is True, denied
error = denied["structuredContent"]["error"]
# fixture.mutate is outside the grant scope, so the call is refused with the
# stable grant-required execution error instead of reaching the broker.
assert error["code"] == "authorization.grant_required", error
assert "fixture.mutate" in error["message"], error
print("frame assertions ok")
EOF

if grep -q "${SMOKE_PASSWORD}" "${OUT_FILE}"; then
  echo "FAIL: MCP output exposed credential material"
  exit 1
fi

echo "mcp fixture smoke passed"
