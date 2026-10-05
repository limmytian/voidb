#!/usr/bin/env bash
set -euo pipefail

PLUGIN="all"
REPORT_PATH=""
STRICT=0
REDACT_OUTPUT=0

ALL_PLUGINS=(email redis kubernetes mongodb elasticsearch jenkins)

usage() {
  cat <<'EOF'
Usage: scripts/live-fixture-smoke.sh [--plugin all|email|redis|kubernetes|mongodb|elasticsearch|jenkins] [options]

Plans fixture-backed live smoke without touching external services by default.
Missing fixture variables are reported as skipped unless --strict is set.

Options:
  --plugin <name>    Limit the fixture plan or redaction scope. Default: all.
  --report <path>    Write a Markdown fixture readiness report.
  --strict           Exit non-zero when any selected fixture is not ready.
  --redact-output    Read stdin and redact selected fixture secret values.
  -h, --help         Show this help.

This harness prints variable names and readiness state, never variable values.
See docs/live-fixture-smoke-harness.md for the shared fixture policy.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plugin)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --plugin" >&2
        exit 2
      fi
      PLUGIN="$2"
      shift 2
      ;;
    --report)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --report" >&2
        exit 2
      fi
      REPORT_PATH="$2"
      shift 2
      ;;
    --strict)
      STRICT=1
      shift
      ;;
    --redact-output)
      REDACT_OUTPUT=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

is_supported_plugin() {
  local candidate="$1"
  [[ "${candidate}" == "all" ]] && return 0
  local plugin
  for plugin in "${ALL_PLUGINS[@]}"; do
    [[ "${plugin}" == "${candidate}" ]] && return 0
  done
  return 1
}

if ! is_supported_plugin "${PLUGIN}"; then
  echo "unsupported plugin: ${PLUGIN}" >&2
  usage >&2
  exit 2
fi

selected_plugins() {
  if [[ "${PLUGIN}" == "all" ]]; then
    printf '%s\n' "${ALL_PLUGINS[@]}"
  else
    printf '%s\n' "${PLUGIN}"
  fi
}

plugin_title() {
  case "$1" in
    email) echo "Email" ;;
    redis) echo "Redis" ;;
    kubernetes) echo "Kubernetes" ;;
    mongodb) echo "MongoDB" ;;
    elasticsearch) echo "Elasticsearch" ;;
    jenkins) echo "Jenkins" ;;
  esac
}

plugin_scope() {
  case "$1" in
    email) echo "disposable mailbox" ;;
    redis) echo "throwaway database or key prefix" ;;
    kubernetes) echo "scratch namespace in a non-production cluster" ;;
    mongodb) echo "disposable database and collection" ;;
    elasticsearch) echo "disposable index and document set" ;;
    jenkins) echo "disposable folder, job, build, and queue path" ;;
  esac
}

required_envs() {
  case "$1" in
    email) echo "VOIDB_EMAIL_SMOKE_CONNECTION VOIDB_EMAIL_SMOKE_FOLDER" ;;
    redis) echo "VOIDB_REDIS_SMOKE_PROFILE VOIDB_REDIS_SMOKE_KEY_PREFIX" ;;
    kubernetes) echo "VOIDB_K8S_SMOKE_PROFILE VOIDB_K8S_SMOKE_NAMESPACE" ;;
    mongodb) echo "VOIDB_MONGODB_SMOKE_PROFILE VOIDB_MONGODB_SMOKE_DB VOIDB_MONGODB_SMOKE_COLLECTION" ;;
    elasticsearch) echo "VOIDB_ES_SMOKE_PROFILE VOIDB_ES_SMOKE_INDEX" ;;
    jenkins) echo "VOIDB_JENKINS_SMOKE_PROFILE VOIDB_JENKINS_SMOKE_JOB VOIDB_JENKINS_SMOKE_BUILD" ;;
  esac
}

optional_envs() {
  case "$1" in
    email) echo "VOIDB_EMAIL_SMOKE_UID VOIDB_EMAIL_SMOKE_SMTP_CONNECTION VOIDB_EMAIL_SMOKE_SEND_TO" ;;
    redis) echo "VOIDB_REDIS_SMOKE_DB VOIDB_REDIS_SMOKE_TTL_SECONDS" ;;
    kubernetes) echo "VOIDB_K8S_SMOKE_CONTEXT VOIDB_K8S_SMOKE_CONFIGMAP" ;;
    mongodb) echo "VOIDB_MONGODB_SMOKE_DOCUMENT_ID" ;;
    elasticsearch) echo "VOIDB_ES_SMOKE_DOCUMENT_ID" ;;
    jenkins) echo "VOIDB_JENKINS_SMOKE_FOLDER VOIDB_JENKINS_SMOKE_QUEUE_ID" ;;
  esac
}

var_state() {
  local name="$1"
  if [[ -n "${!name:-}" ]]; then
    echo "set"
  else
    echo "missing"
  fi
}

missing_required_text() {
  local plugin="$1"
  local missing=()
  local var
  for var in $(required_envs "${plugin}"); do
    if [[ -z "${!var:-}" ]]; then
      missing+=("${var}")
    fi
  done

  if [[ "${#missing[@]}" -eq 0 ]]; then
    echo "None"
  else
    join_by_comma "${missing[@]}"
  fi
}

join_by_comma() {
  local first=1
  local item
  for item in "$@"; do
    if [[ "${first}" -eq 1 ]]; then
      printf '%s' "${item}"
      first=0
    else
      printf ', %s' "${item}"
    fi
  done
}

print_plan() {
  local failed=0
  local plugin
  for plugin in $(selected_plugins); do
    local missing_text
    missing_text="$(missing_required_text "${plugin}")"

    echo "==> $(plugin_title "${plugin}")"
    echo "scope: $(plugin_scope "${plugin}")"
    if [[ "${missing_text}" == "None" ]]; then
      echo "status: ready"
    else
      echo "status: skipped"
      echo "reason: missing required fixture vars: ${missing_text}"
      failed=1
    fi

    local var
    printf 'required:'
    for var in $(required_envs "${plugin}"); do
      printf ' %s=%s' "${var}" "$(var_state "${var}")"
    done
    printf '\n'

    printf 'optional:'
    for var in $(optional_envs "${plugin}"); do
      printf ' %s=%s' "${var}" "$(var_state "${var}")"
    done
    printf '\n'
    echo "redaction: variable values withheld; pipe command logs through --redact-output before recording"
    echo
  done

  return "${failed}"
}

write_report() {
  local path="$1"
  mkdir -p "$(dirname "${path}")"
  {
    echo "# Live Fixture Smoke Readiness"
    echo
    echo "Generated by \`scripts/live-fixture-smoke.sh\` from fixture variable presence only."
    echo "No external service was contacted and no variable values are recorded."
    echo
    echo "| Plugin | Status | Missing required fixture variables | Fixture scope |"
    echo "|---|---|---|---|"

    local plugin
    for plugin in $(selected_plugins); do
      local missing_text
      missing_text="$(missing_required_text "${plugin}")"
      local status="ready"
      if [[ "${missing_text}" != "None" ]]; then
        status="skipped"
      fi
      printf '| %s | %s | %s | %s |\n' \
        "$(plugin_title "${plugin}")" \
        "${status}" \
        "${missing_text}" \
        "$(plugin_scope "${plugin}")"
    done

    echo
    echo "## Recording Rules"
    echo
    echo "- A skipped fixture is an availability decision, not a regression."
    echo "- Reports may include command names, capability IDs, bounded counts, dry-run flags, cleanup steps, and pass/fail status."
    echo "- Reports must not include passwords, tokens, cookies, authorization headers, connection URLs, raw profile JSON, or unredacted target stderr."
    echo "- Mutation checks require disposable resources plus explicit dry-run or acknowledgement gates."
  } > "${path}"
}

redact_output() {
  local line
  while IFS= read -r line; do
    local plugin var value
    for plugin in $(selected_plugins); do
      for var in $(required_envs "${plugin}") $(optional_envs "${plugin}"); do
        value="${!var:-}"
        if [[ -n "${value}" && "${var}" =~ (PASSWORD|TOKEN|SECRET|KEY|URL|URI|CONNECTION_STRING|AUTH|COOKIE) ]]; then
          line="${line//${value}/<redacted:${var}>}"
        fi
      done
    done
    printf '%s\n' "${line}"
  done
}

if [[ "${REDACT_OUTPUT}" -eq 1 ]]; then
  redact_output
  exit 0
fi

set +e
PLAN_OUTPUT="$(print_plan)"
PLAN_STATUS=$?
set -e

printf '%s\n' "${PLAN_OUTPUT}"

if [[ -n "${REPORT_PATH}" ]]; then
  write_report "${REPORT_PATH}"
  echo "wrote report: ${REPORT_PATH}"
fi

if [[ "${STRICT}" -eq 1 && "${PLAN_STATUS}" -ne 0 ]]; then
  exit 1
fi

exit 0
