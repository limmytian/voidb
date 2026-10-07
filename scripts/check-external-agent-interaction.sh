#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

failures=0

fail() {
  printf 'external-agent interaction check failed: %s\n' "$1" >&2
  failures=$((failures + 1))
}

capability_only_plugins=(
  mysql
  postgres
  sqlite
  duckdb
  mongodb
  redis
  elasticsearch
)

for plugin in "${capability_only_plugins[@]}"; do
  source_dir="crates/plugins/voidb-plugin-${plugin}/src"
  if [[ -e "${source_dir}/assist.rs" ]]; then
    fail "${plugin} still has an assist module"
  fi
  if matches=$(rg -n -i \
    'assist|ask[ _-]agent|question[ _-](entry|editor|prompt)|poll[ _-]response|session[ _-]share|context[ _-]share|FrontendAssist|AssistBroker|AgentContextShare' \
    "$source_dir"); then
    printf '%s\n' "$matches" >&2
    fail "${plugin} exposes a conversation or session-share surface"
  fi
done

if matches=$(rg -n -i \
  'ask[ _-]agent|submit[ _-]question|poll[ _-]response|diagnosis[ _-]chat|assist response|question[ _-](entry|editor|prompt)' \
  crates); then
  printf '%s\n' "$matches" >&2
  fail "runtime source still contains a removed conversation workflow"
fi

active_docs=(
  docs/README.md
  docs/architecture.md
  docs/plugin-development-guide.md
  docs/ssh-plugin.md
  docs/storage-tui-launch-and-rollback.md
  docs/email-tui.md
  docs/live-operations-tui-safety.md
  docs/ssh-release-readiness.md
  docs/release-candidate-checklist.md
  docs/readiness.md
  docs/agent-capability-matrix.md
  docs/agent-tui-release-gate.md
)

if matches=$(rg -n -i \
  'ask[ _-]agent|submit[ _-]question|poll[ _-]response|diagnosis[ _-]chat|^#{1,6} .*assist handoff' \
  "${active_docs[@]}"); then
  printf '%s\n' "$matches" >&2
  fail "active documentation still presents the retired workflow"
fi

historical_evidence=(
  docs/non-pty-assist-handoff-evidence-2026-07-12.md
  docs/infra-assist-handoff-evidence-2026-07-12.md
  docs/data-assist-handoff-evidence-2026-07-12.md
  docs/storage-messaging-assist-handoff-evidence-2026-07-12.md
  docs/ssh-assist-handoff-evidence-2026-07-12.md
)

for document in "${historical_evidence[@]}"; do
  [[ -f "$document" ]] || continue
  if ! head -n 12 "$document" | rg -q 'Superseded by Requirement 93'; then
    fail "${document} is not marked as superseded history"
  fi
done

ssh_source='crates/plugins/voidb-plugin-ssh/src/tui.rs'
rg -Fq '"external_agent_interaction"' "$ssh_source" \
  || fail 'SSH lacks external-agent session-share evidence'
rg -Fq '.title("Agent Operation Request")' "$ssh_source" \
  || fail 'SSH operation review is not named externally first'
rg -Fq '"conversation_surface": false' "$ssh_source" \
  || fail 'SSH does not assert that conversation stays outside the TUI'
rg -Fq '"revoke_escape": "Ctrl+] then v"' "$ssh_source" \
  || fail 'SSH evidence lacks the immediate current-PTY revoke path'

contract='docs/assist-handoff.md'
for marker in \
  '| SSH | Shared live PTY view' \
  '| Docker | Capabilities;' \
  '| Kubernetes | Capabilities;' \
  '| Jenkins | Capabilities;' \
  '| MySQL, PostgreSQL, SQLite, DuckDB | Capability discovery/invocation' \
  '| S3, WebDAV | Capability discovery/invocation' \
  '| Email | Capability discovery/invocation' \
  '| Shell | Routing only'; do
  rg -Fq "$marker" "$contract" || fail "interaction matrix is missing ${marker}"
done

if ((failures > 0)); then
  exit 1
fi

"$ROOT/scripts/check-local-filesystem-boundaries.sh"

printf 'external-agent interaction checks passed\n'
