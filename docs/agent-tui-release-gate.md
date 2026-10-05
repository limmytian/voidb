# Agent and TUI Aggregate Release Gate

The aggregate gate provides one evidence-producing command for the current
Agent capability, authorization, credential, session, cancellation, streaming,
transfer, Sync recovery, fixture, and real-PTY boundaries.

## Profiles

```bash
# Fast feedback while editing capability/release metadata
python3 scripts/agent_tui_release_gate.py --profile focused

# Deterministic release evidence, including cross-plugin sessions and real PTYs
python3 scripts/agent_tui_release_gate.py --profile deterministic

# Final requirement/release gate: deterministic phases plus workspace test and Clippy
python3 scripts/agent_tui_release_gate.py --profile full
```

`focused` preserves the existing fast loop: generated-matrix drift, generic
invoke controls, authorization/credential broker tests, Core session contracts,
the external-agent boundary assertion, and `git diff --check`.

`deterministic` adds Redis/MongoDB/Elasticsearch and
Docker/Kubernetes/Jenkins live-session conformance, cross-process context
handoff and mutation review, local-transfer boundaries, promoted-plugin smoke,
Sync client/server recovery, focused Core/CLI/TUI suites, and the eight-surface
real-PTY TUI quality gate.

`full` adds:

```bash
cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets --no-deps
```

The full profile is intentionally slow. Run it once at a requirement or release
boundary after focused implementation work is complete.

## Cross-Plugin Journeys

To run only the representative end-to-end Agent journeys:

```bash
python3 scripts/agent_tui_release_gate.py \
  --scope journeys \
  --profile deterministic
```

The journey profile covers:

| Journey | Representative plugins | Evidence |
|---|---|---|
| Discovery and one-shot controls | All built-ins | Generated matrix plus generic invoke tests. |
| Authorization and credentials | All centrally authorized built-ins | Grant, JIT, expiry, acknowledgement, and redaction tests. |
| Session start/status/wait/cancel/close | SQL, Redis, MongoDB, Elasticsearch, Docker, Kubernetes, Jenkins, Email, SSH, S3, WebDAV | Core/CLI session contracts and plugin conformance suites. |
| Context handoff and mutation review | Docker, Kubernetes, Jenkins | Separate-process real-PTY allow, deny, timeout, replay, multi-action rejection, and crash recovery. |
| Local transfer | SSH, S3, WebDAV, Email | Allowed-root, traversal, conflict, resume, cancellation, audit, and redaction boundaries. |
| Recovery | Sync | Client-only E2E encryption, conflict, tamper, wrong-key, and recovery paths. |
| Terminal restoration | Connection Manager plus seven retained plugin TUIs | Fixture-backed startup, navigation, resize, cancellation, quit, cleanup, and secret scan. |

## Live Fixtures

Deterministic profiles do not silently claim provider or platform evidence.
When a usable local Docker daemon is available, add:

```bash
python3 scripts/agent_tui_release_gate.py \
  --profile full \
  --live-fixtures
```

This adds the shared fixture probe, Redis/MongoDB/Elasticsearch live sessions,
Email, SSH, S3, WebDAV, MySQL, Kubernetes, and Jenkins disposable targets, and
hosted Sync recovery. The report records `not_requested` when this option is
omitted.

## Evidence And Failure Triage

Each run writes below:

```text
target/tmp/agent-tui-release-gate/<run-id>/
├── plan.json
├── report.json
├── report.md
├── config/
└── logs/
    └── <phase>.log
```

Every phase has a plugin group, journey name, safe command, exit code, elapsed
time, call/session correlation ID, log SHA-256, redaction count, and retained
artifact hints. The runner strips secret-bearing environment variables and
sanitizes captured output before writing it. It continues after failures by
default so the report identifies every failing plugin and phase; pass
`--fail-fast` for local iteration.

Inspect a plan without running commands:

```bash
python3 scripts/agent_tui_release_gate.py --profile full --plan
```
