#!/usr/bin/env python3
"""Aggregate VoidB Agent and TUI release evidence with actionable phase logs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Sequence


SCHEMA_VERSION = 1
PROFILE_ORDER = {"focused": 0, "deterministic": 1, "full": 2}


@dataclass(frozen=True)
class Phase:
    phase_id: str
    plugin: str
    journey: str
    command: tuple[str, ...]
    minimum_profile: str = "focused"
    scopes: tuple[str, ...] = ("journeys", "release")
    artifact_hints: tuple[str, ...] = ()
    correlation_kind: str = "call"


@dataclass
class PhaseResult:
    phase_id: str
    plugin: str
    journey: str
    command: list[str]
    status: str
    exit_code: int | None
    duration_ms: int
    log_path: str
    log_sha256: str
    redaction_count: int
    correlation_id: str
    call_id: str | None
    session_id: str | None
    artifact_hints: list[str] = field(default_factory=list)


def phases() -> list[Phase]:
    return [
        Phase(
            "capability-matrix",
            "all",
            "discovery",
            ("scripts/check-agent-capability-matrix.sh",),
            artifact_hints=("docs/agent-capability-matrix.md",),
        ),
        Phase(
            "invoke-controls",
            "all",
            "one-shot",
            (
                "cargo",
                "test",
                "-p",
                "voidb-cli",
                "builtin::invoke",
                "--quiet",
                "--",
                "--test-threads=1",
            ),
        ),
        Phase(
            "authorization-broker",
            "all",
            "authorization-and-credentials",
            (
                "cargo",
                "test",
                "-p",
                "voidb-cli",
                "agent_broker",
                "--quiet",
                "--",
                "--test-threads=1",
            ),
        ),
        Phase(
            "core-session-contract",
            "all",
            "session-start-status-wait-cancel-close",
            (
                "cargo",
                "test",
                "-p",
                "voidb-core",
                "live_session",
                "--quiet",
                "--",
                "--test-threads=1",
            ),
            correlation_kind="session",
        ),
        Phase(
            "external-agent-boundary",
            "all",
            "mutation-review",
            ("scripts/check-external-agent-interaction.sh",),
        ),
        Phase(
            "data-search-sessions",
            "redis,mongodb,elasticsearch",
            "stream-and-session-lifecycle",
            ("scripts/check-data-search-live-session-conformance.sh",),
            minimum_profile="deterministic",
            correlation_kind="session",
            artifact_hints=("target/tmp/data-search-live-session-fixtures",),
        ),
        Phase(
            "local-transfer-boundary",
            "ssh",
            "local-transfer-and-cancellation",
            ("scripts/check-local-filesystem-boundaries.sh",),
            minimum_profile="deterministic",
            correlation_kind="session",
        ),
        Phase(
            "sync-recovery",
            "sync",
            "recovery",
            ("scripts/release-sync-smoke.sh", "--client-only"),
            minimum_profile="deterministic",
            scopes=("journeys",),
            artifact_hints=("target/tmp/voidb-sync-hosted-smoke",),
        ),
        Phase(
            "tui-terminal-restoration-quick",
            "connections,ssh",
            "terminal-restoration",
            (
                "scripts/tui-quality-gate.sh",
                "--quick-journeys",
                "--out",
                "{output_dir}/tui-quality-quick",
            ),
            minimum_profile="deterministic",
            scopes=("journeys",),
            artifact_hints=("{output_dir}/tui-quality-quick",),
            correlation_kind="session",
        ),
        Phase(
            "core-focused",
            "core",
            "focused-regression",
            ("cargo", "test", "-p", "voidb-core", "--quiet"),
            minimum_profile="deterministic",
            scopes=("release",),
        ),
        Phase(
            "cli-focused",
            "cli",
            "focused-regression",
            ("cargo", "test", "-p", "voidb-cli", "--quiet"),
            minimum_profile="deterministic",
            scopes=("release",),
        ),
        Phase(
            "tui-focused",
            "connections",
            "focused-regression",
            ("cargo", "test", "-p", "voidb-tui", "--quiet"),
            minimum_profile="deterministic",
            scopes=("release",),
        ),
        Phase(
            "promoted-plugin-smoke",
            "ssh,mysql",
            "fixture-backed-capability-smoke",
            ("scripts/release-plugin-smoke.sh",),
            minimum_profile="deterministic",
            scopes=("release",),
        ),
        Phase(
            "sync-client-server-smoke",
            "sync",
            "recovery-and-server-boundary",
            ("scripts/release-sync-smoke.sh",),
            minimum_profile="deterministic",
            scopes=("release",),
            artifact_hints=("target/tmp/voidb-sync-hosted-smoke",),
        ),
        Phase(
            "tui-terminal-restoration",
            "connections,ssh",
            "terminal-restoration",
            (
                "scripts/tui-quality-gate.sh",
                "--out",
                "{output_dir}/tui-quality",
            ),
            minimum_profile="deterministic",
            scopes=("release",),
            artifact_hints=("{output_dir}/tui-quality",),
            correlation_kind="session",
        ),
        Phase(
            "workspace-tests",
            "workspace",
            "workspace-regression",
            ("cargo", "test", "--workspace", "--no-fail-fast"),
            minimum_profile="full",
            scopes=("release",),
        ),
        Phase(
            "workspace-clippy",
            "workspace",
            "lint",
            (
                "cargo",
                "clippy",
                "--workspace",
                "--all-targets",
                "--no-deps",
            ),
            minimum_profile="full",
            scopes=("release",),
        ),
        Phase(
            "diff-check",
            "repository",
            "source-integrity",
            ("/usr/bin/git", "diff", "--check"),
        ),
    ]


def live_fixture_phases() -> list[Phase]:
    return [
        Phase(
            "fixture-probe",
            "fixture-harness",
            "live-fixture-preflight",
            (
                "scripts/local-fixture-smoke.sh",
                "run",
                "--fixture",
                "probe",
                "--report",
                "{output_dir}/fixture-probe.md",
            ),
            minimum_profile="deterministic",
            scopes=("release",),
            artifact_hints=("{output_dir}/fixture-probe.md",),
        ),
        Phase(
            "data-search-live-fixtures",
            "redis,mongodb,elasticsearch",
            "live-stream-and-session",
            ("scripts/check-data-search-live-session-conformance.sh", "--live"),
            minimum_profile="deterministic",
            scopes=("release",),
            correlation_kind="session",
        ),
        *[
            Phase(
                f"{plugin}-live-fixture",
                plugin,
                "live-fixture",
                (
                    f"scripts/{plugin}-fixture-smoke.sh",
                    "--report",
                    f"{{output_dir}}/{plugin}-fixture.md",
                ),
                minimum_profile="deterministic",
                scopes=("release",),
                artifact_hints=(
                    f"{{output_dir}}/{plugin}-fixture.md",
                ),
            )
            for plugin in [
                "ssh",
                "mysql",
            ]
        ],
        Phase(
            "sync-hosted-fixture",
            "sync",
            "hosted-recovery",
            ("scripts/release-sync-smoke.sh", "--hosted"),
            minimum_profile="deterministic",
            scopes=("release",),
            artifact_hints=("target/tmp/voidb-sync-hosted-smoke",),
        ),
    ]


SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passphrase|token|secret|api[_-]?key|authorization)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
URL_CREDENTIALS = re.compile(r"(https?://)([^/@\s:]+):([^/@\s]+)@")
PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)
SECRET_MARKERS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----"),
]


def sanitize(text: str) -> tuple[str, int]:
    redactions = 0

    def replace_assignment(match: re.Match[str]) -> str:
        nonlocal redactions
        redactions += 1
        return f"{match.group(1)}{match.group(2)}<redacted>"

    def replace_url(match: re.Match[str]) -> str:
        nonlocal redactions
        redactions += 1
        return f"{match.group(1)}<redacted>@"

    private_matches = len(PRIVATE_KEY_BLOCK.findall(text))
    if private_matches:
        redactions += private_matches
        text = PRIVATE_KEY_BLOCK.sub("<redacted-private-key>", text)
    text = SENSITIVE_ASSIGNMENT.sub(replace_assignment, text)
    text = URL_CREDENTIALS.sub(replace_url, text)
    return text, redactions


def safe_environment(output_dir: pathlib.Path) -> dict[str, str]:
    environment = os.environ.copy()
    for key in list(environment):
        if re.search(
            r"(?i)(?:^|_)(?:password|passphrase|token|secret|api_key|access_key|private_key)(?:_|$)",
            key,
        ):
            environment.pop(key, None)
    isolated_config = output_dir / "config"
    isolated_config.mkdir(parents=True, exist_ok=True)
    environment["VOIDB_CONFIG_DIR"] = str(isolated_config.resolve())
    environment["XDG_CONFIG_HOME"] = str(isolated_config.resolve())
    environment["CARGO_TERM_COLOR"] = "never"
    environment.pop("VOIDB_MASTER_PASSWORD", None)
    return environment


def selected_phases(
    scope: str, profile: str, include_live_fixtures: bool
) -> list[Phase]:
    selected = [
        phase
        for phase in phases()
        if scope in phase.scopes
        and PROFILE_ORDER[phase.minimum_profile] <= PROFILE_ORDER[profile]
    ]
    if include_live_fixtures:
        live = [
            phase
            for phase in live_fixture_phases()
            if scope in phase.scopes
            and PROFILE_ORDER[phase.minimum_profile] <= PROFILE_ORDER[profile]
        ]
        diff_index = next(
            (
                index
                for index, phase in enumerate(selected)
                if phase.phase_id == "diff-check"
            ),
            len(selected),
        )
        selected[diff_index:diff_index] = live
    validate_plan(scope, profile, selected)
    return selected


def validate_plan(scope: str, profile: str, selected: Sequence[Phase]) -> None:
    phase_ids = [phase.phase_id for phase in selected]
    if len(phase_ids) != len(set(phase_ids)):
        raise ValueError("release gate phase IDs must be unique")
    if any("\n" in argument for phase in selected for argument in phase.command):
        raise ValueError("release gate commands must not contain embedded newlines")

    journeys = {phase.journey for phase in selected}
    required = {
        "discovery",
        "one-shot",
        "authorization-and-credentials",
        "session-start-status-wait-cancel-close",
        "mutation-review",
        "source-integrity",
    }
    if profile in {"deterministic", "full"}:
        required.update(
            {
                "stream-and-session-lifecycle",
                "context-handoff-and-mutation-review",
                "local-transfer-and-cancellation",
                "terminal-restoration",
            }
        )
        if scope == "journeys":
            required.add("recovery")
        else:
            required.add("recovery-and-server-boundary")
    if profile == "full" and scope == "release":
        required.update({"workspace-regression", "lint"})
    missing = required - journeys
    if missing:
        raise ValueError(
            f"release gate plan is missing required journey phases: {sorted(missing)}"
        )


def git_output(repo: pathlib.Path, *args: str) -> str:
    completed = subprocess.run(
        ["/usr/bin/git", *args],
        cwd=repo,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout.strip()


def display_path(path: pathlib.Path, repo: pathlib.Path) -> str:
    try:
        return str(path.relative_to(repo))
    except ValueError:
        return str(path)


def run_phase(
    phase: Phase,
    repo: pathlib.Path,
    output_dir: pathlib.Path,
    run_id: str,
    environment: dict[str, str],
) -> PhaseResult:
    log_path = output_dir / "logs" / f"{phase.phase_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    correlation_id = f"{run_id}:{phase.phase_id}"
    call_id = correlation_id if phase.correlation_kind == "call" else None
    session_id = correlation_id if phase.correlation_kind == "session" else None
    command = tuple(
        part.replace("{output_dir}", str(output_dir)) for part in phase.command
    )
    artifact_hints = [
        hint.replace("{output_dir}", str(output_dir)) for hint in phase.artifact_hints
    ]

    print(
        f"==> [{phase.plugin}] {phase.journey} ({correlation_id})\n"
        f"    {shlex.join(command)}",
        flush=True,
    )
    started = time.monotonic()
    redaction_count = 0
    exit_code: int | None = None
    status = "failed"
    digest = hashlib.sha256()

    with log_path.open("w", encoding="utf-8") as log:
        try:
            process = subprocess.Popen(
                list(command),
                cwd=repo,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
            )
        except OSError as error:
            message, count = sanitize(f"failed to start command: {error}\n")
            redaction_count += count
            log.write(message)
            digest.update(message.encode())
            exit_code = 127
            process = None
        if process is None:
            duration_ms = int((time.monotonic() - started) * 1000)
            return PhaseResult(
                phase_id=phase.phase_id,
                plugin=phase.plugin,
                journey=phase.journey,
                command=list(command),
                status="failed",
                exit_code=exit_code,
                duration_ms=duration_ms,
                log_path=display_path(log_path, repo),
                log_sha256=digest.hexdigest(),
                redaction_count=redaction_count,
                correlation_id=correlation_id,
                call_id=call_id,
                session_id=session_id,
                artifact_hints=artifact_hints,
            )
        assert process.stdout is not None
        try:
            for raw_line in process.stdout:
                line, count = sanitize(raw_line)
                redaction_count += count
                log.write(line)
                log.flush()
                digest.update(line.encode())
                print(line, end="")
            exit_code = process.wait()
            status = "passed" if exit_code == 0 else "failed"
        except KeyboardInterrupt:
            process.terminate()
            try:
                exit_code = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                exit_code = process.wait()
            status = "cancelled"
            raise

    duration_ms = int((time.monotonic() - started) * 1000)
    stored_text = log_path.read_text(encoding="utf-8", errors="replace")
    leaked_markers = [
        pattern.pattern for pattern in SECRET_MARKERS if pattern.search(stored_text)
    ]
    if leaked_markers:
        status = "failed"
        with log_path.open("a", encoding="utf-8") as log:
            message = (
                "\nrelease-gate secret scan failed for retained log markers: "
                + ", ".join(leaked_markers)
                + "\n"
            )
            log.write(message)
            digest.update(message.encode())

    return PhaseResult(
        phase_id=phase.phase_id,
        plugin=phase.plugin,
        journey=phase.journey,
        command=list(command),
        status=status,
        exit_code=exit_code,
        duration_ms=duration_ms,
        log_path=display_path(log_path, repo),
        log_sha256=digest.hexdigest(),
        redaction_count=redaction_count,
        correlation_id=correlation_id,
        call_id=call_id,
        session_id=session_id,
        artifact_hints=artifact_hints,
    )


def write_reports(
    output_dir: pathlib.Path,
    report: dict[str, object],
    results: Sequence[PhaseResult],
) -> None:
    report["phases"] = [asdict(result) for result in results]
    report["passed"] = all(result.status == "passed" for result in results)
    report["failed_phase_count"] = sum(
        result.status != "passed" for result in results
    )
    report["finished_at"] = datetime.now(timezone.utc).isoformat()

    json_path = output_dir / "report.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    lines = [
        "# Agent and TUI Release Gate",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Source commit: `{report['source_commit']}`",
        f"- Scope/profile: `{report['scope']}` / `{report['profile']}`",
        f"- Live fixtures: `{report['live_fixtures']}`",
        f"- Passed: `{report['passed']}`",
        "",
        "| Plugin | Journey phase | Correlation | Result | Duration (ms) | Log | Artifacts |",
        "|---|---|---|---:|---:|---|---|",
    ]
    for result in results:
        artifacts = "<br>".join(f"`{path}`" for path in result.artifact_hints) or "—"
        lines.append(
            f"| {result.plugin} | {result.journey} | `{result.correlation_id}` | "
            f"{result.status} | {result.duration_ms} | `{result.log_path}` | {artifacts} |"
        )
    lines.extend(
        [
            "",
            "Every retained log is sanitized before it is written. The JSON report records",
            "the exact safe command, exit code, call/session correlation ID, SHA-256,",
            "redaction count, and expected artifact location for each phase.",
        ]
    )
    (output_dir / "report.md").write_text("\n".join(lines) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run layered Agent/TUI journeys and release gates."
    )
    parser.add_argument(
        "--scope",
        choices=["journeys", "release"],
        default="release",
        help="Run only cross-plugin journeys or the aggregate release gate.",
    )
    parser.add_argument(
        "--profile",
        choices=list(PROFILE_ORDER),
        default="focused",
        help="focused is fast; deterministic adds fixtures/PTY journeys; full adds workspace test and Clippy.",
    )
    parser.add_argument(
        "--live-fixtures",
        action="store_true",
        help="Also provision disposable Docker-backed targets and hosted Sync evidence.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop after the first failed phase; the default retains evidence for all phases.",
    )
    parser.add_argument(
        "--out",
        type=pathlib.Path,
        help="Evidence directory. Defaults below target/tmp/agent-tui-release-gate/.",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Print the selected phase plan as JSON without running it.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = pathlib.Path(__file__).resolve().parents[1]
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
    output_dir = (
        args.out
        if args.out is not None
        else repo / "target" / "tmp" / "agent-tui-release-gate" / run_id
    )
    if not output_dir.is_absolute():
        output_dir = repo / output_dir
    selected = selected_phases(args.scope, args.profile, args.live_fixtures)

    if args.plan:
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "scope": args.scope,
                    "profile": args.profile,
                    "live_fixtures": args.live_fixtures,
                    "phases": [asdict(phase) for phase in selected],
                },
                indent=2,
            )
        )
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)
    source_commit = git_output(repo, "rev-parse", "HEAD")
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "voidb_agent_tui_release_gate",
        "run_id": run_id,
        "scope": args.scope,
        "profile": args.profile,
        "live_fixtures": "requested" if args.live_fixtures else "not_requested",
        "source_commit": source_commit,
        "source_dirty": bool(git_output(repo, "status", "--short")),
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    (output_dir / "plan.json").write_text(
        json.dumps([asdict(phase) for phase in selected], indent=2) + "\n"
    )

    environment = safe_environment(output_dir)
    results: list[PhaseResult] = []
    try:
        for phase in selected:
            result = run_phase(phase, repo, output_dir, run_id, environment)
            results.append(result)
            if result.status != "passed" and args.fail_fast:
                break
    except KeyboardInterrupt:
        print("Release gate interrupted; retaining partial evidence.", file=sys.stderr)
    finally:
        write_reports(output_dir, report, results)

    print(f"Evidence: {output_dir / 'report.md'}")
    failed = [result for result in results if result.status != "passed"]
    if failed or len(results) != len(selected):
        for result in failed:
            print(
                f"FAILED [{result.plugin}] {result.journey} "
                f"{result.correlation_id}: {result.log_path}",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
