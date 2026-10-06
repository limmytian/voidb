#!/usr/bin/env python3
"""Exercise the external context protocol against real fixture-backed TUIs.

The harness uses one scenario matrix for Docker, Kubernetes, and Jenkins. Each
TUI runs in a real pseudo-terminal while a separate voidb-cli process discovers
the share and drives the JSON protocol.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import json
import os
import pathlib
import pty
import select
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any

from tui_journey import OutputCapture, render_terminal, set_window_size


CLIENT_ID = "voidb-context-conformance"
SCENARIOS = (
    "allow",
    "deny",
    "timeout",
    "replay",
    "multi_action",
    "crash_recovery",
)
FORBIDDEN_MARKERS = (
    b"super-secret-password",
    b"PRIVATE KEY",
    b"token_value",
    b"crumb_value",
    b"/fixture/host/path/voidb-fixture-data",
)


class ConformanceError(RuntimeError):
    """Raised when a protocol or TUI assertion fails."""


@dataclass(frozen=True)
class PluginCase:
    plugin_id: str
    fixture: str
    first_frame_marker: str
    deny_key: bytes
    context_env: str
    operation: dict[str, Any]


PLUGIN_CASES = (
    PluginCase(
        plugin_id="docker",
        fixture="crates/plugins/voidb-plugin-docker/fixtures/docker_tui_operations.json",
        first_frame_marker="Docker Operations",
        deny_key=b"n",
        context_env="VOIDB_DOCKER_AGENT_CONTEXT_DIR",
        operation={
            "kind": "capability_call",
            "capability_id": "docker.container_action",
            "input_summary": {
                "action": "stop",
                "target_id": "a1b2c3d4e5f6",
                "target_label": "api",
            },
            "rationale": "Exercise the existing Docker review plan.",
            "risk": "destructive",
            "target": {
                "kind": "capability",
                "capability_id": "docker.container_action",
            },
        },
    ),
    PluginCase(
        plugin_id="kubernetes",
        fixture="crates/plugins/voidb-plugin-kubernetes/fixtures/kubernetes_tui_operations.json",
        first_frame_marker="Kubernetes Operations",
        deny_key=b"d",
        context_env="VOIDB_KUBERNETES_AGENT_CONTEXT_DIR",
        operation={
            "kind": "capability_call",
            "capability_id": "kubernetes.restart",
            "input_summary": {
                "action": "restart",
                "resource_type": "deployment",
                "namespace": "default",
                "target_name": "api",
            },
            "rationale": "Exercise the existing Kubernetes review plan.",
            "risk": "review",
            "target": {
                "kind": "capability",
                "capability_id": "kubernetes.restart",
            },
        },
    ),
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ConformanceError(message)


class TuiProcess:
    def __init__(
        self,
        command: list[str],
        cwd: pathlib.Path,
        env: dict[str, str],
    ) -> None:
        self.command = command
        self.cwd = cwd
        self.env = env
        self.started_at = time.monotonic()
        self.capture = OutputCapture(self.started_at)
        self.master_fd: int | None = None
        self.process: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        master_fd, slave_fd = pty.openpty()
        self.master_fd = master_fd
        set_window_size(slave_fd, 30, 118)
        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        try:
            self.process = subprocess.Popen(
                self.command,
                cwd=self.cwd,
                env=self.env,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                start_new_session=True,
            )
        finally:
            os.close(slave_fd)

    def send(self, data: bytes) -> None:
        require(self.master_fd is not None, "TUI PTY is closed")
        os.write(self.master_fd, data)

    def wait_for(self, marker: str, timeout_seconds: float) -> float:
        started = time.monotonic()
        deadline = started + timeout_seconds
        while time.monotonic() < deadline:
            screen = render_terminal(bytes(self.capture.raw))
            if marker in screen:
                return round((time.monotonic() - started) * 1000, 3)
            if self.process is not None and self.process.poll() is not None:
                break
            self._read(min(0.05, max(0.0, deadline - time.monotonic())))
        screen = render_terminal(bytes(self.capture.raw))
        raise ConformanceError(
            f"TUI did not render {marker!r}; exit={self.returncode}; screen={screen[-1500:]!r}"
        )

    def graceful_exit(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.send(b"q")
            self._wait_for_exit(2.0)
        if self.process.poll() is None:
            self._kill(signal.SIGTERM)
            self._wait_for_exit(1.0)
        if self.process.poll() is None:
            self._kill(signal.SIGKILL)
            self._wait_for_exit(1.0)
        self._drain()
        require(self.process.poll() == 0, f"TUI exited with {self.process.poll()}")
        raw = bytes(self.capture.raw)
        if b"\x1b[?1049h" in raw:
            require(b"\x1b[?1049l" in raw, "TUI did not restore the alternate screen")
        if b"\x1b[?25l" in raw:
            require(b"\x1b[?25h" in raw, "TUI did not restore the cursor")
        self.close()

    def crash(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self._kill(signal.SIGKILL)
            self._wait_for_exit(2.0)
        self._drain()
        require(self.process is not None, "TUI process was not started")
        require(self.process.poll() == -signal.SIGKILL, "TUI crash signal was not observed")
        self.close()

    def close(self) -> None:
        if self.master_fd is not None:
            os.close(self.master_fd)
            self.master_fd = None

    @property
    def returncode(self) -> int | None:
        return None if self.process is None else self.process.poll()

    def _kill(self, sig: signal.Signals) -> None:
        if self.process is None:
            return
        try:
            os.killpg(self.process.pid, sig)
        except ProcessLookupError:
            pass

    def _wait_for_exit(self, timeout_seconds: float) -> None:
        require(self.process is not None, "TUI process was not started")
        deadline = time.monotonic() + timeout_seconds
        while self.process.poll() is None and time.monotonic() < deadline:
            self._read(0.05)
        if self.process.poll() is not None:
            self.process.wait(timeout=1)

    def _read(self, timeout_seconds: float) -> None:
        if self.master_fd is None:
            return
        readable, _, _ = select.select([self.master_fd], [], [], timeout_seconds)
        if not readable:
            return
        try:
            chunk = os.read(self.master_fd, 65_536)
        except BlockingIOError:
            return
        except OSError as error:
            if error.errno == errno.EIO:
                return
            raise
        if chunk:
            self.capture.append(chunk)

    def _drain(self) -> None:
        deadline = time.monotonic() + 0.2
        while time.monotonic() < deadline:
            before = len(self.capture.raw)
            self._read(0.01)
            if len(self.capture.raw) == before:
                break


class ProtocolClient:
    def __init__(
        self,
        cli: pathlib.Path,
        cwd: pathlib.Path,
        env: dict[str, str],
        case: PluginCase,
        task_id: str,
    ) -> None:
        self.cli = cli
        self.cwd = cwd
        self.env = env
        self.case = case
        self.task_id = task_id

    def list(self) -> dict[str, Any]:
        return self._run(
            [
                "context",
                "list",
                *self._principal_args(),
                "--plugin",
                self.case.plugin_id,
            ]
        )

    def show(self, context: dict[str, Any], expected_exit: int = 0) -> dict[str, Any]:
        return self._run(
            ["context", "show", *self._reference_args(context)],
            expected_exit=expected_exit,
        )

    def operation(
        self,
        context: dict[str, Any],
        operation_request_id: str,
        summary: str,
        operations: list[dict[str, Any]],
        expected_exit: int = 0,
    ) -> dict[str, Any]:
        return self._run(
            [
                "context",
                "operation",
                *self._reference_flags(context),
                "--operation-request-id",
                operation_request_id,
                "--summary",
                summary,
                "--operations-json",
                json.dumps(operations, separators=(",", ":")),
                context["context_id"],
            ],
            expected_exit=expected_exit,
        )

    def deny(
        self,
        context: dict[str, Any],
        operation_request_id: str,
        reason: str,
        expected_exit: int = 0,
    ) -> dict[str, Any]:
        return self._run(
            [
                "context",
                "deny",
                *self._reference_flags(context),
                "--operation-request-id",
                operation_request_id,
                "--operation-index",
                "0",
                "--reason",
                reason,
                context["context_id"],
            ],
            expected_exit=expected_exit,
        )

    def status(self, context: dict[str, Any]) -> dict[str, Any]:
        return self._run(["context", "status", *self._reference_args(context)])

    def wait(
        self,
        context: dict[str, Any],
        timeout_ms: int,
        expected_exit: int = 0,
    ) -> dict[str, Any]:
        return self._run(
            [
                "context",
                "wait",
                *self._reference_flags(context),
                "--timeout-ms",
                str(timeout_ms),
                "--poll-interval-ms",
                "10",
                context["context_id"],
            ],
            expected_exit=expected_exit,
        )

    def active_context(self, timeout_seconds: float = 2.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        last_contexts: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            envelope = self.list()
            last_contexts = envelope["data"]["contexts"]
            active = [
                item
                for item in last_contexts
                if item["context"]["plugin_id"] == self.case.plugin_id
                and item["availability"] == "active"
            ]
            if active:
                active.sort(key=lambda item: item["updated_at"], reverse=True)
                return active[0]["context"]
            time.sleep(0.02)
        raise ConformanceError(f"no active context discovered: {last_contexts}")

    def wait_for_availability(
        self,
        context_id: str,
        availability: str,
        timeout_seconds: float = 2.0,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        last_contexts: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            last_contexts = self.list()["data"]["contexts"]
            for item in last_contexts:
                if (
                    item["context"]["context_id"] == context_id
                    and item["availability"] == availability
                ):
                    return item
            time.sleep(0.02)
        raise ConformanceError(
            f"context {context_id} did not become {availability}: {last_contexts}"
        )

    def _principal_args(self) -> list[str]:
        return ["--client-id", CLIENT_ID, "--task-id", self.task_id]

    def _reference_flags(self, context: dict[str, Any]) -> list[str]:
        return [
            *self._principal_args(),
            "--plugin",
            self.case.plugin_id,
            "--generation",
            str(context["generation"]),
        ]

    def _reference_args(self, context: dict[str, Any]) -> list[str]:
        return [*self._reference_flags(context), context["context_id"]]

    def _run(self, args: list[str], expected_exit: int = 0) -> dict[str, Any]:
        command = [str(self.cli), *args]
        completed = subprocess.run(
            command,
            cwd=self.cwd,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        try:
            envelope = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise ConformanceError(
                f"invalid JSON from {' '.join(args[:2])}: "
                f"exit={completed.returncode} stdout={completed.stdout!r} "
                f"stderr={completed.stderr!r}"
            ) from error
        require(
            completed.returncode == expected_exit,
            f"{' '.join(args[:2])} exit {completed.returncode}, expected {expected_exit}; "
            f"envelope={envelope} stderr={completed.stderr!r}",
        )
        require(
            envelope.get("protocol_version") == 1,
            f"unexpected protocol envelope: {envelope}",
        )
        require(
            envelope.get("ok") is (expected_exit == 0),
            f"envelope success does not match exit status: {envelope}",
        )
        if expected_exit:
            require(
                envelope.get("error", {}).get("exit_code") == expected_exit,
                f"error exit projection does not match process exit: {envelope}",
            )
        return envelope


def isolated_env(case: PluginCase, runtime: pathlib.Path) -> dict[str, str]:
    home = runtime / "home"
    config = home / ".config"
    context_store = runtime / "agent-context"
    config.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(config),
            "TERM": "xterm-256color",
            case.context_env: str(context_store),
        }
    )
    env.pop("VOIDB_MASTER_PASSWORD", None)
    return env


def launch_shared_context(
    cli: pathlib.Path,
    repo: pathlib.Path,
    case: PluginCase,
    runtime: pathlib.Path,
    task_id: str,
) -> tuple[TuiProcess, ProtocolClient, dict[str, Any]]:
    env = isolated_env(case, runtime)
    app = TuiProcess(
        [str(cli), case.plugin_id, "tui", "--fixture", case.fixture],
        repo,
        env,
    )
    app.start()
    app.wait_for(case.first_frame_marker, 7.0)
    app.send(b"a")
    app.wait_for("context shared", 2.0)
    client = ProtocolClient(cli, repo, env, case, task_id)
    context = client.active_context()
    shown = client.show(context)
    summary = shown["data"]["context"]["summary"]
    require(summary["availability"] == "active", f"context is not active: {summary}")
    require(summary["principal_bound"] is False, f"new context is already bound: {summary}")
    return app, client, context


def decision_from(envelope: dict[str, Any]) -> str | None:
    requests = envelope["data"]["status"]["operation_requests"]
    require(len(requests) == 1, f"expected one operation request: {requests}")
    operations = requests[0]["operations"]
    require(len(operations) == 1, f"expected one indexed operation: {operations}")
    return operations[0].get("decision")


def submit_default(
    client: ProtocolClient,
    context: dict[str, Any],
    case: PluginCase,
    request_id: str,
    summary: str,
) -> dict[str, Any]:
    return client.operation(context, request_id, summary, [case.operation])


def run_allow(
    cli: pathlib.Path,
    repo: pathlib.Path,
    case: PluginCase,
    runtime: pathlib.Path,
) -> tuple[dict[str, Any], bytes]:
    app, client, context = launch_shared_context(
        cli, repo, case, runtime, f"{case.plugin_id}-allow"
    )
    try:
        accepted = submit_default(
            client, context, case, "operation:allow:1", "Allow fixture operation"
        )
        require(accepted["data"]["created"] is True, "operation was not created")
        poll_latency_ms = app.wait_for("agent operation:", 2.0)
        app.send(b"y")
        app.wait_for("agent operation staged", 2.0)
        completed = client.wait(context, 2_000)
        require(completed["data"]["status"]["complete"] is True, "allow did not complete")
        require(decision_from(completed) == "allowed", "allow decision was not projected")
        app.send(b"\x1b")
        app.wait_for("operation plan cancelled", 1.0)
        app.graceful_exit()
        return {"poll_latency_ms": poll_latency_ms, "decision": "allowed"}, bytes(app.capture.raw)
    finally:
        app.graceful_exit()


def run_deny(
    cli: pathlib.Path,
    repo: pathlib.Path,
    case: PluginCase,
    runtime: pathlib.Path,
) -> tuple[dict[str, Any], bytes]:
    app, client, context = launch_shared_context(
        cli, repo, case, runtime, f"{case.plugin_id}-deny"
    )
    try:
        submit_default(client, context, case, "operation:deny:1", "Deny fixture operation")
        poll_latency_ms = app.wait_for("agent operation:", 2.0)
        app.send(case.deny_key)
        app.wait_for("agent operation denied", 2.0)
        completed = client.wait(context, 2_000)
        require(decision_from(completed) == "denied", "deny decision was not projected")
        app.graceful_exit()
        return {"poll_latency_ms": poll_latency_ms, "decision": "denied"}, bytes(app.capture.raw)
    finally:
        app.graceful_exit()


def run_timeout(
    cli: pathlib.Path,
    repo: pathlib.Path,
    case: PluginCase,
    runtime: pathlib.Path,
) -> tuple[dict[str, Any], bytes]:
    app, client, context = launch_shared_context(
        cli, repo, case, runtime, f"{case.plugin_id}-timeout"
    )
    try:
        submit_default(
            client, context, case, "operation:timeout:1", "Leave fixture operation pending"
        )
        app.wait_for("agent operation:", 2.0)
        timed_out = client.wait(context, 30, expected_exit=10)
        require(timed_out["error"]["code"] == "timeout", f"wrong timeout error: {timed_out}")
        require(timed_out["error"]["retryable"] is True, "timeout is not retryable")
        app.send(case.deny_key)
        app.wait_for("agent operation denied", 2.0)
        app.graceful_exit()
        return {"exit_code": 10, "retryable": True}, bytes(app.capture.raw)
    finally:
        app.graceful_exit()


def run_replay(
    cli: pathlib.Path,
    repo: pathlib.Path,
    case: PluginCase,
    runtime: pathlib.Path,
) -> tuple[dict[str, Any], bytes]:
    app, client, context = launch_shared_context(
        cli, repo, case, runtime, f"{case.plugin_id}-replay"
    )
    try:
        request_id = "operation:replay:1"
        created = submit_default(client, context, case, request_id, "Replay fixture operation")
        require(created["data"]["created"] is True, "first operation was not created")
        retried = submit_default(client, context, case, request_id, "Replay fixture operation")
        require(retried["data"]["created"] is False, "exact retry was not idempotent")
        replay = client.operation(
            context,
            request_id,
            "Changed replay payload",
            [case.operation],
            expected_exit=9,
        )
        require(replay["error"]["code"] == "replay", f"wrong replay error: {replay}")
        denied = client.deny(context, request_id, "external task cancelled")
        require(denied["data"]["created"] is True, "first external denial was not created")
        denial_retry = client.deny(context, request_id, "external task cancelled")
        require(denial_retry["data"]["created"] is False, "exact denial retry was not idempotent")
        denial_replay = client.deny(
            context,
            request_id,
            "changed denial",
            expected_exit=9,
        )
        require(
            denial_replay["error"]["code"] == "replay",
            f"wrong denial replay error: {denial_replay}",
        )
        app.wait_for("decision synchronized", 2.0)
        status = client.status(context)
        require(status["data"]["complete"] is True, "external denial did not complete")
        require(
            status["data"]["operation_requests"][0]["operations"][0]["decision"] == "denied",
            "external denial was not projected",
        )
        app.graceful_exit()
        return {
            "operation_retry_created": False,
            "operation_replay_exit": 9,
            "denial_retry_created": False,
            "denial_replay_exit": 9,
        }, bytes(app.capture.raw)
    finally:
        app.graceful_exit()


def run_multi_action(
    cli: pathlib.Path,
    repo: pathlib.Path,
    case: PluginCase,
    runtime: pathlib.Path,
) -> tuple[dict[str, Any], bytes]:
    app, client, context = launch_shared_context(
        cli, repo, case, runtime, f"{case.plugin_id}-multi"
    )
    try:
        rejected = client.operation(
            context,
            "operation:multi:1",
            "Reject multi-action fixture operation",
            [case.operation, case.operation],
            expected_exit=2,
        )
        require(
            rejected["error"]["code"] == "invalid_request",
            f"wrong multi-action error: {rejected}",
        )
        shown = client.show(context)
        summary = shown["data"]["context"]["summary"]
        require(summary["principal_bound"] is False, "multi-action request bound the principal")
        require(
            summary["operation_request_count"] == 0,
            "multi-action request persisted a partial operation",
        )
        app.graceful_exit()
        return {
            "exit_code": 2,
            "principal_bound": False,
            "operation_request_count": 0,
        }, bytes(app.capture.raw)
    finally:
        app.graceful_exit()


def run_crash_recovery(
    cli: pathlib.Path,
    repo: pathlib.Path,
    case: PluginCase,
    runtime: pathlib.Path,
) -> tuple[dict[str, Any], bytes]:
    app, client, crashed_context = launch_shared_context(
        cli, repo, case, runtime, f"{case.plugin_id}-crash"
    )
    crashed_transcript = b""
    replacement: TuiProcess | None = None
    try:
        crashed_transcript = bytes(app.capture.raw)
        app.crash()
        stale = client.wait_for_availability(crashed_context["context_id"], "stale")
        require(stale["health"] == "closed", f"crashed owner is not closed: {stale}")
        stale_show = client.show(crashed_context, expected_exit=6)
        require(stale_show["error"]["code"] == "stale", f"wrong stale error: {stale_show}")

        replacement = TuiProcess(
            [str(cli), case.plugin_id, "tui", "--fixture", case.fixture],
            repo,
            client.env,
        )
        replacement.start()
        replacement.wait_for(case.first_frame_marker, 7.0)
        replacement.send(b"a")
        replacement.wait_for("context shared", 2.0)
        recovered_context = client.active_context()
        require(
            recovered_context["context_id"] != crashed_context["context_id"],
            "replacement TUI reused the crashed context identity",
        )
        submit_default(
            client,
            recovered_context,
            case,
            "operation:recovery:1",
            "Review operation after owner recovery",
        )
        replacement.wait_for("agent operation:", 2.0)
        replacement.send(case.deny_key)
        replacement.wait_for("agent operation denied", 2.0)
        completed = client.wait(recovered_context, 2_000)
        require(decision_from(completed) == "denied", "recovered owner did not review operation")
        replacement.graceful_exit()
        return {
            "crashed_availability": "stale",
            "stale_exit_code": 6,
            "replacement_context": "active",
        }, crashed_transcript + bytes(replacement.capture.raw)
    finally:
        if app.master_fd is not None:
            if app.returncode is None:
                app.crash()
            else:
                app.close()
        if replacement is not None:
            replacement.graceful_exit()


SCENARIO_RUNNERS = {
    "allow": run_allow,
    "deny": run_deny,
    "timeout": run_timeout,
    "replay": run_replay,
    "multi_action": run_multi_action,
    "crash_recovery": run_crash_recovery,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli-bin", required=True, type=pathlib.Path)
    parser.add_argument(
        "--out",
        type=pathlib.Path,
        default=pathlib.Path("target/tmp/external-context-handoff"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = pathlib.Path(__file__).resolve().parent.parent
    cli = args.cli_bin if args.cli_bin.is_absolute() else repo / args.cli_bin
    require(cli.is_file(), f"voidb-cli binary does not exist: {cli}")
    out = args.out if args.out.is_absolute() else repo / args.out
    out.mkdir(parents=True, exist_ok=True)
    runtime_parent = repo / "target" / "tmp"
    runtime_parent.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {
        "schema_version": 1,
        "kind": "external_context_handoff_conformance",
        "protocol_version": 1,
        "scenario_matrix": list(SCENARIOS),
        "plugins": [],
        "passed": True,
    }

    with tempfile.TemporaryDirectory(
        prefix="voidb-context-handoff-", dir=runtime_parent
    ) as temporary:
        temporary_root = pathlib.Path(temporary)
        for case in PLUGIN_CASES:
            plugin_report: dict[str, Any] = {
                "plugin_id": case.plugin_id,
                "scenarios": [],
                "passed": True,
            }
            for scenario_name in SCENARIOS:
                scenario_runtime = temporary_root / case.plugin_id / scenario_name
                scenario_runtime.mkdir(parents=True, exist_ok=True)
                scenario_report: dict[str, Any] = {
                    "name": scenario_name,
                    "passed": False,
                }
                try:
                    details, transcript = SCENARIO_RUNNERS[scenario_name](
                        cli, repo, case, scenario_runtime
                    )
                    matches = [
                        marker.decode("ascii", "replace")
                        for marker in FORBIDDEN_MARKERS
                        if marker.lower() in transcript.lower()
                    ]
                    require(not matches, f"secret-shaped transcript markers found: {matches}")
                    transcript_path = out / f"{case.plugin_id}-{scenario_name}.ansi"
                    transcript_path.write_bytes(transcript)
                    scenario_report.update(
                        {
                            "passed": True,
                            "details": details,
                            "transcript": transcript_path.name,
                            "transcript_bytes": len(transcript),
                        }
                    )
                except Exception as error:  # Continue to show the full plugin matrix.
                    scenario_report["error"] = str(error)
                    plugin_report["passed"] = False
                    report["passed"] = False
                plugin_report["scenarios"].append(scenario_report)
            require(
                [item["name"] for item in plugin_report["scenarios"]] == list(SCENARIOS),
                f"{case.plugin_id} did not run the shared scenario matrix",
            )
            report["plugins"].append(plugin_report)

    report_path = out / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["passed"]:
        print("external context handoff conformance passed")
        return 0
    print(f"external context handoff conformance failed; report: {report_path}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConformanceError as error:
        print(f"external context handoff conformance failed: {error}", file=sys.stderr)
        raise SystemExit(1)
