#!/usr/bin/env python3
"""Run deterministic terminal journeys in a real pseudo-terminal.

The runner deliberately uses only the Python standard library so it can run on
the same macOS and Linux hosts that build VoidB. A JSON specification describes
the process, terminal size, interaction steps, repetitions, and release budgets.
Each run writes a raw ANSI transcript, timestamped output events, and a JSON
report. The aggregate report contains cold/warm p50 and p95 measurements.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import math
import os
import pathlib
import pty
import re
import select
import shlex
import signal
import struct
import subprocess
import sys
import termios
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable


SCHEMA_VERSION = 1
ANSI_PATTERN = re.compile(
    rb"(?:\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_])"
)


class JourneyError(RuntimeError):
    """Raised when a journey specification cannot be executed safely."""


@dataclass
class OutputCapture:
    started_at: float
    raw: bytearray = field(default_factory=bytearray)
    events: list[dict[str, Any]] = field(default_factory=list)

    def append(self, chunk: bytes) -> None:
        offset = len(self.raw)
        self.raw.extend(chunk)
        self.events.append(
            {
                "timestamp_ms": elapsed_ms(self.started_at),
                "offset": offset,
                "byte_count": len(chunk),
                "screen_hash": hashlib.sha256(self.raw).hexdigest(),
            }
        )

    def visible(self) -> bytes:
        return ANSI_PATTERN.sub(b"", bytes(self.raw))

    def searchable(self, baseline: int = 0) -> bytes:
        plain = ANSI_PATTERN.sub(b" ", bytes(self.raw[baseline:]))
        return b" ".join(plain.split())

    def screen(self) -> str:
        return render_terminal(bytes(self.raw))


def render_terminal(raw: bytes) -> str:
    """Render the cursor/edit subset emitted by crossterm and ratatui."""
    text = raw.decode("utf-8", "ignore")
    cells: dict[tuple[int, int], str] = {}
    row = 0
    col = 0
    saved = (0, 0)
    index = 0

    def erase_line(mode: int) -> None:
        nonlocal cells
        if mode == 2:
            cells = {position: value for position, value in cells.items() if position[0] != row}
        elif mode == 1:
            cells = {
                position: value
                for position, value in cells.items()
                if position[0] != row or position[1] > col
            }
        else:
            cells = {
                position: value
                for position, value in cells.items()
                if position[0] != row or position[1] < col
            }

    def erase_display(mode: int) -> None:
        nonlocal cells
        if mode in (2, 3):
            cells.clear()
        elif mode == 1:
            cells = {
                position: value
                for position, value in cells.items()
                if position[0] > row or (position[0] == row and position[1] > col)
            }
        else:
            cells = {
                position: value
                for position, value in cells.items()
                if position[0] < row or (position[0] == row and position[1] < col)
            }

    while index < len(text):
        char = text[index]
        if char == "\x1b":
            if index + 1 >= len(text):
                break
            introducer = text[index + 1]
            if introducer == "[":
                end = index + 2
                while end < len(text) and not ("@" <= text[end] <= "~"):
                    end += 1
                if end >= len(text):
                    break
                body = text[index + 2 : end]
                final = text[end]
                private_body = body.lstrip("?<>")
                raw_params = private_body.split(";") if private_body else []
                params = [int(value) if value.isdigit() else 0 for value in raw_params]
                first = params[0] if params else 0
                amount = max(1, first)
                if final in ("H", "f"):
                    row = max(0, (params[0] if params else 1) - 1)
                    col = max(0, (params[1] if len(params) > 1 else 1) - 1)
                elif final == "G":
                    col = max(0, amount - 1)
                elif final == "d":
                    row = max(0, amount - 1)
                elif final == "A":
                    row = max(0, row - amount)
                elif final == "B":
                    row += amount
                elif final == "C":
                    col += amount
                elif final == "D":
                    col = max(0, col - amount)
                elif final == "E":
                    row += amount
                    col = 0
                elif final == "F":
                    row = max(0, row - amount)
                    col = 0
                elif final == "J":
                    erase_display(first)
                elif final == "K":
                    erase_line(first)
                elif final == "X":
                    for erase_col in range(col, col + amount):
                        cells.pop((row, erase_col), None)
                elif final == "s":
                    saved = (row, col)
                elif final == "u":
                    row, col = saved
                index = end + 1
                continue
            if introducer == "]":
                end = index + 2
                while end < len(text):
                    if text[end] == "\x07":
                        end += 1
                        break
                    if text[end : end + 2] == "\x1b\\":
                        end += 2
                        break
                    end += 1
                index = end
                continue
            index += 2
            continue
        if char == "\r":
            col = 0
        elif char == "\n":
            row += 1
        elif char == "\b":
            col = max(0, col - 1)
        elif char == "\t":
            col = (col // 8 + 1) * 8
        elif char >= " " and char != "\x7f":
            cells[(row, col)] = char
            width = 0 if unicodedata.combining(char) else (2 if unicodedata.east_asian_width(char) in ("W", "F") else 1)
            col += width
        index += 1

    if not cells:
        return ""
    max_row = max(position[0] for position in cells)
    lines = []
    for output_row in range(max_row + 1):
        row_cells = {position[1]: value for position, value in cells.items() if position[0] == output_row}
        if not row_cells:
            lines.append("")
            continue
        max_col = max(row_cells)
        lines.append("".join(row_cells.get(output_col, " ") for output_col in range(max_col + 1)).rstrip())
    return "\n".join(lines).rstrip()


def elapsed_ms(start: float) -> float:
    return round((time.monotonic() - start) * 1000, 3)


def percentile(samples: list[float], quantile: float) -> float | None:
    if not samples:
        return None
    ordered = sorted(samples)
    if len(ordered) == 1:
        return round(ordered[0], 3)
    rank = (len(ordered) - 1) * quantile
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return round(ordered[lower], 3)
    weight = rank - lower
    return round(ordered[lower] * (1 - weight) + ordered[upper] * weight, 3)


def parse_cpu_time(value: str) -> float:
    """Parse portable `ps -o time=` output into seconds."""
    value = value.strip()
    if not value:
        raise ValueError("empty CPU time")
    days = 0
    if "-" in value:
        day_text, value = value.split("-", 1)
        days = int(day_text)
    parts = value.split(":")
    if len(parts) == 3:
        hours, minutes, seconds = parts
    elif len(parts) == 2:
        hours = "0"
        minutes, seconds = parts
    else:
        raise ValueError(f"unsupported CPU time: {value}")
    return days * 86400 + int(hours) * 3600 + int(minutes) * 60 + float(seconds)


def process_cpu_seconds(pid: int) -> float | None:
    if sys.platform.startswith("linux"):
        try:
            stat = pathlib.Path(f"/proc/{pid}/stat").read_text()
            fields = stat[stat.rfind(")") + 2 :].split()
            ticks = os.sysconf("SC_CLK_TCK")
            return (int(fields[11]) + int(fields[12])) / ticks
        except (IndexError, OSError, TypeError, ValueError):
            pass
    elif sys.platform == "darwin":
        class ProcTaskInfo(ctypes.Structure):
            _fields_ = [
                ("virtual_size", ctypes.c_uint64),
                ("resident_size", ctypes.c_uint64),
                ("total_user", ctypes.c_uint64),
                ("total_system", ctypes.c_uint64),
                ("threads_user", ctypes.c_uint64),
                ("threads_system", ctypes.c_uint64),
                ("policy", ctypes.c_int32),
                ("faults", ctypes.c_int32),
                ("pageins", ctypes.c_int32),
                ("cow_faults", ctypes.c_int32),
                ("messages_sent", ctypes.c_int32),
                ("messages_received", ctypes.c_int32),
                ("syscalls_mach", ctypes.c_int32),
                ("syscalls_unix", ctypes.c_int32),
                ("csw", ctypes.c_int32),
                ("threadnum", ctypes.c_int32),
                ("numrunning", ctypes.c_int32),
                ("priority", ctypes.c_int32),
            ]

        try:
            libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            task_info = ProcTaskInfo()
            read = libproc.proc_pidinfo(
                pid,
                4,  # PROC_PIDTASKINFO
                0,
                ctypes.byref(task_info),
                ctypes.sizeof(task_info),
            )
            if read == ctypes.sizeof(task_info):
                return (task_info.total_user + task_info.total_system) / 1_000_000_000
        except (AttributeError, OSError):
            pass
    try:
        completed = subprocess.run(
            ["ps", "-o", "time=", "-p", str(pid)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        if completed.returncode != 0:
            return None
        return parse_cpu_time(completed.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def decode_action_data(action: dict[str, Any]) -> bytes:
    present = [key for key in ("data", "data_hex", "data_base64") if key in action]
    if len(present) != 1:
        raise JourneyError("input/quit actions require exactly one data encoding")
    key = present[0]
    value = action[key]
    if not isinstance(value, str):
        raise JourneyError(f"{key} must be a string")
    if key == "data":
        return value.encode("utf-8")
    if key == "data_hex":
        try:
            return bytes.fromhex(value)
        except ValueError as error:
            raise JourneyError(f"invalid data_hex: {error}") from error
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as error:
        raise JourneyError(f"invalid data_base64: {error}") from error


def set_window_size(fd: int, rows: int, cols: int) -> None:
    if rows <= 0 or cols <= 0:
        raise JourneyError("terminal rows and columns must be positive")
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def process_group_members(process_group: int) -> list[dict[str, Any]]:
    """Return non-zombie members left in a process group after its leader exits."""
    try:
        completed = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,pgid=,stat=,command="],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    members = []
    for line in completed.stdout.splitlines():
        fields = line.strip().split(None, 4)
        if len(fields) < 4:
            continue
        try:
            pid, ppid, pgid = map(int, fields[:3])
        except ValueError:
            continue
        stat = fields[3]
        if pgid == process_group and not stat.startswith("Z"):
            members.append(
                {
                    "pid": pid,
                    "ppid": ppid,
                    "pgid": pgid,
                    "stat": stat,
                    "command": fields[4] if len(fields) == 5 else "",
                }
            )
    return members


class PtyJourney:
    def __init__(
        self,
        spec: dict[str, Any],
        artifact_dir: pathlib.Path,
        run_id: str,
        phase: str,
    ) -> None:
        self.spec = spec
        self.artifact_dir = artifact_dir
        self.run_id = run_id
        self.phase = phase
        self.started_at = time.monotonic()
        self.capture = OutputCapture(self.started_at)
        self.failures: list[str] = []
        self.action_results: list[dict[str, Any]] = []
        self.metrics: dict[str, float] = {}
        self.forced_cleanup = False
        self.master_fd: int | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.first_output_ms: float | None = None
        self.first_visible_ms: float | None = None
        self.terminal_responses: list[dict[str, Any]] = []
        self._keyboard_query_answered = False

    def run(self) -> dict[str, Any]:
        command = self.spec.get("command")
        if not isinstance(command, list) or not command or not all(
            isinstance(part, str) and part for part in command
        ):
            raise JourneyError("command must be a non-empty string array")

        rows = positive_int(self.spec.get("rows", 30), "rows")
        cols = positive_int(self.spec.get("cols", 100), "cols")
        timeout_ms = positive_int(self.spec.get("timeout_ms", 10_000), "timeout_ms")
        cwd = pathlib.Path(self.spec.get("cwd", ".")).resolve()
        if not cwd.is_dir():
            raise JourneyError(f"journey cwd does not exist: {cwd}")
        command = [self._expand(part, cwd) for part in command]

        env = os.environ.copy()
        spec_env = self.spec.get("env", {})
        if not isinstance(spec_env, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in spec_env.items()
        ):
            raise JourneyError("env must be a string-to-string object")
        expanded_env = {key: self._expand(value, cwd) for key, value in spec_env.items()}
        env.update(expanded_env)
        for key in self.spec.get("unset_env", []):
            env.pop(key, None)
        prepare_dirs = self.spec.get("prepare_dirs", [])
        if not isinstance(prepare_dirs, list) or not all(
            isinstance(path, str) and path for path in prepare_dirs
        ):
            raise JourneyError("prepare_dirs must be a string array")
        for path in prepare_dirs:
            pathlib.Path(self._expand(path, cwd)).mkdir(parents=True, exist_ok=True)

        master_fd, slave_fd = pty.openpty()
        self.master_fd = master_fd
        set_window_size(slave_fd, rows, cols)
        try:
            self.process = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                start_new_session=True,
            )
        finally:
            os.close(slave_fd)

        deadline = self.started_at + timeout_ms / 1000
        try:
            for index, action in enumerate(self.spec.get("actions", [])):
                if not isinstance(action, dict):
                    raise JourneyError(f"action {index} must be an object")
                if time.monotonic() >= deadline:
                    self.failures.append("journey exceeded its global timeout")
                    break
                self._run_action(index, action, deadline)

            if self.process.poll() is None:
                exit_timeout_ms = positive_int(
                    self.spec.get("exit_timeout_ms", 1_000), "exit_timeout_ms"
                )
                self._read_until(
                    lambda: self.process is not None and self.process.poll() is not None,
                    min(deadline, time.monotonic() + exit_timeout_ms / 1000),
                )
            if self.process.poll() is None:
                self.failures.append("process was still running after the journey")
                self._terminate_process_group()
            self.process.wait(timeout=2)
            self._drain(0.2)
        finally:
            if self.process.poll() is None:
                self._terminate_process_group()
            if self.master_fd is not None:
                os.close(self.master_fd)
                self.master_fd = None

        process_group_members_after_exit = process_group_members(self.process.pid)
        process_group_alive = bool(process_group_members_after_exit)
        if process_group_alive:
            self.failures.append("process group still had live descendants after exit")
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        expected_exit_codes = self.spec.get("expected_exit_codes", [0])
        if self.process.returncode not in expected_exit_codes:
            self.failures.append(
                f"exit code {self.process.returncode} not in {expected_exit_codes}"
            )

        raw = bytes(self.capture.raw)
        terminal = {
            "alternate_screen_entered": any(
                marker in raw for marker in (b"\x1b[?1049h", b"\x1b[?47h", b"\x1b[?1047h")
            ),
            "alternate_screen_left": any(
                marker in raw for marker in (b"\x1b[?1049l", b"\x1b[?47l", b"\x1b[?1047l")
            ),
            "cursor_hidden": b"\x1b[?25l" in raw,
            "cursor_shown": b"\x1b[?25h" in raw,
            "bracketed_paste_disabled": b"\x1b[?2004l" in raw,
        }
        if self.spec.get("require_terminal_restore", True):
            if terminal["alternate_screen_entered"] and not terminal["alternate_screen_left"]:
                self.failures.append("alternate screen was entered but not restored")
            if terminal["cursor_hidden"] and not terminal["cursor_shown"]:
                self.failures.append("cursor was hidden but not restored")

        decoded = raw.decode("utf-8", "replace")
        searchable = self.capture.searchable().decode("utf-8", "replace")
        for marker in self.spec.get("required_markers", []):
            if normalize_marker(marker) not in searchable:
                self.failures.append(f"required marker was not observed: {marker!r}")
        for marker in self.spec.get("forbidden_markers", []):
            if marker in decoded or normalize_marker(marker) in searchable:
                self.failures.append(f"forbidden marker was observed: {marker!r}")

        report = {
            "schema_version": SCHEMA_VERSION,
            "kind": "voidb_tui_journey_run",
            "name": self.spec["name"],
            "run_id": self.run_id,
            "phase": self.phase,
            "command": [shlex.quote(part) for part in command],
            "cwd": str(cwd),
            "environment_keys": sorted(spec_env),
            "terminal_size": {"rows": rows, "cols": cols},
            "process": {
                "pid": self.process.pid,
                "exit_code": self.process.returncode,
                "forced_cleanup": self.forced_cleanup,
                "process_group_alive_after_exit": process_group_alive,
                "process_group_members_after_exit": process_group_members_after_exit,
                "elapsed_ms": elapsed_ms(self.started_at),
            },
            "terminal": terminal,
            "terminal_responses": self.terminal_responses,
            "first_output_ms": self.first_output_ms,
            "first_visible_ms": self.first_visible_ms,
            "metrics": self.metrics,
            "actions": self.action_results,
            "output_event_count": len(self.capture.events),
            "output_byte_count": len(raw),
            "transcript_sha256": hashlib.sha256(raw).hexdigest(),
            "failures": self.failures,
            "passed": not self.failures,
        }
        self._write_artifacts(report, raw)
        return report

    def _expand(self, value: str, cwd: pathlib.Path) -> str:
        return value.replace("${RUN_ID}", self.run_id).replace("${REPO_ROOT}", str(cwd))

    def _run_action(
        self, index: int, action: dict[str, Any], global_deadline: float
    ) -> None:
        action_type = action.get("type")
        name = action.get("name", f"action-{index + 1}")
        if not isinstance(name, str) or not name:
            raise JourneyError(f"action {index} has an invalid name")
        started = time.monotonic()
        baseline = len(self.capture.raw)
        result: dict[str, Any] = {"index": index, "name": name, "type": action_type}
        timeout_ms = positive_int(action.get("timeout_ms", 1_000), "action timeout_ms")
        deadline = min(global_deadline, started + timeout_ms / 1000)

        if action_type == "wait":
            marker = required_marker(action)
            observed = self._wait_for_marker(marker, baseline, deadline)
            result.update(self._observed_result(started, marker, observed))
        elif action_type in ("input", "quit"):
            data = decode_action_data(action)
            if self.master_fd is None:
                raise JourneyError("PTY was closed before input")
            os.write(self.master_fd, data)
            result["byte_count"] = len(data)
            marker = action.get("marker")
            if marker is not None:
                if not isinstance(marker, str) or not marker:
                    raise JourneyError("action marker must be a non-empty string")
                observed = self._wait_for_marker(marker, baseline, deadline)
                result.update(self._observed_result(started, marker, observed))
            elif action.get("expect_echo", False):
                observed = self._read_until(
                    lambda: data in bytes(self.capture.raw[baseline:]), deadline
                )
                result.update(self._observed_result(started, "raw input echo", observed))
            elif action_type == "quit":
                observed = self._read_until(
                    lambda: self.process is not None and self.process.poll() is not None,
                    deadline,
                )
                result.update(self._observed_result(started, "process exit", observed))
            else:
                self._drain(min(timeout_ms / 1000, 0.05))
                result["observed"] = True
                result["latency_ms"] = elapsed_ms(started)
            # Crossterm intentionally waits briefly to distinguish a standalone
            # Escape key from an Alt-modified key. Keep the next scripted key
            # outside that decoder window so journeys behave like real typing.
            if action_type == "input" and data == b"\x1b":
                escape_settle_ms = positive_int(
                    action.get("escape_settle_ms", 50), "escape_settle_ms"
                )
                self._drain(escape_settle_ms / 1000)
        elif action_type == "resize":
            rows = positive_int(action.get("rows"), "resize rows")
            cols = positive_int(action.get("cols"), "resize cols")
            if self.master_fd is None:
                raise JourneyError("PTY was closed before resize")
            set_window_size(self.master_fd, rows, cols)
            os.killpg(self.process.pid, signal.SIGWINCH)
            result["terminal_size"] = {"rows": rows, "cols": cols}
            marker = action.get("marker")
            if marker is not None:
                if not isinstance(marker, str) or not marker:
                    raise JourneyError("resize marker must be a non-empty string")
                observed = self._wait_for_marker(marker, baseline, deadline)
                result.update(self._observed_result(started, marker, observed))
            else:
                observed = self._read_until(
                    lambda: len(self.capture.raw) > baseline, deadline
                )
                result.update(self._observed_result(started, "screen repaint", observed))
        elif action_type == "idle":
            duration_ms = positive_int(action.get("duration_ms"), "idle duration_ms")
            settle_ms = positive_int(action.get("settle_ms", 100), "idle settle_ms")
            # Do not charge the final chunks of the preceding repaint to idle.
            self._drain(settle_ms / 1000)
            cpu_before = process_cpu_seconds(self.process.pid)
            event_baseline = len(self.capture.events)
            idle_started = time.monotonic()
            self._drain(duration_ms / 1000)
            wall_seconds = time.monotonic() - idle_started
            cpu_after = process_cpu_seconds(self.process.pid)
            event_count = len(self.capture.events) - event_baseline
            repaint_hz = event_count / wall_seconds if wall_seconds else 0.0
            result.update(
                {
                    "observed": True,
                    "latency_ms": round(wall_seconds * 1000, 3),
                    "output_events": event_count,
                    "repaint_hz": round(repaint_hz, 3),
                }
            )
            self.metrics[f"{name}.repaint_hz"] = round(repaint_hz, 3)
            if cpu_before is not None and cpu_after is not None and wall_seconds:
                cpu_percent = max(0.0, cpu_after - cpu_before) / wall_seconds * 100
                result["cpu_percent"] = round(cpu_percent, 3)
                self.metrics[f"{name}.cpu_percent"] = round(cpu_percent, 3)
        elif action_type == "signal":
            signal_name = action.get("signal")
            if not isinstance(signal_name, str) or not hasattr(signal, signal_name):
                raise JourneyError(f"unsupported signal name: {signal_name!r}")
            os.killpg(self.process.pid, getattr(signal, signal_name))
            marker = action.get("marker")
            if marker is not None:
                observed = self._wait_for_marker(required_marker(action), baseline, deadline)
            else:
                observed = self._read_until(
                    lambda: self.process is not None and self.process.poll() is not None,
                    deadline,
                )
            result.update(self._observed_result(started, marker or "process exit", observed))
        elif action_type == "sleep":
            duration_ms = positive_int(action.get("duration_ms"), "sleep duration_ms")
            self._drain(duration_ms / 1000)
            result.update({"observed": True, "latency_ms": elapsed_ms(started)})
        else:
            raise JourneyError(f"unsupported action type: {action_type!r}")

        if not result.get("observed", False):
            self.failures.append(
                f"action {name!r} did not observe {result.get('expected', 'its result')}"
            )
        if action_type == "wait" and name == "first_frame" and result.get("observed"):
            result["latency_ms"] = elapsed_ms(self.started_at)
        metric = action.get("metric")
        if metric is not None:
            if not isinstance(metric, str) or not metric:
                raise JourneyError("action metric must be a non-empty string")
            if result.get("observed"):
                self.metrics[metric] = result["latency_ms"]
        if action_type == "wait" and name == "first_frame" and result.get("observed"):
            self.metrics.setdefault("first_frame_ms", result["latency_ms"])
        if action_type == "quit" and result.get("observed"):
            self.metrics.setdefault("quit_restore_ms", result["latency_ms"])
        self.action_results.append(result)

    def _observed_result(
        self, started: float, expected: str, observed: bool
    ) -> dict[str, Any]:
        return {
            "expected": expected,
            "observed": observed,
            "latency_ms": elapsed_ms(started),
        }

    def _wait_for_marker(self, marker: str, baseline: int, deadline: float) -> bool:
        normalized = normalize_marker(marker)
        return self._read_until(
            lambda: len(self.capture.raw) > baseline
            and normalized in normalize_marker(self.capture.screen()),
            deadline,
        )

    def _read_until(self, predicate: Callable[[], bool], deadline: float) -> bool:
        while time.monotonic() < deadline:
            if predicate():
                return True
            if self.process is not None and self.process.poll() is not None:
                self._drain(0.05)
                return predicate()
            self._read_once(min(0.05, max(0.0, deadline - time.monotonic())))
        return predicate()

    def _read_once(self, timeout: float) -> bool:
        if self.master_fd is None:
            return False
        ready, _, _ = select.select([self.master_fd], [], [], timeout)
        if not ready:
            return False
        try:
            chunk = os.read(self.master_fd, 65536)
        except OSError as error:
            if error.errno == errno.EIO:
                return False
            raise
        if not chunk:
            return False
        timestamp = elapsed_ms(self.started_at)
        self.capture.append(chunk)
        self._answer_terminal_queries()
        if self.first_output_ms is None:
            self.first_output_ms = timestamp
        if self.first_visible_ms is None and self.capture.visible().strip():
            self.first_visible_ms = timestamp
        return True

    def _answer_terminal_queries(self) -> None:
        if (
            self._keyboard_query_answered
            or not self.spec.get("answer_terminal_queries", True)
            or self.master_fd is None
        ):
            return
        # Crossterm probes the Kitty keyboard protocol and then requests
        # primary device attributes. A bare PTY has no terminal emulator to
        # answer, so provide a conservative standard-terminal response instead
        # of measuring Crossterm's two-second query timeout as startup latency.
        if b"\x1b[?u\x1b[c" in bytes(self.capture.raw):
            response = b"\x1b[?1;2c"
            os.write(self.master_fd, response)
            self._keyboard_query_answered = True
            self.terminal_responses.append(
                {
                    "timestamp_ms": elapsed_ms(self.started_at),
                    "query": "keyboard-enhancement-and-primary-device-attributes",
                    "response": "primary-device-attributes-vt100",
                }
            )

    def _drain(self, duration: float) -> None:
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            if not self._read_once(min(0.05, deadline - time.monotonic())):
                if self.process is not None and self.process.poll() is not None:
                    break

    def _terminate_process_group(self) -> None:
        if self.process is None or self.process.poll() is not None:
            return
        self.forced_cleanup = True
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
            self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=1)
        except ProcessLookupError:
            pass

    def _write_artifacts(self, report: dict[str, Any], raw: bytes) -> None:
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        prefix = self.artifact_dir / self.run_id
        transcript_path = prefix.with_suffix(".ansi")
        events_path = prefix.with_suffix(".events.jsonl")
        report_path = prefix.with_suffix(".json")
        transcript_path.write_bytes(raw)
        events_path.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in self.capture.events),
            encoding="utf-8",
        )
        report["artifacts"] = {
            "transcript": str(transcript_path),
            "events": str(events_path),
            "report": str(report_path),
        }
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


def positive_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise JourneyError(f"{name} must be a positive integer")
    return value


def required_marker(action: dict[str, Any]) -> str:
    marker = action.get("marker")
    if not isinstance(marker, str) or not marker:
        raise JourneyError("wait actions require a non-empty marker")
    return marker


def normalize_marker(marker: str) -> str:
    return " ".join(marker.split())


def validate_spec(spec: dict[str, Any]) -> None:
    if spec.get("schema_version") != SCHEMA_VERSION:
        raise JourneyError(f"schema_version must be {SCHEMA_VERSION}")
    if not isinstance(spec.get("name"), str) or not spec["name"]:
        raise JourneyError("name must be a non-empty string")
    measurement = spec.get("measurement", {})
    if not isinstance(measurement, dict):
        raise JourneyError("measurement must be an object")
    for key in ("cold_runs", "warmup_runs", "warm_runs"):
        value = measurement.get(key, 0)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise JourneyError(f"measurement.{key} must be a non-negative integer")
    if sum(measurement.get(key, 0) for key in ("cold_runs", "warmup_runs", "warm_runs")) == 0:
        measurement["cold_runs"] = 1
        spec["measurement"] = measurement


def run_plan(spec: dict[str, Any], out_dir: pathlib.Path) -> dict[str, Any]:
    validate_spec(spec)
    measurement = spec["measurement"]
    plan = ["cold"] * measurement.get("cold_runs", 0)
    plan += ["warmup"] * measurement.get("warmup_runs", 0)
    plan += ["warm"] * measurement.get("warm_runs", 0)
    runs: list[dict[str, Any]] = []
    counters: dict[str, int] = {"cold": 0, "warmup": 0, "warm": 0}
    for phase in plan:
        counters[phase] += 1
        run_id = f"{spec['name']}-{phase}-{counters[phase]:03d}"
        runs.append(PtyJourney(spec, out_dir / "runs", run_id, phase).run())

    summaries: dict[str, dict[str, Any]] = {}
    for phase in ("cold", "warm"):
        phase_runs = [run for run in runs if run["phase"] == phase]
        metric_names = sorted(
            {name for run in phase_runs for name in run.get("metrics", {}).keys()}
        )
        summaries[phase] = {}
        for name in metric_names:
            samples = [
                float(run["metrics"][name])
                for run in phase_runs
                if name in run.get("metrics", {})
            ]
            summaries[phase][name] = {
                "samples": [round(sample, 3) for sample in samples],
                "p50": percentile(samples, 0.50),
                "p95": percentile(samples, 0.95),
                "max": round(max(samples), 3) if samples else None,
            }

    budget_failures = evaluate_thresholds(summaries, spec.get("thresholds", {}))
    run_failures = [
        f"{run['run_id']}: {failure}"
        for run in runs
        if run["phase"] != "warmup"
        for failure in run["failures"]
    ]
    aggregate = {
        "schema_version": SCHEMA_VERSION,
        "kind": "voidb_tui_journey_report",
        "name": spec["name"],
        "measurement": measurement,
        "thresholds": spec.get("thresholds", {}),
        "summary": summaries,
        "runs": runs,
        "failures": run_failures + budget_failures,
        "passed": not run_failures and not budget_failures,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "report.json"
    report_path.write_text(
        json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    aggregate["report_path"] = str(report_path)
    return aggregate


def evaluate_thresholds(
    summaries: dict[str, dict[str, Any]], thresholds: Any
) -> list[str]:
    if not isinstance(thresholds, dict):
        raise JourneyError("thresholds must be an object")
    failures: list[str] = []
    statistic_names = {
        "p50_ms": "p50",
        "p95_ms": "p95",
        "max_ms": "max",
        "p50_max": "p50",
        "p95_max": "p95",
        "max_value": "max",
    }
    for phase, phase_thresholds in thresholds.items():
        if phase not in ("cold", "warm") or not isinstance(phase_thresholds, dict):
            raise JourneyError("thresholds may contain only cold/warm objects")
        for metric, limits in phase_thresholds.items():
            if not isinstance(limits, dict):
                raise JourneyError(f"threshold {phase}.{metric} must be an object")
            summary = summaries.get(phase, {}).get(metric)
            if summary is None:
                failures.append(f"missing samples for threshold {phase}.{metric}")
                continue
            for limit_name, summary_name in statistic_names.items():
                if limit_name not in limits:
                    continue
                limit = limits[limit_name]
                if not isinstance(limit, (int, float)) or isinstance(limit, bool) or limit < 0:
                    raise JourneyError(
                        f"threshold {phase}.{metric}.{limit_name} must be non-negative"
                    )
                observed = summary[summary_name]
                if observed is None or observed > limit:
                    failures.append(
                        f"{phase}.{metric} {summary_name}={observed} exceeded {limit_name}={limit}"
                    )
    return failures


def load_spec(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise JourneyError(f"failed to load journey spec {path}: {error}") from error
    if not isinstance(value, dict):
        raise JourneyError("journey spec root must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        report = run_plan(load_spec(args.spec), args.out)
    except JourneyError as error:
        parser.error(str(error))
    print(json.dumps({"passed": report["passed"], "report": report["report_path"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
