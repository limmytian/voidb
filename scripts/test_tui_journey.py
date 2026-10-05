#!/usr/bin/env python3
"""Focused unit tests for the real-PTY journey runner."""

from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import textwrap
import unittest

import tui_journey


class TuiJourneyTests(unittest.TestCase):
    def test_process_cpu_sampler_works_without_ps(self) -> None:
        self.assertIsNotNone(tui_journey.process_cpu_seconds(os.getpid()))

    def test_terminal_renderer_reconstructs_cursor_positioned_text(self) -> None:
        raw = b"\x1b[2J\x1b[4;3HHost\x1b[4;8HKey\x1b[5;1Hready"
        screen = tui_journey.render_terminal(raw)
        self.assertIn("Host Key", screen)
        self.assertIn("ready", screen)

    def test_percentile_interpolates_small_samples(self) -> None:
        self.assertEqual(tui_journey.percentile([10.0, 20.0, 30.0], 0.50), 20.0)
        self.assertEqual(tui_journey.percentile([10.0, 20.0], 0.95), 19.5)
        self.assertIsNone(tui_journey.percentile([], 0.95))

    def test_real_pty_journey_records_interactions_and_restoration(self) -> None:
        child = textwrap.dedent(
            """
            import os
            import signal
            import sys
            import tty

            def resized(_signum, _frame):
                os.write(sys.stdout.fileno(), b"RESIZED\\n")

            signal.signal(signal.SIGWINCH, resized)
            tty.setraw(sys.stdin.fileno())
            os.write(sys.stdout.fileno(), b"\\x1b[?u\\x1b[c")
            terminal_response = os.read(sys.stdin.fileno(), 7)
            if terminal_response != b"\\x1b[?1;2c":
                raise SystemExit(3)
            os.write(sys.stdout.fileno(), b"\\x1b[?1049h\\x1b[?25lREADY\\n")
            first = os.read(sys.stdin.fileno(), 1)
            os.write(sys.stdout.fileno(), b"INPUT:" + first + b"\\n")
            second = os.read(sys.stdin.fileno(), 1)
            if second == b"q":
                os.write(sys.stdout.fileno(), b"\\x1b[?25h\\x1b[?1049lBYE\\n")
            """
        )
        spec = {
            "schema_version": 1,
            "name": "harness-self-test",
            "command": [sys.executable, "-c", child],
            "rows": 24,
            "cols": 80,
            "timeout_ms": 3_000,
            "measurement": {"cold_runs": 1, "warmup_runs": 0, "warm_runs": 0},
            "actions": [
                {
                    "type": "wait",
                    "name": "first_frame",
                    "marker": "READY",
                    "timeout_ms": 1_000,
                },
                {
                    "type": "input",
                    "name": "key_repaint",
                    "data": "x",
                    "marker": "INPUT:x",
                    "metric": "key_to_repaint_ms",
                    "timeout_ms": 1_000,
                },
                {
                    "type": "resize",
                    "name": "resize",
                    "rows": 20,
                    "cols": 60,
                    "marker": "RESIZED",
                    "metric": "resize_frame_ms",
                    "timeout_ms": 1_000,
                },
                {
                    "type": "quit",
                    "name": "quit",
                    "data": "q",
                    "timeout_ms": 1_000,
                },
            ],
            "required_markers": ["READY", "INPUT:x", "RESIZED", "BYE"],
        }
        with tempfile.TemporaryDirectory() as directory:
            spec["env"] = {
                "VOIDB_JOURNEY_TEST_DIR": "${REPO_ROOT}/runtime/${RUN_ID}"
            }
            spec["prepare_dirs"] = ["${REPO_ROOT}/runtime/${RUN_ID}"]
            spec["cwd"] = directory
            report = tui_journey.run_plan(spec, pathlib.Path(directory))
            self.assertTrue(report["passed"], report["failures"])
            run = report["runs"][0]
            self.assertTrue(run["terminal"]["alternate_screen_entered"])
            self.assertTrue(run["terminal"]["alternate_screen_left"])
            self.assertTrue(run["terminal"]["cursor_shown"])
            self.assertEqual(
                run["terminal_responses"][0]["response"],
                "primary-device-attributes-vt100",
            )
            self.assertEqual(run["process"]["exit_code"], 0)
            self.assertTrue(
                pathlib.Path(directory, "runtime", run["run_id"]).is_dir()
            )
            self.assertIn("first_frame_ms", run["metrics"])
            self.assertIn("key_to_repaint_ms", run["metrics"])
            self.assertIn("resize_frame_ms", run["metrics"])
            self.assertIn("quit_restore_ms", run["metrics"])
            self.assertTrue(pathlib.Path(run["artifacts"]["transcript"]).exists())
            events = pathlib.Path(run["artifacts"]["events"]).read_text().splitlines()
            self.assertGreaterEqual(len(events), 3)
            self.assertIn("timestamp_ms", json.loads(events[0]))

    def test_threshold_failure_is_actionable(self) -> None:
        summaries = {
            "warm": {
                "first_frame_ms": {"p50": 40, "p95": 80, "max": 90},
                "idle.cpu_percent": {"p50": 1, "p95": 3, "max": 4},
            }
        }
        failures = tui_journey.evaluate_thresholds(
            summaries,
            {
                "warm": {
                    "first_frame_ms": {"p95_ms": 50},
                    "idle.cpu_percent": {"p95_max": 2},
                }
            },
        )
        self.assertEqual(
            failures,
            [
                "warm.first_frame_ms p95=80 exceeded p95_ms=50",
                "warm.idle.cpu_percent p95=3 exceeded p95_max=2",
            ],
        )


if __name__ == "__main__":
    unittest.main()
