#!/usr/bin/env python3
"""Focused tests for the retained TUI CI report combiner."""

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

import tui_quality_report


class TuiQualityReportTests(unittest.TestCase):
    def write_inputs(self, root: pathlib.Path, *, journey_passed: bool) -> None:
        (root / "journeys" / "docker" / "runs").mkdir(parents=True)
        (root / "fixture-report.json").write_text(
            json.dumps({"passed": True, "failures": []})
        )
        failure = "warm.first_frame_ms p95=900 exceeded p95_ms=750"
        (root / "journeys" / "suite-report.json").write_text(
            json.dumps(
                {
                    "passed": journey_passed,
                    "failures": [] if journey_passed else [f"docker: {failure}"],
                    "journeys": [
                        {"name": "docker", "passed": journey_passed, "failures": []}
                    ],
                    "trend_metrics": [
                        {
                            "journey": "docker",
                            "phase": "warm",
                            "metric": "first_frame_ms",
                            "sample_count": 5,
                            "p50": 500,
                            "p95": 900,
                            "max": 920,
                            "threshold": {"p95_ms": 750},
                        }
                    ],
                }
            )
        )
        (root / "journeys" / "docker" / "runs" / "failed.ansi").write_bytes(
            b"redacted failure screen"
        )

    def test_threshold_failure_is_blocking_and_retains_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_inputs(root, journey_passed=False)
            status = tui_quality_report.main(
                [
                    "--out",
                    str(root),
                    "--fixture-status",
                    "0",
                    "--journey-status",
                    "1",
                    "--diff-status",
                    "0",
                ]
            )
            report = json.loads((root / "report.json").read_text())
            manifest = json.loads((root / "artifact-manifest.json").read_text())
            self.assertEqual(status, 1)
            self.assertFalse(report["passed"])
            self.assertFalse(report["release_eligible"])
            self.assertIn(
                "journeys/docker/runs/failed.ansi", report["failure_captures"]
            )
            self.assertTrue(manifest["retain_entire_directory_on_failure"])

    def test_quick_success_is_diagnostic_not_release_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_inputs(root, journey_passed=True)
            status = tui_quality_report.main(
                [
                    "--out",
                    str(root),
                    "--fixture-status",
                    "0",
                    "--journey-status",
                    "0",
                    "--diff-status",
                    "0",
                    "--quick",
                ]
            )
            report = json.loads((root / "report.json").read_text())
            self.assertEqual(status, 0)
            self.assertTrue(report["passed"])
            self.assertFalse(report["release_eligible"])
            self.assertEqual(report["mode"], "quick-diagnostic")


if __name__ == "__main__":
    unittest.main()
