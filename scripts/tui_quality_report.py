#!/usr/bin/env python3
"""Combine fixture assertions and real-PTY journeys into CI gate reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import platform
import sys
from typing import Any


def load_json(path: pathlib.Path) -> dict[str, Any]:
    if not path.is_file():
        return {"passed": False, "failures": [f"missing report: {path}"]}
    return json.loads(path.read_text())


def artifact_kind(path: pathlib.Path) -> str:
    if path.suffix == ".ansi":
        return "ansi_transcript"
    if path.name.endswith(".events.jsonl"):
        return "timestamped_output_events"
    if "evidence" in path.parts and path.suffix == ".json":
        return "fixture_evidence"
    if "runs" in path.parts and path.suffix == ".json":
        return "journey_run_report"
    if path.suffix == ".md":
        return "markdown_report"
    if path.suffix == ".json":
        return "json_report"
    return "supporting_artifact"


def artifact_manifest(out_dir: pathlib.Path) -> list[dict[str, Any]]:
    artifacts = []
    for path in sorted(out_dir.rglob("*")):
        if not path.is_file() or path.name == "artifact-manifest.json":
            continue
        payload = path.read_bytes()
        artifacts.append(
            {
                "path": str(path.relative_to(out_dir)),
                "kind": artifact_kind(path.relative_to(out_dir)),
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return artifacts


def failure_captures(
    out_dir: pathlib.Path, journey_report: dict[str, Any]
) -> list[str]:
    failed = {
        item.get("name")
        for item in journey_report.get("journeys", [])
        if not item.get("passed", False)
    }
    captures = []
    for name in sorted(value for value in failed if isinstance(value, str)):
        root = out_dir / "journeys" / name / "runs"
        if root.is_dir():
            captures.extend(str(path.relative_to(out_dir)) for path in sorted(root.iterdir()))
    return captures


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# Retained TUI Quality Gate",
        "",
        f"Passed: {report['passed']}",
        f"Mode: {report['mode']}",
        f"Release eligible: {report['release_eligible']}",
        "",
        "| Component | Result | Report |",
        "|---|---:|---|",
        f"| Fixture structure/accessibility/security | {'pass' if report['components']['fixture']['passed'] else 'fail'} | `{report['components']['fixture']['report']}` |",
        f"| Real PTY interaction thresholds | {'pass' if report['components']['journeys']['passed'] else 'fail'} | `{report['components']['journeys']['report']}` |",
        f"| Diff check | {'pass' if report['components']['diff_check']['passed'] else 'fail'} | `/usr/bin/git diff --check` |",
        "",
        "## Warm Interaction Trends",
        "",
        "| Journey | Metric | Samples | p50 | p95 | Max | Threshold |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for row in report["trend_metrics"]:
        if row.get("phase") != "warm":
            continue
        threshold = json.dumps(row.get("threshold"), sort_keys=True)
        lines.append(
            f"| {row['journey']} | `{row['metric']}` | {row['sample_count']} | {row['p50']} | {row['p95']} | {row['max']} | `{threshold}` |"
        )
    lines.extend(["", "## Failures", ""])
    if report["failures"]:
        lines.extend(f"- {failure}" for failure in report["failures"])
    else:
        lines.append("- None.")
    lines.extend(["", "## Retention", ""])
    lines.append(
        "Upload this entire directory on failure. Raw ANSI, timestamped events, "
        "per-run JSON, aggregate reports, and fixture evidence are checksummed in "
        "`artifact-manifest.json`."
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--fixture-status", type=int, required=True)
    parser.add_argument("--journey-status", type=int, required=True)
    parser.add_argument("--diff-status", type=int, required=True)
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args(argv)

    args.out.mkdir(parents=True, exist_ok=True)
    fixture_path = args.out / "fixture-report.json"
    journey_path = args.out / "journeys" / "suite-report.json"
    fixture = load_json(fixture_path)
    journeys = load_json(journey_path)
    fixture_passed = args.fixture_status == 0 and fixture.get("passed") is True
    journey_passed = args.journey_status == 0 and journeys.get("passed") is True
    diff_passed = args.diff_status == 0
    failures = [f"fixture: {failure}" for failure in fixture.get("failures", [])]
    failures.extend(f"journey: {failure}" for failure in journeys.get("failures", []))
    if not diff_passed:
        failures.append("/usr/bin/git diff --check failed")

    passed = fixture_passed and journey_passed and diff_passed
    report = {
        "schema_version": 2,
        "kind": "voidb_retained_tui_quality_gate",
        "mode": "quick-diagnostic" if args.quick else "release",
        "passed": passed,
        "release_eligible": passed and not args.quick,
        "environment": {
            "platform": sys.platform,
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "components": {
            "fixture": {"passed": fixture_passed, "report": str(fixture_path)},
            "journeys": {"passed": journey_passed, "report": str(journey_path)},
            "diff_check": {"passed": diff_passed},
        },
        "trend_metrics": journeys.get("trend_metrics", []),
        "failure_captures": failure_captures(args.out, journeys),
        "failures": failures,
        "artifact_manifest": str(args.out / "artifact-manifest.json"),
    }
    report_path = args.out / "report.json"
    markdown_path = args.out / "report.md"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    markdown_path.write_text(markdown_report(report))

    manifest = {
        "schema_version": 1,
        "kind": "voidb_tui_quality_artifact_manifest",
        "retain_entire_directory_on_failure": True,
        "artifacts": artifact_manifest(args.out),
    }
    (args.out / "artifact-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps({"passed": passed, "report": str(report_path)}))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
