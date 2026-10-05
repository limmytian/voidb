#!/usr/bin/env python3
"""Run the checked-in real-PTY journeys and write a suite report."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

import tui_journey


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC_ROOT = pathlib.Path(__file__).resolve().parent / "tui-journeys"


def load_catalog() -> dict[str, pathlib.Path]:
    return {path.stem: path for path in sorted(SPEC_ROOT.glob("*.json"))}


def prepare_spec(
    path: pathlib.Path,
    *,
    cli_bin: pathlib.Path,
    tui_bin: pathlib.Path,
    quick: bool,
    warm_runs: int | None,
) -> dict[str, Any]:
    spec = tui_journey.load_spec(path)
    spec["cwd"] = str(REPO_ROOT)
    command = spec.get("command", [])
    if command and command[0] == "${VOIDB_CLI}":
        command[0] = str(cli_bin.resolve())
    elif command and command[0] == "${VOIDB_TUI}":
        command[0] = str(tui_bin.resolve())
    if quick:
        spec["measurement"] = {"cold_runs": 1, "warmup_runs": 0, "warm_runs": 0}
        spec["thresholds"] = {}
        for action in spec.get("actions", []):
            if action.get("type") == "idle":
                action["duration_ms"] = 250
    elif warm_runs is not None:
        spec["measurement"]["warm_runs"] = warm_runs
    return spec


def trend_rows(name: str, report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    thresholds = report.get("thresholds", {})
    for phase, metrics in sorted(report.get("summary", {}).items()):
        for metric, values in sorted(metrics.items()):
            rows.append(
                {
                    "journey": name,
                    "phase": phase,
                    "metric": metric,
                    "sample_count": len(values.get("samples", [])),
                    "p50": values.get("p50"),
                    "p95": values.get("p95"),
                    "max": values.get("max"),
                    "threshold": thresholds.get(phase, {}).get(metric),
                }
            )
    return rows


def main(argv: list[str] | None = None) -> int:
    catalog = load_catalog()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--journey",
        action="append",
        choices=sorted(catalog),
        help="Run only this journey; repeat to select several.",
    )
    parser.add_argument(
        "--warm-runs",
        type=int,
        help="Override measured warm runs; release CI uses 5.",
    )
    parser.add_argument("--out", type=pathlib.Path, default=REPO_ROOT / "target/tmp/tui-journeys")
    parser.add_argument("--cli-bin", type=pathlib.Path, default=REPO_ROOT / "target/debug/voidb-cli")
    parser.add_argument("--tui-bin", type=pathlib.Path, default=REPO_ROOT / "target/debug/voidb")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run one transition-only process per journey without performance thresholds.",
    )
    parser.add_argument("--list", action="store_true", help="List journey names and exit.")
    args = parser.parse_args(argv)

    if args.warm_runs is not None and args.warm_runs < 1:
        parser.error("--warm-runs must be at least 1")
    if args.quick and args.warm_runs is not None:
        parser.error("--quick and --warm-runs cannot be combined")

    if args.list:
        print("\n".join(sorted(catalog)))
        return 0

    selected = args.journey or list(catalog)
    args.out.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    trends: list[dict[str, Any]] = []
    for name in selected:
        spec = prepare_spec(
            catalog[name],
            cli_bin=args.cli_bin,
            tui_bin=args.tui_bin,
            quick=args.quick,
            warm_runs=args.warm_runs,
        )
        print(f"==> real-PTY journey: {name}", flush=True)
        try:
            report = tui_journey.run_plan(spec, args.out / name)
            trends.extend(trend_rows(name, report))
            results.append(
                {
                    "name": name,
                    "passed": report["passed"],
                    "failures": report["failures"],
                    "report": report["report_path"],
                    "measurement": report["measurement"],
                    "summary": report["summary"],
                    "thresholds": report["thresholds"],
                }
            )
        except tui_journey.JourneyError as error:
            results.append(
                {"name": name, "passed": False, "failures": [str(error)], "report": None}
            )

    failures = [
        f"{result['name']}: {failure}"
        for result in results
        for failure in result["failures"]
    ]
    suite = {
        "schema_version": 1,
        "kind": "voidb_tui_journey_suite",
        "quick": args.quick,
        "journeys": results,
        "trend_metrics": trends,
        "failures": failures,
        "passed": not failures,
    }
    suite_path = args.out / "suite-report.json"
    suite_path.write_text(json.dumps(suite, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"passed": suite["passed"], "report": str(suite_path)}))
    if failures:
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
    return 0 if suite["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
