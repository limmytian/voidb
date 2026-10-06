#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUT_DIR="target/tmp/tui-quality-gate"
DIFF_CHECK=1
BUILD=1
CLI_BIN=""
TUI_BIN=""
QUICK_JOURNEYS=0

usage() {
  cat <<'EOF'
Usage: scripts/tui-quality-gate.sh [--out DIR] [--skip-build] [--cli-bin PATH] [--tui-bin PATH] [--quick-journeys] [--no-diff-check]

Runs the retained standalone TUI automated release gate:
- fixture-backed evidence generation for SSH, Docker,
  and Kubernetes structural assertions;
- real-PTY journeys for those three TUIs plus Connection Manager, including
  warm p50/p95 thresholds, idle CPU/repaint, cancellation, and cleanup;
- trend-friendly JSON/Markdown reports and a manifest of retained artifacts.

Options:
  --out DIR          Output directory. Default: target/tmp/tui-quality-gate.
  --skip-build       Use existing binaries instead of building voidb-cli and voidb.
  --cli-bin PATH     voidb-cli binary to smoke. Default: target/debug/voidb-cli.
  --tui-bin PATH     voidb TUI binary to smoke. Default: target/debug/voidb.
  --quick-journeys  Run one transition-only process per journey; not a release gate.
  --no-diff-check   Skip /usr/bin/git diff --check.
  -h, --help        Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --out" >&2
        exit 2
      fi
      OUT_DIR="$2"
      shift 2
      ;;
    --no-diff-check)
      DIFF_CHECK=0
      shift
      ;;
    --skip-build)
      BUILD=0
      shift
      ;;
    --cli-bin)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --cli-bin" >&2
        exit 2
      fi
      CLI_BIN="$2"
      shift 2
      ;;
    --tui-bin)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --tui-bin" >&2
        exit 2
      fi
      TUI_BIN="$2"
      shift 2
      ;;
    --quick-journeys)
      QUICK_JOURNEYS=1
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

cd "${REPO_ROOT}"

if [[ "${BUILD}" -eq 1 ]]; then
  printf '\n==> cargo build -q -p voidb-cli -p voidb-tui\n'
  cargo build -q -p voidb-cli -p voidb-tui
fi

CLI_BIN="${CLI_BIN:-target/debug/voidb-cli}"
TUI_BIN="${TUI_BIN:-target/debug/voidb}"

set +e
python3 - "${OUT_DIR}" "${CLI_BIN}" "${TUI_BIN}" <<'PY'
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import time

out_dir = pathlib.Path(sys.argv[1])
cli_arg = pathlib.Path(sys.argv[2])
tui_arg = pathlib.Path(sys.argv[3])
evidence_dir = out_dir / "evidence"
evidence_dir.mkdir(parents=True, exist_ok=True)
isolated_home = out_dir / "home"
isolated_config = isolated_home / ".config"
isolated_home.mkdir(parents=True, exist_ok=True)
isolated_config.mkdir(parents=True, exist_ok=True)
child_env = os.environ.copy()
child_env["HOME"] = str(isolated_home.resolve())
child_env["XDG_CONFIG_HOME"] = str(isolated_config.resolve())
child_env.pop("VOIDB_MASTER_PASSWORD", None)

repo = pathlib.Path.cwd()
cli = cli_arg if cli_arg.is_absolute() else repo / cli_arg
tui = tui_arg if tui_arg.is_absolute() else repo / tui_arg

if not cli.exists():
    raise SystemExit(f"missing voidb-cli binary: {cli}")
if not tui.exists():
    raise SystemExit(f"missing voidb TUI binary: {tui}")

plugins = [
    {
        "id": "ssh",
        "kind": "ssh_tui_fixture_evidence",
        "fixture": "crates/plugins/voidb-plugin-ssh/fixtures/ssh_tui_terminal_core.json",
    },
    {
        "id": "docker",
        "kind": "docker_tui_fixture_evidence",
        "fixture": "crates/plugins/voidb-plugin-docker/fixtures/docker_tui_operations.json",
    },
    {
        "id": "kubernetes",
        "kind": "kubernetes_tui_fixture_evidence",
        "fixture": "crates/plugins/voidb-plugin-kubernetes/fixtures/kubernetes_tui_operations.json",
    },
]

secret_patterns = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"super-secret-password",
        r"PRIVATE_BODY_SHOULD_NOT_APPEAR",
        r"BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY",
        r"AKIA[0-9A-Z]{16}",
        r"raw_[a-z0-9_]*config",
        r"(?:password|token|secret|key)_value",
        r"fixture-private-key",
        r"passphrase_value",
    ]
]

failures = []
checks = []


def record(name, passed, detail):
    checks.append({"name": name, "passed": bool(passed), "detail": detail})
    if not passed:
        failures.append(f"{name}: {detail}")


def run(cmd, timeout=60):
    print("==> " + shlex.join(str(part) for part in cmd), flush=True)
    start = time.monotonic()
    completed = subprocess.run(
        [str(part) for part in cmd],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        env=child_env,
    )
    elapsed_ms = int((time.monotonic() - start) * 1000)
    if completed.stdout:
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(
            completed.returncode, cmd, output=completed.stdout
        )
    return elapsed_ms


def scan_secret_text(name, text):
    matches = sorted({pattern.pattern for pattern in secret_patterns if pattern.search(text)})
    record(f"{name} secret-shaped transcript scan", not matches, f"matches={matches}")


def validate_quality_gate(plugin, evidence):
    name = plugin["id"]
    text = json.dumps(evidence, sort_keys=True)

    record(f"{name} schema version", evidence.get("schema_version") == 1, "schema_version=1")
    record(f"{name} kind", evidence.get("kind") == plugin["kind"], evidence.get("kind"))

    coverage = set(evidence.get("coverage", []))
    for item in ["startup", "resize", "quit_restore", "secret_leak_scan"]:
        record(f"{name} coverage {item}", item in coverage, sorted(coverage))

    leak_scan = evidence.get("secret_leak_scan", {})
    record(
        f"{name} evidence secret_leak_scan passed",
        leak_scan.get("passed") is True and leak_scan.get("marker_count") == 0,
        leak_scan,
    )

    gate = evidence.get("quality_gate", {})
    record(f"{name} quality_gate present", isinstance(gate, dict), gate)
    record(
        f"{name} quality_gate plugin",
        gate.get("plugin_id") == name,
        gate.get("plugin_id"),
    )
    record(
        f"{name} keyboard accessibility",
        gate.get("accessibility", {}).get("keyboard_only") is True
        and gate.get("accessibility", {}).get("focus_visible") is True,
        gate.get("accessibility", {}),
    )
    contrast_pairs = gate.get("accessibility", {}).get("contrast_pairs", [])
    record(
        f"{name} contrast assertions",
        bool(contrast_pairs) and all(pair.get("passed") is True for pair in contrast_pairs),
        contrast_pairs,
    )
    layout = gate.get("layout", {})
    viewport = layout.get("minimum_viewport", {})
    record(
        f"{name} minimum viewport assertion",
        viewport.get("width", 0) >= 40 and viewport.get("height", 0) >= 10,
        viewport,
    )
    record(
        f"{name} text clipping/layout assertion",
        layout.get("text_clipping_asserted") is True
        and layout.get("bounded_lists_or_logs") is True,
        layout,
    )

    markers = gate.get("first_frame", {}).get("required_markers", [])
    for marker in markers:
        record(f"{name} first-frame marker {marker}", marker in text, marker)

    for marker in layout.get("error_state_markers", []):
        record(f"{name} error-state marker {marker}", marker in text, marker)

    scan_secret_text(name, text)


def run_plugin_evidence(plugin):
    path = evidence_dir / f"{plugin['id']}.json"
    elapsed_ms = run(
        [
            cli,
            plugin["id"],
            "tui",
            "--fixture",
            plugin["fixture"],
            "--evidence",
            path,
        ],
        timeout=30,
    )
    evidence = json.loads(path.read_text())
    validate_quality_gate(plugin, evidence)
    return {
        "id": plugin["id"],
        "evidence_generation_ms": elapsed_ms,
        "path": str(path),
    }


results = {"schema_version": 1, "kind": "voidb_tui_fixture_quality", "plugins": [], "checks": checks}

for plugin in plugins:
    results["plugins"].append(run_plugin_evidence(plugin))

results["checks"] = checks
results["passed"] = not failures
results["failure_count"] = len(failures)
results["failures"] = failures

report_json = out_dir / "fixture-report.json"
report_json.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")

report_md = out_dir / "fixture-report.md"
lines = ["# Retained TUI Fixture Assertions", "", f"Passed: {results['passed']}", ""]
lines.append("| Check | Result | Detail |")
lines.append("|---|---:|---|")
for check in checks:
    detail = json.dumps(check["detail"], sort_keys=True)
    lines.append(
        f"| {check['name']} | {'pass' if check['passed'] else 'fail'} | `{detail}` |"
    )
report_md.write_text("\n".join(lines) + "\n")

print(f"Wrote TUI fixture assertion report to {report_json}")
if failures:
    print("TUI fixture assertions failed:", file=sys.stderr)
    for failure in failures:
        print(f"- {failure}", file=sys.stderr)
    sys.exit(1)
PY
FIXTURE_STATUS=$?

JOURNEY_ARGS=(
  scripts/run_tui_journeys.py
  --out "${OUT_DIR}/journeys"
  --cli-bin "${CLI_BIN}"
  --tui-bin "${TUI_BIN}"
)
if [[ "${QUICK_JOURNEYS}" -eq 1 ]]; then
  JOURNEY_ARGS+=(--quick)
else
  JOURNEY_ARGS+=(--warm-runs 5)
fi

printf '\n==> real-PTY interaction journeys\n'
python3 "${JOURNEY_ARGS[@]}"
JOURNEY_STATUS=$?

if [[ "${DIFF_CHECK}" -eq 1 ]]; then
  printf '\n==> /usr/bin/git diff --check\n'
  /usr/bin/git diff --check
  DIFF_STATUS=$?
else
  DIFF_STATUS=0
fi

REPORT_ARGS=(
  scripts/tui_quality_report.py
  --out "${OUT_DIR}"
  --fixture-status "${FIXTURE_STATUS}"
  --journey-status "${JOURNEY_STATUS}"
  --diff-status "${DIFF_STATUS}"
)
if [[ "${QUICK_JOURNEYS}" -eq 1 ]]; then
  REPORT_ARGS+=(--quick)
fi
python3 "${REPORT_ARGS[@]}"
REPORT_STATUS=$?
set -e

exit "${REPORT_STATUS}"
