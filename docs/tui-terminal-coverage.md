# TUI CI And Real-Terminal Coverage

VoidB uses two complementary gates for the retained terminal applications:

- the automated real-PTY gate measures visible interaction and process
  lifecycle on every supported CI host;
- the manual matrix checks behavior that a bare PTY cannot prove, including a
  terminal emulator's key protocol, font/layout behavior, IME input, and
  multiplexer compatibility.

Fixture evidence remains a structural, accessibility, layout, and redaction
assertion. Its generation duration is not an interaction metric.

## Automated Release Gate

From a clean checkout, run:

```bash
scripts/tui-quality-gate.sh
```

The release mode builds `voidb-cli` and `voidb`, generates structural fixture
evidence, then runs Connection Manager and the seven retained standalone TUIs
through real pseudo-terminals. It uses one cold run, one warmup, and five warm
measured runs in CI. Any journey failure, missing cleanup/restore evidence, or
p50/p95 threshold regression makes the command exit nonzero.

For a fast transition-only diagnostic while editing:

```bash
scripts/tui-quality-gate.sh \
  --skip-build \
  --quick-journeys \
  --out target/tmp/tui-quality-gate-quick
```

Quick mode deliberately removes performance thresholds. Its `report.json`
sets `release_eligible` to `false`, even when every transition passes.

To validate staged binaries, pass their paths explicitly:

```bash
scripts/tui-quality-gate.sh \
  --skip-build \
  --cli-bin /absolute/path/to/voidb-cli \
  --tui-bin /absolute/path/to/voidb \
  --out target/tmp/tui-quality-gate-package
```

## Reports And CI Retention

The default output is `target/tmp/tui-quality-gate/`:

| Path | Purpose |
|---|---|
| `report.json` | Blocking top-level result plus flat, trend-friendly metric rows. |
| `report.md` | Human review summary of components, warm p50/p95, failures, and retention policy. |
| `artifact-manifest.json` | SHA-256 and byte size for every retained report, capture, and evidence file. |
| `fixture-report.json` | Structural/accessibility/layout/security assertions only. |
| `journeys/suite-report.json` | All journey results, thresholds, summaries, and flat trend rows. |
| `journeys/<name>/report.json` | Cold/warm samples and threshold evaluation for one TUI. |
| `journeys/<name>/runs/*` | Raw ANSI, timestamped output events, and per-process diagnostics. |

CI should upload the entire output directory when the gate fails. Do not upload
only `report.json`: the raw ANSI, event timeline, terminal-restore flags, exit
status, and remaining-process-group report are the evidence needed to diagnose
the failure. Captures are fixture-backed and scanned for known secret shapes,
but CI artifact access should still follow the repository's normal private
retention policy.

For trend storage, ingest `trend_metrics` from the top-level report. The stable
dimensions are `journey`, `phase`, and `metric`; the values include sample
count, p50, p95, maximum, and the threshold applied by that run.

## Reproducing A Failure

Run the full release gate first with a new output directory. To isolate one
journey while preserving its thresholds:

```bash
python3 scripts/run_tui_journeys.py \
  --journey kubernetes \
  --warm-runs 5 \
  --out target/tmp/tui-journey-repro
```

Use `--cli-bin` and `--tui-bin` when reproducing a packaged-binary failure.
Compare `report.json` samples rather than a single stopwatch result. A failure
caused by a missing marker should be debugged from the corresponding `.ansi`
and `.events.jsonl` files. A latency failure should be rerun on the same native
runner before changing a budget; budget changes require a documented reason and
must not hide a visible regression.

## Manual Terminal Matrix

Run the row for every platform that release notes claim for interactive TUI
use. Unix releases also need one multiplexer row on any claimed Unix platform.
Rows may be skipped only when that platform is removed from the release claim.

| Platform claim | Required terminal | Additional coverage | Required result |
|---|---|---|---|
| macOS arm64/x64 | Terminal.app on the native architecture | iTerm2 or WezTerm when either is named in release support | All checks below pass; record macOS and terminal versions. |
| Linux x64/arm64 | One native VTE/xterm-compatible emulator such as GNOME Terminal, Konsole, or foot | `tmux` on one claimed Unix platform | All checks below pass; record desktop/TTY and `$TERM`. |
| Windows x64 | Windows Terminal through native ConPTY | PowerShell and the packaged launch shell actually documented for users | All checks below pass; no stuck alternate screen after exit. |

For each row, exercise this focused set:

1. Launch Connection Manager, open search and help, open/cancel the new-profile
   dialog, resize below and above its minimum, enter non-ASCII text through the
   platform IME, and quit with `Ctrl+Q`.
2. Launch the SSH fixture or a disposable SSH profile, review the host-key
   prompt, type raw input, resize, enter the `Ctrl+]` escape layer, return to the
   terminal, and quit. Confirm local escape keys are not forwarded remotely.
3. Launch one operations TUI (Docker, Kubernetes, or Jenkins), navigate, filter,
   open/close help, start and cancel a fixture stream, and recover from the
   visible fixture error.
4. Launch one storage or messaging TUI (S3, WebDAV, or Email), exercise text
   input and a plan/dialog cancellation, resize, and quit.
5. After every exit, verify the shell prompt, echo, cursor, bracketed paste, and
   normal screen buffer are restored. Confirm no VoidB child remains.

Record evidence in this form:

```text
TUI terminal evidence:
- Commit and package artifact:
- Platform and architecture:
- Terminal emulator and version:
- Shell, TERM, and multiplexer:
- Connection Manager result:
- SSH raw-input/escape result:
- Operations TUI result:
- Storage or Email result:
- Terminal restoration result:
- Skipped checks and release-claim impact:
```

The manual matrix is not a substitute for the automated threshold gate, and a
PTY pass is not a substitute for the claimed platform's required manual row.
