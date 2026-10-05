# TUI Interaction Performance Contract

VoidB release evidence measures user-visible terminal interaction in a real
pseudo-terminal. Fixture JSON generation time and intentional test sleeps are
not interaction measurements and cannot satisfy this contract.

This contract applies to the Connection Manager and the retained SSH, Email,
Docker, Kubernetes, S3, WebDAV, and Jenkins standalone TUIs. The normative UX
targets remain in [Standalone TUI UX Acceptance Criteria](standalone-tui-ux-acceptance.md).

## Measurement Points

| Metric | Start | Stop | Local release target |
|---|---|---|---:|
| `first_frame_ms` | child process creation | a journey-specific visible marker is read from the PTY | warm p50 <= 500 ms, warm p95 <= 750 ms |
| `key_to_repaint_ms` | complete key sequence written to the PTY | a state-specific marker appears in output after that write | warm p50 <= 30 ms, warm p95 <= 50 ms |
| `raw_echo_ms` | raw key bytes written | the same bytes or an explicit remote-echo marker is read | warm p95 <= 35 ms, excluding target latency |
| `resize_frame_ms` | `TIOCSWINSZ` applied to the PTY | a stable marker is repainted after the resize | warm p50 <= 60 ms, warm p95 <= 100 ms |
| `quit_restore_ms` | documented quit sequence written | process exit and terminal restore sequences observed | warm p50 <= 150 ms, warm p95 <= 250 ms |
| `stream_cancel_ms` | cancellation key written | cancelled/stopped state is visible and output stops | plugin budget, never more than 1,000 ms locally |
| `idle.cpu_percent` | start of a five-second steady-state window | end of the window | p95 <= 2% of one logical CPU |
| `idle.repaint_hz` | start of the same steady-state window | timestamped PTY output events counted at its end | p95 <= 2 events/s unless a visible spinner is active |

First-frame detection must use a visible product marker, not the first ANSI
control byte. An input or resize marker must occur after the triggering action;
a marker retained from an earlier frame does not count. Remote operations may
have a separate target latency metric, but they must render a local connecting
state inside the first-frame budget.

## Cold, Warm, And CI Runs

- A cold run is the first process launch after the requested binaries are built.
  It records startup without an intentional pre-run. Operating-system caches are
  not flushed, so evidence must not claim hardware-level cold-boot timing.
- Warmup runs exercise the same journey and retain artifacts, but do not
  contribute samples or pass/fail results.
- Warm measured runs execute after warmup. Local development uses at least one
  cold run and three warm runs. CI uses one cold run, one warmup run, and five
  warm measured runs when the host supports stable PTY timing.
- p50 and p95 use linearly interpolated nearest ranks. Every sample is retained
  in `report.json`; a percentile without its samples is not acceptable evidence.

CI may apply a documented multiplier of at most 2.0 to latency thresholds and
4.0 to idle CPU when shared-runner variance is measured. The multiplier must be
recorded in the journey specification and report. Fixed sleeps are allowed only
as observation windows and are never subtracted from a latency.

## Terminal And Lifecycle Evidence

Every measured run records:

- timestamped output transitions with byte offsets and cumulative hashes;
- the raw ANSI transcript and its SHA-256 digest;
- initial and resized terminal dimensions;
- action dispatch, expected marker, observation result, and latency;
- process exit status, forced cleanup, and remaining process-group state;
- alternate-screen enter/leave, cursor hide/show, and bracketed-paste restore
  markers when emitted;
- required UI markers and forbidden secret-shaped markers.

A run fails if the main process or a descendant survives cleanup, a required
transition is missing, the alternate screen or hidden cursor is not restored,
the exit code is unexpected, or a forbidden marker appears. Failure artifacts
must remain under `target/tmp/` and must be safe to upload.

## Journey Specification

[`scripts/tui_journey.py`](../scripts/tui_journey.py) consumes a versioned JSON
specification. This minimal example measures one visible interaction and quit:

```json
{
  "schema_version": 1,
  "name": "connection-manager",
  "command": ["target/debug/voidb", "--connection-manager"],
  "rows": 30,
  "cols": 100,
  "measurement": {"cold_runs": 1, "warmup_runs": 1, "warm_runs": 5},
  "actions": [
    {"type": "wait", "name": "first_frame", "marker": "Connection Manager", "timeout_ms": 1500},
    {"type": "input", "name": "open_help", "data": "?", "marker": "Keyboard", "metric": "key_to_repaint_ms", "timeout_ms": 500},
    {"type": "quit", "name": "quit", "data_hex": "11", "timeout_ms": 500}
  ],
  "thresholds": {
    "warm": {
      "first_frame_ms": {"p50_ms": 500, "p95_ms": 750},
      "key_to_repaint_ms": {"p50_ms": 30, "p95_ms": 50},
      "quit_restore_ms": {"p50_ms": 150, "p95_ms": 250}
    }
  }
}
```

Run it with:

```bash
python3 scripts/tui_journey.py \
  --spec path/to/journey.json \
  --out target/tmp/tui-journeys/connection-manager
```

The output directory contains one `.ansi`, `.events.jsonl`, and `.json` file
per process run plus an aggregate `report.json`. Generated evidence is never
committed.

The blocking release entry point, CI artifact layout, failure reproduction,
and required real-terminal emulator/platform matrix are defined in
[TUI CI And Real-Terminal Coverage](tui-terminal-coverage.md).
