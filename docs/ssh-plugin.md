# SSH Plugin

The SSH plugin provides SSH capabilities, direct CLI commands, and a
plugin-owned standalone TUI for interactive terminal workflows. The new TUI is
launched from the SSH plugin CLI entrypoint rather than the legacy router-hosted
shell.

## Connection Setup

Create an SSH connection from the Connection Manager (home screen). VoidB supports three authentication methods:

### Password

Provide username and password directly. Credentials are encrypted at rest using AES-256-GCM.

### Public Key

Specify the path to your private key (e.g., `~/.ssh/id_ed25519`). An optional passphrase can be provided for encrypted keys.

### SSH Agent

Delegates authentication to your running SSH agent (via `SSH_AUTH_SOCK`). No credentials are stored.

## Agent Capability Surface

The SSH plugin exposes the following generic invoke capabilities for agents and
automation. Release-facing evidence is recorded in
[Release Plugin Smoke](release-plugin-smoke.md#ssh-live-smoke) and
SSH Release Readiness.

| Capability | Purpose | Effective risk | Dry-run |
|---|---|---|---|
| `ssh.test` | Connect and authenticate without opening an interactive shell. | `read_only` | No |
| `ssh.exec` | Run one remote command and return bounded stdout, stderr, and exit status. | `destructive` | Yes |
| `ssh.terminal_read` | Read bounded incremental output from an agent-owned interactive PTY. | `read_only` | No |
| `ssh.terminal_snapshot` | Read the current plain-text PTY screen, cursor, size, and terminal modes. | `read_only` | No |
| `ssh.terminal_write` | Write bounded text, paste envelopes, or named keys to an agent-owned PTY. | `destructive` | No |
| `ssh.terminal_resize` | Resize an agent-owned PTY and its terminal parser. | `destructive` | No |
| `ssh.terminal_signal` | Send `INT`, `TERM`, `HUP`, `QUIT`, or `KILL` to an agent-owned PTY. | `destructive` | No |
| `ssh.sftp_list` | List a remote directory with bounded cursor pagination. | `read_only` | No |
| `ssh.sftp_get` | Create one local file under an approved root from remote bytes. | `mutating` | No |
| `ssh.sftp_put` | Read one file under an approved local root and upload it. | `destructive` | Yes |
| `ssh.sftp_mkdir` | Create one remote directory. | `destructive` | Yes |
| `ssh.sftp_rm` | Remove one remote file. | `destructive` | Yes |
| `ssh.diagnostics` | Return safe profile diagnostics without opening a network connection. | `read_only` | No |

Non-interactive capability paths use strict `known_hosts` verification. Unknown
or changed host keys fail with structured target error codes
`ssh.host_key_unknown` or `ssh.host_key_changed`; they are not silently learned.
Use the TUI host-key prompt or an explicit `ssh-keyscan` workflow to establish
trust before running agent invocations.

Mutating operations and `ssh.exec` are marked destructive. They require either
an accepted `--dry-run` path or an explicit `--yes` acknowledgement, and audit
summaries must not include passwords, passphrases, private key material, raw
`plugin_config`, or credential-bearing connection details.

## Standalone TUI

Launch the retained SSH terminal TUI through the plugin command:

```bash
voidb-cli ssh tui --profile <profile>
voidb-cli ssh tui --profile <profile> --format json
voidb-cli ssh tui --fixture crates/plugins/voidb-plugin-ssh/fixtures/ssh_tui_terminal_core.json
voidb-cli ssh tui --fixture crates/plugins/voidb-plugin-ssh/fixtures/ssh_tui_terminal_core.json \
  --evidence target/tmp/ssh-tui-fixture-evidence.json
```

The preflight JSON is secret-free: it includes the profile label, purpose,
credential reference count, redaction status, and launch policy, but never
passwords, private key material, passphrases, or decrypted plugin config. The
runtime consumes `SshService` channel mode for PTY input/output, resize,
host-key decisions, SFTP browsing, port-forwarding lifecycle, metrics refresh,
disconnects, and reconnect requests.

Raw terminal input belongs to the remote PTY. Press `Ctrl+]` to open the local
plugin escape layer. Use `q` to quit, `r` to reconnect, `s` for SFTP, `f` for
forwarding, `m` for the session monitor, `t` for terminal, or `?` for help.
Bracketed paste is enabled while the standalone TUI is active, so pasted UTF-8
text is forwarded to the remote PTY in one batch instead of being replayed as
individual key events. Paste input is ignored outside terminal mode and while
the local escape layer is armed.
The standalone TUI recognizes both enhanced-keyboard `Ctrl+]` events and the
legacy terminal `Ctrl+5` decoding of the same control byte. `Ctrl+\` is no
longer reserved by the standalone escape layer.

The standalone SFTP pane consumes the service-owned `SftpHandle`. It lists
remote entries, navigates directories, stages upload/download/delete plans, and
requires explicit confirmation before sending mutating SFTP commands. Delete
plans require a second confirmation key. Download progress is shown in the pane
when the worker emits transfer progress events.

The standalone forwarding pane stages local (`-L`), remote (`-R`), and dynamic
SOCKS5 (`-D`) rules, then submits confirmed rules through
`SshCommand::Forward`. Runtime status updates are shown as service events arrive,
and selected rules can be stopped from the pane. The session monitor requests
metrics through `SshCommand::Metrics` and shows the latest snapshot without
blocking terminal input.

External-agent access is governed by the shared
[External Agent Session Access Contract](assist-handoff.md). Conversation stays
in the external agent. From the escape layer, press `a` to share or refresh the
current bounded, redacted terminal view; the SSH TUI does not collect prompts
or render an agent chat. Set `VOIDB_SSH_AGENT_SESSION_DIR` to override the local
share store for tests or external agent processes. The legacy environment name
is accepted only for compatibility.

External agents use `voidb-cli ssh session list/show/input` against the same
store. The TUI refreshes the shared screen and transcript context non-blockingly
and opens a compact operation review when the agent requests PTY input. Use
`j/k` to select an operation, `y` to approve it once, `n` or `x` to deny it, or
`A` to approve it and allow subsequent current-PTY operations from that exact
agent principal for the lifetime of the share. `voidb-cli ssh assist` remains a
compatibility alias.

Alternate-screen and application-key terminal states are shown as warnings in
the operation review instead of overriding the local operator's decision. A
confirmed operation still acquires the existing single-writer lease before its
input is sent, and the warning acceptance is retained in the confirmation and
audit summaries. Operation confirmations are one-shot: the review closes after
the first decision, and the store rejects repeated confirmation of the same
operation request and operation index.

Agent-side inspection is the default diagnostic route and uses a separate
authorized session. Current-PTY command execution is available only for
`CurrentPty` actions after explicit confirmation. The SSH TUI owns a visible
input-owner state (`human`, `agent-observe`, `agent-control`, `revoking`, or
`closed`), applies a short TTL, records dropped input, blocks stale or risky
takeover contexts, and lets the human revoke immediately with `Ctrl+]` then
`v`. While the agent owns PTY input, ordinary human terminal keys—including
queued repeat approvals—are dropped instead of becoming a second writer. The
SSH service still keeps live PTY handles inside the plugin boundary.

`--evidence` writes deterministic fixture-backed JSON for release notes and
local smoke review. It records startup transcript lines, host-key prompt shape,
SFTP/forwarding/metrics fixture state, external-agent interaction controls, the
disconnected/error recovery contract, residual live-smoke items, and a
marker-based secret-leak scan. The evidence command exits before opening a
network session.

## Raw Input Mode

The SSH plugin uses **raw input mode** (`wants_raw_input() == true`) when connected to a
terminal. This means the shell's soft global shortcuts (`q`, `Q`, `Ctrl+L`) are bypassed
and all key events are forwarded directly to the remote shell.

To access shell-level operations (close tab, switch tab, go home) while in an SSH session,
use the **shell escape menu**: press `Ctrl+\`.

When disconnected or in non-terminal views (SFTP, port forwarding), raw mode is disabled
and standard soft globals work normally.

## Terminal

The terminal emulator provides full ANSI support via vt100 parsing, including:

- 256-color and RGB color
- Bold, italic, underline, inverse text attributes
- Cursor positioning and alternate screen
- Interactive programs (vim, top, htop, etc.)

### Keybindings

| Key | Action |
|-----|--------|
| Any key | Sent to remote shell |
| PgUp/PgDn | Scroll terminal output |
| Ctrl+F | Switch to SFTP file browser |
| Ctrl+P | Switch to port forwarding panel |
| Ctrl+R | Manual reconnect (when disconnected) |
| Ctrl+\ | Shell escape menu (close tab, switch tab, etc.) |

## SFTP File Browser

Press **Ctrl+F** to open the dual-panel SFTP browser. The left panel shows local files; the right panel shows remote files.

### Navigation

| Key | Action |
|-----|--------|
| Tab | Switch between local and remote panels |
| Up/Down | Move selection |
| Enter | Open directory / descend into folder |
| Backspace | Go to parent directory |
| Home / g | Jump to top |
| End / G | Jump to bottom |

### File Operations

| Key | Action |
|-----|--------|
| d | Download selected remote file(s) to local panel's directory |
| u | Upload selected local file(s) to remote panel's directory |
| Space | Toggle selection on current item |
| Ctrl+A | Select / deselect all items |
| Delete | Delete selected file or directory |
| r | Rename selected file or directory |
| m | Create new directory |
| c | Change permissions (chmod) |
| . | Toggle hidden files |
| F5 | Refresh current panel |
| Esc | Cancel active transfer |

### Transfer Progress

Active transfers display a progress bar with filename, percentage, speed (KB/s or MB/s), and estimated time remaining.

### Session Persistence

The SFTP browser remembers your last remote and local paths. When you reopen a connection, it navigates back to where you left off.

## Port Forwarding

Press **Ctrl+P** to open the port forwarding panel. VoidB supports all three SSH forwarding modes:

### Local Forwarding (-L)

Listen on a local port and forward traffic through the SSH tunnel to a remote destination.

Example: Forward local port 8080 to `db.internal:5432` on the remote network.

### Remote Forwarding (-R)

Listen on a port on the remote server and forward traffic back to your local machine.

Example: Expose local port 3000 on the remote server's port 3000.

### Dynamic SOCKS5 (-D)

Create a local SOCKS5 proxy that routes all traffic through the SSH tunnel.

Example: Listen on `127.0.0.1:1080` as a SOCKS5 proxy.

### Forwarding Keybindings

| Key | Action |
|-----|--------|
| a | Add new forwarding rule |
| d / Delete | Remove selected rule |
| Up/Down | Navigate rules |

The panel displays live stats: bytes sent/received, active connections, and total connections.

## Configuration

SSH connections support the following options (configurable via connection dialog):

### Terminal

| Option | Default | Description |
|--------|---------|-------------|
| `term_type` | `xterm-256color` | Terminal type string sent to server |
| `scrollback` | `1000` | Scrollback buffer size in lines |

### Connection

| Option | Default | Description |
|--------|---------|-------------|
| `keep_alive_interval` | `30` | Keepalive interval in seconds (0 = disabled) |
| `connect_timeout` | `10` | Connection timeout in seconds |
| `max_reconnect_attempts` | `5` | Auto-reconnect attempts (0 = disabled) |
| `reconnect_base_delay` | `1` | Base delay for exponential backoff in seconds |

## Auto-Reconnect

When an active connection drops, VoidB automatically attempts to reconnect with exponential backoff:

- Delay doubles each attempt: 1s, 2s, 4s, 8s, 16s (capped)
- Random jitter is added to prevent thundering herd
- After max attempts, reconnect stops; press **Ctrl+R** to retry manually
- A successful reconnect resets the attempt counter

## Host Key Verification

On first connection to a new host, VoidB displays the server's key fingerprint and asks for confirmation. Once accepted, the key is stored in `~/.ssh/known_hosts`. If the key changes, a warning is shown.

## Release Smoke Fixture Strategy

Use a disposable local or containerized OpenSSH server for release smoke. The
fixture should be resettable and isolated from personal hosts so host-key
unknown and changed-key cases can be exercised without editing real production
entries.

The local fixture helper provisions the disposable OpenSSH server, generated
credentials, run-scoped host keys, scratch directory, strict `known_hosts`
file, redacted logs, evidence, and teardown:

```bash
scripts/local-fixture-smoke.sh run \
  --fixture ssh \
  --report target/tmp/local-fixture-ssh-evidence.md
```

Use the split lifecycle when a follow-up capability or TUI smoke needs the
fixture to stay running while commands execute:

```bash
scripts/local-fixture-smoke.sh start --fixture ssh --run-id ssh-smoke-001
scripts/local-fixture-smoke.sh wait --fixture ssh --run-id ssh-smoke-001
source target/fixtures/ssh-smoke-001/ssh.env
scripts/local-fixture-smoke.sh logs --fixture ssh --run-id ssh-smoke-001
scripts/local-fixture-smoke.sh teardown --fixture ssh --run-id ssh-smoke-001
```

`wait` scans the fixture host keys and requires a strict `known_hosts`
public-key `ssh` command to succeed before reporting the fixture as ready. The
generated env file includes a password and private key path for local smoke
only; do not commit it or copy values into release evidence.

For automated capability and service readiness evidence, use the SSH wrapper:

```bash
scripts/ssh-fixture-smoke.sh \
  --report target/tmp/ssh-fixture-smoke-evidence.md
```

The wrapper starts the local fixture, generates a changed-key `known_hosts`
file for negative host-key policy coverage, exercises direct `ssh.*`
capabilities, checks password and public-key auth, drives channel-mode PTY
input, SFTP worker listing, local forwarding status, reconnect events, and
redaction checks, then captures logs and tears the fixture down.

Recommended fixture coverage:

- Password auth for a non-privileged test user.
- Public-key auth with an encrypted or unencrypted test key.
- SSH-agent auth with the same public key loaded through `ssh-add`.
- A scratch remote directory owned by the test user for SFTP operations.
- A command that writes stdout, writes stderr, and exits with a non-zero status.
- A controlled host-key reset path, usually by recreating the container with new
  host keys.
- A simple TCP target behind the SSH server for local, remote, or dynamic
  forwarding smoke.

Use these environment names in release notes or local scripts so smoke commands
stay portable:

```bash
export VOIDB_SSH_SMOKE_PROFILE=ssh-smoke
export VOIDB_SSH_SMOKE_HOST=127.0.0.1
export VOIDB_SSH_SMOKE_PORT=2222
export VOIDB_SSH_SMOKE_USER=voidb
export VOIDB_SSH_SMOKE_PASSWORD=<generated>
export VOIDB_SSH_SMOKE_PRIVATE_KEY_PATH=target/fixtures/ssh-smoke-001/ssh-config/client_ed25519
export VOIDB_SSH_SMOKE_KNOWN_HOSTS=target/fixtures/ssh-smoke-001/ssh_known_hosts
export VOIDB_SSH_SMOKE_CHANGED_KNOWN_HOSTS=target/fixtures/ssh-smoke-001/ssh-config/changed-host-keys/changed_known_hosts
export VOIDB_SSH_SMOKE_SCRATCH=/config/voidb-smoke-ssh-smoke-001
export VOIDB_SSH_SMOKE_REMOTE_FILE=/config/voidb-smoke-ssh-smoke-001/fixture.txt
```

Create the `VOIDB_SSH_SMOKE_PROFILE` profile through the Connection Manager or
use an existing migrated SSH profile with one of the auth methods above. Do not
commit fixture passwords, private keys, key passphrases, or generated
`known_hosts` entries.

Host-key cases:

1. Unknown host: remove only the fixture entry from `~/.ssh/known_hosts` and
   confirm `voidb-cli invoke run ssh.test ...` fails with
   `ssh.host_key_unknown`.
2. Trusted host: accept the key in the TUI prompt or add it with `ssh-keyscan`,
   then confirm `ssh.test` succeeds.
3. Changed host: recreate the fixture with a new host key and confirm
   non-interactive invoke fails with `ssh.host_key_changed`; the TUI should show
   the changed-key warning and must not silently accept it.

## Capability Smoke Commands

Run these against the fixture profile before promoting SSH for a release:

```bash
voidb-cli invoke list ssh --format json
voidb-cli invoke describe ssh.exec --format json
voidb-cli invoke describe ssh.sftp_put --format json
voidb-cli invoke run ssh.diagnostics \
  --profile "$VOIDB_SSH_SMOKE_PROFILE" \
  --input-json '{}' \
  --format json
voidb-cli invoke run ssh.test \
  --profile "$VOIDB_SSH_SMOKE_PROFILE" \
  --input-json '{}' \
  --format json
voidb-cli invoke run ssh.exec \
  --profile "$VOIDB_SSH_SMOKE_PROFILE" \
  --input-json '{"command":"printf ok; printf err >&2; exit 7","max_stdout_bytes":1024,"max_stderr_bytes":1024}' \
  --yes \
  --format json
voidb-cli invoke run ssh.sftp_list \
  --profile "$VOIDB_SSH_SMOKE_PROFILE" \
  --input-json '{"path":"."}' \
  --page-limit 20 \
  --format json
voidb-cli invoke run ssh.sftp_mkdir \
  --profile "$VOIDB_SSH_SMOKE_PROFILE" \
  --input-json '{"path":"voidb-smoke"}' \
  --dry-run \
  --format json
voidb-cli invoke run ssh.sftp_mkdir \
  --profile "$VOIDB_SSH_SMOKE_PROFILE" \
  --input-json '{"path":"voidb-smoke"}' \
  --yes \
  --format json
voidb-cli invoke run ssh.sftp_put \
  --profile "$VOIDB_SSH_SMOKE_PROFILE" \
  --input-json "{\"local_root\":\"$PWD/tmp\",\"local_path\":\"voidb-ssh-smoke.txt\",\"remote_path\":\"voidb-smoke/voidb-ssh-smoke.txt\"}" \
  --yes \
  --format json
voidb-cli invoke run ssh.sftp_get \
  --profile "$VOIDB_SSH_SMOKE_PROFILE" \
  --input-json "{\"remote_path\":\"voidb-smoke/voidb-ssh-smoke.txt\",\"local_root\":\"$PWD/tmp\",\"local_path\":\"voidb-ssh-smoke.downloaded\"}" \
  --format json
voidb-cli invoke run ssh.sftp_rm \
  --profile "$VOIDB_SSH_SMOKE_PROFILE" \
  --input-json '{"path":"voidb-smoke/voidb-ssh-smoke.txt"}' \
  --yes \
  --format json
```

The `ssh.exec` smoke should return `exit_status = 7`, bounded `stdout` and
`stderr`, and truncation metadata showing no truncation at the requested limits.
SFTP mutation dry-runs should report planned actions without changing the
remote fixture.

`scripts/ssh-fixture-smoke.sh` automates the same capability boundary against
the local fixture. Use the manual commands above when debugging a saved profile
or when comparing CLI output with release evidence.

## Persistent Agent Shell

An SSH-scoped agent grant can open an `interactive_terminal` session restricted
to `ssh.exec`. The broker constructs the factory from the grant's immutable
Profile ID and decrypted configuration in memory; the SSH plugin then owns the
authenticated transport and one long-lived non-PTY `sh -s` channel.

Each call sends a safely quoted command through `eval` in the same shell process,
so `cd`, shell variables, exported environment, and process context survive the
next call. A random nonce plus ASCII record/unit separators frames stdout and the
exit code. Command stdin is redirected from `/dev/null` so a command cannot
consume the next frame. Stdout and stderr are collected independently, bounded,
UTF-8 safe, and redacted against known profile values before the broker sees the
result.

Calls are serialized. Timeout or explicit cancellation closes the shell channel;
close, lease expiry, grant use exhaustion, and revoke disconnect the underlying
SSH transport. The implementation does not reconnect a closed shell under the
same generation because cwd, variables, and child-process state cannot be
reconstructed safely.

## Agent-Owned Interactive PTY

Interactive programs use a separate persistent session surface rather than
changing the structured `ssh.exec` contract. Open an `interactive_terminal`
session with one or more of `ssh.terminal_read`, `ssh.terminal_snapshot`,
`ssh.terminal_write`, `ssh.terminal_resize`, and `ssh.terminal_signal`. The
presence of terminal capabilities selects a real SSH PTY; `ssh.exec` cannot be
mixed into the same session binding.

The PTY service retains at most 256 KiB of raw terminal output. Reads use
monotonic byte offsets and report `gap=true` when a slow reader falls behind
the retained window. `terminal_snapshot` passes the retained stream through the
plugin-owned VT100 parser and returns plain screen lines, cursor position,
dimensions, alternate-screen/application-key/bracketed-paste modes, title,
health, and the latest output offset. Incremental text and snapshots are
redacted against known profile values before leaving the plugin.

`terminal_write` accepts UTF-8 text, optional bracketed-paste framing, `enter`,
and named keys. Named keys include navigation/editing keys, `F1` through `F12`,
and `CTRL_A` through `CTRL_Z`. Control bytes embedded directly in `text` are
rejected. A password, passphrase, verification-code, or OTP prompt near the
cursor blocks text and ordinary keys; `ESC`, `CTRL_C`, `CTRL_Z`, and
`CTRL_BACKSLASH` remain available as recovery input. Raw input content is not
included in the capability result or agent-session audit metadata.

PTY control is intentionally excluded from the shared `Interactive/Execute`
preset. Authorize it as an explicit short-lived Custom grant with destructive
access, and select the terminal capabilities again when opening the session:

```bash
voidb-cli agent authorize \
  --profile id:<profile-id> --plugin ssh --preset custom \
  --capability ssh.terminal_read \
  --capability ssh.terminal_snapshot \
  --capability ssh.terminal_write \
  --capability ssh.terminal_resize \
  --capability ssh.terminal_signal \
  --allow-destructive --yes --uses 100

voidb-cli agent session open \
  --grant <grant-id> --purpose interactive_terminal \
  --capability ssh.terminal_read \
  --capability ssh.terminal_snapshot \
  --capability ssh.terminal_write \
  --capability ssh.terminal_resize \
  --capability ssh.terminal_signal \
  --input-json '{"cols":120,"rows":40}'

voidb-cli agent session call --grant <grant-id> <session-id> \
  --capability ssh.terminal_write \
  --input-json '{"text":"vim /tmp/example.txt","enter":true}' --yes

voidb-cli agent session call --grant <grant-id> <session-id> \
  --capability ssh.terminal_snapshot --input-json '{}'
```

Each accepted open/call consumes one grant use, so interactive grants normally
need a larger bounded use count than one-shot command grants. PTY reads support
an optional `wait_ms` up to 1000 milliseconds to reduce empty polling. Session
close, lease expiry, use exhaustion, or revoke closes the SSH PTY. This direct
backend does not survive an SSH transport loss; durable remote jobs still need
a remote supervisor such as tmux or systemd.

## Human TUI Smoke Checklist

Run `cargo run`, open the fixture profile from the Connection Manager, and
verify these flows:

- Unknown host key shows a fingerprint prompt; accepting it writes the fixture
  key to `known_hosts`.
- Changed host key shows the warning path and does not open an interactive
  session until trust is repaired.
- Terminal mode forwards normal keys, control keys, and full-screen programs to
  the remote PTY. Soft globals `q`, `Q`, and `Ctrl+L` are bypassed while raw
  input is active.
- `Ctrl+\` opens the shell escape menu from a connected terminal tab.
- `Ctrl+F` opens SFTP; local and remote panels navigate, refresh, upload,
  download, create directory, delete, rename, chmod, and remember their last
  paths after reconnect.
- `Ctrl+P` opens port forwarding; local, remote, and dynamic forwarding rules
  can be added, show traffic counters, and can be removed without hanging the
  terminal session.
- Dropping the fixture connection triggers exponential reconnect attempts, and
  `Ctrl+R` starts a manual reconnect after automatic attempts stop.
- Closing and reopening the SSH tab restores session-scoped SFTP path state and
  does not require shell-owned focus or notification state.

## Release Gate Commands

Focused SSH changes should run:

```bash
cargo check -p voidb-plugin-ssh --example fixture_smoke
cargo test -p voidb-plugin-ssh capabilities
cargo test -p voidb-plugin-ssh service
cargo test -p voidb-plugin-ssh
cargo test -p voidb-cli invoke
cargo test -p voidb-core profile_adapter
cargo test -p voidb-core profile_store
git diff --check
```

For external session sharing, operation approval, current-PTY ownership, or evidence
changes, also run:

```bash
cargo test -p voidb-core assist
cargo test -p voidb-core session
cargo test -p voidb-cli agent_broker
cargo test -p voidb-plugin-ssh assist
cargo run -p voidb-cli -- ssh tui \
  --fixture crates/plugins/voidb-plugin-ssh/fixtures/ssh_tui_terminal_core.json \
  --evidence target/tmp/ssh-tui-fixture-evidence.json
```

For release candidates or broad policy changes, also run the full workspace and
clippy tiers from [CI Check Tiers](ci-checks.md).

## Residual Risk

Live SSH smoke remains fixture-dependent and is intentionally not part of the
default unit-test tier because it needs a disposable SSH server, generated host
keys, and local credential setup. Req63 records local OpenSSH fixture-backed
password and public-key coverage in SSH Release Readiness.
Release notes should still state whether SSH-agent auth and manual TUI checks
for `Ctrl+]`, external-agent session share/input, current-PTY revoke, forwarding
panel UI, and SFTP path persistence were run.
