# Changelog

All notable changes to VoidB will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`vb plugin update --all`**: one command updates every installed plugin with a newer registry version. Prints the plan (installed → target), requires a typed `UPDATE` confirmation on a terminal or `--yes` for scripts, honors `--dry-run`, and continues past per-plugin failures with a structured summary (`updated`, `up_to_date`, `failed`).

## [0.4.1] - 2026-11-06

### Added
- **MCP gateway (`vb mcp serve`)**: a Model Context Protocol stdio server (spec revision 2025-06-18) that exposes the installed capability catalog as MCP tools. Every `tools/call` is broker-gated exactly like `agent exec` — the server runs on raw configuration, never holds the master password, and missing grants return the stable `authorization.grant_required` execution error with ready-to-run `vb agent authorize` guidance. Tools carry the declared JSON Schemas and risk-mapped annotations (`readOnlyHint`/`destructiveHint`); resources expose the capability matrix (full builds) and redacted profile references. See `docs/mcp-server.md` and `docs/adr-mcp-agent-gateway.md`; verified end to end by `scripts/mcp-fixture-smoke.sh`.
- **`vb credential master setup`**: configures master-password protection on a legacy default-passphrase config (double prompt or `--new-password-env`, refuses an already-protected config, `--yes`/`--dry-run` gated).
- **`vb credential master unlock`**: verifies the master password and reports the process unlock state; one-shot CLI processes never retain it, and non-TTY callers are guided to `VOIDB_MASTER_PASSWORD` or `--password-env`.
- **`vb credential master forget`**: redacted no-op stating exactly that one-shot CLI commands never retain master-password state.
- **`vb invoke list --risk <risk>`**: repeatable filter over the effective risk level (`read_only`, `mutating`, `destructive`, `external_side_effect`), composing with the plugin positional and `--execution-mode` filters.

### Fixed
- Plugin discovery now attaches a `plugin.unmanaged_install_record_missing` warning to available candidates in user/system roots that have no installation record, and integrity failures on unmanaged copies name the shadowed managed version instead of a bare security error; `vb plugin list --include-shadowed` renders shadow diagnostics, and the runtime integrity error carries a stable `details.reason` (`install_record_missing | digest_mismatch | provenance_invalid`).
- Sixty-seven documented `cargo test/run/clippy/check -p vb` commands (the package is `voidb-cli`; only the binary is `vb`) corrected across the docs, and the capability-matrix generator's embedded command spellings fixed so the drift gate is green.

### Changed
- Documentation reconciled with shipped behavior: the storage transfer contract, capability examples, and session capability docs now describe the registry-declared-but-fail-closed session state; the standalone TUI acceptance criteria require startup auto-load of the primary resource view (the reported "docker TUI shows no data" root cause — the fix lands in the external plugin repositories); sync roadmap documentation corrected four already-implemented items (recovery codes, pull-time conflict import, tombstone apply, keyring token persistence).

## [0.4.0] - 2026-11-05

### Added
- **Ambient approval notifications**: `agent watch` (top-level `vb watch`) polls the JIT store and announces each new pending request with a terminal bell and a one-line alert carrying the review command; `--notify` additionally fires best-effort desktop notifications (osascript on macOS, notify-send on Linux, silently skipped when unavailable), `--interval-seconds` tunes the cadence, and Ctrl+C exits. Humans no longer need the agent to tell them or the TUI open.
- **Schema-driven constraint narrowing in the CLI review**: the per-field form lists the plugin's declared approval fields (label, path, value type, constraint kind, required), parses and validates each value by its declared type, and keeps raw JSON as the explicit fallback; secret-typed fields fail closed and cannot constrain an approval.
- **Templated constraints in the TUI JIT dialog**: `c` prefills the editor with one key per declared approval field so values are edited in place instead of authoring JSON from scratch; declarations render structurally and raw JSON stays available for undeclared fields.
- **Unified grant lifecycle screen** in the Connection Manager (press `L`): every grant with its lifecycle status, relative expiry, and destructive flag on the left; the selected grant's revisions and that profile's pending requests on the right. `r` refreshes, `v` prints the exact revoke command, and the screen keeps the 2-second snapshot cadence.
- Builtin `invoke` and `context` commands gained the short aliases `ix` and `ctx` (0.3.7 `conn`/`cred` precedent).

## [0.3.10] - 2026-11-05

### Added
- `agent grants`: a one-screen answer to "what can agents do right now" - grant lifecycle counts (active/expiring/exhausted/offline), the pending JIT approval count, and the grants table; `--watch` re-renders every 2 seconds like the TUI cadence. The top-level `vb grants` alias now points at the summary while `agent list` keeps the full JSON/table contract.
- One-command approvals: `agent request decide` prompts for the hidden master password on an interactive terminal instead of hard-requiring `--password-stdin`, so `vb agent request decide <id> --decision bounded` works as a single local command; automation keeps the stdin path.
- Interactive add-to-grant picker in `agent request review`: the principal's grants on the same profile and plugin are listed numbered with their expiry (Enter picks the first), and a number or a full id is accepted; manual entry remains the fallback.
- Short aliases for wordy subcommands: `agent authorize-batch` = `batch`, `agent request inbox` = `in`, builtin `invoke` = `ix` and `context` = `ctx`, plus top-level verbs `decide`, `renew`, `revoke`, and `run`.
- Short flags for high-frequency agent options: `-p` profile, `-c` capability, `-w` wait-timeout-ms, `-t` ttl-minutes/ttl-seconds, `-y` yes, `-f` format across exec/authorize/authorize-batch/catalog/list/renew/revoke and request create/decide/inbox.
- Quick-authorize guidance in `invoke run`: policy denials (capability denied, destructive denied by default, approval required) now carry the same `quick_authorize` data block as `agent exec` - a TUI hint plus a ready-to-run `vb agent authorize` argv for the profile, plugin, and capability.
- A confirmation gate for multi-grant `agent revoke`: more than one grant selected prints exactly what would be closed (id, profile, capabilities) and requires typing `revoke` on a TTY or `--yes` for scripts; single-grant revokes stay one-step.

### Fixed
- The JIT approval inbox now really groups requests by principal and immutable profile: the projection sorts by (principal, profile) first and the inbox renders a header on the first row of each group, matching the documented promise while keeping the 1:1 selection mapping.

## [0.3.9] - 2026-11-04

### Added
- The agent command family is discoverable: the tree is registered in the top-level clap app so `--help` and shell completions list every `agent` command, and the top-level command name is unified to `voidb-cli`.
- Short top-level aliases for the frequent authorization operations: `vb approve <id>`, `vb inbox`, `vb grants`, `vb auth <profile>`, `vb catalog`, and `vb exec` expand in the pre-clap broker to their `agent ...` equivalents.
- `agent list --format table`: grant id, profile, plugin, lifecycle status badge, relative expiry ("in 12m" / "expired 5m ago"), remaining uses, active sessions, and a DESTRUCTIVE risk flag. JSON stays the default and byte-identical.
- `agent request inbox --format table`: short id, status, risk, plugin, profile, truncated purpose, relative expiry; the previously undocumented command is now described in docs/jit-agent-authorization.md.
- The Connection Manager header shows a bold `[N PENDING]` marker while JIT requests await review, and the footer help line lists the `p` approvals key.
- Risk severity coloring: capability-checklist risk badges grade destructive/external_side_effect red and mutating amber; the JIT approval dialog border turns red while Deny is selected.
- One-line scope summaries replace raw JSON dumps in the TUI detail pane, the TUI approval dialog, and the CLI interactive review.
- Execution-time grant warnings: `agent exec`/`run` print a stderr notice when the selected grant is inside the expiring window, exhausted, or has at most two uses left, with the exact renew command.
- The JIT human-wait ceiling is configurable through `VOIDB_AGENT_MAX_WAIT_SECONDS` (1..=3600 s); `agent exec` announces how long the human has to approve, announces capping instead of silently clamping `--wait-timeout-ms`, and rate-limit responses add a human "try again in Ns" hint.
- Structured `{ok:false,error:{...}}` envelopes for `agent authorize/authorize-batch/catalog/list/renew/revoke` failures, matching the agent-facing commands, plus a next-step line on the `--replace` bail.

### Changed
- **Binary rename (breaking): the CLI dispatcher is now `vb` and the connection manager `vb-tui`.** Crate names (voidb-cli, voidb-tui, voidb-core, SDK) are unchanged. Both resolvers prefer the new sibling names and fall back to the legacy names; the homebrew formula ships `voidb-cli`/`voidb` compatibility symlinks; installer, release staging, smoke/gate scripts, CI, docs, and all guidance strings use the new spellings.
- The batch authorize review reports per-entry risk rollups (read_only/mutating/destructive counts with the destructive capability ids flagged inline) instead of a single boolean.
- `agent request review` verifies the master password right after the request summary, before any decision is collected, so a wrong password no longer discards the whole decision flow.

### Fixed
- The README `agent exec` example includes the hard-required `--purpose`; copying it no longer fails with `purpose_required`.

## [0.3.8] - 2026-11-04

### Added
- Minimal mouse support in the Connection Manager: left click selects a profile row and the wheel navigates while Browse or Search is active; mouse hit-testing shares the render layout geometry so the two can never drift.
- `Enter` copies the selected profile's CLI guidance (test and launch commands) to the clipboard through the existing `voidb-core` clipboard helper; the details pane, help overlay, and keymap docs advertise it, and the clipboard-unavailable fallback keeps the printed guidance.
- Caret editing for the profile editor's name/display fields: `Left`/`Right`/`Home`/`End`/`Delete` with a rendered inverted caret cell, chars inserting at the caret, and pasted text landing at the caret instead of always appending.
- Paging keys across the app: `PageUp`/`PageDown` (±10, matching the plugin TUI family), `Home`/`End`, and vim `g`/`G` on the profile list, capability browser, authorization capability list, and JIT inbox; `j`/`k` now wrap at both ends via one shared selection stepper.

### Fixed
- The idle authorization snapshot no longer spawns three sequential `vb` subprocesses every 2 s regardless of context; the 2 s cadence applies only while an authorization surface is visible and falls back to a 60 s cadence for Browse badges, restoring the idle budget in docs/tui-interaction-performance.md.
- Mouse capture is no longer dead: mouse events are handled, and every event class drains the background poll (mouse motion used to skip it entirely, starving test/install/snapshot workers).
- `Esc` in the profile editor with unsaved work opens a non-default discard confirmation instead of silently discarding, per the no-silent-loss rule in docs/standalone-tui-ux-acceptance.md.
- `Esc` in search clears a non-empty filter first (the documented behavior) and exits only from an empty filter; `Enter` still applies the filter and returns to Browse.
- Destructive confirmations no longer default on `Enter`: profile delete and plugin install require the explicit `y`, with dialog copy matching the new mapping, per the non-default confirmation rule in docs/standalone-tui-ux-acceptance.md.
- The help overlay fits on a 30-row terminal again (it had grown past its popup and truncated silently) and now lists `q`, `Esc` semantics, `Ctrl+C`, the discard confirmation, and the mouse support.
- The JSON editor's cursor no longer drifts on CJK/wide input: caret columns measure display width (`unicode-width`) and long lines truncate instead of reflowing; `Delete` and line-wise `Home`/`End` work in the JSON view.
- Pasted line breaks no longer dispatch as `Enter` keys (which cycled select/boolean values in the Form view); they are dropped outside the JSON text field, and the JIT constraints editor accepts pasted JSON.

### Changed
- The footer status line carries a severity (info/success/error) rendered green/red respectively; background results (test, install, capability discovery, authorization operations, save, delete, clipboard copy) report the matching class instead of one indistinguishable yellow string.
- The authorization snapshot is parsed once on its worker thread into a typed snapshot instead of six serde passes per refresh on the UI thread; the five single-direction `try_recv` poll blocks share one generic drain helper; the four cycle-with-wrap implementations and the TTL/uses steppers reuse the shared selection stepper; the master-password gate repeated across action handlers is one `credentials_locked` helper.
- Removed the unused direct `arboard` and `tui-textarea` dependencies from `voidb-tui`.
- Replaced the vacuous e2e simulation tests, which only recorded key events for the removed embedded data grid, with a real headless driver: key/paste/mouse flows against a temp-store app plus `TestBackend` render assertions for Browse, the help overlay, and the small-terminal notice. The driver caught the help-overlay fit bug fixed above.

## [0.3.7] - 2026-10-30

### Fixed
- Invite-only sync-server registration now succeeds with a valid invite token: the token is stamped after the user row is inserted, instead of always failing the `used_by` foreign key with a 500.

### Added
- `vb completions <shell>` generates shell completion scripts (bash, zsh, fish, powershell, elvish).
- Visible CLI aliases for faster typing: `conn` (connections), `cred` (credential), `profiles` (profile), and `re-encrypt` (`credential master reencrypt`).
- TTY-gated interactive master-password unlock: in a terminal, commands that need credential decryption prompt once (echo disabled, prompt on stderr) instead of requiring `VOIDB_MASTER_PASSWORD`; non-interactive sessions stay fail-closed.
- `VOIDB_DISABLE_KEYRING` opt-out skips the OS keyring for the per-installation secret and uses the 0600 file fallback, so tests and headless runs never trigger keychain authorization prompts.
- `voidb-core::atomic_file::write_private_atomic` centralizes the temp-file + fsync + rename persistence pattern shared by the plugin install record, external context records, and JIT grant files (JIT writes now also clean up their temporary file on failure); covered by new unit tests.

### Changed
- Documentation aligned with the v0.3.6 architecture: README no longer points at in-tree plugin crates or the removed embedded shell, security docs describe the per-installation keyring secret, the docs index lists all current documents, `skills/` references current paths and external plugin repositories, and `config.example.toml` matches the profile-based configuration model.
- CI runs the sync-server test suite, wires the filesystem-boundary, external-agent-interaction, data-search conformance, package smoke, and Docker fixture checks, and adds a weekly scheduled full-tier run; registry update no longer hardcodes archive counts or stale version fallbacks.
- Non-test `unwrap` cleanups: capability-matrix rendering discards the infallible `writeln!` results explicitly, sync CLI argument access reports a validation error instead of panicking, and the six duplicated `print_json` helpers collapse into one shared module.

## [0.3.6] - 2026-10-29

### Security
- Replace the hardcoded default credential passphrase with a random per-installation secret stored in the OS keyring (0600 file fallback where no keyring exists); the retired compiled-in passphrase remains a decrypt-only migration path.
- Make `decrypt()` strict: non-encrypted input is now an error instead of a silent passthrough; legacy plaintext configs opt in explicitly via `decrypt_allow_plaintext()`.
- Zeroize derived Argon2id keys on drop; serialize installation-secret creation and create the file fallback atomically so concurrent first runs cannot mint divergent keys.

### Added
- Direct trust-path test coverage: plugin provenance (tampered payloads, untrusted signers, symlinked proofs, binary-path escapes), signing, redaction, credential protection, sync-server auth; new `vb` integration harness driving the real binary.

### Changed
- The plugin SDK builds terminal-free: `voidb-core` gates its TUI/CLI/registry stacks behind features (defaults unchanged in-repo), verified by an isolated dependency tree with no ratatui/crossterm/arboard/reqwest/clap; SDK contract types are re-exported publicly.
- Remove the legacy embedded shell; the native Connection Manager is the only terminal app and the deprecated `--shell` flag launches it.
- Decompose `agent_broker.rs` (9.9k lines), `builtin/invoke.rs` and `connection_manager_app.rs` into focused directory modules with byte-identical behavior.
- Agent-facing waits gained async variants so long operation reviews no longer park the tokio executor; the Connection Manager backs off its background poll to 800 ms when idle.
- The documented error model now describes the per-domain error-enum convention; docs refreshed to the v4.1 architecture.

### Removed
- Dead database-driver declarations from the root manifest and unused `vt100`/`tar` dependencies from core.

## [0.3.5] - 2026-10-12

- Require trusted Ed25519 plugin provenance before execution; reject missing/legacy records, rewritten digests, forged proofs and modified payloads without silently trusting installed binaries.
- Add verified legacy recovery, serialized atomic installation/update and authenticated rollback while preserving profiles and credentials.
- Prepare new signed v0.3.4 packages for all 14 official plugins; retain explicit unsigned development opt-in and document privileged-compromise/execution-race limits.
- Distribute only the core shell and dispatcher. Install plugins explicitly through the registry, optional first-launch onboarding or selected-connection installation with `i`.
- Keep authenticated registry metadata in a trust-policy cache namespace so fresh legacy caches do not delay verified upgrade.
- Preserve skip and failure retry behavior, avoid downloads during noninteractive startup, and keep installation children free of the main password.
- Validate four plugin targets, five core targets and real signed HTTP/PTY lifecycle; public core, plugin, registry and Homebrew installation acceptance passed.

## [0.3.4] - 2026-10-12

- Fix registry artifact selection when CLI callers supply architecture names instead of full target triples.
- Keep platform and architecture matching strict; never choose another architecture as a fallback.
- Bundle the independently released 0.3.3 default plugins with the 0.3.4 shell and CLI.

## [0.3.3] - 2026-10-09

### Security
- Preserve explicit restrictions on capability-wide authorization and validate bounded live-session metadata when discovering process plugins.
- Require verified release checksums before installation and initialize bundled plugins through the CLI installation record gate.
- **Runtime Binary Integrity Verification Gate**: Introduced SHA-256 binary digest verification before executing any external process plugin. Blocks unauthorized binary replacement or tampering with `SECURITY GATE BLOCKED` to prevent credential leakage.
- **Secure Stdio IPC Credential Channel**: Refactored `test_connection_by_plugin` across all 14 plugins to transfer decrypted connection configurations via secure anonymous pipes (`--stdin-config`), eliminating plaintext credentials in `ps aux` command-line arguments.

### Fixed
- Make broker contract tests independent of installed plugins and export complete authorization and session metadata from all official plugin services.
- Match registry packages by exact architecture and align release asset names with installer and Homebrew conventions.
- **Plugin CLI Argument Discovery**: Fixed Clap 4 `ArgMatches` panic by guarding against undeclared argument IDs using `.ids().any(...)` across all 14 plugins.
- **Graceful Raw Configuration Fallback**: Plugin commands not requiring profile secrets (e.g., `docker ps`, local SQLite/DuckDB) no longer block on master password prompts.
- **SSH Auth & Host Key Validation**: Fixed `SshAuthMethod` serde deserialization aliases and added strict host key failure reporting and TUI prompt handling in `voidb-plugin-ssh`.

### Added
- **Full-Protocol Docker E2E Test Suite**: Added automated integration verification tests for all database, container, and remote connection plugins (SQLite, DuckDB, Docker, Redis, Postgres, MySQL, SSH).
- **GitHub Actions CI/CD Coverage**: Added complete CI matrix workflows (`cargo test`, `cargo clippy`, `cargo build`) and release pipelines across all 14 official plugin repositories.

## [0.3.2] - 2026-10-08

### Added

- **100% Decoupled Process Plugin Architecture**: Completely externalized 6 database and protocol drivers (`mysql`, `postgres`, `sqlite`, `redis`, `ssh`, `duckdb`) into independent repositories, removing all heavy driver crates (`libduckdb-sys`, `tokio-postgres`, `mysql_async`, `rusqlite`, `redis`, `russh`) from the core voidb workspace.
- **Unified Command Dispatcher & Complete Plugin Equality**: `vb` now dynamically discovers all 14 official plugins and transparently routes subcommands, arguments, options, and help messages.
- **Standard Tri-Modal Contract for All 14 Plugins**: Every official plugin provides `test` (fast connectivity check), `tui` (standalone interactive full-screen terminal), and `serve` (headless stdio-jsonrpc for AI coding agents) alongside domain commands.
- **Bundled Default Plugins & One-Click Init**: Built-in discovery checks sibling and installation prefix paths (`<exe_dir>/plugins`, `<prefix>/share/voidb/plugins`). Added `vb plugin install-default` for one-command initialization of core database plugins.
- **Release Packaging & Distribution**: Updated GitHub release workflow and Homebrew formula to build and package both `vb-tui` and `vb` binaries together.

### Changed

- Updated all architectural documentation and AGENTS.md guide to reflect the decoupled v4.1 architecture.
- Cleaned up obsolete in-tree migration documentation.

## [0.3.0] - 2026-10-08

### Added

- Visual Plugin Manager & Online Marketplace in TUI shell (`p` shortcut) with dual-tab (Installed vs Marketplace) navigation, category filtering, search, and async install/update/uninstall operations.
- Hosted Official Plugin Registry on GitHub (`registry/index.json`) and automated CI dispatch workflow (`update-registry.yml`) linking standalone plugin releases.
- Online `voidb plugin install <name>` with remote GitHub release download, SHA256 checksum verification, and Ed25519 signature validation.
- Gzip decompression (`.tar.gz` / `.tgz`) support across plugin archive installation and extraction engine.
- Complete standalone packaging and GitHub Releases for all 8 external plugins: `s3`, `email`, `docker`, `kubernetes`, `elasticsearch`, `mongodb`, `jenkins`, `webdav`.
- Central Connection Manager authorization workflow with Read-only,
  Interactive/Execute, and Custom presets; reviewed TTL/use limits; explicit
  destructive consent; inspect, renew, replace, scoped revoke, and revoke-all.
- Frontend-safe per-profile grant state covering expiry/use exhaustion, broker
  health, exact capability scope, and active persistent session counts.
- Shared authorization metadata and centrally generated exact presets for all
  bundled capability plugins and process-plugin manifests/SDK.

### Security

- Agent grants now reject empty/wildcard or preset-mismatched scopes, preserve
  immutable Profile ID/plugin binding, recover stale brokers without persisted
  credentials, and keep broker tokens/sockets/passwords out of frontend state.
- Interactive SSH authorization requires explicit grant consent and per-call
  destructive acknowledgement. Disposable OpenSSH acceptance verified separate
  persistent `cd` and `ls` calls, SFTP/forwarding lifecycle, and secret scans.
- Plugin packaging and registry verification gates supply-chain security via SHA-256 and Ed25519 signatures.

### Fixed

- TUI quality evidence now runs under an isolated HOME/config and accepts both
  configured and empty-profile first frames without reading user credentials.

## [0.3.0-rc.1] - 2026-07-05

### Changed

- **BREAKING**: Removed `intercepts_event()` from Plugin trait — global shortcuts are now unconditional and cannot be overridden by plugins
- Global shortcuts (`q`, `Q`, `Ctrl+Q`, `Ctrl+L`) are always handled by the shell before events reach plugins

### Added

- `Q` (Shift+Q) global shortcut to close the current tab

### Documentation

- Published release-candidate baseline, release blocker inventory, all-plugin
  RC readiness matrix/report, package smoke, and final tag-readiness workflow
  records for the 2026-07-05 release-candidate cut.
- Recorded plugin release dispositions, skipped live fixture smoke, residual
  risks, package artifact expectations, and release-note waiver requirements.
- Recorded the 2026-07-04 release stabilization rehearsal, including refreshed
  automated gates, package artifact smoke, skipped live-fixture smoke, and a
  no-go tagging decision until required real-terminal TUI smoke and
  version/tag consistency are resolved.

## [0.2.0] - 2026-03-19

### Changed

- **BREAKING**: Complete architecture redesign to v4.0 Pure Router Architecture
- Plugins are now fully autonomous applications with full screen control
- Replaced Component trait with Plugin trait
- Removed Message enum in favor of ShellCapabilities (dependency injection)
- Simplified VoidB toward a pure-router shell architecture
- Channel-based communication for non-blocking tab operations
- Global shortcuts simplified (Ctrl+Q for quit, plugins handle their own keys)

### Added

- **ShellCapabilities** - Dependency injection for plugins
  - `tabs` - Tab operations (open, close, set_title)
  - `connections` - Shared connection registry
- **PluginRegistry** - Factory-based plugin registration system
- **Plugin trait** - Clean lifecycle (init, update)
- **MySQL Plugin** - Fully autonomous table viewer/editor
  - Tree navigation, data grid, SQL editor
  - Vim-style keybindings
  - Multiple editing modes
- **PostgreSQL Plugin** - Full PostgreSQL support
- **SQLite Plugin** - File-based database management
- **Email Plugin** - IMAP/POP3 email client
  - Mailbox browsing, email reading
  - HTML email rendering to text
  - Attachment handling
- **SQL Features**
  - Syntax highlighting (`sql_highlight.rs`)
  - Autocomplete (`autocomplete.rs`)
  - Statement parsing (`sql_split.rs`)
- **Security**
  - AES-256-GCM credential encryption (`crypto.rs`)
- **Import/Export**
  - CSV, JSON, SQL export (`export.rs`)
  - CSV import (`import.rs`)
- **UI Widgets** (in voidb-core/widgets/)
  - Reusable tree, grid, editor components
  - Shared across plugins
- Documentation: v4.0 plugin development guide

### Removed

- **BREAKING**: Component trait and component-based architecture
- **BREAKING**: Action enum (100+ variants)
- **BREAKING**: Message enum (7 variants, replaced by ShellCapabilities)
- **BREAKING**: InputMode enum (moved to plugins)
- **BREAKING**: Old shell-level UI components:
  - DataGrid component
  - QueryEditor component
  - Structure Designer component
  - Dialog components
  - Command Palette
  - Status Bar (minimal version in shell)
  - Tab Bar (replaced with simple top bar)
  - Context Menu
  - Help Overlay
  - Welcome Screen
- **BREAKING**: Centralized state management (TabManager, UndoStack)
  - Plugins now manage their own state
- **BREAKING**: Legacy event/mode/keymap/focus systems
- **Total**: ~16,000 lines of legacy component-based architecture removed

### Fixed

- Event routing now correctly routed to active plugin
- Tab operations are non-blocking via channels
- Clipboard integration works across all platforms
- Email HTML rendering properly converts to text for TUI display

### Migration

**For Plugin Developers**:

Old plugins using the Component trait must be migrated to the new Plugin trait. See the plugin development documentation for the complete v4.0 migration guide.

**Key Changes**:
- Replace `Component` trait with `Plugin` trait
- Store `ShellCapabilities` from `init()` instead of returning `Message`s
- Use `caps.tabs.open/close()` for tab operations
- Implement full-screen rendering in `update(frame, area, event)`
- Handle events directly instead of returning `Action`s

---

## [0.1.0] - 2026-03-18

### Added

- Initial release
- Core foundation (event loop, vim modes, components)
- Database adapters (MySQL, PostgreSQL, SQLite)
- Object tree browser
- Data grid with pagination and editing
- SQL query editor with syntax highlighting
- Table structure designer
- Import/Export (CSV, JSON, SQL)
- Connection management with encryption

---

**Legend**:
- **BREAKING**: Breaking change requiring migration
