//! Persistent agent sessions owned by the SSH plugin.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use voidb_core::{
    AgentSessionCallRequest, AgentSessionCallResult, AgentSessionOpenContext, PluginAgentSession,
    PluginAgentSessionFactory, PluginSessionError, PluginSessionErrorCode, PluginSessionHealth,
    PluginSessionPurpose, RedactionTarget, collect_redaction_targets, redact_text_with_targets,
};

use crate::config::SshConfig;
use crate::service::{
    PersistentPtySession, PersistentPtySignal, PersistentShellSession, SshService,
    direct_connection_error_code,
};

const DEFAULT_STREAM_LIMIT_BYTES: usize = 32 * 1024;
const MAX_STREAM_LIMIT_BYTES: usize = 1024 * 1024;
const DEFAULT_PTY_COLS: u16 = 120;
const DEFAULT_PTY_ROWS: u16 = 40;
const MIN_PTY_COLS: u16 = 20;
const MAX_PTY_COLS: u16 = 240;
const MIN_PTY_ROWS: u16 = 5;
const MAX_PTY_ROWS: u16 = 100;
const AGENT_PTY_SCROLLBACK_ROWS: usize = 500;
const AGENT_PTY_OUTPUT_CAPACITY: usize = 256 * 1024;
const DEFAULT_PTY_READ_BYTES: usize = 32 * 1024;
const MAX_PTY_READ_BYTES: usize = 128 * 1024;
const MAX_PTY_WAIT_MS: u64 = 1_000;
const MAX_PTY_WRITE_BYTES: usize = 16 * 1024;
const MAX_PTY_KEYS: usize = 256;

const EXEC_CAPABILITIES: &[&str] = &["ssh.exec", "exec"];
const PTY_CAPABILITIES: &[&str] = &[
    "ssh.terminal_read",
    "terminal_read",
    "ssh.terminal_snapshot",
    "terminal_snapshot",
    "ssh.terminal_write",
    "terminal_write",
    "ssh.terminal_resize",
    "terminal_resize",
    "ssh.terminal_signal",
    "terminal_signal",
];

pub struct SshAgentSessionFactory {
    config: SshConfig,
    redaction_targets: Arc<Vec<RedactionTarget>>,
}

impl SshAgentSessionFactory {
    pub fn new(config: SshConfig) -> Self {
        let redaction_targets = serde_json::to_value(&config)
            .map(|value| collect_redaction_targets(&value))
            .unwrap_or_default();
        Self {
            config,
            redaction_targets: Arc::new(redaction_targets),
        }
    }
}

#[async_trait]
impl PluginAgentSessionFactory for SshAgentSessionFactory {
    fn plugin_id(&self) -> &str {
        "ssh"
    }

    async fn open(
        &self,
        context: AgentSessionOpenContext,
    ) -> Result<Arc<dyn PluginAgentSession>, PluginSessionError> {
        let service = SshService::new_direct(self.config.clone())
            .await
            .map_err(|error| {
                session_error(
                    PluginSessionErrorCode::OwnerUnavailable,
                    match direct_connection_error_code(&error) {
                        "ssh.host_key_unknown" => "SSH host key is not trusted.",
                        "ssh.host_key_changed" => "SSH host key changed.",
                        _ => "SSH connection or authentication failed.",
                    },
                )
            })?;
        match context.binding.purpose {
            PluginSessionPurpose::InteractiveTerminal => {
                let allowed_capabilities = &context.binding.allowed_capabilities;
                if allowed_capabilities.is_empty() {
                    return Err(session_error(
                        PluginSessionErrorCode::PolicyDenied,
                        "SSH interactive sessions require at least one capability.",
                    ));
                }
                if allowed_capabilities
                    .iter()
                    .all(|capability| EXEC_CAPABILITIES.contains(&capability.as_str()))
                {
                    ensure_capabilities(
                        allowed_capabilities,
                        EXEC_CAPABILITIES,
                        "SSH shell sessions only accept the ssh.exec capability.",
                    )?;
                    let direct = service.into_direct_handle().ok_or_else(|| {
                        session_error(
                            PluginSessionErrorCode::OwnerUnavailable,
                            "SSH direct session handle is unavailable.",
                        )
                    })?;
                    let shell = direct.open_persistent_shell().await.map_err(|_| {
                        session_error(
                            PluginSessionErrorCode::OwnerUnavailable,
                            "SSH persistent shell could not be started.",
                        )
                    })?;
                    return Ok(Arc::new(SshAgentShellSession {
                        shell: Mutex::new(Some(shell)),
                        redaction_targets: Arc::clone(&self.redaction_targets),
                    }));
                }

                ensure_capabilities(
                    allowed_capabilities,
                    PTY_CAPABILITIES,
                    "SSH interactive PTY sessions only accept terminal capabilities.",
                )?;
                let cols = terminal_dimension(
                    &context.request.input,
                    "cols",
                    DEFAULT_PTY_COLS,
                    MIN_PTY_COLS,
                    MAX_PTY_COLS,
                )?;
                let rows = terminal_dimension(
                    &context.request.input,
                    "rows",
                    DEFAULT_PTY_ROWS,
                    MIN_PTY_ROWS,
                    MAX_PTY_ROWS,
                )?;
                let direct = service.into_direct_handle().ok_or_else(|| {
                    session_error(
                        PluginSessionErrorCode::OwnerUnavailable,
                        "SSH direct session handle is unavailable.",
                    )
                })?;
                let terminal = direct
                    .open_interactive_terminal(
                        &self.config.terminal.term_type,
                        cols,
                        rows,
                        AGENT_PTY_SCROLLBACK_ROWS,
                        AGENT_PTY_OUTPUT_CAPACITY,
                    )
                    .await
                    .map_err(|_| {
                        session_error(
                            PluginSessionErrorCode::OwnerUnavailable,
                            "SSH interactive PTY could not be started.",
                        )
                    })?;
                Ok(Arc::new(SshAgentPtySession {
                    terminal,
                    redaction_targets: Arc::clone(&self.redaction_targets),
                }))
            }
            PluginSessionPurpose::FileTransfer => {
                ensure_capabilities(
                    &context.binding.allowed_capabilities,
                    &["ssh.sftp_list", "sftp_list"],
                    "Persistent SFTP sessions currently expose ssh.sftp_list.",
                )?;
                let mut service = service;
                let sftp = service.open_sftp().await.map_err(|_| {
                    session_error(
                        PluginSessionErrorCode::OwnerUnavailable,
                        "SSH SFTP subsystem could not be started.",
                    )
                })?;
                Ok(Arc::new(SshAgentSftpSession {
                    state: Mutex::new(Some((service, sftp))),
                    redaction_targets: Arc::clone(&self.redaction_targets),
                }))
            }
            PluginSessionPurpose::PortForward => {
                ensure_capabilities(
                    &context.binding.allowed_capabilities,
                    &[
                        "ssh.forward_open",
                        "forward_open",
                        "ssh.forward_status",
                        "forward_status",
                    ],
                    "SSH forwarding sessions require forward_open/status capability scope.",
                )?;
                let handle = service.into_direct_handle().ok_or_else(|| {
                    session_error(
                        PluginSessionErrorCode::OwnerUnavailable,
                        "SSH forwarding transport is unavailable.",
                    )
                })?;
                Ok(Arc::new(SshAgentForwardSession {
                    state: Mutex::new(SshAgentForwardState {
                        handle: Some(handle),
                        active: None,
                    }),
                }))
            }
            _ => Err(session_error(
                PluginSessionErrorCode::Unsupported,
                "SSH does not support this persistent session purpose.",
            )),
        }
    }
}

struct SshAgentPtySession {
    terminal: PersistentPtySession,
    redaction_targets: Arc<Vec<RedactionTarget>>,
}

#[async_trait]
impl PluginAgentSession for SshAgentPtySession {
    async fn call(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        match request.capability.as_str() {
            "ssh.terminal_read" => self.read_terminal(request).await,
            "ssh.terminal_snapshot" => self.snapshot_terminal(request).await,
            "ssh.terminal_write" => self.write_terminal(request).await,
            "ssh.terminal_resize" => self.resize_terminal(request).await,
            "ssh.terminal_signal" => self.signal_terminal(request).await,
            _ => Err(session_error(
                PluginSessionErrorCode::PolicyDenied,
                "SSH interactive PTY received a capability outside its binding.",
            )),
        }
    }

    async fn health(&self) -> Result<PluginSessionHealth, PluginSessionError> {
        Ok(self.terminal.health().await)
    }

    async fn cancel(&self, _call_id: &str) -> Result<(), PluginSessionError> {
        // Calls are bounded and cancellation drops only the active call future.
        // The PTY remains alive for subsequent interaction.
        Ok(())
    }

    async fn close(&self, _reason: String) -> Result<(), PluginSessionError> {
        self.terminal.close().await;
        Ok(())
    }
}

impl SshAgentPtySession {
    async fn read_terminal(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        let after_offset = optional_u64(&request.input, "after_offset", 0)?;
        let max_bytes = optional_usize(
            &request.input,
            "max_bytes",
            DEFAULT_PTY_READ_BYTES,
            1,
            MAX_PTY_READ_BYTES,
        )?;
        let wait_ms = optional_u64(&request.input, "wait_ms", 0)?;
        if wait_ms > MAX_PTY_WAIT_MS {
            return Err(session_error(
                PluginSessionErrorCode::PolicyDenied,
                format!("wait_ms must be between 0 and {MAX_PTY_WAIT_MS}."),
            ));
        }
        let output = self
            .terminal
            .read(after_offset, max_bytes, Duration::from_millis(wait_ms))
            .await;
        let text = String::from_utf8_lossy(&output.data);
        let (text, _) = redact_text_with_targets(&text, &self.redaction_targets);
        AgentSessionCallResult::bounded(
            request.call_id,
            json!({
                "text": text,
                "source_bytes": output.data.len(),
                "requested_offset": output.requested_offset,
                "start_offset": output.start_offset,
                "next_offset": output.next_offset,
                "retained_start_offset": output.retained_start_offset,
                "end_offset": output.end_offset,
                "gap": output.gap,
                "more": output.more,
                "timed_out": output.timed_out,
                "closed": output.closed,
            }),
            request.output_limit_bytes,
        )
    }

    async fn snapshot_terminal(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        let snapshot = self.terminal.snapshot().await;
        let screen = snapshot.lines.join("\n");
        let (screen, _) = redact_text_with_targets(&screen, &self.redaction_targets);
        let lines = screen.split('\n').map(str::to_string).collect::<Vec<_>>();
        let (title, _) = redact_text_with_targets(&snapshot.title, &self.redaction_targets);
        AgentSessionCallResult::bounded(
            request.call_id,
            json!({
                "lines": lines,
                "cursor": { "row": snapshot.cursor_row, "col": snapshot.cursor_col },
                "size": { "cols": snapshot.cols, "rows": snapshot.rows },
                "modes": {
                    "alternate_screen": snapshot.alternate_screen,
                    "application_cursor": snapshot.application_cursor,
                    "application_keypad": snapshot.application_keypad,
                    "bracketed_paste": snapshot.bracketed_paste,
                    "hide_cursor": snapshot.hide_cursor,
                },
                "title": title,
                "retained_start_offset": snapshot.retained_start_offset,
                "end_offset": snapshot.end_offset,
                "exit_code": snapshot.exit_code,
                "health": snapshot.health,
            }),
            request.output_limit_bytes,
        )
    }

    async fn write_terminal(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        let write = terminal_write_input(&request.input)?;
        let snapshot = self.terminal.snapshot().await;
        let prompt_start = snapshot.cursor_row.saturating_sub(2) as usize;
        let prompt_end = usize::from(snapshot.cursor_row)
            .saturating_add(1)
            .min(snapshot.lines.len());
        let prompt_context = snapshot
            .lines
            .get(prompt_start..prompt_end)
            .unwrap_or(&[])
            .join("\n");
        if contains_password_like_prompt(&prompt_context) && !write.recovery_only {
            return Err(session_error(
                PluginSessionErrorCode::PolicyDenied,
                "Password-like terminal prompts block agent text input; cancel the prompt or hand control to a human.",
            ));
        }
        let written_bytes = write.bytes.len();
        self.terminal.write(write.bytes).await.map_err(|_| {
            session_error(
                PluginSessionErrorCode::OwnerUnavailable,
                "SSH interactive PTY write failed.",
            )
        })?;
        AgentSessionCallResult::bounded(
            request.call_id,
            json!({
                "written_bytes": written_bytes,
                "text_bytes": write.text_bytes,
                "key_count": write.key_count,
                "paste": write.paste,
                "enter": write.enter,
            }),
            request.output_limit_bytes,
        )
    }

    async fn resize_terminal(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        let cols = required_terminal_dimension(&request.input, "cols", MIN_PTY_COLS, MAX_PTY_COLS)?;
        let rows = required_terminal_dimension(&request.input, "rows", MIN_PTY_ROWS, MAX_PTY_ROWS)?;
        self.terminal.resize(cols, rows).await.map_err(|_| {
            session_error(
                PluginSessionErrorCode::OwnerUnavailable,
                "SSH interactive PTY resize failed.",
            )
        })?;
        AgentSessionCallResult::bounded(
            request.call_id,
            json!({ "cols": cols, "rows": rows }),
            request.output_limit_bytes,
        )
    }

    async fn signal_terminal(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        let name = request
            .input
            .get("signal")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                session_error(PluginSessionErrorCode::PolicyDenied, "signal is required.")
            })?;
        let signal = parse_terminal_signal(name)?;
        self.terminal.signal(signal).await.map_err(|_| {
            session_error(
                PluginSessionErrorCode::OwnerUnavailable,
                "SSH interactive PTY signal failed.",
            )
        })?;
        AgentSessionCallResult::bounded(
            request.call_id,
            json!({ "signal": name.to_ascii_uppercase() }),
            request.output_limit_bytes,
        )
    }
}

struct TerminalWrite {
    bytes: Vec<u8>,
    text_bytes: usize,
    key_count: usize,
    paste: bool,
    enter: bool,
    recovery_only: bool,
}

fn terminal_write_input(input: &Value) -> Result<TerminalWrite, PluginSessionError> {
    let text = input.get("text").and_then(Value::as_str).unwrap_or("");
    if text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(session_error(
            PluginSessionErrorCode::PolicyDenied,
            "Terminal text contains unsupported control characters; use named keys instead.",
        ));
    }
    let paste = input.get("paste").and_then(Value::as_bool).unwrap_or(false);
    if paste && text.is_empty() {
        return Err(session_error(
            PluginSessionErrorCode::PolicyDenied,
            "paste requires non-empty text.",
        ));
    }
    let enter = input.get("enter").and_then(Value::as_bool).unwrap_or(false);
    let keys = input
        .get("keys")
        .map(|value| {
            value.as_array().ok_or_else(|| {
                session_error(
                    PluginSessionErrorCode::PolicyDenied,
                    "keys must be an array of named terminal keys.",
                )
            })
        })
        .transpose()?
        .cloned()
        .unwrap_or_default();
    if keys.len() > MAX_PTY_KEYS {
        return Err(session_error(
            PluginSessionErrorCode::PolicyDenied,
            format!("keys cannot contain more than {MAX_PTY_KEYS} entries."),
        ));
    }

    let mut bytes = Vec::new();
    if paste {
        bytes.extend_from_slice(b"\x1b[200~");
    }
    bytes.extend_from_slice(text.as_bytes());
    if paste {
        bytes.extend_from_slice(b"\x1b[201~");
    }
    let mut recovery_only = text.is_empty() && !enter && !keys.is_empty();
    for key in &keys {
        let key = key.as_str().ok_or_else(|| {
            session_error(
                PluginSessionErrorCode::PolicyDenied,
                "Terminal key names must be strings.",
            )
        })?;
        let (encoded, recovery_key) = terminal_key_bytes(key)?;
        recovery_only &= recovery_key;
        bytes.extend_from_slice(&encoded);
    }
    if enter {
        bytes.push(b'\r');
    }
    if bytes.is_empty() {
        return Err(session_error(
            PluginSessionErrorCode::PolicyDenied,
            "Terminal write requires text, keys, or enter=true.",
        ));
    }
    if bytes.len() > MAX_PTY_WRITE_BYTES {
        return Err(session_error(
            PluginSessionErrorCode::PolicyDenied,
            format!("Terminal write exceeds {MAX_PTY_WRITE_BYTES} bytes."),
        ));
    }

    Ok(TerminalWrite {
        bytes,
        text_bytes: text.len(),
        key_count: keys.len(),
        paste,
        enter,
        recovery_only,
    })
}

fn terminal_key_bytes(key: &str) -> Result<(Vec<u8>, bool), PluginSessionError> {
    let normalized = key.trim().to_ascii_uppercase().replace(['-', '+'], "_");
    let value = match normalized.as_str() {
        "ENTER" => (b"\r".to_vec(), false),
        "BACKSPACE" => (b"\x7f".to_vec(), false),
        "TAB" => (b"\t".to_vec(), false),
        "SHIFT_TAB" => (b"\x1b[Z".to_vec(), false),
        "ESC" | "ESCAPE" => (b"\x1b".to_vec(), true),
        "UP" => (b"\x1b[A".to_vec(), false),
        "DOWN" => (b"\x1b[B".to_vec(), false),
        "RIGHT" => (b"\x1b[C".to_vec(), false),
        "LEFT" => (b"\x1b[D".to_vec(), false),
        "HOME" => (b"\x1b[H".to_vec(), false),
        "END" => (b"\x1b[F".to_vec(), false),
        "INSERT" => (b"\x1b[2~".to_vec(), false),
        "DELETE" => (b"\x1b[3~".to_vec(), false),
        "PAGE_UP" => (b"\x1b[5~".to_vec(), false),
        "PAGE_DOWN" => (b"\x1b[6~".to_vec(), false),
        "F1" => (b"\x1bOP".to_vec(), false),
        "F2" => (b"\x1bOQ".to_vec(), false),
        "F3" => (b"\x1bOR".to_vec(), false),
        "F4" => (b"\x1bOS".to_vec(), false),
        "F5" => (b"\x1b[15~".to_vec(), false),
        "F6" => (b"\x1b[17~".to_vec(), false),
        "F7" => (b"\x1b[18~".to_vec(), false),
        "F8" => (b"\x1b[19~".to_vec(), false),
        "F9" => (b"\x1b[20~".to_vec(), false),
        "F10" => (b"\x1b[21~".to_vec(), false),
        "F11" => (b"\x1b[23~".to_vec(), false),
        "F12" => (b"\x1b[24~".to_vec(), false),
        "CTRL_BACKSLASH" => (b"\x1c".to_vec(), true),
        "CTRL_RIGHT_BRACKET" => (b"\x1d".to_vec(), true),
        _ => {
            let control = normalized.strip_prefix("CTRL_").and_then(|suffix| {
                (suffix.len() == 1)
                    .then(|| suffix.as_bytes()[0])
                    .filter(u8::is_ascii_uppercase)
            });
            if let Some(letter) = control {
                let byte = letter & 0x1f;
                return Ok((vec![byte], matches!(letter, b'C' | b'Z')));
            }
            return Err(session_error(
                PluginSessionErrorCode::PolicyDenied,
                format!("Unsupported terminal key '{key}'."),
            ));
        }
    };
    Ok(value)
}

fn parse_terminal_signal(name: &str) -> Result<PersistentPtySignal, PluginSessionError> {
    match name.trim().to_ascii_uppercase().as_str() {
        "INT" | "SIGINT" => Ok(PersistentPtySignal::Interrupt),
        "TERM" | "SIGTERM" => Ok(PersistentPtySignal::Terminate),
        "HUP" | "SIGHUP" => Ok(PersistentPtySignal::Hangup),
        "QUIT" | "SIGQUIT" => Ok(PersistentPtySignal::Quit),
        "KILL" | "SIGKILL" => Ok(PersistentPtySignal::Kill),
        _ => Err(session_error(
            PluginSessionErrorCode::PolicyDenied,
            "signal must be one of INT, TERM, HUP, QUIT, or KILL.",
        )),
    }
}

fn contains_password_like_prompt(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim().to_ascii_lowercase();
        let prompt_ending = line.ends_with(':') || line.ends_with('?');
        let password_prompt = line.contains("password")
            && (prompt_ending
                || line.starts_with("enter password")
                || line.starts_with("[sudo] password")
                || line.contains("password for "));
        let passphrase_prompt = line.contains("passphrase")
            && (prompt_ending
                || line.starts_with("enter passphrase")
                || line.contains("passphrase for "));
        let code_prompt = ["verification code", "one-time code", "one time code", "otp"]
            .iter()
            .any(|marker| line.contains(marker))
            && prompt_ending;
        password_prompt || passphrase_prompt || code_prompt
    })
}

fn terminal_dimension(
    input: &Value,
    key: &str,
    default: u16,
    minimum: u16,
    maximum: u16,
) -> Result<u16, PluginSessionError> {
    let Some(raw) = input.get(key) else {
        return Ok(default);
    };
    let value = raw.as_u64().ok_or_else(|| {
        session_error(
            PluginSessionErrorCode::PolicyDenied,
            format!("{key} must be an unsigned integer."),
        )
    })?;
    if value < u64::from(minimum) || value > u64::from(maximum) {
        return Err(session_error(
            PluginSessionErrorCode::PolicyDenied,
            format!("{key} must be between {minimum} and {maximum}."),
        ));
    }
    Ok(value as u16)
}

fn required_terminal_dimension(
    input: &Value,
    key: &str,
    minimum: u16,
    maximum: u16,
) -> Result<u16, PluginSessionError> {
    if input.get(key).is_none() {
        return Err(session_error(
            PluginSessionErrorCode::PolicyDenied,
            format!("{key} is required."),
        ));
    }
    terminal_dimension(input, key, minimum, minimum, maximum)
}

fn optional_u64(input: &Value, key: &str, default: u64) -> Result<u64, PluginSessionError> {
    input
        .get(key)
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                session_error(
                    PluginSessionErrorCode::PolicyDenied,
                    format!("{key} must be an unsigned integer."),
                )
            })
        })
        .unwrap_or(Ok(default))
}

fn optional_usize(
    input: &Value,
    key: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, PluginSessionError> {
    let value = optional_u64(input, key, default as u64)?;
    let value = usize::try_from(value).unwrap_or(usize::MAX);
    if value < minimum || value > maximum {
        return Err(session_error(
            PluginSessionErrorCode::PolicyDenied,
            format!("{key} must be between {minimum} and {maximum}."),
        ));
    }
    Ok(value)
}

fn ensure_capabilities(
    capabilities: &[String],
    allowed: &[&str],
    message: &str,
) -> Result<(), PluginSessionError> {
    if capabilities
        .iter()
        .any(|capability| !allowed.contains(&capability.as_str()))
    {
        return Err(session_error(PluginSessionErrorCode::PolicyDenied, message));
    }
    Ok(())
}

struct SshAgentShellSession {
    shell: Mutex<Option<PersistentShellSession>>,
    redaction_targets: Arc<Vec<RedactionTarget>>,
}

#[async_trait]
impl PluginAgentSession for SshAgentShellSession {
    async fn call(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        if request.capability != "ssh.exec" {
            return Err(session_error(
                PluginSessionErrorCode::PolicyDenied,
                "SSH shell sessions only accept ssh.exec calls.",
            ));
        }
        let command = request
            .input
            .get("command")
            .and_then(Value::as_str)
            .filter(|command| !command.trim().is_empty())
            .ok_or_else(|| {
                session_error(
                    PluginSessionErrorCode::PolicyDenied,
                    "SSH shell call requires a non-empty command.",
                )
            })?;
        let per_stream_default = DEFAULT_STREAM_LIMIT_BYTES
            .min(request.output_limit_bytes.saturating_sub(1024) / 2)
            .max(1);
        let stdout_limit = stream_limit(&request.input, "max_stdout_bytes", per_stream_default)?;
        let stderr_limit = stream_limit(&request.input, "max_stderr_bytes", per_stream_default)?;
        let mut guard = self.shell.lock().await;
        let shell = guard.as_mut().ok_or_else(|| {
            session_error(
                PluginSessionErrorCode::OwnerUnavailable,
                "SSH persistent shell is closed.",
            )
        })?;
        let output = shell
            .execute(command, stdout_limit, stderr_limit)
            .await
            .map_err(|_| {
                session_error(
                    PluginSessionErrorCode::OwnerUnavailable,
                    "SSH persistent shell command failed.",
                )
            })?;
        let (stdout, _) = redact_text_with_targets(&output.stdout, &self.redaction_targets);
        let (stderr, _) = redact_text_with_targets(&output.stderr, &self.redaction_targets);
        AgentSessionCallResult::bounded(
            request.call_id,
            json!({
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": output.exit_code,
                "stdout_bytes": output.stdout_bytes,
                "stderr_bytes": output.stderr_bytes,
                "stdout_truncated": output.stdout_truncated,
                "stderr_truncated": output.stderr_truncated,
                "max_stdout_bytes": stdout_limit,
                "max_stderr_bytes": stderr_limit,
            }),
            request.output_limit_bytes,
        )
    }

    async fn health(&self) -> Result<PluginSessionHealth, PluginSessionError> {
        Ok(if self.shell.lock().await.is_some() {
            PluginSessionHealth::Ready
        } else {
            PluginSessionHealth::Closed
        })
    }

    async fn cancel(&self, _call_id: &str) -> Result<(), PluginSessionError> {
        close_shell(&self.shell).await;
        Ok(())
    }

    async fn close(&self, _reason: String) -> Result<(), PluginSessionError> {
        close_shell(&self.shell).await;
        Ok(())
    }
}

struct SshAgentSftpSession {
    state: Mutex<Option<(SshService, russh_sftp::client::SftpSession)>>,
    redaction_targets: Arc<Vec<RedactionTarget>>,
}

#[async_trait]
impl PluginAgentSession for SshAgentSftpSession {
    async fn call(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        if request.capability != "ssh.sftp_list" {
            return Err(session_error(
                PluginSessionErrorCode::PolicyDenied,
                "Persistent SFTP sessions currently expose ssh.sftp_list.",
            ));
        }
        let path = request
            .input
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or(".");
        let limit = request
            .input
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(100)
            .clamp(1, 1000) as usize;
        let mut guard = self.state.lock().await;
        let (_, sftp) = guard.as_mut().ok_or_else(|| {
            session_error(
                PluginSessionErrorCode::OwnerUnavailable,
                "Persistent SFTP session is closed.",
            )
        })?;
        let entries = sftp.read_dir(path).await.map_err(|_| {
            session_error(
                PluginSessionErrorCode::OwnerUnavailable,
                "Persistent SFTP list failed.",
            )
        })?;
        let mut entries = entries.collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        let source_count = entries.len();
        let entries = entries
            .into_iter()
            .take(limit)
            .map(|entry| {
                let (name, _) =
                    redact_text_with_targets(&entry.file_name(), &self.redaction_targets);
                json!({
                    "name": name,
                    "is_dir": entry.file_type().is_dir(),
                    "size": entry.metadata().size.unwrap_or(0),
                })
            })
            .collect::<Vec<_>>();
        AgentSessionCallResult::bounded(
            request.call_id,
            json!({
                "entries": entries,
                "source_count": source_count,
                "truncated": source_count > limit,
                "limit": limit,
            }),
            request.output_limit_bytes,
        )
    }

    async fn health(&self) -> Result<PluginSessionHealth, PluginSessionError> {
        Ok(if self.state.lock().await.is_some() {
            PluginSessionHealth::Ready
        } else {
            PluginSessionHealth::Closed
        })
    }

    async fn cancel(&self, _call_id: &str) -> Result<(), PluginSessionError> {
        close_sftp(&self.state).await;
        Ok(())
    }

    async fn close(&self, _reason: String) -> Result<(), PluginSessionError> {
        close_sftp(&self.state).await;
        Ok(())
    }
}

async fn close_sftp(state: &Mutex<Option<(SshService, russh_sftp::client::SftpSession)>>) {
    if let Some((service, sftp)) = state.lock().await.take() {
        let _ = sftp.close().await;
        service.disconnect().await;
    }
}

struct SshAgentForwardSession {
    state: Mutex<SshAgentForwardState>,
}

struct SshAgentForwardState {
    handle: Option<crate::service::DirectSessionHandle>,
    active: Option<crate::service::PersistentLocalForward>,
}

#[async_trait]
impl PluginAgentSession for SshAgentForwardSession {
    async fn call(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        match request.capability.as_str() {
            "ssh.forward_open" => {
                let bind_addr = request
                    .input
                    .get("bind_addr")
                    .and_then(Value::as_str)
                    .unwrap_or("127.0.0.1");
                let bind_port = required_port(&request.input, "bind_port", true)?;
                let remote_host = request
                    .input
                    .get("remote_host")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        session_error(
                            PluginSessionErrorCode::PolicyDenied,
                            "remote_host is required.",
                        )
                    })?
                    .to_owned();
                let remote_port = required_port(&request.input, "remote_port", false)?;
                let mut state = self.state.lock().await;
                if state.active.is_some() {
                    return Err(session_error(
                        PluginSessionErrorCode::PolicyDenied,
                        "SSH forwarding session already owns an active forward.",
                    ));
                }
                let handle = state.handle.take().ok_or_else(|| {
                    session_error(
                        PluginSessionErrorCode::OwnerUnavailable,
                        "SSH forwarding transport is unavailable.",
                    )
                })?;
                let forward = handle
                    .open_local_forward(bind_addr, bind_port, remote_host, remote_port)
                    .await
                    .map_err(|_| {
                        session_error(
                            PluginSessionErrorCode::OwnerUnavailable,
                            "SSH local forward could not be opened.",
                        )
                    })?;
                let status = forward.status();
                state.active = Some(forward);
                AgentSessionCallResult::bounded(
                    request.call_id,
                    json!({
                        "mode": "local",
                        "bind_addr": status.bind_addr,
                        "bind_port": status.bind_port,
                        "connections": status.connections,
                        "bytes_sent": status.bytes_sent,
                        "bytes_received": status.bytes_received,
                    }),
                    request.output_limit_bytes,
                )
            }
            "ssh.forward_status" => {
                let state = self.state.lock().await;
                let status = state.active.as_ref().map(|forward| forward.status());
                AgentSessionCallResult::bounded(
                    request.call_id,
                    json!({ "active": status.is_some(), "status": status.map(|status| json!({
                        "mode": "local",
                        "bind_addr": status.bind_addr,
                        "bind_port": status.bind_port,
                        "connections": status.connections,
                        "bytes_sent": status.bytes_sent,
                        "bytes_received": status.bytes_received,
                    })) }),
                    request.output_limit_bytes,
                )
            }
            _ => Err(session_error(
                PluginSessionErrorCode::PolicyDenied,
                "SSH forwarding sessions accept forward_open and forward_status.",
            )),
        }
    }

    async fn health(&self) -> Result<PluginSessionHealth, PluginSessionError> {
        let state = self.state.lock().await;
        Ok(if state.handle.is_some() || state.active.is_some() {
            PluginSessionHealth::Ready
        } else {
            PluginSessionHealth::Closed
        })
    }

    async fn cancel(&self, _call_id: &str) -> Result<(), PluginSessionError> {
        close_forward(&self.state).await;
        Ok(())
    }

    async fn close(&self, _reason: String) -> Result<(), PluginSessionError> {
        close_forward(&self.state).await;
        Ok(())
    }
}

async fn close_forward(state: &Mutex<SshAgentForwardState>) {
    let (active, handle) = {
        let mut state = state.lock().await;
        (state.active.take(), state.handle.take())
    };
    if let Some(active) = active {
        active.close().await;
    } else if let Some(handle) = handle {
        let _ = handle.disconnect().await;
    }
}

fn required_port(input: &Value, key: &str, allow_zero: bool) -> Result<u16, PluginSessionError> {
    let value = input.get(key).and_then(Value::as_u64).ok_or_else(|| {
        session_error(
            PluginSessionErrorCode::PolicyDenied,
            format!("{key} is required."),
        )
    })?;
    if value > u16::MAX as u64 || (!allow_zero && value == 0) {
        return Err(session_error(
            PluginSessionErrorCode::PolicyDenied,
            format!("{key} is outside the valid port range."),
        ));
    }
    Ok(value as u16)
}

async fn close_shell(shell: &Mutex<Option<PersistentShellSession>>) {
    if let Some(shell) = shell.lock().await.take() {
        shell.close().await;
    }
}

fn stream_limit(input: &Value, key: &str, default: usize) -> Result<usize, PluginSessionError> {
    let Some(raw) = input.get(key) else {
        return Ok(default);
    };
    let value = raw.as_u64().ok_or_else(|| {
        session_error(
            PluginSessionErrorCode::PolicyDenied,
            format!("{key} must be an unsigned integer."),
        )
    })?;
    let value = usize::try_from(value).unwrap_or(usize::MAX);
    if value == 0 || value > MAX_STREAM_LIMIT_BYTES {
        return Err(session_error(
            PluginSessionErrorCode::PolicyDenied,
            format!("{key} must be between 1 and {MAX_STREAM_LIMIT_BYTES}."),
        ));
    }
    Ok(value)
}

fn session_error(code: PluginSessionErrorCode, message: impl Into<String>) -> PluginSessionError {
    PluginSessionError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SshAuthMethod;

    #[test]
    fn factory_redaction_targets_include_password_without_exposing_it() {
        let factory = SshAgentSessionFactory::new(SshConfig::new(
            "example.invalid".into(),
            22,
            "tester".into(),
            "super-secret-password".into(),
        ));
        let (redacted, status) =
            redact_text_with_targets("value=super-secret-password", &factory.redaction_targets);
        assert!(!redacted.contains("super-secret-password"));
        assert_eq!(status, voidb_core::RedactionStatus::Applied);
        assert!(matches!(
            factory.config.auth,
            SshAuthMethod::Password { .. }
        ));
    }

    #[test]
    fn stream_limits_are_bounded() {
        assert_eq!(
            stream_limit(&json!({}), "max_stdout_bytes", 128).expect("default"),
            128
        );
        assert!(
            stream_limit(
                &json!({ "max_stdout_bytes": MAX_STREAM_LIMIT_BYTES + 1 }),
                "max_stdout_bytes",
                128
            )
            .is_err()
        );
    }

    #[test]
    fn terminal_write_encodes_text_paste_keys_and_enter() {
        let write = terminal_write_input(&json!({
            "text": "hello",
            "paste": true,
            "keys": ["TAB", "CTRL-C"],
            "enter": true
        }))
        .expect("terminal write");

        assert_eq!(write.bytes, b"\x1b[200~hello\x1b[201~\t\x03\r");
        assert_eq!(write.text_bytes, 5);
        assert_eq!(write.key_count, 2);
        assert!(!write.recovery_only);
    }

    #[test]
    fn terminal_write_allows_only_named_recovery_controls() {
        let recovery =
            terminal_write_input(&json!({ "keys": ["ESC", "CTRL_C"] })).expect("recovery keys");
        assert!(recovery.recovery_only);
        assert!(terminal_write_input(&json!({ "text": "bad\u{0003}" })).is_err());
        assert_eq!(terminal_key_bytes("CTRL_X").expect("ctrl-x").0, b"\x18");
        assert!(terminal_write_input(&json!({ "keys": ["META_X"] })).is_err());
    }

    #[test]
    fn terminal_dimensions_and_reads_are_bounded() {
        assert_eq!(
            terminal_dimension(
                &json!({}),
                "cols",
                DEFAULT_PTY_COLS,
                MIN_PTY_COLS,
                MAX_PTY_COLS,
            )
            .expect("default cols"),
            DEFAULT_PTY_COLS
        );
        assert!(
            terminal_dimension(
                &json!({ "cols": MAX_PTY_COLS + 1 }),
                "cols",
                DEFAULT_PTY_COLS,
                MIN_PTY_COLS,
                MAX_PTY_COLS,
            )
            .is_err()
        );
        assert!(optional_usize(&json!({ "max_bytes": 0 }), "max_bytes", 1, 1, 8).is_err());
    }

    #[test]
    fn password_prompt_detection_is_case_insensitive() {
        assert!(contains_password_like_prompt("[sudo] Password: "));
        assert!(contains_password_like_prompt(
            "[sudo] password for operator:"
        ));
        assert!(contains_password_like_prompt(
            "Enter passphrase for key '/tmp/id_ed25519':"
        ));
        assert!(!contains_password_like_prompt("password policy updated"));
    }
}
