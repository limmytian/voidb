//! SSH service layer.
//!
//! Provides the `SshService` facade that manages SSH sessions, SFTP operations,
//! port forwarding, and system metrics collection.
//!
//! # Architecture
//!
//! The service supports two modes via `ServiceMode`:
//!
//! - **Channel mode** (TUI) — background task with typed command/event channels and
//!   dedicated PTY byte channels (high-throughput, no serialization overhead).
//!   The background task coordinates four sub-services:
//!   - `session` -- SSH connection and PTY shell
//!   - `sftp_worker` -- SFTP file operations
//!   - `forwarding` -- Local/remote/dynamic port forwarding
//!   - `metrics` -- Remote system metrics collection
//!
//! - **Direct mode** (CLI) — synchronous connect+auth with direct async methods.
//!   No background task. Caller awaits each operation in their own async context.
//!   Use `SshService::new_direct()` to create, then call async methods directly.
//!
//! # Port forwarding in Direct mode
//!
//! Port forwarding (local, remote, SOCKS5) inherently requires a running accept loop,
//! which cannot be cleanly expressed as a single-call async method. For CLI forwarding
//! commands, `SshService::into_direct_handle()` exposes the underlying russh session
//! handle so the CLI can drive the forwarding loop itself. This is a documented
//! compromise: forwarding is the only operation that bypasses the service abstraction.

mod agent_pty;
pub mod commands;
pub mod events;
mod forwarding;
mod metrics;
mod session;
mod sftp_worker;
pub mod types;

pub use agent_pty::{
    PersistentPtyRead, PersistentPtySession, PersistentPtySignal, PersistentPtySnapshot,
};
pub use commands::{ForwardServiceCommand, MetricsServiceCommand, SftpServiceCommand, SshCommand};
pub use events::{SftpHandle, SshEvent};
pub use types::*;

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use russh::client;
use russh_sftp::client::SftpSession;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::AbortHandle;
use tracing::{error, info};

use crate::config::{SshAuthMethod, SshConfig};
use forwarding::{ForwardCommand, ForwardEvent, ForwardingManager};
use session::{SshInput, SshSession, SshSessionEvent};
use voidb_core::{
    ConnectionProfileRef, PluginSessionDescriptor, PluginSessionError, PluginSessionErrorCode,
    PluginSessionHealth, PluginSessionPurpose, PluginSessionRegistration, PluginSessionRegistry,
    PluginSessionScope, RedactionStatus, TabManager, VoidbError,
};

static NEXT_STANDALONE_SSH_OWNER_ID: AtomicU64 = AtomicU64::new(1);

// ---------------------------------------------------------------------------
// Direct-mode SSH handle (CLI usage)
// ---------------------------------------------------------------------------

pub(crate) type HostKeyFailureSlot = Arc<Mutex<Option<DirectHostKeyFailure>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectHostKeyFailureKind {
    Unknown,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectHostKeyFailure {
    kind: DirectHostKeyFailureKind,
    host: String,
    port: u16,
    fingerprint: String,
    known_hosts_line: Option<usize>,
}

impl DirectHostKeyFailure {
    fn code(&self) -> &'static str {
        match self.kind {
            DirectHostKeyFailureKind::Unknown => "ssh.host_key_unknown",
            DirectHostKeyFailureKind::Changed => "ssh.host_key_changed",
        }
    }

    fn message(&self) -> String {
        match self.kind {
            DirectHostKeyFailureKind::Unknown => format!(
                "{}: host key for {}:{} is not present in known_hosts (fingerprint {})",
                self.code(),
                self.host,
                self.port,
                self.fingerprint
            ),
            DirectHostKeyFailureKind::Changed => format!(
                "{}: host key for {}:{} changed at known_hosts line {} (fingerprint {})",
                self.code(),
                self.host,
                self.port,
                self.known_hosts_line
                    .map(|line| line.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                self.fingerprint
            ),
        }
    }
}

/// Minimal russh client handler for non-interactive CLI / direct-mode usage.
///
/// Direct mode is used by the CLI and agent capability paths, so it must not
/// prompt or trust on first use. It accepts only keys already present in the
/// user's known_hosts file and records structured diagnostics for callers.
pub(crate) struct DirectCliHandler {
    host: String,
    port: u16,
    host_key_failure: HostKeyFailureSlot,
}

impl DirectCliHandler {
    fn strict(host: String, port: u16, host_key_failure: HostKeyFailureSlot) -> Self {
        Self {
            host,
            port,
            host_key_failure,
        }
    }
}

#[async_trait]
impl client::Handler for DirectCliHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        strict_host_key_check(
            &self.host,
            self.port,
            server_public_key,
            &self.host_key_failure,
        )
    }
}

pub(crate) fn new_host_key_failure_slot() -> HostKeyFailureSlot {
    Arc::new(Mutex::new(None))
}

pub(crate) fn strict_host_key_check(
    host: &str,
    port: u16,
    server_public_key: &ssh_key::PublicKey,
    host_key_failure: &HostKeyFailureSlot,
) -> Result<bool, russh::Error> {
    match russh_keys::check_known_hosts(host, port, server_public_key) {
        Ok(true) => Ok(true),
        Ok(false) => {
            record_host_key_failure(
                host_key_failure,
                DirectHostKeyFailure {
                    kind: DirectHostKeyFailureKind::Unknown,
                    host: host.to_string(),
                    port,
                    fingerprint: format_fingerprint(server_public_key),
                    known_hosts_line: None,
                },
            );
            Ok(false)
        }
        Err(russh_keys::Error::KeyChanged { line }) => {
            record_host_key_failure(
                host_key_failure,
                DirectHostKeyFailure {
                    kind: DirectHostKeyFailureKind::Changed,
                    host: host.to_string(),
                    port,
                    fingerprint: format_fingerprint(server_public_key),
                    known_hosts_line: Some(line),
                },
            );
            Ok(false)
        }
        Err(_) => {
            record_host_key_failure(
                host_key_failure,
                DirectHostKeyFailure {
                    kind: DirectHostKeyFailureKind::Unknown,
                    host: host.to_string(),
                    port,
                    fingerprint: format_fingerprint(server_public_key),
                    known_hosts_line: None,
                },
            );
            Ok(false)
        }
    }
}

fn record_host_key_failure(slot: &HostKeyFailureSlot, failure: DirectHostKeyFailure) {
    if let Ok(mut stored) = slot.lock() {
        *stored = Some(failure);
    }
}

pub(crate) fn host_key_connection_error(
    host_key_failure: &HostKeyFailureSlot,
    fallback: impl std::fmt::Display,
) -> VoidbError {
    if let Ok(stored) = host_key_failure.lock()
        && let Some(failure) = stored.clone()
    {
        return VoidbError::Connection(failure.message());
    }

    VoidbError::Connection(format!("SSH connection failed: {}", fallback))
}

pub fn direct_connection_error_code(error: &VoidbError) -> &'static str {
    match error {
        VoidbError::Connection(message) if message.contains("ssh.host_key_unknown") => {
            "ssh.host_key_unknown"
        }
        VoidbError::Connection(message) if message.contains("ssh.host_key_changed") => {
            "ssh.host_key_changed"
        }
        _ => "ssh.connect_failed",
    }
}

fn format_fingerprint(key: &ssh_key::PublicKey) -> String {
    let fp = key.fingerprint(ssh_key::HashAlg::Sha256);
    format!("{} {}", key.algorithm(), fp)
}

/// Low-level russh session handle returned by `SshService::into_direct_handle`.
///
/// The CLI forwarding commands need to drive their own accept loops and therefore
/// require direct access to the russh handle. This type is intentionally opaque
/// to avoid leaking russh types into callers that do not need them.
pub struct DirectSessionHandle {
    pub(crate) inner: client::Handle<DirectCliHandler>,
}

impl DirectSessionHandle {
    /// Gracefully disconnect the SSH session.
    pub async fn disconnect(self) -> Result<(), russh::Error> {
        self.inner
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await
    }

    /// Start one non-interactive POSIX shell whose process state survives
    /// multiple structured agent calls.
    pub async fn open_persistent_shell(
        self,
    ) -> Result<PersistentShellSession, voidb_core::VoidbError> {
        let channel = self.inner.channel_open_session().await.map_err(|error| {
            VoidbError::Plugin(format!("Failed to open shell channel: {error}"))
        })?;
        channel.exec(true, b"sh -s").await.map_err(|error| {
            VoidbError::Plugin(format!("Failed to start persistent shell: {error}"))
        })?;
        Ok(PersistentShellSession {
            handle: Some(self.inner),
            channel: Some(channel),
            pending_stdout: Vec::new(),
            pending_stderr: Vec::new(),
        })
    }

    /// Start one agent-owned interactive PTY shell with bounded retained output.
    pub async fn open_interactive_terminal(
        self,
        term_type: &str,
        cols: u16,
        rows: u16,
        scrollback_rows: usize,
        output_capacity: usize,
    ) -> Result<PersistentPtySession, voidb_core::VoidbError> {
        PersistentPtySession::open(
            self.inner,
            term_type,
            cols,
            rows,
            scrollback_rows,
            output_capacity,
        )
        .await
    }

    pub async fn open_local_forward(
        self,
        bind_addr: &str,
        bind_port: u16,
        remote_host: String,
        remote_port: u16,
    ) -> Result<PersistentLocalForward, VoidbError> {
        let listener = TcpListener::bind((bind_addr, bind_port))
            .await
            .map_err(|_| VoidbError::Plugin("Failed to bind local SSH forward".into()))?;
        let local_addr = listener
            .local_addr()
            .map_err(|_| VoidbError::Plugin("Failed to inspect local SSH forward".into()))?;
        let handle = Arc::new(self.inner);
        let stats = Arc::new(PersistentForwardStats::default());
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let task_handle = Arc::clone(&handle);
        let task_stats = Arc::clone(&stats);
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    changed = cancel_rx.changed() => {
                        if changed.is_err() || *cancel_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, peer)) = accepted else { break };
                        let handle = Arc::clone(&task_handle);
                        let remote_host = remote_host.clone();
                        let stats = Arc::clone(&task_stats);
                        children.spawn(async move {
                            stats.connections.fetch_add(1, Ordering::Relaxed);
                            let _ = bridge_local_forward(
                                stream,
                                handle,
                                remote_host,
                                remote_port,
                                peer.ip().to_string(),
                                peer.port(),
                                Arc::clone(&stats),
                            )
                            .await;
                            stats.connections.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Some(_) = children.join_next(), if !children.is_empty() => {}
                }
            }
            children.abort_all();
            while children.join_next().await.is_some() {}
        });
        Ok(PersistentLocalForward {
            handle,
            cancel_tx,
            task: Some(task),
            stats,
            bind_addr: local_addr.ip().to_string(),
            bind_port: local_addr.port(),
        })
    }
}

#[derive(Default)]
struct PersistentForwardStats {
    connections: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentForwardStatus {
    pub bind_addr: String,
    pub bind_port: u16,
    pub connections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

pub struct PersistentLocalForward {
    handle: Arc<client::Handle<DirectCliHandler>>,
    cancel_tx: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
    stats: Arc<PersistentForwardStats>,
    bind_addr: String,
    bind_port: u16,
}

impl PersistentLocalForward {
    pub fn status(&self) -> PersistentForwardStatus {
        PersistentForwardStatus {
            bind_addr: self.bind_addr.clone(),
            bind_port: self.bind_port,
            connections: self.stats.connections.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
        }
    }

    pub async fn close(mut self) {
        let _ = self.cancel_tx.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        let _ = self
            .handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
    }
}

async fn bridge_local_forward(
    mut tcp: TcpStream,
    handle: Arc<client::Handle<DirectCliHandler>>,
    remote_host: String,
    remote_port: u16,
    originator_addr: String,
    originator_port: u16,
    stats: Arc<PersistentForwardStats>,
) -> Result<(), russh::Error> {
    let mut channel = handle
        .channel_open_direct_tcpip(
            &remote_host,
            remote_port as u32,
            &originator_addr,
            originator_port as u32,
        )
        .await?;
    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            read = tcp.read(&mut buffer) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(count) => {
                        channel.data(&buffer[..count]).await?;
                        stats.bytes_sent.fetch_add(count as u64, Ordering::Relaxed);
                    }
                }
            }
            message = channel.wait() => {
                match message {
                    Some(russh::ChannelMsg::Data { data }) => {
                        if tcp.write_all(&data).await.is_err() { break; }
                        stats.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                    Some(russh::ChannelMsg::Close) | None => break,
                    _ => {}
                }
            }
        }
    }
    let _ = channel.close().await;
    Ok(())
}

/// Output from one framed command in a persistent shell process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentShellOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: u32,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

/// Plugin-owned long-lived shell channel. The SSH transport and channel never
/// leave the SSH service module.
pub struct PersistentShellSession {
    handle: Option<client::Handle<DirectCliHandler>>,
    channel: Option<russh::Channel<client::Msg>>,
    pending_stdout: Vec<u8>,
    pending_stderr: Vec<u8>,
}

impl PersistentShellSession {
    pub async fn execute(
        &mut self,
        command: &str,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<PersistentShellOutput, VoidbError> {
        if command.trim().is_empty() {
            return Err(VoidbError::Plugin("SSH shell command is empty".into()));
        }
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let marker_prefix = format!("\u{1e}voidb:{nonce}:").into_bytes();
        let marker_suffix = b"\x1f\n";
        let quoted = quote_posix_shell(command);
        let script = format!(
            "__voidb_cmd={quoted}\neval \"$__voidb_cmd\" </dev/null\n__voidb_status=$?\ncommand printf '\\036voidb:{nonce}:%s\\037\\n' \"$__voidb_status\"\nunset __voidb_cmd __voidb_status\n"
        );
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| VoidbError::Plugin("Persistent SSH shell is closed".into()))?;
        channel.data(script.as_bytes()).await.map_err(|error| {
            VoidbError::Plugin(format!("Failed to write shell command: {error}"))
        })?;

        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    self.pending_stdout.extend_from_slice(&data);
                }
                Some(russh::ChannelMsg::ExtendedData { data, ext: 1 }) => {
                    self.pending_stderr.extend_from_slice(&data);
                }
                Some(russh::ChannelMsg::Close) | None => {
                    self.channel = None;
                    return Err(VoidbError::Plugin(
                        "Persistent SSH shell closed before completing the command".into(),
                    ));
                }
                _ => {}
            }

            if let Some((start, end, exit_code)) =
                find_shell_marker(&self.pending_stdout, &marker_prefix, marker_suffix)
            {
                let stdout = self.pending_stdout[..start].to_vec();
                self.pending_stdout.drain(..end);
                let stderr = std::mem::take(&mut self.pending_stderr);
                let (stdout, stdout_bytes, stdout_truncated) =
                    bounded_utf8(&stdout, max_stdout_bytes);
                let (stderr, stderr_bytes, stderr_truncated) =
                    bounded_utf8(&stderr, max_stderr_bytes);
                return Ok(PersistentShellOutput {
                    stdout,
                    stderr,
                    exit_code,
                    stdout_bytes,
                    stderr_bytes,
                    stdout_truncated,
                    stderr_truncated,
                });
            }
        }
    }

    pub async fn close(mut self) {
        if let Some(channel) = self.channel.take() {
            let _ = channel.eof().await;
            let _ = channel.close().await;
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle
                .disconnect(russh::Disconnect::ByApplication, "", "en")
                .await;
        }
    }
}

fn quote_posix_shell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn find_shell_marker(buffer: &[u8], prefix: &[u8], suffix: &[u8]) -> Option<(usize, usize, u32)> {
    let start = buffer
        .windows(prefix.len())
        .position(|window| window == prefix)?;
    let status_start = start + prefix.len();
    let relative_end = buffer[status_start..]
        .windows(suffix.len())
        .position(|window| window == suffix)?;
    let status_end = status_start + relative_end;
    let exit_code = std::str::from_utf8(&buffer[status_start..status_end])
        .ok()?
        .parse()
        .ok()?;
    Some((start, status_end + suffix.len(), exit_code))
}

fn bounded_utf8(bytes: &[u8], limit: usize) -> (String, usize, bool) {
    let source_bytes = bytes.len();
    let value = String::from_utf8_lossy(bytes);
    let mut end = value.len().min(limit);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), source_bytes, value.len() > limit)
}

/// Structured output from a direct-mode SSH exec call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<u32>,
}

#[derive(Clone)]
struct SshSessionRegistryContext {
    sessions: Arc<PluginSessionRegistry>,
    owner_id: String,
    profile_ref: Option<ConnectionProfileRef>,
    control_tx: mpsc::UnboundedSender<SshCommand>,
}

#[derive(Debug, Clone)]
struct RegisteredSshSession {
    id: String,
}

impl RegisteredSshSession {
    fn from_descriptor(descriptor: PluginSessionDescriptor) -> Self {
        Self {
            id: descriptor.session_id,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SshSessionCloseCommand {
    Disconnect,
    CloseSftp,
    RemoveForward(u32),
}

struct SshSessionDescriptorSpec {
    purpose: PluginSessionPurpose,
    initial_health: PluginSessionHealth,
    authenticated: bool,
    destructive_capable: bool,
    stream_capable: bool,
    metadata: Value,
    close_command: SshSessionCloseCommand,
}

struct SshBackgroundTaskContext {
    control_tx: mpsc::UnboundedSender<SshCommand>,
    event_tx: mpsc::UnboundedSender<SshEvent>,
    pty_input_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pty_output_tx: mpsc::UnboundedSender<Vec<u8>>,
    tabs: Arc<dyn TabManager>,
    sessions: Arc<PluginSessionRegistry>,
    owner_id: String,
    profile_ref: Option<ConnectionProfileRef>,
}

impl SshSessionCloseCommand {
    fn send(
        self,
        control_tx: &mpsc::UnboundedSender<SshCommand>,
    ) -> Result<(), PluginSessionError> {
        let command = match self {
            Self::Disconnect => SshCommand::Disconnect,
            Self::CloseSftp => SshCommand::Sftp(SftpServiceCommand::Close),
            Self::RemoveForward(id) => SshCommand::Forward(ForwardServiceCommand::Remove(id)),
        };
        control_tx.send(command).map_err(|_| {
            PluginSessionError::new(
                PluginSessionErrorCode::OwnerUnavailable,
                "SSH service command channel is closed.",
            )
        })
    }
}

impl SshSessionRegistryContext {
    fn register(&self, spec: SshSessionDescriptorSpec) -> Option<RegisteredSshSession> {
        let close_command = spec.close_command;
        let mut registration = PluginSessionRegistration::new(
            "ssh",
            self.owner_id.clone(),
            spec.purpose,
            PluginSessionScope::RemoteTarget,
        )
        .with_health(spec.initial_health)
        .with_authenticated(spec.authenticated)
        .with_destructive_capable(spec.destructive_capable)
        .with_stream_capable(spec.stream_capable)
        .with_metadata(spec.metadata, RedactionStatus::NotRequired)
        .with_close_callback({
            let control_tx = self.control_tx.clone();
            move |_request| close_command.send(&control_tx)
        });

        if let Some(profile_ref) = self.profile_ref.clone() {
            registration = registration.with_profile_ref(profile_ref);
        }

        self.sessions
            .register(registration)
            .ok()
            .map(RegisteredSshSession::from_descriptor)
    }

    fn mark_health(
        &self,
        session: &RegisteredSshSession,
        health: PluginSessionHealth,
        reason: &str,
    ) {
        let Some(descriptor) = self.sessions.get(&session.id) else {
            return;
        };
        let _ = self
            .sessions
            .update_health(&session.id, descriptor.generation, health, reason);
    }
}

fn terminal_session_metadata(cols: u16, rows: u16) -> Value {
    json!({
        "kind": "pty",
        "cols": cols,
        "rows": rows,
    })
}

fn sftp_session_metadata() -> Value {
    json!({ "kind": "sftp" })
}

fn forward_session_metadata(id: u32) -> Value {
    json!({
        "kind": "port_forward",
        "forward_id": id,
    })
}

fn forward_status_health(status: &ForwardStatus) -> PluginSessionHealth {
    match status {
        ForwardStatus::Starting => PluginSessionHealth::Starting,
        ForwardStatus::Active => PluginSessionHealth::Ready,
        ForwardStatus::Error(_) => PluginSessionHealth::Failed,
        ForwardStatus::Stopped => PluginSessionHealth::Closed,
    }
}

fn forward_status_reason(status: &ForwardStatus) -> &'static str {
    match status {
        ForwardStatus::Starting => "forward_starting",
        ForwardStatus::Active => "forward_active",
        ForwardStatus::Error(_) => "forward_error",
        ForwardStatus::Stopped => "forward_stopped",
    }
}

fn close_registered_ssh_sessions(
    lifecycle: &SshSessionRegistryContext,
    terminal_session: &mut Option<RegisteredSshSession>,
    sftp_session: &mut Option<RegisteredSshSession>,
    forward_sessions: &mut HashMap<u32, RegisteredSshSession>,
    reason: &str,
) {
    for (_, session) in forward_sessions.drain() {
        lifecycle.mark_health(&session, PluginSessionHealth::Closed, reason);
    }
    if let Some(session) = sftp_session.take() {
        lifecycle.mark_health(&session, PluginSessionHealth::Closed, reason);
    }
    if let Some(session) = terminal_session.take() {
        lifecycle.mark_health(&session, PluginSessionHealth::Closed, reason);
    }
}

// ---------------------------------------------------------------------------
// ServiceMode
// ---------------------------------------------------------------------------

/// Operating mode for `SshService`.
enum ServiceMode {
    /// Channel-based mode for TUI plugins (background task with mpsc channels).
    Channel {
        cmd_tx: mpsc::UnboundedSender<SshCommand>,
        event_rx: mpsc::UnboundedReceiver<SshEvent>,
        pty_input_tx: mpsc::UnboundedSender<Vec<u8>>,
        pty_output_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        _task: tokio::task::JoinHandle<()>,
    },
    /// Direct async mode for CLI usage (no background task).
    Direct {
        handle: client::Handle<DirectCliHandler>,
    },
}

// ---------------------------------------------------------------------------
// SshService
// ---------------------------------------------------------------------------

/// SSH service facade.
///
/// Supports two construction modes:
/// - [`SshService::new`] — channel/TUI mode with a background task
/// - [`SshService::new_direct`] — direct/CLI mode, connects synchronously
///
/// # Send + Sync
///
/// `SshService` is `Send` but NOT `Sync` (because `UnboundedReceiver`
/// is `!Sync`). Plugin structs must wrap it in `std::sync::Mutex` to
/// satisfy `Plugin: Send + Sync`.
pub struct SshService {
    mode: ServiceMode,
}

impl SshService {
    /// Create a new SshService with a background processing task (TUI / Channel mode).
    pub fn new(
        config: SshConfig,
        tabs: Arc<dyn TabManager>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        let owner_sequence = NEXT_STANDALONE_SSH_OWNER_ID.fetch_add(1, Ordering::Relaxed);
        Self::new_with_sessions(
            config,
            tabs,
            runtime,
            Arc::new(PluginSessionRegistry::new()),
            format!("ssh-standalone-service-{}", owner_sequence),
            None,
        )
    }

    /// Create a new SshService with a shared session descriptor registry.
    pub fn new_with_sessions(
        config: SshConfig,
        tabs: Arc<dyn TabManager>,
        runtime: tokio::runtime::Handle,
        sessions: Arc<PluginSessionRegistry>,
        owner_id: String,
        profile_ref: Option<ConnectionProfileRef>,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<SshCommand>();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<SshEvent>();
        let (pty_input_tx, pty_input_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (pty_output_tx, pty_output_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        let task = runtime.spawn(background_task(
            config,
            cmd_rx,
            SshBackgroundTaskContext {
                control_tx: cmd_tx.clone(),
                event_tx,
                pty_input_rx,
                pty_output_tx,
                tabs,
                sessions,
                owner_id,
                profile_ref,
            },
        ));

        Self {
            mode: ServiceMode::Channel {
                cmd_tx,
                event_rx,
                pty_input_tx,
                pty_output_rx,
                _task: task,
            },
        }
    }

    /// Create a new SshService in Direct mode by connecting and authenticating
    /// immediately (CLI / non-interactive use).
    ///
    /// Returns an error if the connection or authentication fails.
    pub async fn new_direct(config: SshConfig) -> Result<Self, voidb_core::VoidbError> {
        let handle = connect_and_auth_direct(&config).await?;
        Ok(Self {
            mode: ServiceMode::Direct { handle },
        })
    }

    // -----------------------------------------------------------------------
    // Channel-mode methods (TUI)
    // -----------------------------------------------------------------------

    /// Send a command to the background service task (non-blocking).
    ///
    /// Only valid in Channel mode; silently drops the command in Direct mode.
    pub fn send(&self, cmd: SshCommand) {
        if let ServiceMode::Channel { cmd_tx, .. } = &self.mode {
            let _ = cmd_tx.send(cmd);
        }
    }

    /// Poll for the next event from the service (non-blocking).
    ///
    /// Only valid in Channel mode; always returns `None` in Direct mode.
    pub fn poll_event(&mut self) -> Option<SshEvent> {
        if let ServiceMode::Channel { event_rx, .. } = &mut self.mode {
            event_rx.try_recv().ok()
        } else {
            None
        }
    }

    /// Send raw PTY input data to the SSH session (non-blocking).
    ///
    /// Only valid in Channel mode; silently drops data in Direct mode.
    pub fn send_pty_input(&self, data: Vec<u8>) {
        if let ServiceMode::Channel { pty_input_tx, .. } = &self.mode {
            let _ = pty_input_tx.send(data);
        }
    }

    /// Poll for the next PTY output data from the SSH session (non-blocking).
    ///
    /// Only valid in Channel mode; always returns `None` in Direct mode.
    pub fn poll_pty_output(&mut self) -> Option<Vec<u8>> {
        if let ServiceMode::Channel { pty_output_rx, .. } = &mut self.mode {
            pty_output_rx.try_recv().ok()
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // Direct-mode methods (CLI)
    // -----------------------------------------------------------------------

    /// Execute a command on the remote host and return its stdout as a string.
    ///
    /// Also returns the exit code (if the server sends one). Stderr is written
    /// directly to the process stderr.
    ///
    /// Only valid in Direct mode.
    pub async fn exec(
        &mut self,
        command: &str,
    ) -> Result<(String, Option<u32>), voidb_core::VoidbError> {
        let output = self.exec_output(command).await?;
        eprint!("{}", output.stderr);
        Ok((output.stdout, output.exit_code))
    }

    /// Execute a command on the remote host and return structured stdout,
    /// stderr, and exit-code data.
    ///
    /// Only valid in Direct mode.
    pub async fn exec_output(
        &mut self,
        command: &str,
    ) -> Result<SshExecOutput, voidb_core::VoidbError> {
        let handle = self.require_direct_handle()?;
        let mut channel = handle.channel_open_session().await.map_err(|e| {
            voidb_core::VoidbError::Plugin(format!("Failed to open channel: {}", e))
        })?;

        channel.exec(true, command.as_bytes()).await.map_err(|e| {
            voidb_core::VoidbError::Plugin(format!("Failed to exec command: {}", e))
        })?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code: Option<u32> = None;

        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    stdout.extend_from_slice(&data);
                }
                Some(russh::ChannelMsg::ExtendedData { data, ext }) => {
                    if ext == 1 {
                        stderr.extend_from_slice(&data);
                    }
                }
                Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                    exit_code = Some(exit_status);
                }
                Some(russh::ChannelMsg::Eof) => {}
                Some(russh::ChannelMsg::Close) | None => break,
                _ => {}
            }
        }

        Ok(SshExecOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code,
        })
    }

    /// Open an SFTP session on the current direct connection.
    ///
    /// Returns a `russh_sftp::client::SftpSession` that the caller can use directly.
    /// Only valid in Direct mode.
    pub async fn open_sftp(&mut self) -> Result<SftpSession, voidb_core::VoidbError> {
        let handle = self.require_direct_handle()?;
        let channel = handle.channel_open_session().await.map_err(|e| {
            voidb_core::VoidbError::Plugin(format!("Failed to open channel: {}", e))
        })?;

        channel.request_subsystem(true, "sftp").await.map_err(|e| {
            voidb_core::VoidbError::Plugin(format!("Failed to request SFTP: {}", e))
        })?;

        SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| voidb_core::VoidbError::Plugin(format!("SFTP init failed: {}", e)))
    }

    /// List a remote directory via SFTP. Returns a vec of `(name, is_dir, size)` tuples.
    ///
    /// Only valid in Direct mode.
    pub async fn sftp_ls(
        &mut self,
        path: &str,
    ) -> Result<Vec<(String, bool, u64)>, voidb_core::VoidbError> {
        let sftp = self.open_sftp().await?;
        let entries = sftp.read_dir(path).await.map_err(|e| {
            voidb_core::VoidbError::Plugin(format!("Failed to list directory: {}", e))
        })?;

        Ok(entries
            .into_iter()
            .map(|e| {
                let is_dir = e.file_type().is_dir();
                let size = e.metadata().size.unwrap_or(0);
                (e.file_name(), is_dir, size)
            })
            .collect())
    }

    /// Download a remote file to a local path via SFTP.
    ///
    /// Returns the number of bytes downloaded.
    /// Only valid in Direct mode.
    pub async fn sftp_get(
        &mut self,
        remote: &str,
        local: &str,
    ) -> Result<usize, voidb_core::VoidbError> {
        let data = self.sftp_read_remote(remote).await?;
        let len = data.len();
        tokio::fs::write(local, &data).await.map_err(|e| {
            voidb_core::VoidbError::Plugin(format!("Failed to write local file: {}", e))
        })?;
        Ok(len)
    }

    /// Upload a local file to a remote path via SFTP.
    ///
    /// Returns the number of bytes uploaded.
    /// Only valid in Direct mode.
    pub async fn sftp_put(
        &mut self,
        local: &str,
        remote: &str,
    ) -> Result<usize, voidb_core::VoidbError> {
        let data = tokio::fs::read(local).await.map_err(|e| {
            voidb_core::VoidbError::Plugin(format!("Failed to read local file: {}", e))
        })?;
        self.sftp_write_remote(remote, &data).await
    }

    /// Read a remote SFTP file without choosing a local destination.
    pub async fn sftp_read_remote(
        &mut self,
        remote: &str,
    ) -> Result<Vec<u8>, voidb_core::VoidbError> {
        let sftp = self.open_sftp().await?;
        sftp.read(remote).await.map_err(|e| {
            voidb_core::VoidbError::Plugin(format!("Failed to read remote file: {}", e))
        })
    }

    /// Write caller-provided bytes to a remote SFTP file.
    pub async fn sftp_write_remote(
        &mut self,
        remote: &str,
        data: &[u8],
    ) -> Result<usize, voidb_core::VoidbError> {
        let len = data.len();
        let sftp = self.open_sftp().await?;
        let mut remote_file = sftp.create(remote).await.map_err(|e| {
            voidb_core::VoidbError::Plugin(format!("Failed to create remote file: {}", e))
        })?;

        use tokio::io::AsyncWriteExt;
        remote_file.write_all(data).await.map_err(|e| {
            voidb_core::VoidbError::Plugin(format!("Failed to write remote file: {}", e))
        })?;
        remote_file.shutdown().await.map_err(|e| {
            voidb_core::VoidbError::Plugin(format!("Failed to close remote file: {}", e))
        })?;
        Ok(len)
    }

    /// Delete a remote file via SFTP.
    ///
    /// Only valid in Direct mode.
    pub async fn sftp_rm(&mut self, path: &str) -> Result<(), voidb_core::VoidbError> {
        let sftp = self.open_sftp().await?;
        sftp.remove_file(path)
            .await
            .map_err(|e| voidb_core::VoidbError::Plugin(format!("Failed to remove file: {}", e)))
    }

    /// Create a remote directory via SFTP.
    ///
    /// Only valid in Direct mode.
    pub async fn sftp_mkdir(&mut self, path: &str) -> Result<(), voidb_core::VoidbError> {
        let sftp = self.open_sftp().await?;
        sftp.create_dir(path).await.map_err(|e| {
            voidb_core::VoidbError::Plugin(format!("Failed to create directory: {}", e))
        })
    }

    /// Gracefully disconnect and consume the service.
    ///
    /// In Channel mode, sends a `Disconnect` command and drops the background task handle.
    /// In Direct mode, disconnects the russh session.
    pub async fn disconnect(self) {
        match self.mode {
            ServiceMode::Channel { cmd_tx, .. } => {
                let _ = cmd_tx.send(SshCommand::Disconnect);
            }
            ServiceMode::Direct { handle, .. } => {
                let _ = handle
                    .disconnect(russh::Disconnect::ByApplication, "", "en")
                    .await;
            }
        }
    }

    /// Consume the service and return the underlying russh session handle.
    ///
    /// **This is a documented compromise**: port forwarding requires an accept loop that
    /// cannot be expressed as a single-call async method. CLI forwarding commands use
    /// this method to take ownership of the session handle and drive the loop themselves.
    ///
    /// Only valid in Direct mode; returns `None` in Channel mode.
    pub fn into_direct_handle(self) -> Option<DirectSessionHandle> {
        match self.mode {
            ServiceMode::Direct { handle, .. } => Some(DirectSessionHandle { inner: handle }),
            ServiceMode::Channel { .. } => None,
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Borrow the russh handle, returning an error if not in Direct mode.
    fn require_direct_handle(
        &mut self,
    ) -> Result<&mut client::Handle<DirectCliHandler>, voidb_core::VoidbError> {
        match &mut self.mode {
            ServiceMode::Direct { handle, .. } => Ok(handle),
            ServiceMode::Channel { .. } => Err(voidb_core::VoidbError::Plugin(
                "Operation requires Direct mode (use SshService::new_direct)".to_string(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Connection + authentication helper for Direct mode
// ---------------------------------------------------------------------------

/// Connect to an SSH server and authenticate using the given config.
///
/// Uses strict known_hosts verification. Returns the authenticated russh
/// session handle on success.
async fn connect_and_auth_direct(
    config: &SshConfig,
) -> Result<client::Handle<DirectCliHandler>, voidb_core::VoidbError> {
    let client_config = client::Config {
        keepalive_interval: None,
        ..Default::default()
    };

    let host_key_failure = new_host_key_failure_slot();
    let handler =
        DirectCliHandler::strict(config.host.clone(), config.port, host_key_failure.clone());
    let addr = (config.host.as_str(), config.port);
    let timeout_dur = std::time::Duration::from_secs(config.options.connect_timeout);

    let mut session = tokio::time::timeout(
        timeout_dur,
        client::connect(Arc::new(client_config), addr, handler),
    )
    .await
    .map_err(|_| {
        voidb_core::VoidbError::Connection(format!(
            "Connection timed out after {}s",
            config.options.connect_timeout
        ))
    })?
    .map_err(|e| host_key_connection_error(&host_key_failure, e))?;

    // Authenticate
    match &config.auth {
        SshAuthMethod::Password { password } => {
            let ok = session
                .authenticate_password(&config.username, password)
                .await
                .map_err(|e| voidb_core::VoidbError::Connection(format!("Auth error: {}", e)))?;
            if !ok {
                return Err(voidb_core::VoidbError::Connection(
                    "Authentication failed: invalid username or password".to_string(),
                ));
            }
        }
        SshAuthMethod::PublicKey {
            private_key_path,
            passphrase,
        } => {
            let key = russh_keys::load_secret_key(private_key_path, passphrase.as_deref())
                .map_err(|e| {
                    voidb_core::VoidbError::Connection(format!("Failed to load key: {}", e))
                })?;
            let ok = session
                .authenticate_publickey(&config.username, Arc::new(key))
                .await
                .map_err(|e| voidb_core::VoidbError::Connection(format!("Auth error: {}", e)))?;
            if !ok {
                return Err(voidb_core::VoidbError::Connection(
                    "Public key authentication failed".to_string(),
                ));
            }
        }
        SshAuthMethod::Agent => {
            let mut agent = russh_keys::agent::client::AgentClient::connect_env()
                .await
                .map_err(|e| {
                    voidb_core::VoidbError::Connection(format!("SSH agent not available: {}", e))
                })?;
            let identities = agent.request_identities().await.map_err(|e| {
                voidb_core::VoidbError::Connection(format!("Agent list failed: {}", e))
            })?;
            if identities.is_empty() {
                return Err(voidb_core::VoidbError::Connection(
                    "SSH agent has no keys".to_string(),
                ));
            }
            let mut ok = false;
            for key in &identities {
                if let Ok(true) = session
                    .authenticate_publickey_with(&config.username, key.clone(), &mut agent)
                    .await
                {
                    ok = true;
                    break;
                }
            }
            if !ok {
                return Err(voidb_core::VoidbError::Connection(
                    "SSH agent authentication failed".to_string(),
                ));
            }
        }
    }

    Ok(session)
}

/// Background task that coordinates all SSH sub-services.
///
/// Architecture: The task waits for a `Connect` command first, then enters
/// the main event loop with all channels wired up. On `Disconnect`, the task
/// exits. For reconnection, the TUI creates a new `SshService` instance.
async fn background_task(
    _initial_config: SshConfig,
    mut cmd_rx: mpsc::UnboundedReceiver<SshCommand>,
    context: SshBackgroundTaskContext,
) {
    let SshBackgroundTaskContext {
        control_tx,
        event_tx,
        mut pty_input_rx,
        pty_output_tx,
        tabs,
        sessions,
        owner_id,
        profile_ref,
    } = context;

    // Wait for Connect command. A standalone TUI can send the pane size before
    // Connect so the remote PTY does not start with the fallback 80x24 size.
    let mut initial_cols: u16 = 80;
    let mut initial_rows: u16 = 24;
    let connect_config = loop {
        match cmd_rx.recv().await {
            Some(SshCommand::Connect { config }) => break config,
            Some(SshCommand::Resize { cols, rows }) => {
                initial_cols = cols.max(1);
                initial_rows = rows.max(1);
            }
            Some(SshCommand::Disconnect) | None => return,
            // Ignore other commands before connection
            Some(_) => continue,
        }
    };

    let config = connect_config;
    let last_config = config.clone();
    let lifecycle = SshSessionRegistryContext {
        sessions,
        owner_id,
        profile_ref,
        control_tx,
    };

    // === Create all internal channels ===

    // SSH session event bridge
    let (session_event_tx, mut session_event_rx) = mpsc::unbounded_channel::<SshSessionEvent>();

    // SSH input channel -- shared with forwarding manager and metrics collector
    let (ssh_input_tx, ssh_input_rx) = mpsc::unbounded_channel::<SshInput>();

    // Forwarding channels
    let (fwd_cmd_tx, fwd_cmd_rx) = mpsc::unbounded_channel::<ForwardCommand>();
    let (fwd_event_tx, mut fwd_event_rx) = mpsc::unbounded_channel::<ForwardEvent>();

    // Metrics channels
    let (metrics_cmd_tx, mut metrics_cmd_rx_opt) = {
        let (tx, rx) = mpsc::unbounded_channel::<types::MetricsCommand>();
        (tx, Some(rx))
    };
    let (metrics_event_tx, mut metrics_event_rx) = mpsc::unbounded_channel::<types::MetricsEvent>();

    // === Spawn SSH session ===
    let cols = initial_cols;
    let rows = initial_rows;
    let (forwarded_rx, session_join) =
        SshSession::spawn(config, cols, rows, session_event_tx.clone(), ssh_input_rx);

    // === Spawn forwarding manager ===
    let mgr = ForwardingManager::new(ssh_input_tx.clone(), fwd_event_tx, fwd_cmd_rx, forwarded_rx);
    let fwd_join = mgr.spawn();
    let mut fwd_abort: Option<AbortHandle> = Some(fwd_join.abort_handle());

    // === State ===
    let mut session_abort: Option<AbortHandle> = Some(session_join.abort_handle());
    let mut metrics_cancel: Option<Arc<AtomicBool>> = None;
    let mut sftp_worker_cancel: Option<Arc<AtomicBool>> = None;
    // Track terminal size for potential reconnection (future use)
    let mut _current_cols = cols;
    let mut _current_rows = rows;
    let mut reconnect_attempt: u32 = 0;
    let mut reconnect_timer: Option<Pin<Box<tokio::time::Sleep>>> = None;
    let mut terminal_session: Option<RegisteredSshSession> = None;
    let mut sftp_session: Option<RegisteredSshSession> = None;
    let mut forward_sessions: HashMap<u32, RegisteredSshSession> = HashMap::new();

    // PTY output throttle (60fps = 16ms frame intervals, per Pitfall 1)
    let mut last_render = Instant::now();
    let frame_interval = std::time::Duration::from_millis(16);

    // === Main event loop ===
    loop {
        tokio::select! {
            // --- Process commands from the TUI ---
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(SshCommand::Connect { .. }) => {
                        // Already connected; ignore duplicate Connect
                    }

                    Some(SshCommand::Disconnect) => {
                        // Structured shutdown: metrics -> forwarding -> sftp -> session
                        // (per Pitfall 3: ordered teardown)
                        if let Some(cancel) = metrics_cancel.take() {
                            cancel.store(true, Ordering::Relaxed);
                        }
                        if let Some(h) = fwd_abort.take() {
                            h.abort();
                        }
                        if let Some(cancel) = sftp_worker_cancel.take() {
                            cancel.store(true, Ordering::Relaxed);
                        }
                        if let Some(h) = session_abort.take() {
                            h.abort();
                        }
                        close_registered_ssh_sessions(
                            &lifecycle,
                            &mut terminal_session,
                            &mut sftp_session,
                            &mut forward_sessions,
                            "disconnect",
                        );
                        let _ = event_tx.send(SshEvent::Disconnected);
                        let _ = tabs.request_render();
                        break;
                    }

                    Some(SshCommand::Reconnect) => {
                        let max = last_config.options.max_reconnect_attempts;
                        if max == 0 {
                            let _ = event_tx.send(SshEvent::ReconnectFailed);
                            let _ = tabs.request_render();
                            continue;
                        }
                        reconnect_attempt += 1;
                        if reconnect_attempt > max {
                            let _ = event_tx.send(SshEvent::ReconnectFailed);
                            let _ = tabs.request_render();
                            reconnect_attempt = 0;
                            continue;
                        }

                        // Exponential backoff with jitter (D-03)
                        let base = last_config.options.reconnect_base_delay;
                        let exp = 2u64.pow((reconnect_attempt - 1).min(4));
                        let delay_secs = (base * exp).min(base * 16);
                        let jitter_ms = Instant::now().elapsed().subsec_nanos() % 1000;
                        let total_delay = std::time::Duration::from_secs(delay_secs)
                            + std::time::Duration::from_millis(jitter_ms as u64);

                        let _ = event_tx.send(SshEvent::Reconnecting {
                            attempt: reconnect_attempt,
                            max_attempts: max,
                            retry_in_secs: total_delay.as_secs_f64(),
                        });
                        let _ = tabs.request_render();

                        reconnect_timer = Some(Box::pin(tokio::time::sleep(total_delay)));
                    }

                    Some(SshCommand::Resize { cols, rows }) => {
                        _current_cols = cols;
                        _current_rows = rows;
                        let _ = ssh_input_tx.send(SshInput::Resize(cols, rows));
                    }

                    Some(SshCommand::Sftp(SftpServiceCommand::Open)) => {
                        if sftp_session.is_none() {
                            sftp_session = lifecycle.register(SshSessionDescriptorSpec {
                                purpose: PluginSessionPurpose::FileTransfer,
                                initial_health: PluginSessionHealth::Starting,
                                authenticated: true,
                                destructive_capable: true,
                                stream_capable: true,
                                metadata: sftp_session_metadata(),
                                close_command: SshSessionCloseCommand::CloseSftp,
                            });
                        }
                        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                        if ssh_input_tx.send(SshInput::OpenSftp(reply_tx)).is_err() {
                            if let Some(session) = &sftp_session {
                                lifecycle.mark_health(
                                    session,
                                    PluginSessionHealth::Failed,
                                    "ssh_session_unavailable",
                                );
                            }
                            let _ = event_tx.send(SshEvent::SftpError(
                                "SSH session not connected".to_string(),
                            ));
                            let _ = tabs.request_render();
                            continue;
                        }

                        let evt_tx = event_tx.clone();
                        let tabs_c = tabs.clone();
                        let lifecycle_c = lifecycle.clone();
                        let sftp_session_c = sftp_session.clone();
                        tokio::spawn(async move {
                            match reply_rx.await {
                                Ok(Ok(sftp_session)) => {
                                    if let Some(session) = &sftp_session_c {
                                        lifecycle_c.mark_health(
                                            session,
                                            PluginSessionHealth::Ready,
                                            "sftp_ready",
                                        );
                                    }
                                    let (worker_cmd_tx, worker_cmd_rx) =
                                        mpsc::unbounded_channel();
                                    let (worker_event_tx, worker_event_rx) =
                                        mpsc::unbounded_channel();
                                    let cancel = sftp_worker::SftpWorker::spawn(
                                        sftp_session,
                                        worker_cmd_rx,
                                        worker_event_tx,
                                    );
                                    let handle = SftpHandle {
                                        cmd_tx: worker_cmd_tx,
                                        event_rx: worker_event_rx,
                                        cancel,
                                    };
                                    let _ = evt_tx.send(SshEvent::SftpReady(handle));
                                    let _ = tabs_c.request_render();
                                }
                                Ok(Err(e)) => {
                                    if let Some(session) = &sftp_session_c {
                                        lifecycle_c.mark_health(
                                            session,
                                            PluginSessionHealth::Failed,
                                            "sftp_open_failed",
                                        );
                                    }
                                    let _ = evt_tx.send(SshEvent::SftpError(e));
                                    let _ = tabs_c.request_render();
                                }
                                Err(_) => {
                                    if let Some(session) = &sftp_session_c {
                                        lifecycle_c.mark_health(
                                            session,
                                            PluginSessionHealth::Failed,
                                            "ssh_session_closed",
                                        );
                                    }
                                    let _ = evt_tx.send(SshEvent::SftpError(
                                        "SSH session closed".to_string(),
                                    ));
                                    let _ = tabs_c.request_render();
                                }
                            }
                        });
                    }

                    Some(SshCommand::Sftp(SftpServiceCommand::Close)) => {
                        if let Some(cancel) = sftp_worker_cancel.take() {
                            cancel.store(true, Ordering::Relaxed);
                        }
                        if let Some(session) = sftp_session.take() {
                            lifecycle.mark_health(
                                &session,
                                PluginSessionHealth::Closed,
                                "sftp_closed",
                            );
                        }
                        let _ = event_tx.send(SshEvent::SftpClosed);
                        let _ = tabs.request_render();
                    }

                    Some(SshCommand::Forward(ForwardServiceCommand::Add(fwd_type))) => {
                        let _ = fwd_cmd_tx.send(ForwardCommand::Add(fwd_type));
                    }

                    Some(SshCommand::Forward(ForwardServiceCommand::Remove(id))) => {
                        let _ = fwd_cmd_tx.send(ForwardCommand::Remove(id));
                    }

                    Some(SshCommand::Metrics(MetricsServiceCommand::Start)) => {
                        if metrics_cancel.is_some() {
                            continue; // Already running
                        }
                        // metrics::spawn consumes the receiver, so we take it from the Option
                        if let Some(rx) = metrics_cmd_rx_opt.take() {
                            let cancel = metrics::spawn(
                                ssh_input_tx.clone(),
                                rx,
                                metrics_event_tx.clone(),
                            );
                            metrics_cancel = Some(cancel);
                        }
                    }

                    Some(SshCommand::Metrics(MetricsServiceCommand::Stop)) => {
                        if let Some(cancel) = metrics_cancel.take() {
                            cancel.store(true, Ordering::Relaxed);
                        }
                        // Note: metrics can be started once per connection in this
                        // initial implementation. Stop+Start within the same connection
                        // requires recreating the command channel, which will be added
                        // when the TUI integration is done in Plan 02.
                    }

                    Some(SshCommand::Metrics(MetricsServiceCommand::Refresh)) => {
                        let _ = metrics_cmd_tx.send(types::MetricsCommand::Refresh);
                    }

                    None => break, // Command channel closed
                }
            }

            // --- Process SSH session events (bridge to public SshEvent) ---
            session_evt = session_event_rx.recv() => {
                match session_evt {
                    Some(SshSessionEvent::Connected) => {
                        reconnect_attempt = 0;
                        reconnect_timer = None;
                        if let Some(session) = &terminal_session {
                            lifecycle.mark_health(session, PluginSessionHealth::Ready, "connected");
                        } else {
                            terminal_session = lifecycle.register(SshSessionDescriptorSpec {
                                purpose: PluginSessionPurpose::InteractiveTerminal,
                                initial_health: PluginSessionHealth::Ready,
                                authenticated: true,
                                destructive_capable: true,
                                stream_capable: true,
                                metadata: terminal_session_metadata(cols, rows),
                                close_command: SshSessionCloseCommand::Disconnect,
                            });
                        }
                        let _ = event_tx.send(SshEvent::Connected);
                        let _ = tabs.request_render();
                    }
                    Some(SshSessionEvent::Data(data)) => {
                        // PTY data goes through dedicated byte channel (D-02)
                        let _ = pty_output_tx.send(data);
                        // Throttle render to ~60fps (T-07-05 mitigation)
                        if last_render.elapsed() >= frame_interval {
                            let _ = tabs.request_render();
                            last_render = Instant::now();
                        }
                    }
                    Some(SshSessionEvent::Error(msg)) => {
                        error!("SSH session error: {}", msg);
                        if let Some(session) = &terminal_session {
                            lifecycle.mark_health(
                                session,
                                PluginSessionHealth::Failed,
                                "session_error",
                            );
                        }
                        let _ = event_tx.send(SshEvent::Error(msg));
                        let _ = tabs.request_render();
                    }
                    Some(SshSessionEvent::Eof) => {
                        info!("SSH session EOF");
                    }
                    Some(SshSessionEvent::Disconnected) => {
                        close_registered_ssh_sessions(
                            &lifecycle,
                            &mut terminal_session,
                            &mut sftp_session,
                            &mut forward_sessions,
                            "session_disconnected",
                        );
                        let _ = event_tx.send(SshEvent::Disconnected);
                        let _ = tabs.request_render();
                        session_abort = None;
                    }
                    Some(SshSessionEvent::HostKeyVerify {
                        host,
                        port,
                        fingerprint,
                        key_changed,
                        reply,
                    }) => {
                        // Pass oneshot through to TUI (T-07-01 mitigation)
                        let _ = event_tx.send(SshEvent::HostKeyVerify {
                            host,
                            port,
                            fingerprint,
                            key_changed,
                            reply,
                        });
                        let _ = tabs.request_render();
                    }
                    None => {}
                }
            }

            // --- Forward PTY input to SSH session ---
            pty_data = pty_input_rx.recv() => {
                if let Some(data) = pty_data {
                    let _ = ssh_input_tx.send(SshInput::Data(data));
                }
            }

            // --- Drain forwarding events ---
            fwd_evt = fwd_event_rx.recv() => {
                if let Some(ForwardEvent::StatusChanged { id, status }) = fwd_evt {
                    if !forward_sessions.contains_key(&id)
                        && let Some(session) = lifecycle.register(SshSessionDescriptorSpec {
                            purpose: PluginSessionPurpose::PortForward,
                            initial_health: forward_status_health(&status),
                            authenticated: true,
                            destructive_capable: true,
                            stream_capable: true,
                            metadata: forward_session_metadata(id),
                            close_command: SshSessionCloseCommand::RemoveForward(id),
                        })
                    {
                        forward_sessions.insert(id, session);
                    }
                    if let Some(session) = forward_sessions.get(&id) {
                        lifecycle.mark_health(
                            session,
                            forward_status_health(&status),
                            forward_status_reason(&status),
                        );
                    }
                    if matches!(status, ForwardStatus::Stopped) {
                        forward_sessions.remove(&id);
                    }
                    let _ = event_tx.send(SshEvent::ForwardStatusChanged { id, status });
                    let _ = tabs.request_render();
                }
            }

            // --- Drain metrics events ---
            metrics_evt = metrics_event_rx.recv() => {
                match metrics_evt {
                    Some(types::MetricsEvent::Updated(m)) => {
                        let _ = event_tx.send(SshEvent::MetricsUpdate(m));
                        let _ = tabs.request_render();
                    }
                    Some(types::MetricsEvent::Error(e)) => {
                        let _ = event_tx.send(SshEvent::MetricsError(e));
                        let _ = tabs.request_render();
                    }
                    None => {}
                }
            }

            // --- Reconnect timer ---
            _ = async {
                if let Some(timer) = reconnect_timer.as_mut() {
                    timer.as_mut().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                reconnect_timer = None;
                // For reconnect, emit ReconnectFailed since we cannot re-create
                // the session channels within this task. The TUI should create a
                // new SshService instance for a fresh connection.
                info!(
                    "Reconnect timer fired (attempt {}) -- TUI should create new service",
                    reconnect_attempt
                );
                let _ = event_tx.send(SshEvent::ReconnectFailed);
                let _ = tabs.request_render();
            }
        }
    }

    // Cleanup on exit -- structured shutdown (per Pitfall 3)
    if let Some(cancel) = metrics_cancel.take() {
        cancel.store(true, Ordering::Relaxed);
    }
    if let Some(h) = fwd_abort.take() {
        h.abort();
    }
    if let Some(cancel) = sftp_worker_cancel.take() {
        cancel.store(true, Ordering::Relaxed);
    }
    if let Some(h) = session_abort.take() {
        h.abort();
    }
    close_registered_ssh_sessions(
        &lifecycle,
        &mut terminal_session,
        &mut sftp_session,
        &mut forward_sessions,
        "service_shutdown",
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use voidb_core::PluginSessionListFilter;

    fn assert_send<T: Send>() {}
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn service_is_send() {
        assert_send::<SshService>();
    }

    #[test]
    fn mutex_service_is_send_sync() {
        assert_send_sync::<std::sync::Mutex<SshService>>();
    }

    #[test]
    fn direct_error_code_classifies_host_key_failures() {
        let unknown = VoidbError::Connection(
            "ssh.host_key_unknown: host key for example.invalid:22 is not present in known_hosts"
                .into(),
        );
        let changed = VoidbError::Connection(
            "ssh.host_key_changed: host key for example.invalid:22 changed at known_hosts line 4"
                .into(),
        );
        let other = VoidbError::Connection("connection refused".into());

        assert_eq!(
            direct_connection_error_code(&unknown),
            "ssh.host_key_unknown"
        );
        assert_eq!(
            direct_connection_error_code(&changed),
            "ssh.host_key_changed"
        );
        assert_eq!(direct_connection_error_code(&other), "ssh.connect_failed");
    }

    #[test]
    fn persistent_shell_quotes_commands_and_parses_split_safe_markers() {
        assert_eq!(
            quote_posix_shell("printf '%s' ok"),
            "'printf '\"'\"'%s'\"'\"' ok'"
        );
        let prefix = b"\x1evoidb:nonce:";
        let suffix = b"\x1f\n";
        let buffer = b"hello\n\x1evoidb:nonce:17\x1f\nremaining";
        assert_eq!(
            find_shell_marker(buffer, prefix, suffix),
            Some(("hello\n".len(), "hello\n\x1evoidb:nonce:17\x1f\n".len(), 17))
        );
        assert_eq!(
            find_shell_marker(b"partial\x1evoidb:nonce:1", prefix, suffix),
            None
        );
    }

    #[test]
    fn persistent_shell_bounds_utf8_without_splitting_characters() {
        let (value, source_bytes, truncated) = bounded_utf8("a🙂b".as_bytes(), 4);
        assert_eq!(value, "a");
        assert_eq!(source_bytes, 6);
        assert!(truncated);
    }

    #[test]
    fn strict_host_key_check_rejects_unknown_hosts_without_prompting() {
        let key = ssh_key::PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ",
        )
        .expect("public key");
        let slot = new_host_key_failure_slot();

        let accepted = strict_host_key_check("voidb-agent-test.invalid", 2222, &key, &slot)
            .expect("strict check");

        assert!(!accepted);
        let failure = slot
            .lock()
            .expect("failure lock")
            .clone()
            .expect("failure stored");
        assert_eq!(failure.kind, DirectHostKeyFailureKind::Unknown);
        assert_eq!(failure.code(), "ssh.host_key_unknown");
        assert!(failure.message().contains("known_hosts"));
    }

    #[test]
    fn terminal_session_close_requests_disconnect_without_secret_metadata() {
        let sessions = Arc::new(PluginSessionRegistry::new());
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        let lifecycle = SshSessionRegistryContext {
            sessions: sessions.clone(),
            owner_id: "ssh-test-owner".into(),
            profile_ref: Some(ConnectionProfileRef::name("ssh-test-profile")),
            control_tx,
        };

        let registered = lifecycle
            .register(SshSessionDescriptorSpec {
                purpose: PluginSessionPurpose::InteractiveTerminal,
                initial_health: PluginSessionHealth::Ready,
                authenticated: true,
                destructive_capable: true,
                stream_capable: true,
                metadata: terminal_session_metadata(120, 40),
                close_command: SshSessionCloseCommand::Disconnect,
            })
            .expect("registered session");

        let listed = sessions.list(PluginSessionListFilter {
            include_terminal: true,
            ..PluginSessionListFilter::default()
        });
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].purpose, PluginSessionPurpose::InteractiveTerminal);
        assert_eq!(listed[0].metadata["kind"], "pty");

        let encoded = serde_json::to_string(&listed).expect("serialize descriptors");
        assert!(!encoded.contains("prod.example.com"));
        assert!(!encoded.contains("root"));

        sessions
            .close(&registered.id, "test_close")
            .expect("close descriptor");
        match control_rx.try_recv().expect("close command") {
            SshCommand::Disconnect => {}
            other => panic!("unexpected close command: {:?}", other),
        }
    }

    #[test]
    fn forward_session_status_and_close_are_descriptor_backed() {
        let sessions = Arc::new(PluginSessionRegistry::new());
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        let lifecycle = SshSessionRegistryContext {
            sessions: sessions.clone(),
            owner_id: "ssh-test-owner".into(),
            profile_ref: Some(ConnectionProfileRef::name("ssh-test-profile")),
            control_tx,
        };

        let registered = lifecycle
            .register(SshSessionDescriptorSpec {
                purpose: PluginSessionPurpose::PortForward,
                initial_health: PluginSessionHealth::Starting,
                authenticated: true,
                destructive_capable: true,
                stream_capable: true,
                metadata: forward_session_metadata(42),
                close_command: SshSessionCloseCommand::RemoveForward(42),
            })
            .expect("registered forward");

        lifecycle.mark_health(&registered, PluginSessionHealth::Ready, "forward_active");
        let descriptor = sessions.get(&registered.id).expect("descriptor");
        assert_eq!(descriptor.health, PluginSessionHealth::Ready);
        assert_eq!(descriptor.metadata["forward_id"], 42);

        sessions
            .close(&registered.id, "test_close")
            .expect("close descriptor");
        match control_rx.try_recv().expect("close command") {
            SshCommand::Forward(ForwardServiceCommand::Remove(42)) => {}
            other => panic!("unexpected close command: {:?}", other),
        }
    }
}
