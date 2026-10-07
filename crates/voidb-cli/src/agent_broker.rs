//! Short-lived local authorization broker for agent-initiated VoidB commands.
//!
//! The broker holds the master password only in process memory. Agents receive
//! a profile-, plugin-, capability-, and time-scoped grant that lets the
//! broker execute a narrow set of VoidB commands and return their already
//! redacted output. A finite use budget is optional. The master password is
//! never returned through this API.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};
use clap::{Arg, ArgAction, ArgMatches, Command, error::ErrorKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex as AsyncMutex, Notify, watch};
use tokio::task::{AbortHandle, JoinSet};
use uuid::Uuid;
use voidb_core::{
    AGENT_BROKER_LEGACY_PROTOCOL_VERSION, AGENT_BROKER_PROTOCOL_VERSION,
    AGENT_BROKER_SUPPORTED_PROTOCOL_VERSIONS, AgentAuthorizationCapability,
    AgentAuthorizationPluginCatalog, AgentAuthorizationPresetDefinition,
    AgentAuthorizationPresetKind, AgentAuthorizationProfileSummary, AgentAuthorizationScope,
    AgentAuthorizationSupportStatus, AgentAuthorizationSupportSummary, AgentBrokerHealth,
    AgentGrantAmendment, AgentGrantRevision, AgentPrincipal, AgentSessionCallLifecycle,
    AgentSessionCallRequest, AgentSessionCallResult, AgentSessionCallState,
    AgentSessionCallStatusRequest, AgentSessionCallView, AgentSessionCallWaitRequest,
    AgentSessionCallWaitResult, AgentSessionCancelRequest, AgentSessionCloseAgentRequest,
    AgentSessionConcurrency, AgentSessionControlDisposition, AgentSessionControlKind,
    AgentSessionListRequest, AgentSessionOpenRequest, AgentSessionRef, AgentSessionRenewRequest,
    AgentSessionStatusRequest, AppConfig, AuditEvent, AuditEventStatus, AuditOperation,
    CapabilityDefinition, CapabilityExecutionMode, ConnectionProfile, ConnectionProfileRef,
    DEFAULT_AGENT_GRANT_TTL_MINUTES, DEFAULT_AGENT_GRANT_USES, FrontendAgentGrant,
    LocalProfileStore, MAX_AGENT_GRANT_TTL_MINUTES, MAX_AGENT_GRANT_USES,
    MAX_AGENT_SESSION_CONTROL_TIMEOUT_MS, PluginSessionError, PluginSessionErrorCode,
    PluginSessionPurpose, RedactionStatus, VOIDB_MASTER_PASSWORD_ENV,
    authorize_normalized_operation, is_supported_agent_broker_protocol_version,
    normalize_agent_operation, profile_names_equal, validate_agent_session_call_id,
};

#[cfg(not(test))]
use voidb_core::{AuditEventStore, LocalAuditStore};

use crate::agent_session_host::{AgentSessionHost, PreparedAgentSessionCall};
use crate::builtin::invoke::{
    resolved_authorization_capabilities, resolved_capability_risk, session_handoff_guidance,
};
use crate::jit_authorization::{
    CreateAuthorizationRequest, JitAuthorizationStore, JitAuthorizationStoreError,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

const GRANT_VERSION: u32 = 1;
const BROKER_READY_TIMEOUT: Duration = Duration::from_secs(3);
const BROKER_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
const BROKER_CHILD_ENV: &str = "VOIDB_INTERNAL_BROKER_CHILD";
const AGENT_CLIENT_ID_ENV: &str = "VOIDB_AGENT_CLIENT_ID";
const AGENT_TASK_ID_ENV: &str = "VOIDB_AGENT_TASK_ID";
const AGENT_INSTANCE_ID_ENV: &str = "VOIDB_AGENT_INSTANCE_ID";
const AGENT_THREAD_ID_ENV: &str = "VOIDB_AGENT_THREAD_ID";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentGrantFile {
    version: u32,
    id: String,
    token: String,
    profile_id: String,
    profile_name: String,
    plugin_id: String,
    capabilities: Vec<String>,
    /// Broker transport boundary. Legacy grant files default to stateless so
    /// they cannot silently authorize persistent-session operations.
    #[serde(default)]
    execution_mode: CapabilityExecutionMode,
    #[serde(default)]
    preset: Option<AgentAuthorizationPresetKind>,
    allow_destructive: bool,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    /// `None` means the grant is bounded only by `expires_at`.
    #[serde(default)]
    remaining_uses: Option<u32>,
    socket_path: PathBuf,

    /// Empty for compatible proactive grants. JIT-issued grants persist exact
    /// Core-owned scopes and revalidate normalized operations before every
    /// stateless execution. Persistent sessions require an explicit proactive
    /// session grant.
    #[serde(default)]
    authorization_scopes: Vec<AgentAuthorizationScope>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    principal_fingerprint: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant_revision: Option<u64>,
}

impl AgentGrantFile {
    fn public(
        &self,
        broker_health: AgentBrokerHealth,
        active_session_count: usize,
    ) -> FrontendAgentGrant {
        FrontendAgentGrant {
            id: self.id.clone(),
            profile_id: self.profile_id.clone(),
            profile_name: self.profile_name.clone(),
            plugin_id: self.plugin_id.clone(),
            preset: self.preset.or(Some(if self.allow_destructive {
                AgentAuthorizationPresetKind::Custom
            } else {
                AgentAuthorizationPresetKind::ReadOnly
            })),
            capabilities: self.capabilities.clone(),
            execution_mode: self.execution_mode,
            destructive_acknowledged: self.allow_destructive,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            remaining_uses: self.remaining_uses,
            broker_health,
            active_session_count,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct GrantInspection {
    broker_health: AgentBrokerHealth,
    active_session_count: usize,
}

const MAX_BATCH_AUTHORIZATION_GRANTS: usize = 64;
const MAX_BATCH_AUTHORIZATION_SPEC_BYTES: u64 = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchAuthorizationSpec {
    grants: Vec<BatchAuthorizationEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchAuthorizationEntry {
    profile: String,
    plugin: String,
    purpose: String,

    #[serde(default)]
    execution_mode: Option<String>,

    #[serde(default)]
    preset: Option<String>,

    #[serde(default)]
    capabilities: Vec<String>,
}

#[derive(Debug)]
struct PreparedBatchGrant {
    profile: ConnectionProfile,
    plugin_id: String,
    purpose: String,
    execution_mode: CapabilityExecutionMode,
    preset: AgentAuthorizationPresetKind,
    capabilities: Vec<String>,
    allow_destructive: bool,
    existing: Vec<AgentGrantFile>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum BrokerRequest {
    Inspect {
        token: String,
    },
    RenewGrant {
        token: String,
        expires_at: DateTime<Utc>,
        remaining_uses: Option<u32>,
    },
    Run {
        token: String,
        argv: Vec<String>,
    },
    SessionOpen {
        token: String,
        request: AgentSessionOpenRequest,
    },
    SessionCall {
        token: String,
        request: AgentSessionCallRequest,
    },
    SessionCallStart {
        token: String,
        request: AgentSessionCallRequest,
    },
    SessionCallStatus {
        token: String,
        request: AgentSessionCallStatusRequest,
    },
    SessionCallWait {
        token: String,
        request: AgentSessionCallWaitRequest,
    },
    SessionStatus {
        token: String,
        request: AgentSessionStatusRequest,
    },
    SessionList {
        token: String,
        request: AgentSessionListRequest,
    },
    SessionRenew {
        token: String,
        request: AgentSessionRenewRequest,
    },
    SessionCancel {
        token: String,
        request: AgentSessionCancelRequest,
    },
    SessionClose {
        token: String,
        request: AgentSessionCloseAgentRequest,
    },
    Shutdown {
        token: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct BrokerWireRequest {
    #[serde(default = "legacy_broker_protocol_version")]
    protocol_version: u32,

    #[serde(flatten)]
    request: BrokerRequest,
}

fn legacy_broker_protocol_version() -> u32 {
    AGENT_BROKER_LEGACY_PROTOCOL_VERSION
}

#[derive(Debug, Serialize, Deserialize)]
struct BrokerResponse {
    #[serde(default = "legacy_broker_protocol_version")]
    protocol_version: u32,
    ok: bool,
    exit_code: i32,
    stdout: String,
    stderr: String,
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(default)]
    remaining_uses: Option<u32>,
    expires_at: DateTime<Utc>,
}

struct BrokerCallEntry {
    view: StdMutex<AgentSessionCallView>,
    changed: Notify,
    abort_handle: StdMutex<Option<AbortHandle>>,
}

impl BrokerCallEntry {
    fn new(view: AgentSessionCallView) -> Self {
        Self {
            view: StdMutex::new(view),
            changed: Notify::new(),
            abort_handle: StdMutex::new(None),
        }
    }

    fn snapshot(&self) -> AgentSessionCallView {
        self.view
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn set_abort_handle(&self, abort_handle: AbortHandle) {
        let view = self.view.lock().unwrap_or_else(|error| error.into_inner());
        if view.lifecycle.state.is_terminal() {
            return;
        }
        *self
            .abort_handle
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(abort_handle);
    }

    fn clear_abort_handle(&self) {
        self.abort_handle
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
    }

    fn abort(&self) {
        if let Some(abort_handle) = self
            .abort_handle
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            abort_handle.abort();
        }
    }

    async fn wait_for_control(&self) {
        loop {
            let mut changed = Box::pin(self.changed.notified());
            changed.as_mut().enable();
            let lifecycle = &self.snapshot().lifecycle;
            if lifecycle.control.is_some() || lifecycle.state.is_terminal() {
                return;
            }
            changed.await;
        }
    }
}

#[derive(Default)]
struct BrokerCallRegistry {
    calls: StdMutex<BTreeMap<(String, u64, String), Arc<BrokerCallEntry>>>,
}

impl BrokerCallRegistry {
    fn register(
        &self,
        request: &AgentSessionCallRequest,
        accepted_at: DateTime<Utc>,
        deadline_at: DateTime<Utc>,
    ) -> Result<Arc<BrokerCallEntry>, PluginSessionError> {
        request.validate_call_id()?;
        let mut calls = self.calls.lock().unwrap_or_else(|error| error.into_inner());
        let key = (
            request.session.session_id.clone(),
            request.session.generation,
            request.call_id.clone(),
        );
        if calls.contains_key(&key) {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::CallIdConflict,
                "Session call ID is already registered for this session generation.",
            )
            .with_session_id(request.session.session_id.clone()));
        }
        let entry = Arc::new(BrokerCallEntry::new(AgentSessionCallView {
            session: request.session.clone(),
            capability: request.capability.clone(),
            lifecycle: AgentSessionCallLifecycle::accepted(
                request.call_id.clone(),
                accepted_at,
                Some(deadline_at),
            )?,
            result: None,
            error: None,
        }));
        calls.insert(key, Arc::clone(&entry));
        Ok(entry)
    }

    fn entry(
        &self,
        session: &AgentSessionRef,
        call_id: &str,
    ) -> Result<Arc<BrokerCallEntry>, PluginSessionError> {
        validate_agent_session_call_id(call_id)?;
        let entry = self
            .calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&(
                session.session_id.clone(),
                session.generation,
                call_id.to_owned(),
            ))
            .cloned()
            .ok_or_else(|| {
                PluginSessionError::new(
                    PluginSessionErrorCode::CallNotFound,
                    "Session call was not found.",
                )
                .with_session_id(session.session_id.clone())
            })?;
        if entry.snapshot().session != *session {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::CallNotFound,
                "Session call was not found for this session generation.",
            )
            .with_session_id(session.session_id.clone()));
        }
        Ok(entry)
    }

    fn snapshot(
        &self,
        request: &AgentSessionCallStatusRequest,
    ) -> Result<AgentSessionCallView, PluginSessionError> {
        request.validate_call_id()?;
        Ok(self.entry(&request.session, &request.call_id)?.snapshot())
    }

    async fn wait(
        &self,
        request: &AgentSessionCallWaitRequest,
    ) -> Result<AgentSessionCallWaitResult, PluginSessionError> {
        request.validate_call_id()?;
        let timeout = request.timeout()?;
        let entry = self.entry(&request.session, &request.call_id)?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let mut changed = Box::pin(entry.changed.notified());
            changed.as_mut().enable();
            let call = entry.snapshot();
            if call.lifecycle.state.is_terminal() {
                return Ok(AgentSessionCallWaitResult {
                    call,
                    wait_timed_out: false,
                });
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() || tokio::time::timeout(remaining, changed).await.is_err() {
                return Ok(AgentSessionCallWaitResult {
                    call: entry.snapshot(),
                    wait_timed_out: true,
                });
            }
        }
    }

    async fn wait_until_terminal(&self, entry: &BrokerCallEntry) -> AgentSessionCallView {
        loop {
            let mut changed = Box::pin(entry.changed.notified());
            changed.as_mut().enable();
            let call = entry.snapshot();
            if call.lifecycle.state.is_terminal() {
                return call;
            }
            changed.await;
        }
    }

    fn mark_running(&self, entry: &BrokerCallEntry, started_at: DateTime<Utc>) -> bool {
        let mut view = entry.view.lock().unwrap_or_else(|error| error.into_inner());
        let started = view.lifecycle.mark_running(started_at);
        drop(view);
        if started {
            entry.changed.notify_waiters();
        }
        started
    }

    fn request_control(
        &self,
        session: &AgentSessionRef,
        call_id: &str,
        control: AgentSessionControlKind,
        requested_at: DateTime<Utc>,
    ) -> Result<(AgentSessionControlDisposition, AgentSessionCallView), PluginSessionError> {
        let entry = self.entry(session, call_id)?;
        let mut view = entry.view.lock().unwrap_or_else(|error| error.into_inner());
        let disposition = view.lifecycle.request_control(control, requested_at);
        let snapshot = view.clone();
        drop(view);
        entry.changed.notify_waiters();
        Ok((disposition, snapshot))
    }

    fn request_session_control(
        &self,
        session: &AgentSessionRef,
        control: AgentSessionControlKind,
        requested_at: DateTime<Utc>,
    ) -> Vec<Arc<BrokerCallEntry>> {
        let entries = self
            .calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .filter(|entry| {
                let view = entry.snapshot();
                view.session == *session && !view.lifecycle.state.is_terminal()
            })
            .cloned()
            .collect::<Vec<_>>();
        for entry in &entries {
            let mut view = entry.view.lock().unwrap_or_else(|error| error.into_inner());
            view.lifecycle.request_control(control, requested_at);
            drop(view);
            entry.changed.notify_waiters();
        }
        entries
    }

    fn request_all_control(
        &self,
        control: AgentSessionControlKind,
        requested_at: DateTime<Utc>,
    ) -> Vec<Arc<BrokerCallEntry>> {
        let entries = self
            .calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .filter(|entry| !entry.snapshot().lifecycle.state.is_terminal())
            .cloned()
            .collect::<Vec<_>>();
        for entry in &entries {
            let mut view = entry.view.lock().unwrap_or_else(|error| error.into_inner());
            view.lifecycle.request_control(control, requested_at);
            drop(view);
            entry.changed.notify_waiters();
        }
        entries
    }

    fn finish(
        &self,
        entry: &BrokerCallEntry,
        result: Result<AgentSessionCallResult, PluginSessionError>,
        completed_at: DateTime<Utc>,
    ) -> AgentSessionCallView {
        let mut view = entry.view.lock().unwrap_or_else(|error| error.into_inner());
        let terminal_state = match &result {
            Ok(_) => AgentSessionCallState::Succeeded,
            Err(error) => match error.code {
                PluginSessionErrorCode::TimedOut => AgentSessionCallState::TimedOut,
                PluginSessionErrorCode::Cancelled => AgentSessionCallState::Cancelled,
                PluginSessionErrorCode::Aborted => AgentSessionCallState::Aborted,
                _ => AgentSessionCallState::Failed,
            },
        };
        let changed = view
            .lifecycle
            .finish(terminal_state, completed_at)
            .unwrap_or(false);
        if changed {
            match view.lifecycle.state {
                AgentSessionCallState::Succeeded => {
                    view.result = result.ok();
                    view.error = None;
                }
                AgentSessionCallState::Cancelled => {
                    view.result = None;
                    view.error = Some(
                        PluginSessionError::new(
                            PluginSessionErrorCode::Cancelled,
                            "Session call was cancelled.",
                        )
                        .with_session_id(view.session.session_id.clone()),
                    );
                }
                AgentSessionCallState::Aborted => {
                    view.result = None;
                    view.error = Some(
                        PluginSessionError::new(
                            PluginSessionErrorCode::Aborted,
                            "Session call was aborted because its session closed.",
                        )
                        .with_session_id(view.session.session_id.clone()),
                    );
                }
                _ => {
                    view.result = None;
                    view.error = result.err();
                }
            }
        }
        let snapshot = view.clone();
        drop(view);
        entry.clear_abort_handle();
        entry.changed.notify_waiters();
        snapshot
    }

    fn abort_entries(&self, entries: &[Arc<BrokerCallEntry>], completed_at: DateTime<Utc>) {
        for entry in entries {
            entry.abort();
            self.finish(
                entry,
                Err(PluginSessionError::new(
                    PluginSessionErrorCode::Aborted,
                    "Session call was aborted by a higher-priority control request.",
                )),
                completed_at,
            );
        }
    }

    fn snapshots(entries: &[Arc<BrokerCallEntry>]) -> Vec<AgentSessionCallView> {
        entries.iter().map(|entry| entry.snapshot()).collect()
    }
}

pub async fn handle_early(args: Vec<String>) -> anyhow::Result<Option<i32>> {
    let Some(command) = args.get(1).map(String::as_str) else {
        return Ok(None);
    };
    if command == "__agent-broker" {
        let grant_file = args
            .get(2)
            .ok_or_else(|| anyhow!("internal broker grant file is required"))?;
        run_broker(Path::new(grant_file)).await?;
        return Ok(Some(0));
    }
    if command != "agent" {
        return Ok(None);
    }

    let matches = match agent_command().try_get_matches_from(args) {
        Ok(matches) => matches,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            error.print()?;
            return Ok(Some(0));
        }
        Err(error) => return Err(error.into()),
    };
    let (_, matches) = matches
        .subcommand()
        .expect("agent command requires a subcommand");
    let exit_code = match matches.subcommand() {
        Some(("authorize", sub_matches)) => authorize(sub_matches).await?,
        Some(("authorize-batch", sub_matches)) => authorize_batch(sub_matches).await?,
        Some(("catalog", sub_matches)) => list_authorization_catalog(sub_matches)?,
        Some(("list", sub_matches)) => list_grants(sub_matches).await?,
        Some(("renew", sub_matches)) => renew_grant(sub_matches).await?,
        Some(("revoke", sub_matches)) => revoke(sub_matches).await?,
        Some(("exec", sub_matches)) => exec_capability(sub_matches).await?,
        Some(("run", sub_matches)) => run_granted(sub_matches).await?,
        Some(("session", sub_matches)) => run_session_command(sub_matches).await?,
        Some(("request", sub_matches)) => run_jit_request_command(sub_matches).await?,
        _ => unreachable!("clap enforces agent subcommands"),
    };
    Ok(Some(exit_code))
}

pub async fn take_broker_child_password() -> anyhow::Result<Option<String>> {
    if std::env::var(BROKER_CHILD_ENV).as_deref() != Ok("1") {
        return Ok(None);
    }
    let mut password = String::new();
    tokio::io::stdin().read_to_string(&mut password).await?;
    if password.is_empty() {
        bail!("broker child did not receive a master password");
    }
    Ok(Some(password))
}

fn agent_command() -> Command {
    Command::new("voidb-cli")
        .subcommand_required(true)
        .subcommand(
            Command::new("agent")
                .about("Manage short-lived, scoped agent access")
                .subcommand_required(true)
                .subcommand(with_hidden_optional_principal_args(
                    Command::new("exec")
                        .about("Run one capability through matching access or request exact approval")
                        .arg(
                            Arg::new("capability")
                                .required(true)
                                .value_name("PLUGIN.CAPABILITY")
                                .help("Qualified capability, for example docker.list_containers"),
                        )
                        .arg(
                            Arg::new("profile")
                                .long("profile")
                                .short('p')
                                .required(true)
                                .value_name("PROFILE")
                                .help("Friendly profile name, name:<name>, or id:<profile-id>"),
                        )
                        .arg(
                            Arg::new("input-json")
                                .long("input-json")
                                .default_value("{}")
                                .value_name("JSON")
                                .help("Inline capability input JSON"),
                        )
                        .arg(
                            Arg::new("purpose")
                                .long("purpose")
                                .visible_alias("reason")
                                .value_name("TEXT")
                                .help(
                                    "Specific intended use shown to the user if authorization is required",
                                ),
                        )
                        .arg(
                            Arg::new("wait-timeout-ms")
                                .long("wait-timeout-ms")
                                .default_value("30000")
                                .value_name("MILLISECONDS")
                                .value_parser(clap::value_parser!(u64))
                                .help("How long to wait for an automatic JIT decision"),
                        )
                        .arg(
                            Arg::new("request-ttl-seconds")
                                .long("request-ttl-seconds")
                                .default_value("300")
                                .value_name("SECONDS")
                                .value_parser(clap::value_parser!(u64))
                                .help("Lifetime of an automatic JIT request"),
                        )
                        .arg(
                            Arg::new("timeout-ms")
                                .long("timeout-ms")
                                .value_name("MILLISECONDS")
                                .value_parser(clap::value_parser!(u64)),
                        )
                        .arg(
                            Arg::new("page-limit")
                                .long("page-limit")
                                .value_name("LIMIT")
                                .value_parser(clap::value_parser!(u32)),
                        )
                        .arg(
                            Arg::new("page-cursor")
                                .long("page-cursor")
                                .value_name("CURSOR"),
                        )
                        .arg(
                            Arg::new("dry-run")
                                .long("dry-run")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("yes")
                                .long("yes")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("no-request")
                                .long("no-request")
                                .action(ArgAction::SetTrue)
                                .help("Fail with authorization_required instead of creating a JIT request"),
                        ),
                ))
                .subcommand(
                    Command::new("authorize")
                        .about("Authorize time-bounded agent access to one profile")
                        .arg(Arg::new("profile").long("profile").required(true))
                        .arg(Arg::new("plugin").long("plugin").required(true))
                        .arg(
                            Arg::new("execution-mode")
                                .long("execution-mode")
                                .default_value("stateless")
                                .value_parser(["stateless", "session_only", "both"])
                                .help("Grant one-shot, persistent-session, or explicitly combined transport access"),
                        )
                        .arg(
                            Arg::new("preset")
                                .long("preset")
                                .value_parser([
                                    "read_only",
                                    "interactive_execute",
                                    "full_access",
                                    "custom",
                                ])
                                .help("Resolve and record a shared preset; explicit capabilities without this flag infer Custom"),
                        )
                        .arg(
                            Arg::new("capability")
                                .long("capability")
                                .action(ArgAction::Append)
                                .help("Exact qualified capability; without --preset explicit values infer Custom"),
                        )
                        .arg(
                            Arg::new("ttl-minutes")
                                .long("ttl-minutes")
                                .default_value("15")
                                .value_parser(clap::value_parser!(u64)),
                        )
                        .arg(
                            Arg::new("uses")
                                .long("uses")
                                .value_parser(clap::value_parser!(u32))
                                .help("Optional accepted-command limit; omit for time-only access"),
                        )
                        .arg(
                            Arg::new("allow-destructive")
                                .long("allow-destructive")
                                .action(ArgAction::SetTrue)
                                .requires("yes"),
                        )
                        .arg(
                            Arg::new("yes")
                                .long("yes")
                                .action(ArgAction::SetTrue)
                                .help("Confirm an authorization that permits --yes operations"),
                        )
                        .arg(
                            Arg::new("password-stdin")
                                .long("password-stdin")
                                .action(ArgAction::SetTrue)
                                .hide(true),
                        )
                        .arg(
                            Arg::new("replace")
                                .long("replace")
                                .action(ArgAction::SetTrue)
                                .help("Replace existing grants for the same immutable profile and plugin"),
                        ),
                )
                .subcommand(
                    Command::new("authorize-batch")
                        .about("Review and authorize multiple profile-scoped grants at once")
                        .arg(
                            Arg::new("spec")
                                .long("spec")
                                .required(true)
                                .value_name("PATH")
                                .help("Local JSON file containing a grants array"),
                        )
                        .arg(
                            Arg::new("ttl-minutes")
                                .long("ttl-minutes")
                                .default_value("15")
                                .value_parser(clap::value_parser!(u64)),
                        )
                        .arg(
                            Arg::new("uses")
                                .long("uses")
                                .value_parser(clap::value_parser!(u32))
                                .help("Optional accepted-command limit per grant; omit for time-only access"),
                        )
                        .arg(
                            Arg::new("allow-destructive")
                                .long("allow-destructive")
                                .action(ArgAction::SetTrue)
                                .help("Permit reviewed grants containing non-read-only capabilities"),
                        )
                        .arg(
                            Arg::new("yes")
                                .long("yes")
                                .action(ArgAction::SetTrue)
                                .help("Accept the rendered batch review non-interactively"),
                        )
                        .arg(
                            Arg::new("replace")
                                .long("replace")
                                .action(ArgAction::SetTrue)
                                .help("Replace existing grants for matching immutable profile scopes"),
                        ),
                )
                .subcommand(
                    Command::new("catalog")
                        .about("List the password-free central authorization capability catalog")
                        .arg(Arg::new("plugin").long("plugin"))
                        .arg(
                            Arg::new("execution-mode")
                                .long("execution-mode")
                                .value_parser(["stateless", "session_only", "both"])
                                .action(ArgAction::Append)
                                .help("Filter capabilities by supported execution mode and presets by grant mode; repeat to select multiple modes"),
                        )
                        .arg(
                            Arg::new("format")
                                .long("format")
                                .default_value("json")
                                .value_parser(["json", "table"])
                                .help("Output format; json is stable for agents, table is human-readable"),
                        ),
                )
                .subcommand(jit_request_command())
                .subcommand(
                    Command::new("list")
                        .about("List frontend-safe agent grant and broker summaries")
                        .arg(Arg::new("profile").long("profile"))
                        .arg(Arg::new("plugin").long("plugin")),
                )
                .subcommand(
                    Command::new("renew")
                        .about("Renew one grant without changing its profile, plugin, or capability scope")
                        .arg(Arg::new("grant").value_name("GRANT_ID").required(true))
                        .arg(
                            Arg::new("ttl-minutes")
                                .long("ttl-minutes")
                                .default_value("15")
                                .value_parser(clap::value_parser!(u64)),
                        )
                        .arg(
                            Arg::new("uses")
                                .long("uses")
                                .value_parser(clap::value_parser!(u32))
                                .help("Optional renewed use limit; omit for time-only access"),
                        ),
                )
                .subcommand(
                    Command::new("revoke")
                        .about("Revoke one grant, one immutable profile scope, or all grants")
                        .arg(Arg::new("grant").value_name("GRANT_ID"))
                        .arg(
                            Arg::new("profile")
                                .long("profile")
                                .requires("plugin")
                                .conflicts_with_all(["grant", "all"]),
                        )
                        .arg(
                            Arg::new("plugin")
                                .long("plugin")
                                .requires("profile")
                                .conflicts_with_all(["grant", "all"]),
                        )
                        .arg(
                            Arg::new("all")
                                .long("all")
                                .action(ArgAction::SetTrue)
                                .conflicts_with_all(["grant", "profile", "plugin"]),
                        ),
                )
                .subcommand(with_optional_principal_args(
                    Command::new("run")
                        .about("Run a scoped VoidB command through an active grant")
                        .arg(Arg::new("grant").long("grant"))
                        .arg(
                            Arg::new("command")
                                .required(true)
                                .trailing_var_arg(true)
                                .num_args(1..),
                        ),
                ))
                .subcommand(with_optional_principal_args(session_command())),
        )
}

fn jit_request_command() -> Command {
    Command::new("request")
        .about("Request, inspect, wait for, cancel, or locally review JIT authorization")
        .subcommand_required(true)
        .subcommand(with_principal_args(
            Command::new("create")
                .about("Create a short-lived authorization request (JSON output)")
                .arg(Arg::new("profile").long("profile").required(true))
                .arg(Arg::new("plugin").long("plugin").required(true))
                .arg(Arg::new("capability").long("capability").required(true))
                .arg(
                    Arg::new("scope")
                        .long("scope")
                        .required(true)
                        .value_parser(["capability", "constrained", "exact"]),
                )
                .arg(
                    Arg::new("input-json")
                        .long("input-json")
                        .required_if_eq("scope", "exact")
                        .conflicts_with("constraints-json"),
                )
                .arg(
                    Arg::new("constraints-json")
                        .long("constraints-json")
                        .required_if_eq("scope", "constrained")
                        .conflicts_with("input-json"),
                )
                .arg(
                    Arg::new("purpose")
                        .long("purpose")
                        .visible_alias("reason")
                        .required(true)
                        .help("Specific intended use shown to the user during review"),
                )
                .arg(
                    Arg::new("ttl-seconds")
                        .long("ttl-seconds")
                        .default_value("300")
                        .value_parser(clap::value_parser!(u64)),
                ),
        ))
        .subcommand(with_principal_args(
            Command::new("get")
                .about("Get the safe canonical status of one request")
                .arg(Arg::new("request-id").required(true)),
        ))
        .subcommand(with_principal_args(Command::new("list").about(
            "List safe requests belonging to the authenticated principal",
        )))
        .subcommand(with_principal_args(
            Command::new("wait")
                .about("Wait for a terminal decision with a bounded timeout")
                .arg(Arg::new("request-id").required(true))
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .default_value("30000")
                        .value_parser(clap::value_parser!(u64)),
                ),
        ))
        .subcommand(with_principal_args(
            Command::new("cancel")
                .about("Cancel the principal's own pending request")
                .arg(Arg::new("request-id").required(true)),
        ))
        .subcommand(
            Command::new("inbox")
                .about("List the canonical secret-free local approval inbox and grant revisions"),
        )
        .subcommand(
            Command::new("decide")
                .about(
                    "Apply one local frontend approval decision; use request review for an interactive password prompt",
                )
                .arg(Arg::new("request-id").required(true))
                .arg(
                    Arg::new("decision")
                        .long("decision")
                        .required(true)
                        .value_parser(["deny", "once", "bounded", "add_to_grant"]),
                )
                .arg(Arg::new("reason").long("reason"))
                .arg(
                    Arg::new("ttl-seconds")
                        .long("ttl-seconds")
                        .default_value("900")
                        .value_parser(clap::value_parser!(u64)),
                )
                .arg(
                    Arg::new("uses")
                        .long("uses")
                        .value_parser(clap::value_parser!(u32))
                        .help("Optional accepted-command limit; omit for time-only access"),
                )
                .arg(Arg::new("grant").long("grant"))
                .arg(
                    Arg::new("ttl-delta-seconds")
                        .long("ttl-delta-seconds")
                        .default_value("0")
                        .value_parser(clap::value_parser!(u64)),
                )
                .arg(
                    Arg::new("uses-delta")
                        .long("uses-delta")
                        .default_value("0")
                        .value_parser(clap::value_parser!(u32)),
                )
                .arg(
                    Arg::new("constraints-json")
                        .long("constraints-json")
                        .help("Non-secret declarative narrowing constraints"),
                )
                .arg(
                    Arg::new("password-stdin")
                        .long("password-stdin")
                        .action(ArgAction::SetTrue)
                        .hide(true),
                ),
        )
        .subcommand(
            Command::new("review")
                .about("Review canonical details and decide locally through a TTY")
                .arg(Arg::new("request-id").required(true)),
        )
}

fn with_principal_args(command: Command) -> Command {
    command
        .arg(Arg::new("client-id").long("client-id").required(true))
        .arg(Arg::new("task-id").long("task-id").required(true))
        .arg(Arg::new("instance-id").long("instance-id"))
}

fn with_optional_principal_args(command: Command) -> Command {
    command
        .arg(Arg::new("client-id").long("client-id").global(true))
        .arg(Arg::new("task-id").long("task-id").global(true))
        .arg(Arg::new("instance-id").long("instance-id").global(true))
}

fn with_hidden_optional_principal_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("client-id")
                .long("client-id")
                .global(true)
                .hide(true),
        )
        .arg(Arg::new("task-id").long("task-id").global(true).hide(true))
        .arg(
            Arg::new("instance-id")
                .long("instance-id")
                .global(true)
                .hide(true),
        )
}

const JIT_EXIT_PENDING: i32 = 10;
const JIT_EXIT_DENIED: i32 = 11;
const JIT_EXIT_EXPIRED: i32 = 12;
const JIT_EXIT_CANCELLED: i32 = 13;
const JIT_EXIT_SUPERSEDED: i32 = 14;
const JIT_EXIT_BROKER_OFFLINE: i32 = 15;
const JIT_EXIT_RATE_LIMITED: i32 = 16;
const JIT_EXIT_INVALID: i32 = 17;
const JIT_EXIT_CONFLICT: i32 = 18;

async fn run_jit_request_command(matches: &ArgMatches) -> anyhow::Result<i32> {
    let (operation, matches) = matches
        .subcommand()
        .expect("request command requires an operation");
    if operation == "review" {
        return review_jit_request(
            matches
                .get_one::<String>("request-id")
                .expect("required by clap"),
        )
        .await;
    }
    let store = match JitAuthorizationStore::default_store() {
        Ok(store) => store,
        Err(error) => return print_jit_store_error(error),
    };
    if operation == "inbox" {
        return print_jit_review_inbox(&store);
    }
    if operation == "decide" {
        return decide_jit_request(&store, matches).await;
    }
    let principal = principal_from_matches(matches);
    let principal = match principal.and_then(|principal| {
        principal
            .validate()
            .map(|_| principal)
            .map_err(|error| anyhow!(error))
    }) {
        Ok(principal) => principal,
        Err(error) => {
            return print_jit_error(
                JIT_EXIT_INVALID,
                "invalid_principal",
                &error.to_string(),
                None,
            );
        }
    };

    match operation {
        "create" => create_jit_request(&store, matches, principal),
        "get" => {
            let id = matches
                .get_one::<String>("request-id")
                .expect("required by clap");
            match store.get_for_principal(id, &principal, Utc::now()) {
                Ok(request) => print_jit_request_status(request, false),
                Err(error) => print_jit_store_error(error),
            }
        }
        "list" => match store.list_for_principal(&principal, Utc::now()) {
            Ok(requests) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "data": { "requests": requests, "count": requests.len() }
                    }))?
                );
                Ok(0)
            }
            Err(error) => print_jit_store_error(error),
        },
        "wait" => {
            let id = matches
                .get_one::<String>("request-id")
                .expect("required by clap");
            let timeout = Duration::from_millis(
                *matches
                    .get_one::<u64>("timeout-ms")
                    .expect("defaulted by clap"),
            );
            match store.wait_for_principal(id, &principal, timeout).await {
                Ok(result) => print_jit_request_status(result.request, result.timed_out),
                Err(error) => print_jit_store_error(error),
            }
        }
        "cancel" => {
            let id = matches
                .get_one::<String>("request-id")
                .expect("required by clap");
            match store.cancel(id, &principal, Utc::now()) {
                Ok(request) => print_jit_request_status(request, false),
                Err(error) => print_jit_store_error(error),
            }
        }
        _ => unreachable!("clap enforces request operations"),
    }
}

fn print_jit_review_inbox(store: &JitAuthorizationStore) -> anyhow::Result<i32> {
    let requests = match store.list_for_review(Utc::now()) {
        Ok(requests) => requests,
        Err(error) => return print_jit_store_error(error),
    };
    let revisions = match store.list_revisions() {
        Ok(revisions) => revisions,
        Err(error) => return print_jit_store_error(error),
    };
    let pending_count = requests
        .iter()
        .filter(|request| request.status == voidb_core::AgentAuthorizationRequestStatus::Pending)
        .count();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": {
                "requests": requests,
                "revisions": revisions,
                "pending_count": pending_count,
                "observed_at": Utc::now(),
            }
        }))?
    );
    Ok(0)
}

async fn decide_jit_request(
    store: &JitAuthorizationStore,
    matches: &ArgMatches,
) -> anyhow::Result<i32> {
    let request_id = matches
        .get_one::<String>("request-id")
        .expect("required by clap");
    let request = match store.get_for_review(request_id, Utc::now()) {
        Ok(request) => request,
        Err(error) => return print_jit_store_error(error),
    };
    if request.status != voidb_core::AgentAuthorizationRequestStatus::Pending {
        return print_jit_request_status(
            voidb_core::FrontendAuthorizationRequest::try_from(&request)?,
            false,
        );
    }
    let decision = matches
        .get_one::<String>("decision")
        .expect("required by clap")
        .as_str();
    if !matches.get_flag("password-stdin") {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "authentication_required",
            &format!(
                "frontend decisions require the master password on standard input; run 'voidb-cli agent request review {request_id}' in a local terminal for an interactive hidden password prompt"
            ),
            None,
        );
    }
    let mut password = String::new();
    tokio::io::stdin().read_to_string(&mut password).await?;
    if password.is_empty() {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "authentication_failed",
            "master password is required",
            None,
        );
    }
    if AppConfig::load_with_password(Some(&password)).is_err() {
        password.clear();
        return print_jit_error(
            JIT_EXIT_INVALID,
            "authentication_failed",
            "master password verification failed",
            None,
        );
    }
    if decision == "deny" {
        let reason = matches
            .get_one::<String>("reason")
            .cloned()
            .unwrap_or_else(|| "Denied from Connection Manager".into());
        let denied = match store.deny(request_id, reason, Utc::now()) {
            Ok(request) => request,
            Err(error) => {
                password.clear();
                return print_jit_store_error(error);
            }
        };
        password.clear();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "data": { "request": denied }
            }))?
        );
        return Ok(0);
    }

    let mut approved_scope = request.scope.clone();
    if let Some(raw) = matches.get_one::<String>("constraints-json") {
        let additional: BTreeMap<String, Value> = match serde_json::from_str(raw) {
            Ok(value) => value,
            Err(error) => {
                return print_jit_error(
                    JIT_EXIT_INVALID,
                    "invalid_constraints",
                    &format!("constraints must be a JSON object: {error}"),
                    None,
                );
            }
        };
        let capability_id = request.scope.capability_id().to_string();
        approved_scope = match &request.scope {
            AgentAuthorizationScope::Capability { .. } => AgentAuthorizationScope::Constrained {
                capability_id,
                constraints: additional,
            },
            AgentAuthorizationScope::Constrained { constraints, .. } => {
                let mut narrowed = constraints.clone();
                for (path, value) in additional {
                    if narrowed.insert(path.clone(), value).is_some() {
                        return print_jit_error(
                            JIT_EXIT_INVALID,
                            "scope_widening",
                            &format!("requested constraint '{path}' cannot be replaced"),
                            None,
                        );
                    }
                }
                AgentAuthorizationScope::Constrained {
                    capability_id,
                    constraints: narrowed,
                }
            }
            AgentAuthorizationScope::ExactInvocation { .. } if additional.is_empty() => {
                request.scope.clone()
            }
            AgentAuthorizationScope::ExactInvocation { .. } => {
                return print_jit_error(
                    JIT_EXIT_INVALID,
                    "scope_widening",
                    "exact invocations cannot be changed during approval",
                    None,
                );
            }
        };
    }
    if !request.scope.can_narrow_to(&approved_scope) {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "scope_widening",
            "approved scope must be equal to or narrower than the request",
            None,
        );
    }
    let definitions = match resolved_authorization_capabilities(Some(&request.plugin_id)) {
        Ok(definitions) => definitions,
        Err(error) => return print_jit_error(JIT_EXIT_INVALID, "invalid_scope", &error, None),
    };
    let Some(definition) = definitions
        .iter()
        .find(|definition| definition.qualified_id() == request.scope.capability_id())
    else {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "invalid_scope",
            "capability authorization declaration is no longer available",
            None,
        );
    };
    if let Err(error) = validate_declared_jit_scope(definition, &approved_scope) {
        return print_jit_error(JIT_EXIT_INVALID, "invalid_scope", &error.to_string(), None);
    }

    let amendment = match decision {
        "once" => AgentGrantAmendment::Once,
        "bounded" => AgentGrantAmendment::Bounded {
            ttl_seconds: *matches
                .get_one::<u64>("ttl-seconds")
                .expect("defaulted by clap"),
            uses: matches.get_one::<u32>("uses").copied(),
        },
        "add_to_grant" => {
            let Some(grant_id) = matches.get_one::<String>("grant") else {
                return print_jit_error(
                    JIT_EXIT_INVALID,
                    "invalid_amendment",
                    "add_to_grant requires --grant",
                    None,
                );
            };
            AgentGrantAmendment::AddToGrant {
                grant_id: grant_id.clone(),
                ttl_delta_seconds: *matches
                    .get_one::<u64>("ttl-delta-seconds")
                    .expect("defaulted by clap"),
                uses_delta: *matches
                    .get_one::<u32>("uses-delta")
                    .expect("defaulted by clap"),
            }
        }
        _ => unreachable!("clap validates decisions"),
    };

    let profile_store = LocalProfileStore::default_store()?;
    let profile = resolve_profile(
        &profile_store.load_profiles()?,
        &request.profile_id,
        &request.plugin_id,
    );
    if profile
        .and_then(|profile| verify_profile_credentials(&profile_store, &profile, &password))
        .is_err()
    {
        password.clear();
        return print_jit_error(
            JIT_EXIT_INVALID,
            "authentication_failed",
            "master password or target profile credential verification failed",
            None,
        );
    }

    let revision = match store.approve(request_id, approved_scope, amendment, Utc::now()) {
        Ok(revision) => revision,
        Err(error) => {
            password.clear();
            return print_jit_store_error(error);
        }
    };
    let scopes = store.effective_scopes(&revision.grant_id)?;
    let activation = activate_jit_revision(&request, &revision, scopes, &password).await;
    password.clear();
    let grant = match activation {
        Ok(grant) => grant,
        Err(error) => {
            return print_jit_error(
                JIT_EXIT_BROKER_OFFLINE,
                "broker_offline",
                &format!("approval was recorded but broker activation failed: {error}"),
                Some(1_000),
            );
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": { "revision": revision, "grant": grant }
        }))?
    );
    Ok(0)
}

fn principal_from_matches(matches: &ArgMatches) -> anyhow::Result<AgentPrincipal> {
    Ok(AgentPrincipal {
        client_id: matches
            .get_one::<String>("client-id")
            .expect("required by clap")
            .clone(),
        task_id: matches
            .get_one::<String>("task-id")
            .expect("required by clap")
            .clone(),
        instance_id: matches.get_one::<String>("instance-id").cloned(),
    })
}

fn create_jit_request(
    store: &JitAuthorizationStore,
    matches: &ArgMatches,
    principal: AgentPrincipal,
) -> anyhow::Result<i32> {
    let plugin_id = matches
        .get_one::<String>("plugin")
        .expect("required by clap");
    let capability_id = matches
        .get_one::<String>("capability")
        .expect("required by clap");
    if capability_id.split_once('.').map(|(plugin, _)| plugin) != Some(plugin_id.as_str()) {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "binding_mismatch",
            "qualified capability does not belong to --plugin",
            None,
        );
    }
    let definitions = match resolved_authorization_capabilities(Some(plugin_id)) {
        Ok(definitions) => definitions,
        Err(error) => {
            return print_jit_error(JIT_EXIT_INVALID, "unsupported_capability", &error, None);
        }
    };
    let Some(definition) = definitions
        .iter()
        .find(|definition| definition.qualified_id() == *capability_id)
    else {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "unsupported_capability",
            "capability has no current authorization declaration",
            None,
        );
    };
    if !matches!(
        definition.authorization.jit_support(),
        voidb_core::CapabilityJitSupport::Supported
    ) {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "unsupported_capability",
            "capability does not support JIT authorization",
            None,
        );
    }
    let scope = match matches
        .get_one::<String>("scope")
        .expect("required by clap")
        .as_str()
    {
        "capability" => AgentAuthorizationScope::Capability {
            capability_id: capability_id.clone(),
        },
        "constrained" => {
            let raw = matches
                .get_one::<String>("constraints-json")
                .expect("required by clap");
            let constraints: BTreeMap<String, Value> = match serde_json::from_str(raw) {
                Ok(constraints) => constraints,
                Err(error) => {
                    return print_jit_error(
                        JIT_EXIT_INVALID,
                        "invalid_constraints",
                        &format!("constraints must be a JSON object: {error}"),
                        None,
                    );
                }
            };
            AgentAuthorizationScope::Constrained {
                capability_id: capability_id.clone(),
                constraints,
            }
        }
        "exact" => {
            let raw = matches
                .get_one::<String>("input-json")
                .expect("required by clap");
            let input: Value = match serde_json::from_str(raw) {
                Ok(input) => input,
                Err(error) => {
                    return print_jit_error(
                        JIT_EXIT_INVALID,
                        "invalid_input",
                        &format!("input must be valid JSON: {error}"),
                        None,
                    );
                }
            };
            if voidb_core::collect_redaction_targets(&input)
                .iter()
                .any(|target| matches!(target.kind, voidb_core::RedactionTargetKind::Credential(_)))
            {
                return print_jit_error(
                    JIT_EXIT_INVALID,
                    "secret_input_forbidden",
                    "authorization requests cannot persist credential-bearing input fields",
                    None,
                );
            }
            let operation = match normalize_agent_operation(capability_id, input) {
                Ok(operation) => operation,
                Err(error) => {
                    return print_jit_error(
                        JIT_EXIT_INVALID,
                        "invalid_input",
                        &error.to_string(),
                        None,
                    );
                }
            };
            AgentAuthorizationScope::ExactInvocation {
                capability_id: operation.capability_id,
                normalized_input: operation.input,
                invocation_fingerprint: operation.fingerprint,
            }
        }
        _ => unreachable!("clap validates scope"),
    };
    if let Err(error) = validate_declared_jit_scope(definition, &scope) {
        return print_jit_error(JIT_EXIT_INVALID, "invalid_scope", &error.to_string(), None);
    }
    let ttl_seconds = *matches
        .get_one::<u64>("ttl-seconds")
        .expect("defaulted by clap");
    let profile_id = matches
        .get_one::<String>("profile")
        .expect("required by clap")
        .strip_prefix("id:")
        .unwrap_or_else(|| matches.get_one::<String>("profile").unwrap())
        .to_string();
    let now = Utc::now();
    match store.create(
        CreateAuthorizationRequest {
            principal,
            profile_id,
            plugin_id: plugin_id.clone(),
            scope,
            risk: definition.effective_risk(),
            purpose: matches
                .get_one::<String>("purpose")
                .expect("required by clap")
                .clone(),
            expires_at: now + chrono::Duration::seconds(ttl_seconds as i64),
        },
        now,
    ) {
        Ok(result) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "ok": true, "data": result }))?
            );
            Ok(JIT_EXIT_PENDING)
        }
        Err(error) => print_jit_store_error(error),
    }
}

fn validate_declared_jit_scope(
    definition: &CapabilityDefinition,
    scope: &AgentAuthorizationScope,
) -> anyhow::Result<()> {
    if !definition.supports_stateless_execution() {
        bail!(
            "capability '{}' is session-only; JIT agent exec grants are stateless. Use an explicit --execution-mode session_only proactive grant and the declared session handoff",
            definition.qualified_id()
        );
    }
    match scope {
        AgentAuthorizationScope::Capability { .. } => {
            if !definition.authorization.capability_wide_allowed {
                bail!("capability-wide approval is disabled by the plugin declaration");
            }
        }
        AgentAuthorizationScope::Constrained { constraints, .. } => {
            let schema = definition
                .authorization
                .approval_schema
                .as_ref()
                .ok_or_else(|| anyhow!("capability has no structured approval schema"))?;
            schema.validate().map_err(|error| anyhow!(error))?;
            for path in constraints.keys() {
                if !schema.fields.iter().any(|field| field.path == *path) {
                    bail!("constraint path '{path}' is not declared by the plugin");
                }
            }
            for field in schema.fields.iter().filter(|field| field.required) {
                if !constraints.contains_key(&field.path) {
                    bail!("required constraint '{}' is missing", field.path);
                }
            }
        }
        AgentAuthorizationScope::ExactInvocation {
            capability_id,
            normalized_input,
            invocation_fingerprint,
        } => {
            let operation = normalize_agent_operation(capability_id, normalized_input.clone())?;
            if operation.fingerprint != *invocation_fingerprint {
                bail!("exact invocation fingerprint does not match normalized input");
            }
            authorize_normalized_operation(&definition.authorization, scope, &operation)?;
        }
    }
    Ok(())
}

fn print_jit_request_status(
    request: voidb_core::FrontendAuthorizationRequest,
    timed_out: bool,
) -> anyhow::Result<i32> {
    use voidb_core::AgentAuthorizationRequestStatus as Status;
    let request_timed_out = request.timed_out;
    let broker_offline = request.status == Status::Approved
        && request.grant_id.as_ref().is_some_and(|grant_id| {
            load_grants(false)
                .map(|grants| {
                    !grants
                        .iter()
                        .any(|grant| grant.id == *grant_id && grant.socket_path.exists())
                })
                .unwrap_or(true)
        });
    let (exit_code, error_code) = match request.status {
        Status::Pending => (JIT_EXIT_PENDING, timed_out.then_some("pending")),
        Status::Approved if broker_offline => (JIT_EXIT_BROKER_OFFLINE, Some("broker_offline")),
        Status::Approved => (0, None),
        Status::Denied if request_timed_out => (JIT_EXIT_DENIED, Some("timed_out")),
        Status::Denied => (JIT_EXIT_DENIED, Some("denied")),
        Status::Expired => (JIT_EXIT_EXPIRED, Some("expired")),
        Status::Cancelled => (JIT_EXIT_CANCELLED, Some("cancelled")),
        Status::Superseded => (JIT_EXIT_SUPERSEDED, Some("superseded")),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": error_code.is_none() || request.status == Status::Pending,
            "data": { "request": request, "timed_out": timed_out },
            "error": error_code.map(|code| json!({
                "code": code,
                "message": if request_timed_out {
                    "authorization request timed out and was automatically denied"
                } else if timed_out {
                    "authorization decision is still pending"
                } else {
                    "authorization request reached a terminal non-approved state"
                }
            }))
        }))?
    );
    Ok(exit_code)
}

fn print_jit_store_error(error: JitAuthorizationStoreError) -> anyhow::Result<i32> {
    match error {
        JitAuthorizationStoreError::RateLimited { retry_after_ms }
        | JitAuthorizationStoreError::QueueFull { retry_after_ms }
        | JitAuthorizationStoreError::DenialCooldown { retry_after_ms } => print_jit_error(
            JIT_EXIT_RATE_LIMITED,
            "rate_limited",
            "authorization request is temporarily throttled",
            Some(retry_after_ms),
        ),
        JitAuthorizationStoreError::Io(_) | JitAuthorizationStoreError::Corrupt(_) => {
            print_jit_error(
                JIT_EXIT_BROKER_OFFLINE,
                "broker_offline",
                "local authorization broker state is unavailable",
                Some(1_000),
            )
        }
        JitAuthorizationStoreError::Contract(
            voidb_core::AgentAuthorizationError::AlreadyDecided,
        )
        | JitAuthorizationStoreError::Busy => print_jit_error(
            JIT_EXIT_CONFLICT,
            "decision_conflict",
            "authorization request was already decided or is being decided",
            Some(250),
        ),
        other => print_jit_error(
            JIT_EXIT_INVALID,
            "invalid_request",
            &other.to_string(),
            None,
        ),
    }
}

fn print_jit_error(
    exit_code: i32,
    code: &str,
    message: &str,
    retry_after_ms: Option<u64>,
) -> anyhow::Result<i32> {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": false,
            "data": null,
            "error": {
                "code": code,
                "message": message,
                "retry_after_ms": retry_after_ms,
            }
        }))?
    );
    Ok(exit_code)
}

async fn review_jit_request(request_id: &str) -> anyhow::Result<i32> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "tty_required",
            "local review requires an interactive controlling TTY",
            None,
        );
    }
    let store = match JitAuthorizationStore::default_store() {
        Ok(store) => store,
        Err(error) => return print_jit_store_error(error),
    };
    let request = match store.get_for_review(request_id, Utc::now()) {
        Ok(request) => request,
        Err(error) => return print_jit_store_error(error),
    };
    if request.status != voidb_core::AgentAuthorizationRequestStatus::Pending {
        return print_jit_request_status(
            voidb_core::FrontendAuthorizationRequest::try_from(&request)?,
            false,
        );
    }

    let profile_label = format_review_profile(&request.profile_id, &request.plugin_id);
    let principal_label = format_review_principal(&request.principal);
    let risk_label = format_review_risk(request.risk);
    let scope_summary = format_review_scope_summary(&request.scope);

    println!("==================================================");
    println!("          VoidB JIT Authorization Review          ");
    println!("==================================================");
    println!("Request:  {}", request.id);
    println!("Agent:    {}", principal_label);
    println!("Profile:  {}", profile_label);
    println!("Plugin:   {}", sanitize_terminal_text(&request.plugin_id));
    println!("Risk:     {}", risk_label);
    println!("Purpose:  {}", sanitize_terminal_text(&request.purpose));
    println!("Scope:    {}", scope_summary);
    println!(
        "Raw scope:\n{}",
        serde_json::to_string_pretty(&request.scope)?
    );
    println!("Expires:  {}", request.expires_at.to_rfc3339());
    println!("--------------------------------------------------");

    let action_str = prompt_tty_line(
        "Decision [b=time-bounded (recommended, Enter), o=once, a=add-to-grant, d=deny]: ",
    )?;
    let action = match parse_review_decision(&action_str) {
        Some(action) => action,
        None => {
            return print_jit_error(
                JIT_EXIT_INVALID,
                "invalid_decision",
                &format!("review decision '{action_str}' was not recognized; choose b, o, a, or d"),
                None,
            );
        }
    };
    if action == "d" {
        let reason = prompt_tty_line("Denial reason: ")?;
        let denied = match store.deny(request_id, reason, Utc::now()) {
            Ok(request) => request,
            Err(error) => return print_jit_store_error(error),
        };
        println!("Request {} denied.", denied.id);
        return Ok(0);
    }
    let amendment = match action {
        "o" => AgentGrantAmendment::Once,
        "b" => AgentGrantAmendment::Bounded {
            ttl_seconds: prompt_tty_number_with_default(
                "Grant TTL seconds (1-3600, Enter for default 300): ",
                300,
            )?,
            uses: prompt_tty_optional_number("Optional use limit (1-100, Enter for unlimited): ")?,
        },
        "a" => AgentGrantAmendment::AddToGrant {
            grant_id: prompt_tty_line("Existing logical grant ID: ")?,
            ttl_delta_seconds: prompt_tty_number_with_default(
                "TTL extension seconds (0 allowed, Enter for default 300): ",
                300,
            )?,
            uses_delta: prompt_tty_number_with_default(
                "Additional uses (0 allowed, Enter for default 0): ",
                0,
            )?,
        },
        _ => unreachable!(),
    };
    let approved_scope = prompt_narrowed_scope(&request.scope)?;
    if !request.scope.can_narrow_to(&approved_scope) {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "scope_widening",
            "approved scope must be equal to or narrower than the request",
            None,
        );
    }
    let definitions = resolved_authorization_capabilities(Some(&request.plugin_id))
        .map_err(|error| anyhow!(error))?;
    let definition = definitions
        .iter()
        .find(|definition| definition.qualified_id() == request.scope.capability_id())
        .ok_or_else(|| anyhow!("capability authorization declaration is no longer available"))?;
    if let Err(error) = validate_declared_jit_scope(definition, &approved_scope) {
        return print_jit_error(JIT_EXIT_INVALID, "invalid_scope", &error.to_string(), None);
    }

    let mut password = rpassword::prompt_password("VoidB master password: ")?;
    if password.is_empty() {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "authentication_failed",
            "master password is required",
            None,
        );
    }
    let verified = AppConfig::load_with_password(Some(&password));
    if verified.is_err() {
        password.clear();
        return print_jit_error(
            JIT_EXIT_INVALID,
            "authentication_failed",
            "master password verification failed",
            None,
        );
    }
    let profile_store = LocalProfileStore::default_store()?;
    let profile = resolve_profile(
        &profile_store.load_profiles()?,
        &request.profile_id,
        &request.plugin_id,
    );
    let credentials_verified =
        profile.and_then(|profile| verify_profile_credentials(&profile_store, &profile, &password));
    if credentials_verified.is_err() {
        password.clear();
        return print_jit_error(
            JIT_EXIT_INVALID,
            "authentication_failed",
            "master password or target profile credential verification failed",
            None,
        );
    }

    let revision = match store.approve(request_id, approved_scope, amendment, Utc::now()) {
        Ok(revision) => revision,
        Err(error) => {
            password.clear();
            return print_jit_store_error(error);
        }
    };
    let scopes = store.effective_scopes(&revision.grant_id)?;
    let activation = activate_jit_revision(&request, &revision, scopes, &password).await;
    password.clear();
    let public = match activation {
        Ok(public) => public,
        Err(error) => {
            eprintln!("JIT approval was recorded but broker activation failed: {error}");
            return Ok(JIT_EXIT_BROKER_OFFLINE);
        }
    };
    let use_limit = public.remaining_uses.map_or_else(
        || "unlimited uses".to_string(),
        |uses| format!("{uses} uses"),
    );
    println!(
        "Approved request {} as grant {} revision {} (expires {}, {}).",
        request.id,
        public.id,
        revision.revision,
        public.expires_at.to_rfc3339(),
        use_limit
    );
    println!("--------------------------------------------------");
    println!("✓ JIT authorization approved successfully.");
    println!("  Target Profile: {}", profile_label);
    println!("  Active Grant:   {}", public.id);
    println!("  Capabilities:   {}", request.scope.capability_id());
    println!("  Valid Until:    {} ({})", public.expires_at.to_rfc3339(), use_limit);
    println!("==================================================");
    Ok(0)
}

fn prompt_narrowed_scope(
    requested: &AgentAuthorizationScope,
) -> anyhow::Result<AgentAuthorizationScope> {
    if matches!(requested, AgentAuthorizationScope::ExactInvocation { .. }) {
        return Ok(requested.clone());
    }
    let choice = prompt_tty_line("Scope [r=requested, n=add non-secret constraints]: ")?;
    if choice.eq_ignore_ascii_case("r") || choice.is_empty() {
        return Ok(requested.clone());
    }
    if !choice.eq_ignore_ascii_case("n") {
        bail!("scope choice was not recognized");
    }
    let raw = prompt_tty_line("Additional constraints JSON object: ")?;
    let additional: BTreeMap<String, Value> =
        serde_json::from_str(&raw).context("constraints must be a JSON object")?;
    let mut constraints = match requested {
        AgentAuthorizationScope::Capability { .. } => BTreeMap::new(),
        AgentAuthorizationScope::Constrained { constraints, .. } => constraints.clone(),
        AgentAuthorizationScope::ExactInvocation { .. } => unreachable!(),
    };
    for (path, value) in additional {
        if constraints.contains_key(&path) {
            bail!("existing requested constraints cannot be replaced during narrowing");
        }
        constraints.insert(path, value);
    }
    Ok(AgentAuthorizationScope::Constrained {
        capability_id: requested.capability_id().to_string(),
        constraints,
    })
}

fn prompt_tty_line(prompt: &str) -> anyhow::Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut value = String::new();
    std::io::stdin().lock().read_line(&mut value)?;
    Ok(value.trim().to_string())
}


fn prompt_tty_optional_number<T>(prompt: &str) -> anyhow::Result<Option<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = prompt_tty_line(prompt)?;
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse()
        .map(Some)
        .map_err(|error| anyhow!("invalid numeric value: {error}"))
}

fn prompt_tty_number_with_default<T>(prompt: &str, default: T) -> anyhow::Result<T>
where
    T: std::str::FromStr + Copy,
    T::Err: std::fmt::Display,
{
    let value = prompt_tty_line(prompt)?;
    if value.is_empty() {
        return Ok(default);
    }
    value
        .parse()
        .map_err(|error| anyhow!("invalid numeric value: {error}"))
}

fn parse_review_decision(input: &str) -> Option<&'static str> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Some("b"); // Default to recommended (time-bounded)
    }
    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "b" | "bounded" | "time-bounded" => Some("b"),
        "o" | "once" | "single" => Some("o"),
        "a" | "add" | "add-to-grant" => Some("a"),
        "d" | "deny" | "reject" => Some("d"),
        _ => None,
    }
}

fn format_review_profile(profile_id: &str, plugin_id: &str) -> String {
    let store = match LocalProfileStore::default_store() {
        Ok(store) => store,
        Err(_) => return sanitize_terminal_text(profile_id),
    };
    let profiles = match store.load_profiles() {
        Ok(profiles) => profiles,
        Err(_) => return sanitize_terminal_text(profile_id),
    };
    let format_one = |profile: &ConnectionProfile| {
        match &profile.display_name {
            Some(dn) if !dn.trim().is_empty() && dn != &profile.name => {
                format!("{} [{}] ({})", profile.name, dn, profile.id)
            }
            _ => format!("{} ({})", profile.name, profile.id),
        }
    };
    if let Ok(profile) = resolve_profile(&profiles, profile_id, plugin_id) {
        format_one(&profile)
    } else if let Some(profile) = profiles.into_iter().find(|p| p.id == profile_id) {
        format_one(&profile)
    } else {
        sanitize_terminal_text(profile_id)
    }
}

fn format_review_principal(principal: &AgentPrincipal) -> String {
    let fingerprint = principal
        .fingerprint()
        .unwrap_or_else(|_| "unknown-fingerprint".to_string());
    if let Some(instance_id) = &principal.instance_id {
        format!(
            "client={} task={} instance={} ({})",
            principal.client_id, principal.task_id, instance_id, fingerprint
        )
    } else {
        format!(
            "client={} task={} ({})",
            principal.client_id, principal.task_id, fingerprint
        )
    }
}

fn format_review_risk(risk: voidb_core::CapabilityRiskLevel) -> &'static str {
    use voidb_core::CapabilityRiskLevel;
    match risk {
        CapabilityRiskLevel::ReadOnly => "read_only (safe)",
        CapabilityRiskLevel::Mutating => "mutating (state change)",
        CapabilityRiskLevel::Destructive => "destructive (high risk)",
        CapabilityRiskLevel::ExternalSideEffect => "external_side_effect",
    }
}

fn format_review_scope_summary(scope: &AgentAuthorizationScope) -> String {
    match scope {
        AgentAuthorizationScope::Capability { capability_id } => {
            format!("Capability '{}' (all invocations allowed)", capability_id)
        }
        AgentAuthorizationScope::Constrained {
            capability_id,
            constraints,
        } => {
            format!(
                "Capability '{}' with constraints: {}",
                capability_id,
                serde_json::to_string(constraints).unwrap_or_else(|_| "{}".to_string())
            )
        }
        AgentAuthorizationScope::ExactInvocation {
            capability_id,
            normalized_input,
            ..
        } => {
            if normalized_input.as_object().is_none_or(|o| o.is_empty()) {
                format!("Exact invocation: '{}' (no arguments)", capability_id)
            } else {
                format!(
                    "Exact invocation: '{}' with input: {}",
                    capability_id,
                    serde_json::to_string(normalized_input).unwrap_or_else(|_| "{}".to_string())
                )
            }
        }
    }
}

fn sanitize_terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .take(1_000)
        .collect()
}

async fn activate_jit_revision(
    request: &voidb_core::AgentAuthorizationRequest,
    revision: &AgentGrantRevision,
    scopes: Vec<AgentAuthorizationScope>,
    password: &str,
) -> anyhow::Result<FrontendAgentGrant> {
    ensure_unix()?;
    if scopes.is_empty() {
        bail!("approved grant revision has no effective scopes");
    }
    let profile_store = LocalProfileStore::default_store()?;
    let profile = resolve_profile(
        &profile_store.load_profiles()?,
        &request.profile_id,
        &request.plugin_id,
    )?;
    verify_profile_credentials(&profile_store, &profile, password)
        .context("profile credential verification failed")?;

    if let Some(existing) = load_grants(false)?
        .into_iter()
        .find(|grant| grant.id == revision.grant_id)
    {
        shutdown_grant(&existing, "jit_revision_replaced").await?;
    }
    let file_stem = revision.grant_id.trim_start_matches("agent-grant:");
    let grant_path = grant_path_for_id(&revision.grant_id)?;
    let socket_path = PathBuf::from("/tmp").join(format!(
        "voidb-agent-{}.sock",
        file_stem.chars().take(16).collect::<String>()
    ));
    let mut capabilities = scopes
        .iter()
        .map(|scope| scope.capability_id().to_string())
        .collect::<Vec<_>>();
    capabilities.sort();
    capabilities.dedup();
    let grant = AgentGrantFile {
        version: GRANT_VERSION,
        id: revision.grant_id.clone(),
        token: Uuid::new_v4().to_string(),
        profile_id: request.profile_id.clone(),
        profile_name: profile.name,
        plugin_id: request.plugin_id.clone(),
        capabilities,
        execution_mode: CapabilityExecutionMode::Stateless,
        preset: Some(AgentAuthorizationPresetKind::Custom),
        allow_destructive: request.risk != voidb_core::CapabilityRiskLevel::ReadOnly,
        issued_at: revision.issued_at,
        expires_at: revision.expires_at,
        remaining_uses: revision.remaining_uses,
        socket_path,
        authorization_scopes: scopes,
        principal_fingerprint: Some(revision.principal_fingerprint.clone()),
        grant_revision: Some(revision.revision),
    };
    write_grant(&grant_path, &grant)?;
    spawn_agent_broker(&grant_path, &grant, password).await?;
    append_agent_audit(
        &grant,
        AuditOperation::CredentialGrantIssued,
        json!({
            "lifecycle": "jit_revision",
            "revision": revision.revision,
            "request_id": revision.source_request_id,
            "principal_fingerprint": revision.principal_fingerprint,
            "scope_fingerprints": grant.authorization_scopes.iter().map(AgentAuthorizationScope::canonical_fingerprint).collect::<Vec<_>>(),
            "execution_mode": grant.execution_mode,
        }),
    );
    let inspection = inspect_grant(&grant).await;
    Ok(grant.public(inspection.broker_health, inspection.active_session_count))
}

async fn spawn_agent_broker(
    grant_path: &Path,
    grant: &AgentGrantFile,
    password: &str,
) -> anyhow::Result<()> {
    let mut command = tokio::process::Command::new(std::env::current_exe()?);
    command
        .arg("__agent-broker")
        .arg(grant_path)
        .env_remove(VOIDB_MASTER_PASSWORD_ENV)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            remove_grant_artifacts(grant)?;
            return Err(error).context("start agent broker");
        }
    };
    let Some(stdin) = child.stdin.take() else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        remove_grant_artifacts(grant)?;
        bail!("open broker password pipe");
    };
    if let Err(error) = write_password_and_close(stdin, password.as_bytes()).await {
        let _ = child.kill().await;
        let _ = child.wait().await;
        remove_grant_artifacts(grant)?;
        return Err(error).context("write broker password pipe");
    }
    if let Err(error) = wait_for_socket(&grant.socket_path).await {
        let _ = child.kill().await;
        let detail = child
            .wait_with_output()
            .await
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stderr).trim().to_string())
            .filter(|detail| !detail.is_empty());
        remove_grant_artifacts(grant)?;
        return Err(match detail {
            Some(detail) => anyhow!("{error}: {detail}"),
            None => error,
        });
    }
    drop(child);
    Ok(())
}

fn list_authorization_catalog(matches: &ArgMatches) -> anyhow::Result<i32> {
    let plugin_filter = matches.get_one::<String>("plugin").map(String::as_str);
    let definitions =
        resolved_authorization_capabilities(plugin_filter).map_err(|error| anyhow!(error))?;
    let execution_modes = matches
        .get_many::<String>("execution-mode")
        .into_iter()
        .flatten()
        .map(|mode| parse_execution_mode(mode))
        .collect::<Vec<_>>();
    let filtered_definitions = definitions
        .iter()
        .filter(|capability| capability_matches_execution_modes(capability, &execution_modes))
        .collect::<Vec<_>>();
    let mut plugins = build_authorization_plugin_catalogs(&definitions, plugin_filter);
    if !execution_modes.is_empty() {
        for plugin in &mut plugins {
            plugin.capabilities.retain(|capability| {
                execution_modes.iter().any(|filter| match filter {
                    CapabilityExecutionMode::Stateless => {
                        capability.execution_mode.supports_stateless()
                    }
                    CapabilityExecutionMode::SessionOnly => {
                        capability.execution_mode.supports_session()
                    }
                    CapabilityExecutionMode::Both => true,
                })
            });
            plugin
                .presets
                .retain(|preset| execution_modes.contains(&preset.execution_mode));
        }
    }
    if matches.get_one::<String>("format").map(String::as_str) == Some("table") {
        println!("{}", authorization_catalog_table(&filtered_definitions));
        return Ok(0);
    }
    let capabilities = filtered_definitions
        .into_iter()
        .map(|capability| {
            let mut value = serde_json::to_value(capability)?;
            if let Some(object) = value.as_object_mut() {
                object.insert("qualified_id".into(), json!(capability.qualified_id()));
            }
            Ok::<_, serde_json::Error>(value)
        })
        .collect::<serde_json::Result<Vec<_>>>()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": {
                "capabilities": capabilities,
                "count": capabilities.len(),
                "plugins": plugins,
            }
        }))?
    );
    Ok(0)
}

fn authorization_catalog_table(definitions: &[&CapabilityDefinition]) -> String {
    let mut lines = vec!["Capability\tMode\tRisk\tStream\tSession purpose".to_string()];
    for definition in definitions {
        let purpose = definition
            .session_handoff
            .as_ref()
            .map(|handoff| crate::builtin::invoke::session_purpose_cli_name(&handoff.purpose))
            .unwrap_or_else(|| "-".into());
        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}",
            sanitize_table_cell(&definition.qualified_id()),
            execution_mode_name(definition.execution_mode),
            capability_risk_name(definition.effective_risk()),
            definition.streaming,
            sanitize_table_cell(&purpose),
        ));
    }
    lines.join("\n")
}

fn sanitize_table_cell(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ")
}

fn capability_risk_name(risk: voidb_core::CapabilityRiskLevel) -> &'static str {
    match risk {
        voidb_core::CapabilityRiskLevel::ReadOnly => "read_only",
        voidb_core::CapabilityRiskLevel::Mutating => "mutating",
        voidb_core::CapabilityRiskLevel::Destructive => "destructive",
        voidb_core::CapabilityRiskLevel::ExternalSideEffect => "external_side_effect",
    }
}

fn build_authorization_plugin_catalogs(
    definitions: &[CapabilityDefinition],
    _plugin_filter: Option<&str>,
) -> Vec<AgentAuthorizationPluginCatalog> {
    let mut grouped = BTreeMap::<String, Vec<&CapabilityDefinition>>::new();
    for definition in definitions {
        grouped
            .entry(definition.plugin_id.clone())
            .or_default()
            .push(definition);
    }

    let mut catalogs = grouped
        .into_iter()
        .map(|(plugin_id, mut definitions)| {
            definitions.sort_by_key(|definition| definition.qualified_id());
            let metadata_complete = definitions
                .iter()
                .all(|definition| definition.authorization.declared);
            let capabilities = definitions
                .iter()
                .map(|definition| AgentAuthorizationCapability {
                    id: definition.qualified_id(),
                    risk: definition.effective_risk(),
                    streaming: definition.streaming,
                    execution_mode: definition.execution_mode,
                    session_handoff: definition.session_handoff.clone(),
                    session_purposes: definition.authorization.session_purposes.clone(),
                })
                .collect::<Vec<_>>();
            let presets = [
                CapabilityExecutionMode::Stateless,
                CapabilityExecutionMode::SessionOnly,
                CapabilityExecutionMode::Both,
            ]
            .into_iter()
            .flat_map(|execution_mode| {
                authorization_presets_for_mode(&definitions, metadata_complete, execution_mode)
            })
            .collect();
            AgentAuthorizationPluginCatalog {
                plugin_id,
                support: AgentAuthorizationSupportSummary {
                    status: AgentAuthorizationSupportStatus::Supported,
                    reason: if metadata_complete {
                        "Capability authorization metadata is centrally normalized.".into()
                    } else {
                        "Authorization metadata is incomplete; only explicit Custom scopes are available."
                            .into()
                    },
                },
                capabilities,
                presets,
            }
        })
        .collect::<Vec<_>>();

    catalogs.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
    catalogs
}

fn authorization_presets_for_mode(
    definitions: &[&CapabilityDefinition],
    metadata_complete: bool,
    execution_mode: CapabilityExecutionMode,
) -> Vec<AgentAuthorizationPresetDefinition> {
    if execution_mode == CapabilityExecutionMode::Both
        && (!definitions
            .iter()
            .any(|definition| definition.supports_stateless_execution())
            || !definitions
                .iter()
                .any(|definition| definition.supports_session_execution()))
    {
        return Vec::new();
    }
    let matching = definitions
        .iter()
        .copied()
        .filter(|definition| capability_supports_grant_mode(definition, execution_mode))
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return Vec::new();
    }

    let read_only_definitions = matching
        .iter()
        .copied()
        .filter(|definition| {
            definition.authorization.declared
                && definition.effective_risk() == voidb_core::CapabilityRiskLevel::ReadOnly
        })
        .collect::<Vec<_>>();
    let read_only = read_only_definitions
        .iter()
        .map(|definition| definition.qualified_id())
        .collect::<Vec<_>>();
    let interactive_definitions = matching
        .iter()
        .copied()
        .filter(|definition| {
            definition.authorization.declared && definition.authorization.interactive_execute
        })
        .collect::<Vec<_>>();
    let interactive = interactive_definitions
        .iter()
        .map(|definition| definition.qualified_id())
        .collect::<Vec<_>>();
    let interactive_purposes = if execution_mode.supports_session() {
        unique_session_purposes(&interactive_definitions)
    } else {
        Vec::new()
    };
    let read_only_purposes = if execution_mode.supports_session() {
        unique_session_purposes(&read_only_definitions)
    } else {
        Vec::new()
    };
    let full_access_purposes = if execution_mode.supports_session() {
        unique_session_purposes(&matching)
    } else {
        Vec::new()
    };
    let interactive_requires_ack = interactive_definitions
        .iter()
        .any(|definition| definition.requires_acknowledgement());
    let full_access = matching
        .iter()
        .map(|definition| definition.qualified_id())
        .collect::<Vec<_>>();
    let full_access_requires_ack = matching
        .iter()
        .any(|definition| definition.requires_acknowledgement());
    let suffix = match execution_mode {
        CapabilityExecutionMode::Stateless => "",
        CapabilityExecutionMode::SessionOnly => " (session)",
        CapabilityExecutionMode::Both => " (combined)",
    };
    let mut presets = Vec::new();
    if metadata_complete && !read_only.is_empty() {
        presets.push(AgentAuthorizationPresetDefinition {
            kind: AgentAuthorizationPresetKind::ReadOnly,
            label: format!("Read-only{suffix}"),
            description: format!(
                "Policy-reviewed operations without target side effects for {} execution.",
                execution_mode_name(execution_mode)
            ),
            execution_mode,
            recommended: execution_mode == CapabilityExecutionMode::Stateless,
            capabilities: read_only,
            session_purposes: read_only_purposes,
            requires_destructive_acknowledgement: false,
        });
    }
    if metadata_complete && !interactive.is_empty() {
        presets.push(AgentAuthorizationPresetDefinition {
            kind: AgentAuthorizationPresetKind::InteractiveExecute,
            label: format!("Interactive/Execute{suffix}"),
            description: format!(
                "The plugin's narrow, reviewed interactive scope for {} execution.",
                execution_mode_name(execution_mode)
            ),
            execution_mode,
            recommended: false,
            capabilities: interactive,
            session_purposes: interactive_purposes,
            requires_destructive_acknowledgement: interactive_requires_ack,
        });
    }
    if metadata_complete && !full_access.is_empty() {
        presets.push(AgentAuthorizationPresetDefinition {
            kind: AgentAuthorizationPresetKind::FullAccess,
            label: format!("Full access{suffix}"),
            description: format!(
                "Every {} capability in the current catalog, captured as an exact snapshot.",
                execution_mode_name(execution_mode)
            ),
            execution_mode,
            recommended: false,
            capabilities: full_access.clone(),
            session_purposes: full_access_purposes.clone(),
            requires_destructive_acknowledgement: full_access_requires_ack,
        });
    }
    presets.push(AgentAuthorizationPresetDefinition {
        kind: AgentAuthorizationPresetKind::Custom,
        label: format!("Custom{suffix}"),
        description: format!(
            "Explicit exact capability selection for {} execution.",
            execution_mode_name(execution_mode)
        ),
        execution_mode,
        recommended: false,
        capabilities: full_access,
        session_purposes: full_access_purposes,
        requires_destructive_acknowledgement: false,
    });
    presets
}

fn unique_session_purposes(definitions: &[&CapabilityDefinition]) -> Vec<PluginSessionPurpose> {
    definitions
        .iter()
        .flat_map(|definition| definition.authorization.session_purposes.clone())
        .fold(Vec::new(), |mut purposes, purpose| {
            if !purposes.contains(&purpose) {
                purposes.push(purpose);
            }
            purposes
        })
}

fn session_command() -> Command {
    let grant = || Arg::new("grant").long("grant").required(true);
    let session_id = || Arg::new("session-id").required(true);
    let generation = || {
        Arg::new("generation")
            .long("generation")
            .default_value("1")
            .value_parser(clap::value_parser!(u64))
    };
    Command::new("session")
        .about("Open and operate grant-scoped persistent plugin sessions")
        .subcommand_required(true)
        .subcommand(
            Command::new("open")
                .arg(grant())
                .arg(Arg::new("purpose").long("purpose").required(true))
                .arg(
                    Arg::new("capability")
                        .long("capability")
                        .action(ArgAction::Append),
                )
                .arg(
                    Arg::new("lease-seconds")
                        .long("lease-seconds")
                        .default_value("300")
                        .value_parser(clap::value_parser!(u64)),
                )
                .arg(
                    Arg::new("input-json")
                        .long("input-json")
                        .default_value("{}"),
                )
                .arg(
                    Arg::new("multiplexed")
                        .long("multiplexed")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .help("Acknowledge side effects caused by starting this live session")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("call")
                .arg(grant())
                .arg(session_id())
                .arg(generation())
                .arg(Arg::new("capability").long("capability").required(true))
                .arg(
                    Arg::new("call-id")
                        .long("call-id")
                        .value_name("ID")
                        .help("Caller-owned stable ID; supply it before launch when another process may cancel the call"),
                )
                .arg(
                    Arg::new("input-json")
                        .long("input-json")
                        .default_value("{}"),
                )
                .arg(Arg::new("yes").long("yes").action(ArgAction::SetTrue))
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .value_parser(clap::value_parser!(u64)),
                )
                .arg(
                    Arg::new("output-limit-bytes")
                        .long("output-limit-bytes")
                        .default_value("65536")
                        .value_parser(clap::value_parser!(usize)),
                ),
        )
        .subcommand(
            Command::new("start")
                .about("Start a session call and return its lifecycle immediately")
                .arg(grant())
                .arg(session_id())
                .arg(generation())
                .arg(Arg::new("capability").long("capability").required(true))
                .arg(
                    Arg::new("call-id")
                        .long("call-id")
                        .value_name("ID")
                        .help("Caller-owned stable ID; generated when omitted"),
                )
                .arg(
                    Arg::new("input-json")
                        .long("input-json")
                        .default_value("{}"),
                )
                .arg(Arg::new("yes").long("yes").action(ArgAction::SetTrue))
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .value_parser(clap::value_parser!(u64)),
                )
                .arg(
                    Arg::new("output-limit-bytes")
                        .long("output-limit-bytes")
                        .default_value("65536")
                        .value_parser(clap::value_parser!(usize)),
                ),
        )
        .subcommand(
            Command::new("status")
                .arg(grant())
                .arg(session_id())
                .arg(generation())
                .arg(
                    Arg::new("call-id")
                        .long("call-id")
                        .value_name("ID")
                        .help("Inspect one asynchronous call instead of session health"),
                ),
        )
        .subcommand(
            Command::new("wait")
                .about("Wait for one asynchronous call without blocking broker control traffic")
                .arg(grant())
                .arg(session_id())
                .arg(generation())
                .arg(Arg::new("call-id").long("call-id").required(true))
                .arg(
                    Arg::new("wait-timeout-ms")
                        .long("wait-timeout-ms")
                        .value_name("MILLISECONDS")
                        .value_parser(clap::value_parser!(u64)),
                ),
        )
        .subcommand(
            Command::new("list")
                .arg(grant())
                .arg(Arg::new("purpose").long("purpose"))
                .arg(
                    Arg::new("include-terminal")
                        .long("include-terminal")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("renew")
                .arg(grant())
                .arg(session_id())
                .arg(generation())
                .arg(
                    Arg::new("lease-seconds")
                        .long("lease-seconds")
                        .required(true)
                        .value_parser(clap::value_parser!(u64)),
                ),
        )
        .subcommand(
            Command::new("cancel")
                .arg(grant())
                .arg(session_id())
                .arg(generation())
                .arg(Arg::new("call-id").long("call-id").required(true))
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .value_name("MILLISECONDS")
                        .value_parser(clap::value_parser!(u64)),
                ),
        )
        .subcommand(
            Command::new("close")
                .arg(grant())
                .arg(session_id())
                .arg(generation())
                .arg(
                    Arg::new("reason")
                        .long("reason")
                        .default_value("user_closed"),
                )
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .value_name("MILLISECONDS")
                        .value_parser(clap::value_parser!(u64)),
                ),
        )
}

async fn authorize(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let ttl_minutes = *matches
        .get_one::<u64>("ttl-minutes")
        .expect("defaulted by clap");
    if !(1..=MAX_AGENT_GRANT_TTL_MINUTES).contains(&ttl_minutes) {
        bail!("TTL must be between 1 and {MAX_AGENT_GRANT_TTL_MINUTES} minutes");
    }
    let max_uses = matches.get_one::<u32>("uses").copied();
    if max_uses.is_some_and(|uses| !(1..=MAX_AGENT_GRANT_USES).contains(&uses)) {
        bail!("Uses must be between 1 and {MAX_AGENT_GRANT_USES} when specified");
    }

    let raw_config = AppConfig::load_raw_from_path(&AppConfig::config_path()?)?;
    if !raw_config.requires_master_password() {
        bail!(
            "agent authorization requires user-passphrase protection; set a master password first"
        );
    }

    let password = if matches.get_flag("password-stdin") {
        let mut password = String::new();
        tokio::io::stdin().read_to_string(&mut password).await?;
        if password.is_empty() {
            bail!("master password was not provided on standard input");
        }
        password
    } else {
        match std::env::var(VOIDB_MASTER_PASSWORD_ENV) {
            Ok(password) if !password.is_empty() => password,
            _ => rpassword::prompt_password("VoidB master password: ")?,
        }
    };
    AppConfig::load_with_password(Some(&password))
        .context("master password verification failed")?;

    let profile_ref = matches
        .get_one::<String>("profile")
        .expect("required by clap");
    let plugin_id = matches
        .get_one::<String>("plugin")
        .expect("required by clap");
    let store = LocalProfileStore::default_store()?;
    let profile = resolve_profile(&store.load_profiles()?, profile_ref, plugin_id)?;
    verify_profile_credentials(&store, &profile, &password)
        .context("profile credential verification failed")?;

    let requested_capabilities = matches
        .get_many::<String>("capability")
        .map(|values| values.cloned().collect::<Vec<_>>());
    let requested_preset = matches.get_one::<String>("preset").map(String::as_str);
    let execution_mode = parse_execution_mode(
        matches
            .get_one::<String>("execution-mode")
            .expect("defaulted by clap"),
    );
    let (preset, capabilities) = resolve_authorization_scope(
        plugin_id,
        execution_mode,
        requested_preset,
        requested_capabilities,
    )?;
    validate_grant_capabilities(
        plugin_id,
        &capabilities,
        execution_mode,
        matches.get_flag("allow-destructive"),
    )?;
    let allow_destructive = matches.get_flag("allow-destructive");
    let existing = grants_for_profile(&load_grants(false)?, &profile.id, plugin_id);
    if !existing.is_empty() && !matches.get_flag("replace") {
        bail!(
            "profile already has an agent grant; inspect it or pass --replace to close its sessions and replace it"
        );
    }
    let now = Utc::now();
    let id = format!("agent-grant:{}", Uuid::new_v4());
    let file_stem = id.trim_start_matches("agent-grant:");
    let directory = grant_directory()?;
    let grant_path = directory.join(format!("{file_stem}.json"));
    let socket_path = PathBuf::from("/tmp").join(format!(
        "voidb-agent-{}.sock",
        file_stem.chars().take(16).collect::<String>()
    ));
    let grant = AgentGrantFile {
        version: GRANT_VERSION,
        id: id.clone(),
        token: Uuid::new_v4().to_string(),
        profile_id: profile.id,
        profile_name: profile.name,
        plugin_id: plugin_id.clone(),
        capabilities,
        execution_mode,
        preset: Some(preset),
        allow_destructive,
        issued_at: now,
        expires_at: now + chrono::Duration::minutes(ttl_minutes as i64),
        remaining_uses: max_uses,
        socket_path,
        authorization_scopes: Vec::new(),
        principal_fingerprint: None,
        grant_revision: None,
    };
    write_grant(&grant_path, &grant)?;

    let mut command = tokio::process::Command::new(std::env::current_exe()?);
    command
        .arg("__agent-broker")
        .arg(&grant_path)
        .env_remove(VOIDB_MASTER_PASSWORD_ENV)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            remove_grant_artifacts(&grant)?;
            return Err(error).context("start agent broker");
        }
    };
    let stdin = child.stdin.take().context("open broker password pipe")?;
    write_password_and_close(stdin, password.as_bytes()).await?;
    drop(password);
    if let Err(error) = wait_for_socket(&grant.socket_path).await {
        let _ = child.kill().await;
        let detail = child
            .wait_with_output()
            .await
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stderr).trim().to_string())
            .filter(|detail| !detail.is_empty());
        remove_grant_artifacts(&grant)?;
        return Err(match detail {
            Some(detail) => anyhow!("{error}: {detail}"),
            None => error,
        });
    }
    drop(child);
    let mut replaced = Vec::new();
    for displaced in existing {
        shutdown_grant(&displaced, "replaced").await?;
        replaced.push(displaced.id);
    }
    append_agent_audit(
        &grant,
        AuditOperation::CredentialGrantIssued,
        json!({
            "expires_at": grant.expires_at,
            "max_uses": max_uses,
            "capabilities": grant.capabilities,
            "execution_mode": grant.execution_mode,
            "allow_destructive": grant.allow_destructive,
            "replaced": replaced,
        }),
    );
    let inspection = inspect_grant(&grant).await;
    let public_grant = grant.public(inspection.broker_health, inspection.active_session_count);
    let status = public_grant.status_at(Utc::now());
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": {
                "grant": public_grant,
                "status": status,
                "replaced": replaced,
                "defaults": {
                    "ttl_minutes": DEFAULT_AGENT_GRANT_TTL_MINUTES,
                    "max_uses": DEFAULT_AGENT_GRANT_USES,
                    "destructive_denied": !grant.allow_destructive,
                    "execution_mode": grant.execution_mode,
                },
                "usage_args": [
                    "voidb-cli", "agent", "exec", "<plugin.capability>",
                    "--profile", grant.profile_name, "--input-json", "{}"
                ],
                "advanced_usage": format!("voidb-cli agent run --grant {} -- invoke run <plugin.capability> --profile id:{} --input-json '{{}}' --format json", grant.id, grant.profile_id),
            }
        }))?
    );
    Ok(0)
}

async fn authorize_batch(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let ttl_minutes = *matches
        .get_one::<u64>("ttl-minutes")
        .expect("defaulted by clap");
    if !(1..=MAX_AGENT_GRANT_TTL_MINUTES).contains(&ttl_minutes) {
        bail!("TTL must be between 1 and {MAX_AGENT_GRANT_TTL_MINUTES} minutes");
    }
    let max_uses = matches.get_one::<u32>("uses").copied();
    if max_uses.is_some_and(|uses| !(1..=MAX_AGENT_GRANT_USES).contains(&uses)) {
        bail!("Uses must be between 1 and {MAX_AGENT_GRANT_USES} when specified");
    }

    let raw_config = AppConfig::load_raw_from_path(&AppConfig::config_path()?)?;
    if !raw_config.requires_master_password() {
        bail!(
            "agent authorization requires user-passphrase protection; set a master password first"
        );
    }

    let spec_path = PathBuf::from(matches.get_one::<String>("spec").expect("required by clap"));
    let spec = load_batch_authorization_spec(&spec_path)?;
    if spec.grants.is_empty() {
        bail!("batch authorization spec must contain at least one grant");
    }
    if spec.grants.len() > MAX_BATCH_AUTHORIZATION_GRANTS {
        bail!("batch authorization spec exceeds the {MAX_BATCH_AUTHORIZATION_GRANTS}-grant limit");
    }

    let profile_store = LocalProfileStore::default_store()?;
    let profiles = profile_store.load_profiles()?;
    let current_grants = load_grants(false)?;
    let mut scopes = BTreeSet::new();
    let mut prepared = Vec::with_capacity(spec.grants.len());
    for entry in spec.grants {
        validate_review_purpose(&entry.purpose)?;
        let execution_mode = parse_batch_execution_mode(entry.execution_mode.as_deref())?;
        let requested_capabilities = (!entry.capabilities.is_empty()).then_some(entry.capabilities);
        let (preset, capabilities) = resolve_authorization_scope(
            &entry.plugin,
            execution_mode,
            entry.preset.as_deref(),
            requested_capabilities,
        )?;
        let requires_destructive = grant_scope_requires_destructive(&capabilities)?;
        validate_grant_capabilities(
            &entry.plugin,
            &capabilities,
            execution_mode,
            matches.get_flag("allow-destructive"),
        )?;
        let profile = resolve_profile(&profiles, &entry.profile, &entry.plugin)?;
        if !scopes.insert((profile.id.clone(), entry.plugin.clone())) {
            bail!(
                "batch authorization contains duplicate scope for profile '{}' and plugin '{}'",
                profile.name,
                entry.plugin
            );
        }
        let existing = grants_for_profile(&current_grants, &profile.id, &entry.plugin);
        if !existing.is_empty() && !matches.get_flag("replace") {
            bail!(
                "profile '{}' already has an agent grant; pass --replace to review its replacement",
                profile.name
            );
        }
        prepared.push(PreparedBatchGrant {
            profile,
            plugin_id: entry.plugin,
            purpose: entry.purpose,
            execution_mode,
            preset,
            capabilities,
            allow_destructive: requires_destructive,
            existing,
        });
    }

    render_batch_authorization_review(&prepared, ttl_minutes, max_uses)?;
    if !matches.get_flag("yes") {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            bail!(
                "batch authorization review requires an interactive TTY; rerun locally or pass --yes after reviewing the spec"
            );
        }
        let confirmation = prompt_tty_line("Type AUTHORIZE to create these grants: ")?;
        if confirmation != "AUTHORIZE" {
            bail!("batch authorization was not confirmed");
        }
    }

    let mut password = rpassword::prompt_password("VoidB master password: ")?;
    if password.is_empty() {
        bail!("master password is required");
    }
    if AppConfig::load_with_password(Some(&password)).is_err() {
        password.clear();
        bail!("master password verification failed");
    }
    for plan in &prepared {
        if let Err(error) = verify_profile_credentials(&profile_store, &plan.profile, &password) {
            password.clear();
            return Err(error).with_context(|| {
                format!(
                    "profile credential verification failed for '{}' ({})",
                    plan.profile.name, plan.plugin_id
                )
            });
        }
    }

    let now = Utc::now();
    let mut started = Vec::<AgentGrantFile>::with_capacity(prepared.len());
    let mut replacements = BTreeMap::<String, Vec<String>>::new();
    for plan in &prepared {
        let (grant_path, grant) = build_proactive_grant(plan, now, ttl_minutes, max_uses)?;
        if let Err(error) = write_grant(&grant_path, &grant) {
            rollback_batch_grants(&started).await;
            password.clear();
            return Err(error).context("write batch agent grant");
        }
        if let Err(error) = spawn_agent_broker(&grant_path, &grant, &password).await {
            rollback_batch_grants(&started).await;
            password.clear();
            return Err(error).with_context(|| {
                format!(
                    "start batch agent broker for '{}' ({})",
                    plan.profile.name, plan.plugin_id
                )
            });
        }
        replacements.insert(
            grant.id.clone(),
            plan.existing
                .iter()
                .map(|existing| existing.id.clone())
                .collect(),
        );
        started.push(grant);
    }
    password.clear();

    for plan in &prepared {
        for existing in &plan.existing {
            if let Err(error) = shutdown_grant(existing, "batch_replaced").await {
                rollback_batch_grants(&started).await;
                return Err(error).with_context(|| {
                    format!(
                        "replace existing grant '{}' for '{}' ({})",
                        existing.id, plan.profile.name, plan.plugin_id
                    )
                });
            }
        }
    }

    let mut results = Vec::with_capacity(started.len());
    for grant in &started {
        let replaced = replacements.get(&grant.id).cloned().unwrap_or_default();
        append_agent_audit(
            grant,
            AuditOperation::CredentialGrantIssued,
            json!({
                "lifecycle": "batch",
                "expires_at": grant.expires_at,
                "max_uses": grant.remaining_uses,
                "capabilities": grant.capabilities,
                "execution_mode": grant.execution_mode,
                "allow_destructive": grant.allow_destructive,
                "replaced": replaced,
            }),
        );
        let inspection = inspect_grant(grant).await;
        let public = grant.public(inspection.broker_health, inspection.active_session_count);
        let status = public.status_at(Utc::now());
        results.push(json!({
            "grant": public,
            "status": status,
            "replaced": replaced,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": {
                "grants": results,
                "count": results.len(),
                "defaults": {
                    "ttl_minutes": DEFAULT_AGENT_GRANT_TTL_MINUTES,
                    "max_uses": DEFAULT_AGENT_GRANT_USES,
                }
            }
        }))?
    );
    Ok(0)
}

fn load_batch_authorization_spec(path: &Path) -> anyhow::Result<BatchAuthorizationSpec> {
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect batch authorization spec '{}'", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        bail!("batch authorization spec must be a regular, non-symlink file");
    }
    if path_metadata.len() > MAX_BATCH_AUTHORIZATION_SPEC_BYTES {
        bail!(
            "batch authorization spec exceeds the {}-byte limit",
            MAX_BATCH_AUTHORIZATION_SPEC_BYTES
        );
    }

    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("open batch authorization spec '{}'", path.display()))?;
    let opened_metadata = file.metadata().with_context(|| {
        format!(
            "inspect opened batch authorization spec '{}'",
            path.display()
        )
    })?;
    #[cfg(unix)]
    if path_metadata.dev() != opened_metadata.dev()
        || path_metadata.ino() != opened_metadata.ino()
        || !opened_metadata.is_file()
    {
        bail!("batch authorization spec changed while it was being opened");
    }
    if opened_metadata.len() > MAX_BATCH_AUTHORIZATION_SPEC_BYTES {
        bail!(
            "batch authorization spec exceeds the {}-byte limit",
            MAX_BATCH_AUTHORIZATION_SPEC_BYTES
        );
    }

    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    file.take(MAX_BATCH_AUTHORIZATION_SPEC_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BATCH_AUTHORIZATION_SPEC_BYTES {
        bail!(
            "batch authorization spec exceeds the {}-byte limit",
            MAX_BATCH_AUTHORIZATION_SPEC_BYTES
        );
    }
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse batch authorization spec '{}'", path.display()))
}

fn parse_batch_execution_mode(value: Option<&str>) -> anyhow::Result<CapabilityExecutionMode> {
    match value.unwrap_or("stateless") {
        "stateless" => Ok(CapabilityExecutionMode::Stateless),
        "session_only" => Ok(CapabilityExecutionMode::SessionOnly),
        "both" => Ok(CapabilityExecutionMode::Both),
        value => bail!("unsupported batch grant execution mode '{value}'"),
    }
}

fn grant_scope_requires_destructive(capabilities: &[String]) -> anyhow::Result<bool> {
    capabilities.iter().try_fold(false, |required, capability| {
        let risk = resolved_capability_risk(capability).map_err(|error| anyhow!(error))?;
        Ok(required || risk != voidb_core::CapabilityRiskLevel::ReadOnly)
    })
}

fn render_batch_authorization_review(
    prepared: &[PreparedBatchGrant],
    ttl_minutes: u64,
    max_uses: Option<u32>,
) -> anyhow::Result<()> {
    println!("VoidB batch agent authorization review");
    println!("Duration: {ttl_minutes} minutes");
    println!(
        "Use limit: {}",
        max_uses.map_or_else(|| "unlimited".to_string(), |uses| uses.to_string())
    );
    for (index, plan) in prepared.iter().enumerate() {
        let preset = serde_json::to_value(plan.preset)?
            .as_str()
            .unwrap_or("custom")
            .to_string();
        println!(
            "{}. {} ({}) preset={} mode={} destructive={}{}",
            index + 1,
            sanitize_terminal_text(&plan.profile.name),
            sanitize_terminal_text(&plan.plugin_id),
            preset,
            execution_mode_name(plan.execution_mode),
            plan.allow_destructive,
            if plan.existing.is_empty() {
                ""
            } else {
                " replacing-existing-grant"
            }
        );
        println!(
            "   purpose: {}",
            sanitize_terminal_text(plan.purpose.trim())
        );
        println!("   capabilities: {}", plan.capabilities.join(", "));
    }
    Ok(())
}

fn validate_review_purpose(purpose: &str) -> anyhow::Result<()> {
    if purpose.trim().is_empty() || purpose.len() > 1000 {
        bail!("authorization purpose must contain 1 to 1000 bytes");
    }
    Ok(())
}

fn build_proactive_grant(
    plan: &PreparedBatchGrant,
    issued_at: DateTime<Utc>,
    ttl_minutes: u64,
    max_uses: Option<u32>,
) -> anyhow::Result<(PathBuf, AgentGrantFile)> {
    let id = format!("agent-grant:{}", Uuid::new_v4());
    let file_stem = id.trim_start_matches("agent-grant:");
    let grant_path = grant_directory()?.join(format!("{file_stem}.json"));
    let socket_path = PathBuf::from("/tmp").join(format!(
        "voidb-agent-{}.sock",
        file_stem.chars().take(16).collect::<String>()
    ));
    Ok((
        grant_path,
        AgentGrantFile {
            version: GRANT_VERSION,
            id,
            token: Uuid::new_v4().to_string(),
            profile_id: plan.profile.id.clone(),
            profile_name: plan.profile.name.clone(),
            plugin_id: plan.plugin_id.clone(),
            capabilities: plan.capabilities.clone(),
            execution_mode: plan.execution_mode,
            preset: Some(plan.preset),
            allow_destructive: plan.allow_destructive,
            issued_at,
            expires_at: issued_at + chrono::Duration::minutes(ttl_minutes as i64),
            remaining_uses: max_uses,
            socket_path,
            authorization_scopes: Vec::new(),
            principal_fingerprint: None,
            grant_revision: None,
        },
    ))
}

async fn rollback_batch_grants(grants: &[AgentGrantFile]) {
    for grant in grants.iter().rev() {
        let _ = shutdown_grant(grant, "batch_rollback").await;
    }
}

fn resolve_authorization_scope(
    plugin_id: &str,
    execution_mode: CapabilityExecutionMode,
    requested_preset: Option<&str>,
    requested_capabilities: Option<Vec<String>>,
) -> anyhow::Result<(AgentAuthorizationPresetKind, Vec<String>)> {
    let preset = match requested_preset {
        Some("read_only") => AgentAuthorizationPresetKind::ReadOnly,
        Some("interactive_execute") => AgentAuthorizationPresetKind::InteractiveExecute,
        Some("full_access") => AgentAuthorizationPresetKind::FullAccess,
        Some("custom") => AgentAuthorizationPresetKind::Custom,
        Some(value) => bail!("unsupported authorization preset '{value}'"),
        None if requested_capabilities.is_some() => AgentAuthorizationPresetKind::Custom,
        None => AgentAuthorizationPresetKind::ReadOnly,
    };
    let mut capabilities = match requested_capabilities {
        Some(capabilities) => capabilities,
        None => match preset {
            AgentAuthorizationPresetKind::ReadOnly => read_only_scope(plugin_id, execution_mode)?,
            AgentAuthorizationPresetKind::InteractiveExecute => {
                interactive_execute_scope(plugin_id, execution_mode)?
            }
            AgentAuthorizationPresetKind::FullAccess => {
                full_access_scope(plugin_id, execution_mode)?
            }
            AgentAuthorizationPresetKind::Custom => {
                bail!("the Custom preset requires at least one explicit --capability")
            }
        },
    };
    capabilities.sort();
    capabilities.dedup();
    match preset {
        AgentAuthorizationPresetKind::ReadOnly => {
            for capability in &capabilities {
                if resolved_capability_risk(capability).map_err(|error| anyhow!(error))?
                    != voidb_core::CapabilityRiskLevel::ReadOnly
                {
                    bail!("the Read-only preset cannot include '{capability}'");
                }
            }
            let expected = read_only_scope(plugin_id, execution_mode)?;
            if capabilities != expected {
                bail!(
                    "the Read-only preset must use its exact central {} capability scope",
                    execution_mode_name(execution_mode)
                );
            }
        }
        AgentAuthorizationPresetKind::InteractiveExecute => {
            let expected = interactive_execute_scope(plugin_id, execution_mode)?;
            if capabilities != expected {
                bail!(
                    "the Interactive/Execute preset must use its exact central {} capability scope",
                    execution_mode_name(execution_mode)
                );
            }
        }
        AgentAuthorizationPresetKind::FullAccess => {
            let expected = full_access_scope(plugin_id, execution_mode)?;
            if capabilities != expected {
                bail!(
                    "the Full access preset must use its exact central {} capability scope",
                    execution_mode_name(execution_mode)
                );
            }
        }
        AgentAuthorizationPresetKind::Custom => {}
    }
    if capabilities.is_empty() {
        bail!("authorization capability scope is empty");
    }
    Ok((preset, capabilities))
}

fn read_only_scope(
    plugin_id: &str,
    execution_mode: CapabilityExecutionMode,
) -> anyhow::Result<Vec<String>> {
    let mut capabilities = resolved_authorization_capabilities(Some(plugin_id))
        .map_err(|error| anyhow!(error))?
        .into_iter()
        .filter(|definition| {
            definition.authorization.declared
                && definition.effective_risk() == voidb_core::CapabilityRiskLevel::ReadOnly
                && capability_supports_grant_mode(definition, execution_mode)
        })
        .map(|definition| definition.qualified_id())
        .collect::<Vec<_>>();
    capabilities.sort();
    capabilities.dedup();
    if capabilities.is_empty() {
        bail!(
            "plugin '{plugin_id}' has no agent-ready read-only capabilities for {} execution",
            execution_mode_name(execution_mode)
        );
    }
    Ok(capabilities)
}

fn interactive_execute_scope(
    plugin_id: &str,
    execution_mode: CapabilityExecutionMode,
) -> anyhow::Result<Vec<String>> {
    let mut capabilities = resolved_authorization_capabilities(Some(plugin_id))
        .map_err(|error| anyhow!(error))?
        .into_iter()
        .filter(|definition| {
            definition.authorization.declared
                && definition.authorization.interactive_execute
                && capability_supports_grant_mode(definition, execution_mode)
        })
        .map(|definition| definition.qualified_id())
        .collect::<Vec<_>>();
    capabilities.sort();
    capabilities.dedup();
    if capabilities.is_empty() {
        bail!(
            "plugin '{plugin_id}' has no Interactive/Execute preset for {} execution",
            execution_mode_name(execution_mode)
        );
    }
    Ok(capabilities)
}

fn full_access_scope(
    plugin_id: &str,
    execution_mode: CapabilityExecutionMode,
) -> anyhow::Result<Vec<String>> {
    let definitions =
        resolved_authorization_capabilities(Some(plugin_id)).map_err(|error| anyhow!(error))?;
    if definitions
        .iter()
        .any(|definition| !definition.authorization.declared)
    {
        bail!(
            "plugin '{plugin_id}' has incomplete authorization metadata; use an explicit Custom scope"
        );
    }
    let mut capabilities = definitions
        .into_iter()
        .filter(|definition| capability_supports_grant_mode(definition, execution_mode))
        .map(|definition| definition.qualified_id())
        .collect::<Vec<_>>();
    capabilities.sort();
    capabilities.dedup();
    if capabilities.is_empty() {
        bail!(
            "plugin '{plugin_id}' has no capabilities for the {} Full access preset",
            execution_mode_name(execution_mode)
        );
    }
    Ok(capabilities)
}

fn parse_execution_mode(value: &str) -> CapabilityExecutionMode {
    match value {
        "stateless" => CapabilityExecutionMode::Stateless,
        "session_only" => CapabilityExecutionMode::SessionOnly,
        "both" => CapabilityExecutionMode::Both,
        _ => unreachable!("clap validates execution modes"),
    }
}

fn execution_mode_name(mode: CapabilityExecutionMode) -> &'static str {
    match mode {
        CapabilityExecutionMode::Stateless => "stateless",
        CapabilityExecutionMode::SessionOnly => "session_only",
        CapabilityExecutionMode::Both => "both",
    }
}

fn capability_supports_grant_mode(
    definition: &CapabilityDefinition,
    execution_mode: CapabilityExecutionMode,
) -> bool {
    match execution_mode {
        CapabilityExecutionMode::Stateless => definition.supports_stateless_execution(),
        CapabilityExecutionMode::SessionOnly => definition.supports_session_execution(),
        CapabilityExecutionMode::Both => {
            definition.supports_stateless_execution() || definition.supports_session_execution()
        }
    }
}

fn capability_matches_execution_modes(
    definition: &CapabilityDefinition,
    filters: &[CapabilityExecutionMode],
) -> bool {
    filters.is_empty()
        || filters
            .iter()
            .any(|filter| capability_supports_grant_mode(definition, *filter))
}

fn resolve_profile(
    profiles: &[ConnectionProfile],
    profile_ref: &str,
    plugin_id: &str,
) -> anyhow::Result<ConnectionProfile> {
    if plugin_id == "sync" {
        let profile = sync_system_profile();
        let requested_id = profile_ref.strip_prefix("id:");
        let requested_name = profile_ref.strip_prefix("name:").unwrap_or(profile_ref);
        if requested_id.is_some_and(|id| id == profile.id)
            || requested_id.is_none()
                && (profile_ref == profile.id || profile_names_equal(&profile.name, requested_name))
        {
            return Ok(profile);
        }
        bail!(
            "connection-independent Sync capabilities use '--profile local' or '--profile id:system:sync'"
        );
    }
    let requested_id = profile_ref.strip_prefix("id:");
    let requested_name = profile_ref.strip_prefix("name:").unwrap_or(profile_ref);
    let matches = profiles
        .iter()
        .filter(|profile| profile.plugin_id == plugin_id)
        .filter(|profile| {
            requested_id.is_some_and(|id| profile.id == id)
                || requested_id.is_none()
                    && (profile.id == profile_ref
                        || profile_names_equal(&profile.name, requested_name))
        })
        .cloned()
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [profile] => Ok(profile.clone()),
        [] => bail!("profile '{profile_ref}' was not found for plugin '{plugin_id}'"),
        _ => bail!("profile '{profile_ref}' is ambiguous; use id:<profile-id>"),
    }
}

fn sync_system_profile() -> ConnectionProfile {
    ConnectionProfile {
        id: "system:sync".into(),
        name: "local".into(),
        plugin_id: "sync".into(),
        display_name: Some("Local Sync control surface".into()),
        metadata: json!({
            "scope": "local_system",
            "connection_required": false
        }),
        default_options: Value::Null,
        credential_refs: Vec::new(),
        policy: Default::default(),
    }
}

fn verify_profile_credentials(
    store: &LocalProfileStore,
    profile: &ConnectionProfile,
    password: &str,
) -> anyhow::Result<()> {
    if profile.metadata.get("scope").and_then(Value::as_str) == Some("local_system") {
        return Ok(());
    }
    store
        .native_connection(profile, Some(password))
        .map(|_| ())
        .map_err(anyhow::Error::from)
}

fn validate_grant_capabilities(
    plugin_id: &str,
    capabilities: &[String],
    execution_mode: CapabilityExecutionMode,
    allow_destructive: bool,
) -> anyhow::Result<()> {
    if capabilities.is_empty() {
        bail!("agent grant capability scope cannot be empty");
    }
    let definitions = resolved_authorization_capabilities(Some(plugin_id))
        .map_err(|error| anyhow!("capability catalog could not be verified: {error}"))?;
    for capability in capabilities {
        if capability == "*" {
            bail!("wildcard agent grant scopes are not allowed; select exact capabilities");
        }
        let Some((plugin, _)) = capability.split_once('.') else {
            bail!("agent grant capabilities must be qualified as <plugin>.<capability>");
        };
        if plugin != plugin_id {
            bail!("capability '{capability}' is outside plugin '{plugin_id}'");
        }
        let definition = definitions
            .iter()
            .find(|definition| definition.qualified_id() == *capability)
            .ok_or_else(|| anyhow!("capability '{capability}' is not in the current catalog"))?;
        if !capability_supports_grant_mode(definition, execution_mode) {
            bail!(
                "capability '{capability}' does not support {} grant execution",
                execution_mode_name(execution_mode)
            );
        }
        let risk = definition.effective_risk();
        if risk != voidb_core::CapabilityRiskLevel::ReadOnly && !allow_destructive {
            bail!(
                "capability '{capability}' has risk '{risk:?}'; pass --allow-destructive and complete the required CLI confirmation"
            );
        }
    }
    Ok(())
}

fn grants_for_profile(
    grants: &[AgentGrantFile],
    profile_id: &str,
    plugin_id: &str,
) -> Vec<AgentGrantFile> {
    grants
        .iter()
        .filter(|grant| grant.profile_id == profile_id && grant.plugin_id == plugin_id)
        .cloned()
        .collect()
}

fn grant_matches_profile(grant: &AgentGrantFile, profile: &str) -> bool {
    profile
        .strip_prefix("id:")
        .is_some_and(|id| grant.profile_id == id)
        || profile
            .strip_prefix("name:")
            .is_some_and(|name| profile_names_equal(&grant.profile_name, name))
        || !profile.contains(':') && profile_names_equal(&grant.profile_name, profile)
}

async fn inspect_grant(grant: &AgentGrantFile) -> GrantInspection {
    if !grant.socket_path.exists() {
        return GrantInspection {
            broker_health: AgentBrokerHealth::Offline,
            active_session_count: 0,
        };
    }
    let response = tokio::time::timeout(
        BROKER_PROBE_TIMEOUT,
        send_request(
            grant,
            BrokerRequest::Inspect {
                token: grant.token.clone(),
            },
        ),
    )
    .await;
    let Ok(Ok(response)) = response else {
        return GrantInspection {
            broker_health: AgentBrokerHealth::StaleSocket,
            active_session_count: 0,
        };
    };
    if !response.ok {
        return GrantInspection {
            broker_health: AgentBrokerHealth::StaleSocket,
            active_session_count: 0,
        };
    }
    GrantInspection {
        broker_health: AgentBrokerHealth::Online,
        active_session_count: response
            .data
            .as_ref()
            .and_then(|data| data.get("active_session_count"))
            .and_then(Value::as_u64)
            .and_then(|count| usize::try_from(count).ok())
            .unwrap_or(0),
    }
}

fn frontend_grant_value(grant: &FrontendAgentGrant, now: DateTime<Utc>) -> anyhow::Result<Value> {
    let status = grant.status_at(now);
    let mut value = serde_json::to_value(grant)?;
    if let Some(object) = value.as_object_mut() {
        object.insert("status".into(), serde_json::to_value(status)?);
        object.insert(
            "active".into(),
            Value::Bool(matches!(
                status,
                voidb_core::AgentGrantStatus::Active | voidb_core::AgentGrantStatus::Expiring
            )),
        );
    }
    Ok(value)
}

async fn list_grants(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let profile_filter = matches.get_one::<String>("profile");
    let plugin_filter = matches.get_one::<String>("plugin");
    let grants = load_grants(false)?
        .into_iter()
        .filter(|grant| {
            plugin_filter.is_none_or(|plugin| grant.plugin_id == *plugin)
                && profile_filter.is_none_or(|profile| grant_matches_profile(grant, profile))
        })
        .collect::<Vec<_>>();
    let mut public_grants = Vec::with_capacity(grants.len());
    let mut grouped = BTreeMap::<(String, String), Vec<FrontendAgentGrant>>::new();
    for grant in &grants {
        let inspection = inspect_grant(grant).await;
        let public = grant.public(inspection.broker_health, inspection.active_session_count);
        public_grants.push(frontend_grant_value(&public, Utc::now())?);
        grouped
            .entry((grant.profile_id.clone(), grant.plugin_id.clone()))
            .or_default()
            .push(grant.public(inspection.broker_health, inspection.active_session_count));
    }
    let mut profiles = Vec::with_capacity(grouped.len());
    for ((_profile_id, _plugin_id), mut grants) in grouped {
        grants.sort_by_key(|grant| grant.issued_at);
        let grant = grants.pop().expect("group contains one grant");
        profiles.push(AgentAuthorizationProfileSummary {
            profile_id: grant.profile_id.clone(),
            profile_name: grant.profile_name.clone(),
            plugin_id: grant.plugin_id.clone(),
            support: AgentAuthorizationSupportSummary {
                status: AgentAuthorizationSupportStatus::Supported,
                reason: "A central agent capability grant exists for this profile.".into(),
            },
            broker_health: grant.broker_health,
            active_session_count: grant.active_session_count,
            grant_status: Some(grant.status_at(Utc::now())),
            grant: Some(grant),
            refreshed_at: Utc::now(),
        });
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": {
                "profiles": profiles,
                "grants": public_grants,
                "count": public_grants.len(),
            }
        }))?
    );
    Ok(0)
}

async fn renew_grant(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let ttl_minutes = *matches
        .get_one::<u64>("ttl-minutes")
        .expect("defaulted by clap");
    if !(1..=MAX_AGENT_GRANT_TTL_MINUTES).contains(&ttl_minutes) {
        bail!("TTL must be between 1 and {MAX_AGENT_GRANT_TTL_MINUTES} minutes");
    }
    let remaining_uses = matches.get_one::<u32>("uses").copied();
    if remaining_uses.is_some_and(|uses| !(1..=MAX_AGENT_GRANT_USES).contains(&uses)) {
        bail!("Uses must be between 1 and {MAX_AGENT_GRANT_USES} when specified");
    }
    let requested = matches
        .get_one::<String>("grant")
        .expect("required by clap");
    let grant = load_grants(false)?
        .into_iter()
        .find(|grant| grant.id == *requested)
        .ok_or_else(|| anyhow!("agent grant was not found"))?;
    let inspection = inspect_grant(&grant).await;
    if inspection.broker_health != AgentBrokerHealth::Online {
        bail!("agent broker is not online; revoke or replace the stale grant instead");
    }
    let expires_at = Utc::now() + chrono::Duration::minutes(ttl_minutes as i64);
    let response = send_request(
        &grant,
        BrokerRequest::RenewGrant {
            token: grant.token.clone(),
            expires_at,
            remaining_uses,
        },
    )
    .await?;
    if !response.ok {
        bail!(
            "agent grant renewal failed: {}",
            response
                .error
                .unwrap_or_else(|| "broker rejected renewal".into())
        );
    }
    let refreshed = read_grant(&grant_path_for_id(&grant.id)?)?;
    let inspection = inspect_grant(&refreshed).await;
    let public = refreshed.public(inspection.broker_health, inspection.active_session_count);
    let status = public.status_at(Utc::now());
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": {
                "grant": public,
                "status": status,
                "renewed": true,
            }
        }))?
    );
    Ok(0)
}

async fn revoke(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let all = matches.get_flag("all");
    let requested = matches.get_one::<String>("grant");
    let profile = matches.get_one::<String>("profile");
    let plugin = matches.get_one::<String>("plugin");
    if !all && requested.is_none() && profile.is_none() {
        bail!("pass a grant ID, --profile with --plugin, or --all");
    }
    let grants = load_grants(false)?;
    let selected = select_grants_for_revoke(&grants, all, requested, profile, plugin);
    if selected.is_empty() && !all {
        bail!("agent grant was not found");
    }
    let mut revoked = Vec::new();
    for grant in selected {
        shutdown_grant(&grant, "scoped_revoke").await?;
        if grant.grant_revision.is_some() {
            JitAuthorizationStore::default_store()
                .context("open JIT authorization ledger for revoke")?
                .revoke_grant(&grant.id, Utc::now())
                .context("record JIT logical grant revoke")?;
        }
        revoked.push(grant.id);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": { "revoked": revoked, "count": revoked.len() }
        }))?
    );
    Ok(0)
}

fn select_grants_for_revoke(
    grants: &[AgentGrantFile],
    all: bool,
    requested: Option<&String>,
    profile: Option<&String>,
    plugin: Option<&String>,
) -> Vec<AgentGrantFile> {
    grants
        .iter()
        .filter(|grant| {
            all || requested.is_some_and(|id| grant.id == *id)
                || profile.is_some_and(|profile| {
                    plugin.is_some_and(|plugin| grant.plugin_id == *plugin)
                        && grant_matches_profile(grant, profile)
                })
        })
        .cloned()
        .collect()
}

async fn exec_capability(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let capability = matches
        .get_one::<String>("capability")
        .expect("required by clap");
    let plugin_id = capability
        .split_once('.')
        .map(|(plugin_id, _)| plugin_id)
        .filter(|plugin_id| !plugin_id.is_empty())
        .ok_or_else(|| anyhow!("capability must be qualified as <plugin>.<capability>"))?;
    let profile_ref = matches
        .get_one::<String>("profile")
        .expect("required by clap");
    let definitions =
        resolved_authorization_capabilities(Some(plugin_id)).map_err(|error| anyhow!(error))?;
    if let Some(definition) = definitions
        .iter()
        .find(|definition| definition.qualified_id() == *capability)
        && !definition.supports_stateless_execution()
    {
        let discovery = voidb_core::discover_process_plugins();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": false,
                "data": session_handoff_guidance(definition, profile_ref, &discovery),
                "error": {
                    "code": "execution_mode_mismatch",
                    "message": "Capability is session-only; agent exec creates stateless JIT requests. Follow data.authorize_args and data.session_open_args instead."
                }
            }))?
        );
        return Ok(JIT_EXIT_INVALID);
    }
    let profile_store = LocalProfileStore::default_store()?;
    let profile = resolve_profile(&profile_store.load_profiles()?, profile_ref, plugin_id)?;
    let input = parse_agent_exec_input(matches)?;
    let argv = agent_exec_argv(matches, capability, &profile.id, &input);
    let principal = agent_exec_principal(matches)?;

    if let Some(grant) = find_agent_exec_grant(&argv, principal.as_ref()).await? {
        return execute_granted_command(grant, argv).await;
    }

    if matches.get_flag("no-request") || principal.is_none() {
        return print_agent_exec_authorization_required(
            &profile.name,
            plugin_id,
            capability,
            principal.is_none(),
        );
    }

    let principal = principal.expect("checked above");
    let request_ttl_seconds = *matches
        .get_one::<u64>("request-ttl-seconds")
        .expect("defaulted by clap");
    if !(1..=voidb_core::MAX_AUTHORIZATION_REQUEST_TTL_SECONDS as u64)
        .contains(&request_ttl_seconds)
    {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "invalid_request_ttl",
            &format!(
                "request TTL must be between 1 and {} seconds",
                voidb_core::MAX_AUTHORIZATION_REQUEST_TTL_SECONDS
            ),
            None,
        );
    }
    let Some(purpose) = matches.get_one::<String>("purpose").cloned() else {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "purpose_required",
            "authorization requests require --purpose with the specific intended use for user review",
            None,
        );
    };
    let (scope, risk) = exact_agent_exec_scope(plugin_id, capability, input)?;
    let now = Utc::now();
    let store = match JitAuthorizationStore::default_store() {
        Ok(store) => store,
        Err(error) => return print_jit_store_error(error),
    };
    let created = match store.create(
        CreateAuthorizationRequest {
            principal: principal.clone(),
            profile_id: profile.id,
            plugin_id: plugin_id.to_string(),
            scope,
            risk,
            purpose,
            expires_at: now + chrono::Duration::seconds(request_ttl_seconds as i64),
        },
        now,
    ) {
        Ok(created) => created,
        Err(error) => return print_jit_store_error(error),
    };

    eprintln!(
        "{}",
        agent_exec_review_prompt(plugin_id, &profile.name, &created.review_command)
    );
    let wait_timeout = Duration::from_millis(
        *matches
            .get_one::<u64>("wait-timeout-ms")
            .expect("defaulted by clap"),
    );
    let waited = match store
        .wait_for_principal(&created.request.id, &principal, wait_timeout)
        .await
    {
        Ok(waited) => waited,
        Err(error) => return print_jit_store_error(error),
    };
    if waited.request.status != voidb_core::AgentAuthorizationRequestStatus::Approved {
        return print_agent_exec_request_status(
            waited.request,
            &created.review_command,
            created.deduplicated,
            waited.timed_out,
        );
    }

    let Some(grant_id) = waited.request.grant_id.as_deref() else {
        return print_jit_error(
            JIT_EXIT_BROKER_OFFLINE,
            "broker_offline",
            "authorization was approved without an active grant binding",
            Some(1_000),
        );
    };
    let Some(grant) = load_grants(true)?
        .into_iter()
        .find(|grant| grant.id == grant_id)
    else {
        return print_jit_error(
            JIT_EXIT_BROKER_OFFLINE,
            "broker_offline",
            "authorization was approved but its broker is unavailable",
            Some(1_000),
        );
    };
    if !grant_matches_agent_exec_principal(&grant, Some(&principal))?
        || command_allowed(&grant, &argv).is_err()
        || inspect_grant(&grant).await.broker_health != AgentBrokerHealth::Online
    {
        return print_jit_error(
            JIT_EXIT_BROKER_OFFLINE,
            "broker_offline",
            "the approved grant could not safely execute this request",
            Some(1_000),
        );
    }
    execute_granted_command(grant, argv).await
}

fn parse_agent_exec_input(matches: &ArgMatches) -> anyhow::Result<Value> {
    let raw = matches
        .get_one::<String>("input-json")
        .expect("defaulted by clap");
    serde_json::from_str(raw).context("parse --input-json JSON")
}

fn agent_exec_argv(
    matches: &ArgMatches,
    capability: &str,
    profile_id: &str,
    input: &Value,
) -> Vec<String> {
    let mut argv = vec![
        "invoke".into(),
        "run".into(),
        capability.into(),
        "--profile".into(),
        format!("id:{profile_id}"),
        "--input-json".into(),
        input.to_string(),
        "--format".into(),
        "json".into(),
    ];
    if let Some(timeout_ms) = matches.get_one::<u64>("timeout-ms") {
        argv.extend(["--timeout-ms".into(), timeout_ms.to_string()]);
    }
    if let Some(page_limit) = matches.get_one::<u32>("page-limit") {
        argv.extend(["--page-limit".into(), page_limit.to_string()]);
    }
    if let Some(page_cursor) = matches.get_one::<String>("page-cursor") {
        argv.extend(["--page-cursor".into(), page_cursor.clone()]);
    }
    if matches.get_flag("dry-run") {
        argv.push("--dry-run".into());
    }
    if matches.get_flag("yes") {
        argv.push("--yes".into());
    }
    argv
}

fn agent_exec_principal(matches: &ArgMatches) -> anyhow::Result<Option<AgentPrincipal>> {
    let explicit_client = matches.get_one::<String>("client-id").cloned();
    let explicit_task = matches.get_one::<String>("task-id").cloned();
    let explicit_instance = matches.get_one::<String>("instance-id").cloned();
    if explicit_client.is_some() || explicit_task.is_some() || explicit_instance.is_some() {
        let principal = AgentPrincipal {
            client_id: explicit_client
                .ok_or_else(|| anyhow!("--client-id and --task-id must be provided together"))?,
            task_id: explicit_task
                .ok_or_else(|| anyhow!("--client-id and --task-id must be provided together"))?,
            instance_id: explicit_instance,
        };
        principal.validate().map_err(|error| anyhow!(error))?;
        return Ok(Some(principal));
    }

    let environment_client = nonempty_env(AGENT_CLIENT_ID_ENV);
    let environment_task = nonempty_env(AGENT_TASK_ID_ENV);
    let environment_instance = nonempty_env(AGENT_INSTANCE_ID_ENV);
    if environment_client.is_some() || environment_task.is_some() || environment_instance.is_some()
    {
        let principal = AgentPrincipal {
            client_id: environment_client.ok_or_else(|| {
                anyhow!("{AGENT_CLIENT_ID_ENV} and {AGENT_TASK_ID_ENV} must be set together")
            })?,
            task_id: environment_task.ok_or_else(|| {
                anyhow!("{AGENT_CLIENT_ID_ENV} and {AGENT_TASK_ID_ENV} must be set together")
            })?,
            instance_id: environment_instance,
        };
        principal.validate().map_err(|error| anyhow!(error))?;
        return Ok(Some(principal));
    }

    if let Some(thread_id) = nonempty_env(AGENT_THREAD_ID_ENV) {
        let principal = AgentPrincipal {
            client_id: "agent".into(),
            task_id: thread_id,
            instance_id: None,
        };
        principal.validate().map_err(|error| anyhow!(error))?;
        return Ok(Some(principal));
    }
    Ok(None)
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn exact_agent_exec_scope(
    plugin_id: &str,
    capability: &str,
    input: Value,
) -> anyhow::Result<(AgentAuthorizationScope, voidb_core::CapabilityRiskLevel)> {
    let definitions =
        resolved_authorization_capabilities(Some(plugin_id)).map_err(|error| anyhow!(error))?;
    let definition = definitions
        .iter()
        .find(|definition| definition.qualified_id() == capability)
        .ok_or_else(|| anyhow!("capability has no current authorization declaration"))?;
    if !matches!(
        definition.authorization.jit_support(),
        voidb_core::CapabilityJitSupport::Supported
    ) {
        bail!("capability does not support JIT authorization");
    }
    if voidb_core::collect_redaction_targets(&input)
        .iter()
        .any(|target| matches!(target.kind, voidb_core::RedactionTargetKind::Credential(_)))
    {
        bail!("authorization requests cannot persist credential-bearing input fields");
    }
    let operation = normalize_agent_operation(capability, input)?;
    let scope = AgentAuthorizationScope::ExactInvocation {
        capability_id: operation.capability_id,
        normalized_input: operation.input,
        invocation_fingerprint: operation.fingerprint,
    };
    validate_declared_jit_scope(definition, &scope)?;
    Ok((scope, definition.effective_risk()))
}

async fn find_agent_exec_grant(
    argv: &[String],
    principal: Option<&AgentPrincipal>,
) -> anyhow::Result<Option<AgentGrantFile>> {
    let mut candidates = Vec::new();
    for grant in load_grants(true)? {
        if command_allowed(&grant, argv).is_err()
            || !grant_matches_agent_exec_principal(&grant, principal)?
            || inspect_grant(&grant).await.broker_health != AgentBrokerHealth::Online
        {
            continue;
        }
        candidates.push(grant);
    }
    candidates.sort_by_key(|grant| {
        (
            grant.principal_fingerprint.is_none(),
            grant.authorization_scopes.is_empty(),
            grant.expires_at,
        )
    });
    Ok(candidates.into_iter().next())
}

fn grant_matches_agent_exec_principal(
    grant: &AgentGrantFile,
    principal: Option<&AgentPrincipal>,
) -> anyhow::Result<bool> {
    match grant.principal_fingerprint.as_deref() {
        None => Ok(true),
        Some(expected) => Ok(principal
            .map(AgentPrincipal::fingerprint)
            .transpose()?
            .as_deref()
            == Some(expected)),
    }
}

fn print_agent_exec_authorization_required(
    profile_name: &str,
    plugin_id: &str,
    capability: &str,
    identity_missing: bool,
) -> anyhow::Result<i32> {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": false,
            "data": {
                "profile": profile_name,
                "plugin": plugin_id,
                "capability": capability,
                "quick_authorize": {
                    "tui": "Select this profile in the Connection Manager, press a, then confirm read-only access.",
                    "cli_args": [
                        "voidb-cli", "agent", "authorize", "--profile", profile_name,
                        "--plugin", plugin_id
                    ]
                }
            },
            "error": {
                "code": if identity_missing { "agent_identity_required" } else { "authorization_required" },
                "message": if identity_missing {
                    "No active grant permits this operation, and no stable agent identity is available for automatic JIT approval."
                } else {
                    "No active grant permits this operation."
                }
            }
        }))?
    );
    Ok(JIT_EXIT_PENDING)
}

fn agent_exec_review_prompt(plugin_id: &str, profile_name: &str, review_command: &str) -> String {
    format!(
        "Authorization required for {}/{}.\nApprove from a local terminal (the password prompt hides input):\n  {}\nOr open the Connection Manager approval inbox (p).",
        sanitize_terminal_text(plugin_id),
        sanitize_terminal_text(profile_name),
        sanitize_terminal_text(review_command),
    )
}

fn print_agent_exec_request_status(
    request: voidb_core::FrontendAuthorizationRequest,
    review_command: &str,
    deduplicated: bool,
    timed_out: bool,
) -> anyhow::Result<i32> {
    use voidb_core::AgentAuthorizationRequestStatus as Status;
    let (exit_code, code, message) = match request.status {
        Status::Pending => (
            JIT_EXIT_PENDING,
            "authorization_required",
            if timed_out {
                "Authorization is still pending. Run data.review_command in a local terminal for an interactive hidden password prompt, or use the Connection Manager approval inbox."
            } else {
                "Authorization is required. Run data.review_command in a local terminal for an interactive hidden password prompt, or use the Connection Manager approval inbox."
            },
        ),
        Status::Denied if request.timed_out => (
            JIT_EXIT_DENIED,
            "timed_out",
            "Authorization request timed out and was automatically denied.",
        ),
        Status::Denied => (JIT_EXIT_DENIED, "denied", "Authorization was denied."),
        Status::Expired => (
            JIT_EXIT_EXPIRED,
            "expired",
            "Authorization request expired.",
        ),
        Status::Cancelled => (
            JIT_EXIT_CANCELLED,
            "cancelled",
            "Authorization request was cancelled.",
        ),
        Status::Superseded => (
            JIT_EXIT_SUPERSEDED,
            "superseded",
            "Authorization request was superseded.",
        ),
        Status::Approved => (
            JIT_EXIT_BROKER_OFFLINE,
            "broker_offline",
            "Authorization was approved but execution could not start.",
        ),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": false,
            "data": {
                "request": request,
                "review_command": review_command,
                "deduplicated": deduplicated,
                "timed_out": timed_out,
            },
            "error": { "code": code, "message": message }
        }))?
    );
    Ok(exit_code)
}

async fn run_granted(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let argv = matches
        .get_many::<String>("command")
        .expect("required by clap")
        .cloned()
        .collect::<Vec<_>>();
    let grants = load_grants(true)?;
    let grant = if let Some(id) = matches.get_one::<String>("grant") {
        grants
            .into_iter()
            .find(|grant| grant.id == *id)
            .ok_or_else(|| anyhow!("active agent grant '{id}' was not found"))?
    } else {
        let matches = grants
            .into_iter()
            .filter(|grant| command_allowed(grant, &argv).is_ok())
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [grant] => grant.clone(),
            [] => bail!("no active agent grant permits this command"),
            _ => bail!("multiple grants permit this command; pass --grant <grant-id>"),
        }
    };
    ensure_grant_principal(&grant, matches)?;
    command_allowed(&grant, &argv)?;
    execute_granted_command(grant, argv).await
}

async fn execute_granted_command(grant: AgentGrantFile, argv: Vec<String>) -> anyhow::Result<i32> {
    let response = send_request(
        &grant,
        BrokerRequest::Run {
            token: grant.token.clone(),
            argv,
        },
    )
    .await?;
    print!("{}", response.stdout);
    std::io::stdout().flush()?;
    eprint!("{}", response.stderr);
    if let Some(error) = response.error {
        eprintln!("Agent broker rejected command: {error}");
    }
    Ok(response.exit_code)
}

async fn run_session_command(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let (operation_name, operation) = matches
        .subcommand()
        .expect("session command requires an operation");
    let grant_id = operation
        .get_one::<String>("grant")
        .expect("required by clap");
    let grant = load_grants(true)?
        .into_iter()
        .find(|grant| grant.id == *grant_id)
        .ok_or_else(|| anyhow!("active agent grant '{grant_id}' was not found"))?;
    ensure_grant_principal(&grant, operation)?;
    let token = grant.token.clone();
    let request = match matches.subcommand_name().expect("subcommand") {
        "open" => BrokerRequest::SessionOpen {
            token,
            request: AgentSessionOpenRequest {
                purpose: parse_session_purpose(
                    operation
                        .get_one::<String>("purpose")
                        .expect("required by clap"),
                )?,
                capabilities: operation
                    .get_many::<String>("capability")
                    .map(|values| values.cloned().collect())
                    .unwrap_or_default(),
                lease_seconds: *operation
                    .get_one::<u64>("lease-seconds")
                    .expect("defaulted by clap"),
                concurrency: if operation.get_flag("multiplexed") {
                    AgentSessionConcurrency::Multiplexed
                } else {
                    AgentSessionConcurrency::Serialized
                },
                destructive_acknowledged: operation.get_flag("yes"),
                input: parse_session_json(operation, "input-json")?,
            },
        },
        "call" => BrokerRequest::SessionCall {
            token,
            request: session_call_request(operation)?,
        },
        "start" => BrokerRequest::SessionCallStart {
            token,
            request: session_call_request(operation)?,
        },
        "status" => {
            if let Some(call_id) = operation.get_one::<String>("call-id") {
                BrokerRequest::SessionCallStatus {
                    token,
                    request: AgentSessionCallStatusRequest {
                        session: session_ref(operation),
                        call_id: validated_session_call_id(call_id.clone())?,
                    },
                }
            } else {
                BrokerRequest::SessionStatus {
                    token,
                    request: AgentSessionStatusRequest {
                        session: session_ref(operation),
                    },
                }
            }
        }
        "wait" => BrokerRequest::SessionCallWait {
            token,
            request: AgentSessionCallWaitRequest {
                session: session_ref(operation),
                call_id: validated_session_call_id(
                    operation
                        .get_one::<String>("call-id")
                        .expect("required by clap")
                        .clone(),
                )?,
                timeout_ms: operation.get_one::<u64>("wait-timeout-ms").copied(),
            },
        },
        "list" => BrokerRequest::SessionList {
            token,
            request: AgentSessionListRequest {
                purpose: operation
                    .get_one::<String>("purpose")
                    .map(|purpose| parse_session_purpose(purpose))
                    .transpose()?,
                include_terminal: operation.get_flag("include-terminal"),
            },
        },
        "renew" => BrokerRequest::SessionRenew {
            token,
            request: AgentSessionRenewRequest {
                session: session_ref(operation),
                lease_seconds: *operation
                    .get_one::<u64>("lease-seconds")
                    .expect("required by clap"),
            },
        },
        "cancel" => BrokerRequest::SessionCancel {
            token,
            request: AgentSessionCancelRequest {
                session: session_ref(operation),
                call_id: validated_session_call_id(
                    operation
                        .get_one::<String>("call-id")
                        .expect("required by clap")
                        .clone(),
                )?,
                timeout_ms: operation.get_one::<u64>("timeout-ms").copied(),
            },
        },
        "close" => BrokerRequest::SessionClose {
            token,
            request: AgentSessionCloseAgentRequest {
                session: session_ref(operation),
                reason: operation
                    .get_one::<String>("reason")
                    .expect("defaulted by clap")
                    .clone(),
                timeout_ms: operation.get_one::<u64>("timeout-ms").copied(),
            },
        },
        _ => unreachable!("clap enforces session operations"),
    };
    let call_id = match &request {
        BrokerRequest::SessionCall { request, .. }
        | BrokerRequest::SessionCallStart { request, .. } => Some(request.call_id.clone()),
        BrokerRequest::SessionCallStatus { request, .. } => Some(request.call_id.clone()),
        BrokerRequest::SessionCallWait { request, .. } => Some(request.call_id.clone()),
        BrokerRequest::SessionCancel { request, .. } => Some(request.call_id.clone()),
        _ => None,
    };
    let response = send_session_request(&grant, request).await?;
    let error = response.error.as_ref().map(|message| {
        json!({
            "code": response.error_code.as_deref().unwrap_or("session.host_error"),
            "message": message,
        })
    });
    let message = session_response_message(operation_name, &response);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "protocol_version": response.protocol_version,
            "operation": operation_name,
            "ok": response.ok,
            "data": response.data,
            "error": error,
            "message": message,
            "call_id": call_id,
            "grant": {
                "id": grant.id,
                "remaining_uses": response.remaining_uses,
                "expires_at": response.expires_at,
            }
        }))?
    );
    Ok(response.exit_code)
}

fn session_response_message(operation: &str, response: &BrokerResponse) -> Option<&'static str> {
    if !response.ok {
        return None;
    }
    match operation {
        "start" => Some("Call accepted; use status or wait with the returned call ID."),
        "wait"
            if response
                .data
                .as_ref()
                .and_then(|data| data.get("wait_timed_out"))
                .and_then(Value::as_bool)
                == Some(true) =>
        {
            Some("Call is still active; repeat wait or issue cancel/close.")
        }
        "wait" => Some("Call reached a terminal state."),
        "cancel" => Some("Cancellation was accepted or had already been requested."),
        "close" => Some("Session close completed; associated calls are terminal."),
        _ => None,
    }
}

async fn send_session_request(
    grant: &AgentGrantFile,
    request: BrokerRequest,
) -> anyhow::Result<BrokerResponse> {
    let requires_async_lifecycle = request_requires_current_broker_protocol(&request);
    if requires_async_lifecycle {
        let negotiated = send_request(
            grant,
            BrokerRequest::Inspect {
                token: grant.token.clone(),
            },
        )
        .await?;
        if !negotiated.ok {
            return Ok(negotiated);
        }
        if negotiated.protocol_version < AGENT_BROKER_PROTOCOL_VERSION {
            return Ok(BrokerResponse {
                protocol_version: negotiated.protocol_version,
                ok: false,
                exit_code: 6,
                stdout: String::new(),
                stderr: String::new(),
                error: Some(
                    "The active broker supports synchronous session calls only; renew the grant to launch a current broker before using start/status/wait."
                        .into(),
                ),
                error_code: Some("session.protocol_unsupported".into()),
                data: Some(json!({
                    "required_protocol_version": AGENT_BROKER_PROTOCOL_VERSION,
                    "selected_protocol_version": negotiated.protocol_version,
                })),
                remaining_uses: negotiated.remaining_uses,
                expires_at: negotiated.expires_at,
            });
        }
    }
    send_request(grant, request).await
}

fn request_requires_current_broker_protocol(request: &BrokerRequest) -> bool {
    matches!(
        request,
        BrokerRequest::SessionCallStart { .. }
            | BrokerRequest::SessionCallStatus { .. }
            | BrokerRequest::SessionCallWait { .. }
    )
}

fn session_call_request(matches: &ArgMatches) -> anyhow::Result<AgentSessionCallRequest> {
    Ok(AgentSessionCallRequest {
        session: session_ref(matches),
        call_id: session_call_id(matches)?,
        capability: matches
            .get_one::<String>("capability")
            .expect("required by clap")
            .clone(),
        input: parse_session_json(matches, "input-json")?,
        destructive_acknowledged: matches.get_flag("yes"),
        timeout_ms: matches.get_one::<u64>("timeout-ms").copied(),
        output_limit_bytes: *matches
            .get_one::<usize>("output-limit-bytes")
            .expect("defaulted by clap"),
    })
}

fn session_ref(matches: &ArgMatches) -> AgentSessionRef {
    AgentSessionRef::new(
        matches
            .get_one::<String>("session-id")
            .expect("required by clap"),
        *matches
            .get_one::<u64>("generation")
            .expect("defaulted by clap"),
    )
}

fn session_call_id(matches: &ArgMatches) -> anyhow::Result<String> {
    validated_session_call_id(
        matches
            .get_one::<String>("call-id")
            .cloned()
            .unwrap_or_else(|| format!("call:{}", Uuid::new_v4())),
    )
}

fn validated_session_call_id(call_id: String) -> anyhow::Result<String> {
    validate_agent_session_call_id(&call_id).map_err(anyhow::Error::from)?;
    Ok(call_id)
}

fn ensure_grant_principal(grant: &AgentGrantFile, matches: &ArgMatches) -> anyhow::Result<()> {
    let Some(expected) = grant.principal_fingerprint.as_deref() else {
        return Ok(());
    };
    let client_id = matches
        .get_one::<String>("client-id")
        .ok_or_else(|| anyhow!("JIT grant execution requires --client-id and --task-id"))?;
    let task_id = matches
        .get_one::<String>("task-id")
        .ok_or_else(|| anyhow!("JIT grant execution requires --client-id and --task-id"))?;
    let principal = AgentPrincipal {
        client_id: client_id.clone(),
        task_id: task_id.clone(),
        instance_id: matches.get_one::<String>("instance-id").cloned(),
    };
    if principal.fingerprint()?.as_str() != expected {
        bail!("agent principal is outside the JIT grant binding");
    }
    Ok(())
}

fn parse_session_json(matches: &ArgMatches, name: &str) -> anyhow::Result<Value> {
    let raw = matches.get_one::<String>(name).expect("defaulted by clap");
    serde_json::from_str(raw).with_context(|| format!("parse --{} JSON", name.replace('_', "-")))
}

fn parse_session_purpose(value: &str) -> anyhow::Result<PluginSessionPurpose> {
    Ok(match value {
        "interactive_terminal" => PluginSessionPurpose::InteractiveTerminal,
        "file_transfer" => PluginSessionPurpose::FileTransfer,
        "port_forward" => PluginSessionPurpose::PortForward,
        "database_query" => PluginSessionPurpose::DatabaseQuery,
        "database_transaction" => PluginSessionPurpose::DatabaseTransaction,
        "cache_command" => PluginSessionPurpose::CacheCommand,
        "log_stream" => PluginSessionPurpose::LogStream,
        "watch_stream" => PluginSessionPurpose::WatchStream,
        "infrastructure_client" => PluginSessionPurpose::InfrastructureClient,
        "sync_client" => PluginSessionPurpose::SyncClient,
        "capability_invocation" => PluginSessionPurpose::CapabilityInvocation,
        custom if custom.starts_with("plugin_defined:") => PluginSessionPurpose::PluginDefined(
            custom.trim_start_matches("plugin_defined:").to_owned(),
        ),
        _ => bail!("unsupported session purpose '{value}'"),
    })
}

fn command_allowed(grant: &AgentGrantFile, argv: &[String]) -> anyhow::Result<()> {
    if grant.expires_at <= Utc::now() || grant_uses_exhausted(grant) {
        bail!("agent grant has expired or has no remaining uses");
    }
    if has_long_option(argv, "--input-file") {
        bail!("agent grants require inline --input-json; local input files are not allowed");
    }
    if has_long_option(argv, "--yes") && !grant.allow_destructive {
        bail!("agent grant does not permit destructive acknowledgements");
    }
    match argv {
        [group, command, profile_ref, rest @ ..] if group == "profile" && command == "test" => {
            ensure_profile_ref(grant, profile_ref)?;
            let plugin = scoped_option_value(rest, "--plugin", None)?;
            if plugin != grant.plugin_id {
                bail!("command plugin is outside the agent grant scope");
            }
            Ok(())
        }
        [group, command, capability, rest @ ..] if group == "invoke" && command == "run" => {
            let capability_plugin = capability
                .split_once('.')
                .map(|(plugin, _)| plugin)
                .ok_or_else(|| anyhow!("invoke capability must be qualified"))?;
            if capability_plugin != grant.plugin_id {
                bail!("capability plugin is outside the agent grant scope");
            }
            if !grant.capabilities.iter().any(|allowed| {
                allowed == "*"
                    || allowed == capability
                    || allowed == capability.split_once('.').unwrap().1
            }) {
                bail!("capability is outside the agent grant scope");
            }
            ensure_grant_execution_mode(grant, capability, CapabilityExecutionMode::Stateless)?;
            let profile_ref = scoped_option_value(rest, "--profile", Some("-p"))?;
            ensure_profile_ref(grant, profile_ref)?;
            if grant.authorization_scopes.is_empty() {
                ensure_capability_wide_authorization_allowed(grant, capability)?;
            } else {
                let input = scoped_option_value(rest, "--input-json", None)?;
                let input: Value = serde_json::from_str(input)
                    .context("JIT authorization requires valid inline JSON input")?;
                ensure_jit_operation_allowed(grant, capability, input)?;
            }
            Ok(())
        }
        _ => bail!("agent grants only permit 'profile test' and 'invoke run' commands"),
    }
}

fn scoped_option_value<'a>(
    args: &'a [String],
    long: &str,
    short: Option<&str>,
) -> anyhow::Result<&'a str> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == long || short.is_some_and(|short| argument == short) {
            let value = args
                .get(index + 1)
                .ok_or_else(|| anyhow!("{long} requires a value"))?;
            values.push(value.as_str());
            index += 2;
            continue;
        }
        if let Some(value) = argument.strip_prefix(&format!("{long}=")) {
            values.push(value);
        } else if let Some(short) = short
            && let Some(value) = argument.strip_prefix(short)
            && !value.is_empty()
        {
            values.push(value.strip_prefix('=').unwrap_or(value));
        }
        index += 1;
    }
    match values.as_slice() {
        [value] if !value.is_empty() => Ok(value),
        [] => bail!("command must include exactly one {long}"),
        _ => bail!("command must not repeat {long}"),
    }
}

fn has_long_option(args: &[String], option: &str) -> bool {
    args.iter()
        .any(|argument| argument == option || argument.starts_with(&format!("{option}=")))
}

fn ensure_profile_ref(grant: &AgentGrantFile, profile_ref: &str) -> anyhow::Result<()> {
    let matches =
        profile_ref == grant.profile_id || profile_ref == format!("id:{}", grant.profile_id);
    if matches {
        Ok(())
    } else {
        bail!("agent commands must use the immutable granted Profile ID")
    }
}

struct BrokerMutableState {
    grant: AgentGrantFile,
    session_host: AgentSessionHost,
}

struct BrokerStartedCall {
    entry: Arc<BrokerCallEntry>,
    grant: AgentGrantFile,
}

struct BrokerRuntime {
    grant_path: PathBuf,
    state: AsyncMutex<BrokerMutableState>,
    calls: BrokerCallRegistry,
    password: AsyncMutex<String>,
    shutdown_tx: watch::Sender<Option<String>>,
}

impl BrokerRuntime {
    fn new(
        grant_path: PathBuf,
        grant: AgentGrantFile,
        session_host: AgentSessionHost,
        password: String,
    ) -> Self {
        let (shutdown_tx, _) = watch::channel(None);
        Self {
            grant_path,
            state: AsyncMutex::new(BrokerMutableState {
                grant,
                session_host,
            }),
            calls: BrokerCallRegistry::default(),
            password: AsyncMutex::new(password),
            shutdown_tx,
        }
    }

    fn subscribe_shutdown(&self) -> watch::Receiver<Option<String>> {
        self.shutdown_tx.subscribe()
    }

    fn request_shutdown(&self, reason: impl Into<String>) {
        let _ = self.shutdown_tx.send(Some(reason.into()));
    }

    async fn grant_snapshot(&self) -> AgentGrantFile {
        self.state.lock().await.grant.clone()
    }

    async fn dispatch(
        self: &Arc<Self>,
        request: BrokerRequest,
    ) -> (BrokerResponse, Option<String>) {
        match request {
            BrokerRequest::SessionCall { token, request } => {
                (self.session_call(token, request).await, None)
            }
            BrokerRequest::SessionCallStart { token, request } => {
                (self.session_call_start(token, request).await, None)
            }
            BrokerRequest::SessionCallStatus { token, request } => {
                (self.session_call_status(token, request).await, None)
            }
            BrokerRequest::SessionCallWait { token, request } => {
                (self.session_call_wait(token, request).await, None)
            }
            BrokerRequest::SessionCancel { token, request } => {
                (self.session_cancel(token, request).await, None)
            }
            BrokerRequest::SessionClose { token, request } => {
                (self.session_close(token, request).await, None)
            }
            request => self.dispatch_serialized(request).await,
        }
    }

    async fn dispatch_serialized(
        &self,
        request: BrokerRequest,
    ) -> (BrokerResponse, Option<String>) {
        let explicit_shutdown = matches!(&request, BrokerRequest::Shutdown { .. });
        let consumes_use = matches!(
            &request,
            BrokerRequest::Run { .. } | BrokerRequest::SessionOpen { .. }
        );
        let mut state = self.state.lock().await;
        if consumes_use && !grant_accepts_new_work(&state.grant) {
            return (
                broker_session_error(
                    &state.grant,
                    "session.expired",
                    "Agent grant has expired or has no remaining uses.",
                ),
                None,
            );
        }
        let BrokerMutableState {
            grant,
            session_host,
        } = &mut *state;
        let (response, terminate) =
            handle_broker_request(grant, session_host, &self.password.lock().await, request).await;
        let _ = write_grant(&self.grant_path, grant);
        let shutdown_reason = (explicit_shutdown && terminate).then(|| "user_revoked".into());
        (response, shutdown_reason)
    }

    async fn session_call_start(
        self: &Arc<Self>,
        token: String,
        request: AgentSessionCallRequest,
    ) -> BrokerResponse {
        match self.start_call(token, request).await {
            Ok(started) => session_result(&started.grant, Ok(started.entry.snapshot())),
            Err(response) => response,
        }
    }

    async fn session_call(
        self: &Arc<Self>,
        token: String,
        request: AgentSessionCallRequest,
    ) -> BrokerResponse {
        let started = match self.start_call(token, request).await {
            Ok(started) => started,
            Err(response) => return response,
        };
        let call = self.calls.wait_until_terminal(&started.entry).await;
        let grant = self.grant_snapshot().await;
        terminal_call_response(&grant, call)
    }

    async fn start_call(
        self: &Arc<Self>,
        token: String,
        request: AgentSessionCallRequest,
    ) -> Result<BrokerStartedCall, BrokerResponse> {
        let started_at = Utc::now();
        let session = request.session.clone();
        let capability = request.capability.clone();
        let call_id = request.call_id.clone();
        let (prepared, entry, grant) = {
            let mut state = self.state.lock().await;
            if token != state.grant.token {
                return Err(invalid_token_response(&state.grant).0);
            }
            if !grant_accepts_new_work(&state.grant) {
                return Err(broker_session_error(
                    &state.grant,
                    "session.expired",
                    "Agent grant has expired or has no remaining uses.",
                ));
            }
            if let Err(error) = request.validate_call_id() {
                let response =
                    broker_session_error(&state.grant, error.code.as_str(), error.to_string());
                append_agent_session_audit(
                    &state.grant,
                    AuditOperation::SessionCall,
                    &response,
                    AgentSessionAuditContext {
                        session: Some(&session),
                        capability: Some(&capability),
                        ..AgentSessionAuditContext::default()
                    },
                    started_at,
                );
                return Err(response);
            }
            if let Err(error) = session_call_allowed(&state.grant, &request) {
                let response =
                    broker_session_error(&state.grant, "session.policy_denied", error.to_string());
                append_agent_session_audit(
                    &state.grant,
                    AuditOperation::SessionCall,
                    &response,
                    AgentSessionAuditContext {
                        session: Some(&session),
                        call_id: Some(&call_id),
                        capability: Some(&capability),
                        ..AgentSessionAuditContext::default()
                    },
                    started_at,
                );
                return Err(response);
            }
            let prepared = match state.session_host.prepare_call(&request, started_at).await {
                Ok(prepared) => prepared,
                Err(error) => {
                    let response =
                        broker_session_error(&state.grant, error.code.as_str(), error.to_string());
                    append_agent_session_audit(
                        &state.grant,
                        AuditOperation::SessionCall,
                        &response,
                        AgentSessionAuditContext {
                            session: Some(&session),
                            call_id: Some(&call_id),
                            capability: Some(&capability),
                            ..AgentSessionAuditContext::default()
                        },
                        started_at,
                    );
                    return Err(response);
                }
            };
            let entry = match self
                .calls
                .register(&request, started_at, prepared.deadline_at())
            {
                Ok(entry) => entry,
                Err(error) => {
                    state
                        .session_host
                        .finish_prepared_call(&request.session, Utc::now());
                    let response =
                        broker_session_error(&state.grant, error.code.as_str(), error.to_string());
                    append_agent_session_audit(
                        &state.grant,
                        AuditOperation::SessionCall,
                        &response,
                        AgentSessionAuditContext {
                            session: Some(&session),
                            call_id: Some(&call_id),
                            capability: Some(&capability),
                            ..AgentSessionAuditContext::default()
                        },
                        started_at,
                    );
                    return Err(response);
                }
            };
            consume_agent_use(
                &mut state.grant,
                "session",
                "call",
                Some(&request.capability),
            );
            if let Err(error) = write_grant(&self.grant_path, &state.grant) {
                state
                    .session_host
                    .finish_prepared_call(&request.session, Utc::now());
                self.calls.finish(
                    &entry,
                    Err(PluginSessionError::new(
                        PluginSessionErrorCode::OwnerUnavailable,
                        format!("Persist agent grant use: {error}"),
                    )),
                    Utc::now(),
                );
                return Err(broker_session_error(
                    &state.grant,
                    "session.owner_unavailable",
                    "Agent broker could not persist the grant use reservation.",
                ));
            }
            (prepared, entry, state.grant.clone())
        };
        self.spawn_call(request, prepared, Arc::clone(&entry), started_at);
        Ok(BrokerStartedCall { entry, grant })
    }

    fn spawn_call(
        self: &Arc<Self>,
        request: AgentSessionCallRequest,
        prepared: PreparedAgentSessionCall,
        entry: Arc<BrokerCallEntry>,
        accepted_at: DateTime<Utc>,
    ) {
        let runtime = Arc::clone(self);
        let task_entry = Arc::clone(&entry);
        let task = tokio::spawn(async move {
            let serialized = tokio::select! {
                biased;
                _ = task_entry.wait_for_control() => None,
                serialized = prepared.acquire_serialized() => Some(serialized),
            };
            let result = if let Some(_serialized) = serialized {
                let may_run = {
                    let state = runtime.state.lock().await;
                    state
                        .session_host
                        .call_is_active(&request.session, prepared.current_time())
                        .is_ok()
                } && runtime
                    .calls
                    .mark_running(&task_entry, prepared.current_time());
                if may_run {
                    prepared.execute(request.clone()).await
                } else {
                    Err(PluginSessionError::new(
                        PluginSessionErrorCode::Cancelled,
                        "Session call was stopped before execution began.",
                    )
                    .with_session_id(request.session.session_id.clone()))
                }
            } else {
                Err(PluginSessionError::new(
                    PluginSessionErrorCode::Cancelled,
                    "Session call was stopped before execution began.",
                )
                .with_session_id(request.session.session_id.clone()))
            };
            {
                let mut state = runtime.state.lock().await;
                state
                    .session_host
                    .finish_prepared_call(&request.session, prepared.current_time());
            }
            let call = runtime.calls.finish(&task_entry, result, Utc::now());
            let grant = runtime.grant_snapshot().await;
            let response = terminal_call_response(&grant, call);
            append_agent_session_audit(
                &grant,
                AuditOperation::SessionCall,
                &response,
                AgentSessionAuditContext {
                    session: Some(&request.session),
                    call_id: Some(&request.call_id),
                    capability: Some(&request.capability),
                    ..AgentSessionAuditContext::default()
                },
                accepted_at,
            );
        });
        entry.set_abort_handle(task.abort_handle());
        drop(task);
    }

    fn abort_calls_and_release_host_reservations(
        &self,
        session_host: &mut AgentSessionHost,
        entries: &[Arc<BrokerCallEntry>],
        completed_at: DateTime<Utc>,
    ) {
        self.calls.abort_entries(entries, completed_at);
        for entry in entries {
            session_host.finish_prepared_call(&entry.snapshot().session, completed_at);
        }
    }

    async fn authorized_grant(&self, token: &str) -> Result<AgentGrantFile, BrokerResponse> {
        let state = self.state.lock().await;
        if token == state.grant.token {
            Ok(state.grant.clone())
        } else {
            Err(invalid_token_response(&state.grant).0)
        }
    }

    async fn session_call_status(
        &self,
        token: String,
        request: AgentSessionCallStatusRequest,
    ) -> BrokerResponse {
        let grant = match self.authorized_grant(&token).await {
            Ok(grant) => grant,
            Err(response) => return response,
        };
        let started_at = Utc::now();
        let response = session_result(&grant, self.calls.snapshot(&request));
        append_agent_session_audit(
            &grant,
            AuditOperation::SessionStatus,
            &response,
            AgentSessionAuditContext {
                session: Some(&request.session),
                call_id: Some(&request.call_id),
                ..AgentSessionAuditContext::default()
            },
            started_at,
        );
        response
    }

    async fn session_call_wait(
        &self,
        token: String,
        request: AgentSessionCallWaitRequest,
    ) -> BrokerResponse {
        let grant = match self.authorized_grant(&token).await {
            Ok(grant) => grant,
            Err(response) => return response,
        };
        let started_at = Utc::now();
        let response = session_result(&grant, self.calls.wait(&request).await);
        append_agent_session_audit(
            &grant,
            AuditOperation::SessionStatus,
            &response,
            AgentSessionAuditContext {
                session: Some(&request.session),
                call_id: Some(&request.call_id),
                ..AgentSessionAuditContext::default()
            },
            started_at,
        );
        response
    }

    async fn session_cancel(
        &self,
        token: String,
        request: AgentSessionCancelRequest,
    ) -> BrokerResponse {
        let started_at = Utc::now();
        let grant = match self.authorized_grant(&token).await {
            Ok(grant) => grant,
            Err(response) => return response,
        };
        let (disposition, call) = match self.calls.request_control(
            &request.session,
            &request.call_id,
            AgentSessionControlKind::Cancel,
            started_at,
        ) {
            Ok(control) => control,
            Err(error) => {
                let response = broker_session_error(&grant, error.code.as_str(), error.to_string());
                append_agent_session_audit(
                    &grant,
                    AuditOperation::SessionCancel,
                    &response,
                    AgentSessionAuditContext {
                        session: Some(&request.session),
                        call_id: Some(&request.call_id),
                        ..AgentSessionAuditContext::default()
                    },
                    started_at,
                );
                return response;
            }
        };
        if matches!(
            disposition,
            AgentSessionControlDisposition::AlreadyRequested
                | AgentSessionControlDisposition::AlreadyTerminal
        ) {
            return broker_data_response(
                &grant,
                json!({ "call": call, "control_disposition": disposition }),
            );
        }
        let mut state = self.state.lock().await;
        let BrokerMutableState {
            grant,
            session_host,
        } = &mut *state;
        let (mut response, _) = handle_broker_request(
            grant,
            session_host,
            &self.password.lock().await,
            BrokerRequest::SessionCancel {
                token,
                request: request.clone(),
            },
        )
        .await;
        let _ = write_grant(&self.grant_path, grant);
        let session_data = response.data.take();
        let mut close_escalated = false;
        if !response.ok {
            close_escalated = true;
            let controlled = self.calls.request_session_control(
                &request.session,
                AgentSessionControlKind::Close,
                Utc::now(),
            );
            let _ = session_host
                .close(
                    AgentSessionCloseAgentRequest {
                        session: request.session.clone(),
                        reason: "cancel_failed".into(),
                        timeout_ms: None,
                    },
                    Utc::now(),
                )
                .await;
            self.abort_calls_and_release_host_reservations(session_host, &controlled, Utc::now());
        }
        response.data = Some(json!({
            "session": session_data,
            "call": self.calls.entry(&request.session, &request.call_id).map(|entry| entry.snapshot()).ok(),
            "control_disposition": disposition,
            "close_escalated": close_escalated,
        }));
        response
    }

    async fn session_close(
        &self,
        token: String,
        request: AgentSessionCloseAgentRequest,
    ) -> BrokerResponse {
        if let Err(response) = self.authorized_grant(&token).await {
            return response;
        }
        let controlled = self.calls.request_session_control(
            &request.session,
            AgentSessionControlKind::Close,
            Utc::now(),
        );
        let mut state = self.state.lock().await;
        let BrokerMutableState {
            grant,
            session_host,
        } = &mut *state;
        let (mut response, _) = handle_broker_request(
            grant,
            session_host,
            &self.password.lock().await,
            BrokerRequest::SessionClose { token, request },
        )
        .await;
        let _ = write_grant(&self.grant_path, grant);
        self.abort_calls_and_release_host_reservations(session_host, &controlled, Utc::now());
        let session_data = response.data.take();
        response.data = Some(json!({
            "session": session_data,
            "calls": BrokerCallRegistry::snapshots(&controlled),
        }));
        response
    }

    async fn shutdown(&self, reason: &str) -> AgentGrantFile {
        let controlled = self
            .calls
            .request_all_control(AgentSessionControlKind::Shutdown, Utc::now());
        let mut state = self.state.lock().await;
        let close_all = state.session_host.close_all(reason.into(), Utc::now());
        let _ = tokio::time::timeout(
            Duration::from_millis(MAX_AGENT_SESSION_CONTROL_TIMEOUT_MS),
            close_all,
        )
        .await;
        self.abort_calls_and_release_host_reservations(
            &mut state.session_host,
            &controlled,
            Utc::now(),
        );
        self.password.lock().await.clear();
        state.grant.clone()
    }
}

fn grant_accepts_new_work(grant: &AgentGrantFile) -> bool {
    grant.expires_at > Utc::now() && !grant_uses_exhausted(grant)
}

fn terminal_call_response(grant: &AgentGrantFile, call: AgentSessionCallView) -> BrokerResponse {
    if let Some(result) = call.result {
        session_result(grant, Ok(result))
    } else if let Some(error) = call.error {
        broker_session_error(grant, error.code.as_str(), error.to_string())
    } else {
        broker_session_error(
            grant,
            "session.owner_unavailable",
            "Session call reached a terminal state without a result.",
        )
    }
}

#[cfg(unix)]
async fn run_broker(grant_path: &Path) -> anyhow::Result<()> {
    let mut password = String::new();
    tokio::io::stdin().read_to_string(&mut password).await?;
    if password.is_empty() {
        bail!("broker did not receive a master password");
    }
    let result = broker_loop(grant_path, &password).await;
    password.clear();
    result
}

#[cfg(unix)]
async fn broker_loop(grant_path: &Path, password: &str) -> anyhow::Result<()> {
    let grant = read_grant(grant_path)?;
    let host_generation = Utc::now().timestamp_micros().unsigned_abs().max(1);
    let mut session_host = AgentSessionHost::new(
        grant.id.clone(),
        grant.profile_id.clone(),
        grant.plugin_id.clone(),
        grant.capabilities.clone(),
        grant.expires_at,
        host_generation,
    );
    register_session_factories(&mut session_host, &grant, password)?;
    broker_loop_with_host(grant_path, grant, session_host, password).await
}

#[cfg(unix)]
async fn broker_loop_with_host(
    grant_path: &Path,
    grant: AgentGrantFile,
    session_host: AgentSessionHost,
    password: &str,
) -> anyhow::Result<()> {
    let _ = fs::remove_file(&grant.socket_path);
    let listener = UnixListener::bind(&grant.socket_path)?;
    fs::set_permissions(&grant.socket_path, fs::Permissions::from_mode(0o600))?;

    let socket_path = grant.socket_path.clone();
    let runtime = Arc::new(BrokerRuntime::new(
        grant_path.to_path_buf(),
        grant,
        session_host,
        password.to_owned(),
    ));
    let mut shutdown_rx = runtime.subscribe_shutdown();
    let mut clients = JoinSet::new();
    let release_reason = loop {
        if let Some(reason) = shutdown_rx.borrow().clone() {
            break reason;
        }
        let current_grant = runtime.grant_snapshot().await;
        let remaining = (current_grant.expires_at - Utc::now())
            .to_std()
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            break "expired".to_owned();
        }
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() {
                    break "broker_shutdown".to_owned();
                }
            }
            accepted = listener.accept() => {
                if let Ok((stream, _)) = accepted {
                    let runtime = Arc::clone(&runtime);
                    clients.spawn(async move {
                        let _ = handle_broker_connection(runtime, stream).await;
                    });
                }
            }
            _ = tokio::time::sleep(remaining) => {}
            _ = clients.join_next(), if !clients.is_empty() => {}
        }
    };
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    let grant = runtime.shutdown(&release_reason).await;
    append_agent_audit(
        &grant,
        AuditOperation::CredentialGrantReleased,
        json!({ "reason": release_reason }),
    );
    let _ = fs::remove_file(&socket_path);
    let _ = fs::remove_file(grant_path);
    Ok(())
}

#[cfg(unix)]
async fn handle_broker_connection(
    runtime: Arc<BrokerRuntime>,
    mut stream: UnixStream,
) -> anyhow::Result<()> {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    let Ok(wire_request) = serde_json::from_slice::<BrokerWireRequest>(&bytes) else {
        return Ok(());
    };
    let selected_protocol_version = wire_request.protocol_version;
    let requires_current_protocol = request_requires_current_broker_protocol(&wire_request.request);
    let (mut response, shutdown_reason) = if is_supported_agent_broker_protocol_version(
        selected_protocol_version,
    ) && (!requires_current_protocol
        || selected_protocol_version >= AGENT_BROKER_PROTOCOL_VERSION)
    {
        runtime.dispatch(wire_request.request).await
    } else if is_supported_agent_broker_protocol_version(selected_protocol_version) {
        let grant = runtime.grant_snapshot().await;
        let mut response = broker_session_error(
            &grant,
            "session.protocol_unsupported",
            "Asynchronous session-call lifecycle operations require agent-broker protocol version 2.",
        );
        response.data = Some(json!({
            "required_protocol_version": AGENT_BROKER_PROTOCOL_VERSION,
            "selected_protocol_version": selected_protocol_version,
        }));
        (response, None)
    } else {
        let grant = runtime.grant_snapshot().await;
        let mut response = broker_session_error(
            &grant,
            "session.protocol_unsupported",
            format!("Agent broker protocol version {selected_protocol_version} is unsupported."),
        );
        response.data = Some(json!({
            "supported_protocol_versions": AGENT_BROKER_SUPPORTED_PROTOCOL_VERSIONS,
        }));
        (response, None)
    };
    response.protocol_version =
        if is_supported_agent_broker_protocol_version(selected_protocol_version) {
            selected_protocol_version
        } else {
            AGENT_BROKER_PROTOCOL_VERSION
        };
    if stream
        .write_all(&serde_json::to_vec(&response)?)
        .await
        .is_ok()
    {
        // A client may close immediately after receiving the response. A
        // BrokenPipe during the best-effort shutdown belongs to this one
        // socket and must not terminate the long-lived broker.
        let _ = stream.shutdown().await;
    }
    if let Some(reason) = shutdown_reason {
        runtime.request_shutdown(reason);
    }
    Ok(())
}

#[cfg(not(unix))]
async fn run_broker(_grant_path: &Path) -> anyhow::Result<()> {
    bail!("agent broker currently requires a Unix-domain socket platform")
}

async fn handle_broker_request(
    grant: &mut AgentGrantFile,
    session_host: &mut AgentSessionHost,
    password: &str,
    request: BrokerRequest,
) -> (BrokerResponse, bool) {
    match request {
        BrokerRequest::Inspect { token } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let sessions = session_host
                .list(AgentSessionListRequest::default(), Utc::now())
                .await;
            (
                broker_data_response(
                    grant,
                    json!({
                        "active_session_count": sessions.len(),
                        "broker": "online",
                    }),
                ),
                false,
            )
        }
        BrokerRequest::RenewGrant {
            token,
            expires_at,
            remaining_uses,
        } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let now = Utc::now();
            let maximum_expiry =
                now + chrono::Duration::minutes(MAX_AGENT_GRANT_TTL_MINUTES as i64);
            if expires_at <= now
                || expires_at > maximum_expiry
                || remaining_uses.is_some_and(|uses| !(1..=MAX_AGENT_GRANT_USES).contains(&uses))
            {
                return (
                    broker_response(
                        grant,
                        Some("grant renewal limits are invalid".into()),
                        6,
                        String::new(),
                        String::new(),
                    ),
                    false,
                );
            }
            grant.expires_at = expires_at;
            grant.remaining_uses = remaining_uses;
            session_host.renew_grant(expires_at);
            append_agent_audit(
                grant,
                AuditOperation::CredentialGrantIssued,
                json!({
                    "lifecycle": "renewed",
                    "expires_at": expires_at,
                    "remaining_uses": remaining_uses,
                    "profile_id": grant.profile_id,
                    "plugin_id": grant.plugin_id,
                }),
            );
            (
                broker_data_response(grant, json!({ "renewed": true })),
                false,
            )
        }
        BrokerRequest::Shutdown { token } => {
            if token != grant.token {
                (
                    broker_response(
                        grant,
                        Some("invalid grant token".into()),
                        6,
                        String::new(),
                        String::new(),
                    ),
                    false,
                )
            } else {
                (
                    broker_response(grant, None, 0, String::new(), String::new()),
                    true,
                )
            }
        }
        BrokerRequest::Run { token, argv } => {
            if token != grant.token {
                return (
                    broker_response(
                        grant,
                        Some("invalid grant token".into()),
                        6,
                        String::new(),
                        String::new(),
                    ),
                    false,
                );
            }
            if let Err(error) = command_allowed(grant, &argv) {
                return (
                    broker_response(
                        grant,
                        Some(error.to_string()),
                        6,
                        String::new(),
                        String::new(),
                    ),
                    false,
                );
            }
            if !grant.allow_destructive
                && !has_long_option(&argv, "--dry-run")
                && let Some(capability) = invoked_capability(&argv)
                && let Err(error) = ensure_read_only_capability(capability)
            {
                return (
                    broker_response(
                        grant,
                        Some(error.to_string()),
                        6,
                        String::new(),
                        String::new(),
                    ),
                    false,
                );
            }
            decrement_grant_use(grant);
            append_agent_audit(
                grant,
                AuditOperation::CredentialGrantUsed,
                json!({
                    "remaining_uses": grant.remaining_uses,
                    "command_group": argv.first(),
                    "command": argv.get(1),
                }),
            );
            let remaining = (grant.expires_at - Utc::now())
                .to_std()
                .unwrap_or(Duration::ZERO);
            match run_scoped_child(&argv, password, remaining).await {
                Ok(output) => {
                    let exit_code = output.status.code().unwrap_or(1);
                    (
                        broker_response(
                            grant,
                            None,
                            exit_code,
                            String::from_utf8_lossy(&output.stdout).into_owned(),
                            String::from_utf8_lossy(&output.stderr).into_owned(),
                        ),
                        grant_uses_exhausted(grant),
                    )
                }
                Err(error) => (
                    broker_response(
                        grant,
                        Some(format!("start scoped VoidB command: {error}")),
                        5,
                        String::new(),
                        String::new(),
                    ),
                    grant_uses_exhausted(grant),
                ),
            }
        }
        BrokerRequest::SessionOpen { token, request } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let started_at = Utc::now();
            let purpose = request.purpose.clone();
            if let Err(error) = session_open_allowed(grant, &request) {
                let response =
                    broker_session_error(grant, "session.policy_denied", error.to_string());
                append_agent_session_audit(
                    grant,
                    AuditOperation::SessionOpen,
                    &response,
                    AgentSessionAuditContext {
                        purpose: Some(&purpose),
                        ..AgentSessionAuditContext::default()
                    },
                    started_at,
                );
                return (response, false);
            }
            consume_agent_use(grant, "session", "open", None);
            let response = session_result(grant, session_host.open(request, Utc::now()).await);
            let session = response_session_ref(&response);
            append_agent_session_audit(
                grant,
                AuditOperation::SessionOpen,
                &response,
                AgentSessionAuditContext {
                    session: session.as_ref(),
                    purpose: Some(&purpose),
                    ..AgentSessionAuditContext::default()
                },
                started_at,
            );
            (response, grant_uses_exhausted(grant))
        }
        BrokerRequest::SessionCall { token, request } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let started_at = Utc::now();
            let session = request.session.clone();
            let capability = request.capability.clone();
            let call_id = request.call_id.clone();
            if let Err(error) = request.validate_call_id() {
                let response = broker_session_error(grant, error.code.as_str(), error.to_string());
                append_agent_session_audit(
                    grant,
                    AuditOperation::SessionCall,
                    &response,
                    AgentSessionAuditContext {
                        session: Some(&session),
                        capability: Some(&capability),
                        ..AgentSessionAuditContext::default()
                    },
                    started_at,
                );
                return (response, false);
            }
            if let Err(error) = session_call_allowed(grant, &request) {
                let response =
                    broker_session_error(grant, "session.policy_denied", error.to_string());
                append_agent_session_audit(
                    grant,
                    AuditOperation::SessionCall,
                    &response,
                    AgentSessionAuditContext {
                        session: Some(&session),
                        call_id: Some(&call_id),
                        capability: Some(&capability),
                        ..AgentSessionAuditContext::default()
                    },
                    started_at,
                );
                return (response, false);
            }
            consume_agent_use(grant, "session", "call", Some(&request.capability));
            let response = session_result(grant, session_host.call(request, Utc::now()).await);
            append_agent_session_audit(
                grant,
                AuditOperation::SessionCall,
                &response,
                AgentSessionAuditContext {
                    session: Some(&session),
                    call_id: Some(&call_id),
                    capability: Some(&capability),
                    ..AgentSessionAuditContext::default()
                },
                started_at,
            );
            (response, grant_uses_exhausted(grant))
        }
        BrokerRequest::SessionCallStart { .. }
        | BrokerRequest::SessionCallStatus { .. }
        | BrokerRequest::SessionCallWait { .. } => (
            broker_session_error(
                grant,
                "session.protocol_unsupported",
                "Asynchronous session-call operations require the concurrent broker dispatcher.",
            ),
            false,
        ),
        BrokerRequest::SessionStatus { token, request } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let started_at = Utc::now();
            let session = request.session.clone();
            let response = session_result(grant, session_host.status(request, Utc::now()).await);
            append_agent_session_audit(
                grant,
                AuditOperation::SessionStatus,
                &response,
                AgentSessionAuditContext {
                    session: Some(&session),
                    ..AgentSessionAuditContext::default()
                },
                started_at,
            );
            (response, false)
        }
        BrokerRequest::SessionList { token, request } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let started_at = Utc::now();
            let purpose = request.purpose.clone();
            let sessions = session_host.list(request, Utc::now()).await;
            let response = broker_data_response(
                grant,
                json!({ "count": sessions.len(), "sessions": sessions }),
            );
            append_agent_session_audit(
                grant,
                AuditOperation::SessionList,
                &response,
                AgentSessionAuditContext {
                    purpose: purpose.as_ref(),
                    ..AgentSessionAuditContext::default()
                },
                started_at,
            );
            (response, false)
        }
        BrokerRequest::SessionRenew { token, request } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let started_at = Utc::now();
            let session = request.session.clone();
            let response = session_result(grant, session_host.renew(request, Utc::now()).await);
            append_agent_session_audit(
                grant,
                AuditOperation::SessionRenew,
                &response,
                AgentSessionAuditContext {
                    session: Some(&session),
                    ..AgentSessionAuditContext::default()
                },
                started_at,
            );
            (response, false)
        }
        BrokerRequest::SessionCancel { token, request } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let started_at = Utc::now();
            let session = request.session.clone();
            let call_id = request.call_id.clone();
            if let Err(error) = request.validate_call_id() {
                let response = broker_session_error(grant, error.code.as_str(), error.to_string());
                append_agent_session_audit(
                    grant,
                    AuditOperation::SessionCancel,
                    &response,
                    AgentSessionAuditContext {
                        session: Some(&session),
                        ..AgentSessionAuditContext::default()
                    },
                    started_at,
                );
                return (response, false);
            }
            let response = session_result(grant, session_host.cancel(request, Utc::now()).await);
            append_agent_session_audit(
                grant,
                AuditOperation::SessionCancel,
                &response,
                AgentSessionAuditContext {
                    session: Some(&session),
                    call_id: Some(&call_id),
                    ..AgentSessionAuditContext::default()
                },
                started_at,
            );
            (response, false)
        }
        BrokerRequest::SessionClose { token, request } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let started_at = Utc::now();
            let session = request.session.clone();
            let response = session_result(grant, session_host.close(request, Utc::now()).await);
            append_agent_session_audit(
                grant,
                AuditOperation::SessionClose,
                &response,
                AgentSessionAuditContext {
                    session: Some(&session),
                    ..AgentSessionAuditContext::default()
                },
                started_at,
            );
            (response, false)
        }
    }
}

#[cfg(not(test))]
fn register_session_factories(
    host: &mut AgentSessionHost,
    grant: &AgentGrantFile,
    password: &str,
) -> anyhow::Result<()> {
    if !matches!(
        grant.plugin_id.as_str(),
        "ssh"
            | "sqlite"
            | "duckdb"
            | "mysql"
            | "postgres"
            | "redis"
            | "mongodb"
            | "elasticsearch"
            | "webdav"
    ) {
        return Ok(());
    }
    let store = LocalProfileStore::default_store()?;
    let profile = store
        .load_profiles()?
        .into_iter()
        .find(|profile| profile.id == grant.profile_id && profile.plugin_id == grant.plugin_id)
        .ok_or_else(|| anyhow!("granted session profile is unavailable"))?;
    let connection = store
        .native_connection(&profile, Some(password))
        .map_err(|_| anyhow!("granted session profile credentials are unavailable"))?;
    let config = connection
        .plugin_config
        .ok_or_else(|| anyhow!("granted session profile configuration is unavailable"))?;
    match grant.plugin_id.as_str() {
        #[cfg(feature = "ssh")]
        "ssh" => host.register_factory(Arc::new(voidb_plugin_ssh::SshAgentSessionFactory::new(
            serde_json::from_value(config)
                .map_err(|_| anyhow!("granted SSH profile configuration is invalid"))?,
        ))),
        #[cfg(feature = "sqlite")]
        "sqlite" => host.register_factory(Arc::new(
            voidb_plugin_sqlite::SqliteAgentSessionFactory::new(
                serde_json::from_value(config)
                    .map_err(|_| anyhow!("granted SQLite profile configuration is invalid"))?,
            ),
        )),
        #[cfg(feature = "duckdb")]
        "duckdb" => host.register_factory(Arc::new(
            voidb_plugin_duckdb::DuckDbAgentSessionFactory::new(
                serde_json::from_value(config)
                    .map_err(|_| anyhow!("granted DuckDB profile configuration is invalid"))?,
            ),
        )),
        #[cfg(feature = "mysql")]
        "mysql" => {
            host.register_factory(Arc::new(voidb_plugin_mysql::MySqlAgentSessionFactory::new(
                serde_json::from_value(config)
                    .map_err(|_| anyhow!("granted MySQL profile configuration is invalid"))?,
            )))
        }
        #[cfg(feature = "postgres")]
        "postgres" => host.register_factory(Arc::new(
            voidb_plugin_postgres::PostgresAgentSessionFactory::new(
                serde_json::from_value(config)
                    .map_err(|_| anyhow!("granted PostgreSQL profile configuration is invalid"))?,
            ),
        )),
        #[cfg(feature = "redis")]
        "redis" => {
            host.register_factory(Arc::new(voidb_plugin_redis::RedisAgentSessionFactory::new(
                serde_json::from_value(config)
                    .map_err(|_| anyhow!("granted Redis profile configuration is invalid"))?,
            )))
        }
        #[cfg(feature = "mongodb")]
        "mongodb" => host.register_factory(Arc::new(
            voidb_plugin_mongodb::MongoAgentSessionFactory::new(
                serde_json::from_value(config)
                    .map_err(|_| anyhow!("granted MongoDB profile configuration is invalid"))?,
            ),
        )),
        #[cfg(feature = "elasticsearch")]
        "elasticsearch" => host.register_factory(Arc::new(
            voidb_plugin_elasticsearch::EsAgentSessionFactory::new(
                serde_json::from_value(config).map_err(|_| {
                    anyhow!("granted Elasticsearch profile configuration is invalid")
                })?,
            ),
        )),
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
fn register_session_factories(
    _host: &mut AgentSessionHost,
    _grant: &AgentGrantFile,
    _password: &str,
) -> anyhow::Result<()> {
    Ok(())
}

async fn run_scoped_child(
    argv: &[String],
    password: &str,
    deadline: Duration,
) -> std::io::Result<std::process::Output> {
    let mut command = tokio::process::Command::new(
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("voidb-cli")),
    );
    command
        .args(argv)
        .env_remove(VOIDB_MASTER_PASSWORD_ENV)
        .env(BROKER_CHILD_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let stdin = child.stdin.take().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "open broker child input")
    })?;
    write_password_and_close(stdin, password.as_bytes()).await?;
    tokio::time::timeout(deadline, child.wait_with_output())
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "agent grant expired while the command was running",
            )
        })?
}

async fn write_password_and_close<W>(mut writer: W, password: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(password).await?;
    writer.shutdown().await?;
    drop(writer);
    Ok(())
}

fn invoked_capability(argv: &[String]) -> Option<&str> {
    (argv.first().map(String::as_str) == Some("invoke")
        && argv.get(1).map(String::as_str) == Some("run"))
    .then(|| argv.get(2).map(String::as_str))
    .flatten()
}

fn ensure_read_only_capability(capability: &str) -> anyhow::Result<()> {
    let risk = resolved_capability_risk(capability)
        .map_err(|error| anyhow!("capability risk could not be verified: {error}"))?;
    if risk == voidb_core::CapabilityRiskLevel::ReadOnly {
        Ok(())
    } else {
        bail!("agent grant is read-only; capability risk is '{risk:?}'")
    }
}

fn session_call_allowed(
    grant: &AgentGrantFile,
    request: &AgentSessionCallRequest,
) -> anyhow::Result<()> {
    let Some((plugin, operation)) = request.capability.split_once('.') else {
        bail!("session capability must be qualified");
    };
    if plugin != grant.plugin_id {
        bail!("capability plugin is outside the agent grant scope");
    }
    if !grant
        .capabilities
        .iter()
        .any(|allowed| allowed == "*" || allowed == &request.capability || allowed == operation)
    {
        bail!("capability is outside the agent grant scope");
    }
    ensure_grant_execution_mode(
        grant,
        &request.capability,
        CapabilityExecutionMode::SessionOnly,
    )?;
    let risk = resolved_capability_risk(&request.capability)
        .map_err(|error| anyhow!("capability risk could not be verified: {error}"))?;
    if risk != voidb_core::CapabilityRiskLevel::ReadOnly {
        if !grant.allow_destructive {
            bail!("agent grant is read-only; capability risk is '{risk:?}'");
        }
        if !request.destructive_acknowledged {
            bail!("session call requires --yes for capability risk '{risk:?}'");
        }
    } else if request.destructive_acknowledged && !grant.allow_destructive {
        bail!("agent grant does not permit destructive acknowledgements");
    }
    if grant.authorization_scopes.is_empty() {
        ensure_capability_wide_authorization_allowed(grant, &request.capability)?;
    } else {
        ensure_jit_operation_allowed(grant, &request.capability, request.input.clone())?;
    }
    Ok(())
}

fn session_open_allowed(
    grant: &AgentGrantFile,
    request: &AgentSessionOpenRequest,
) -> anyhow::Result<()> {
    if !grant.execution_mode.supports_session() {
        bail!(
            "agent grant execution mode '{}' does not permit persistent sessions",
            execution_mode_name(grant.execution_mode)
        );
    }
    if request.capabilities.is_empty() {
        bail!("session open requires one or more explicit --capability values");
    }
    let mut session_family = None;
    for capability in &request.capabilities {
        let operation = capability
            .split_once('.')
            .map(|(_, operation)| operation)
            .ok_or_else(|| anyhow!("session capability must be qualified"))?;
        if !grant
            .capabilities
            .iter()
            .any(|allowed| allowed == "*" || allowed == capability || allowed == operation)
        {
            bail!("capability is outside the agent grant scope");
        }
        let definition =
            ensure_grant_execution_mode(grant, capability, CapabilityExecutionMode::SessionOnly)?;
        let handoff = definition.session_handoff.as_ref().ok_or_else(|| {
            anyhow!("capability '{capability}' has no persistent-session handoff declaration")
        })?;
        if handoff.purpose != request.purpose {
            bail!(
                "capability '{capability}' requires session purpose '{}'",
                crate::builtin::invoke::session_purpose_cli_name(&handoff.purpose)
            );
        }
        if !handoff
            .capabilities
            .iter()
            .any(|declared| declared == capability)
        {
            bail!("capability '{capability}' is outside its declared session handoff binding");
        }
        if let Some(expected) = &session_family {
            if expected != handoff {
                bail!("session capabilities must belong to one declared session handoff family");
            }
        } else {
            session_family = Some(handoff.clone());
        }
    }
    if let Some(handoff) = &session_family {
        if handoff.live_session.is_some() {
            let requested = request.capabilities.iter().collect::<BTreeSet<_>>();
            let declared = handoff.capabilities.iter().collect::<BTreeSet<_>>();
            if requested != declared {
                bail!("live sessions require the complete declared capability family at open");
            }
        }
        live_session_start_allowed(grant, request, handoff)?;
    }
    Ok(())
}

fn live_session_start_allowed(
    grant: &AgentGrantFile,
    request: &AgentSessionOpenRequest,
    handoff: &voidb_core::CapabilitySessionHandoff,
) -> anyhow::Result<()> {
    if let Some(contract) = &handoff.live_session {
        contract
            .validate(&handoff.capabilities)
            .map_err(|error| anyhow!(error))?;
        contract
            .validate_start(&request.input)
            .map_err(|error| anyhow!(error))?;
        if contract.start_risk != voidb_core::CapabilityRiskLevel::ReadOnly {
            if !grant.allow_destructive {
                bail!(
                    "agent grant is read-only; live-session start risk is '{:?}'",
                    contract.start_risk
                );
            }
            if !request.destructive_acknowledged {
                bail!(
                    "live-session start requires --yes for risk '{:?}'",
                    contract.start_risk
                );
            }
        } else if request.destructive_acknowledged && !grant.allow_destructive {
            bail!("agent grant does not permit destructive acknowledgements");
        }
    }
    Ok(())
}

fn ensure_grant_execution_mode(
    grant: &AgentGrantFile,
    capability: &str,
    requested_mode: CapabilityExecutionMode,
) -> anyhow::Result<CapabilityDefinition> {
    let grant_allows = match requested_mode {
        CapabilityExecutionMode::Stateless => grant.execution_mode.supports_stateless(),
        CapabilityExecutionMode::SessionOnly => grant.execution_mode.supports_session(),
        CapabilityExecutionMode::Both => grant.execution_mode == CapabilityExecutionMode::Both,
    };
    if !grant_allows {
        bail!(
            "agent grant execution mode '{}' does not permit {} execution",
            execution_mode_name(grant.execution_mode),
            execution_mode_name(requested_mode)
        );
    }
    let definitions = resolved_authorization_capabilities(Some(&grant.plugin_id))
        .map_err(|error| anyhow!("load capability execution metadata: {error}"))?;
    let definition = definitions
        .into_iter()
        .find(|definition| definition.qualified_id() == capability)
        .ok_or_else(|| anyhow!("capability has no current execution-mode declaration"))?;
    let capability_allows = match requested_mode {
        CapabilityExecutionMode::Stateless => definition.supports_stateless_execution(),
        CapabilityExecutionMode::SessionOnly => definition.supports_session_execution(),
        CapabilityExecutionMode::Both => {
            definition.supports_stateless_execution() && definition.supports_session_execution()
        }
    };
    if !capability_allows {
        bail!(
            "capability '{capability}' does not support {} execution; declared mode is '{}'",
            execution_mode_name(requested_mode),
            execution_mode_name(definition.execution_mode)
        );
    }
    Ok(definition)
}

fn ensure_capability_wide_authorization_allowed(
    grant: &AgentGrantFile,
    capability: &str,
) -> anyhow::Result<()> {
    let definitions = resolved_authorization_capabilities(Some(&grant.plugin_id))
        .map_err(|error| anyhow!("load capability authorization metadata: {error}"))?;
    let definition = definitions
        .iter()
        .find(|definition| definition.qualified_id() == capability)
        .ok_or_else(|| anyhow!("capability has no current authorization declaration"))?;
    if !definition.authorization.capability_wide_allowed {
        bail!(
            "permission.local_path_scope_required: capability requires a structured or exact JIT authorization scope; a proactive capability grant is insufficient"
        );
    }
    Ok(())
}

fn ensure_jit_operation_allowed(
    grant: &AgentGrantFile,
    capability: &str,
    input: Value,
) -> anyhow::Result<()> {
    let operation = normalize_agent_operation(capability, input)
        .map_err(|error| anyhow!("normalize JIT operation: {error}"))?;
    let definitions = resolved_authorization_capabilities(Some(&grant.plugin_id))
        .map_err(|error| anyhow!("load JIT capability metadata: {error}"))?;
    let definition = definitions
        .iter()
        .find(|definition| definition.qualified_id() == capability)
        .ok_or_else(|| anyhow!("capability has no current JIT authorization declaration"))?;
    if grant.authorization_scopes.iter().any(|scope| {
        authorize_normalized_operation(&definition.authorization, scope, &operation).is_ok()
    }) {
        Ok(())
    } else {
        bail!("normalized operation is outside the current JIT grant revision")
    }
}

fn consume_agent_use(
    grant: &mut AgentGrantFile,
    command_group: &str,
    command: &str,
    capability: Option<&str>,
) {
    decrement_grant_use(grant);
    append_agent_audit(
        grant,
        AuditOperation::CredentialGrantUsed,
        json!({
            "remaining_uses": grant.remaining_uses,
            "command_group": command_group,
            "command": command,
            "capability": capability,
        }),
    );
}

fn decrement_grant_use(grant: &mut AgentGrantFile) {
    if let Some(remaining) = grant.remaining_uses.as_mut() {
        *remaining = remaining.saturating_sub(1);
    }
}

fn grant_uses_exhausted(grant: &AgentGrantFile) -> bool {
    grant.remaining_uses == Some(0)
}

fn invalid_token_response(grant: &AgentGrantFile) -> (BrokerResponse, bool) {
    (
        broker_response(
            grant,
            Some("invalid grant token".into()),
            6,
            String::new(),
            String::new(),
        ),
        false,
    )
}

fn session_result<T: Serialize>(
    grant: &AgentGrantFile,
    result: Result<T, PluginSessionError>,
) -> BrokerResponse {
    match result {
        Ok(data) => match serde_json::to_value(data) {
            Ok(data) => broker_data_response(grant, data),
            Err(error) => broker_session_error(
                grant,
                "session.redaction_failed",
                format!("serialize session response: {error}"),
            ),
        },
        Err(error) => broker_session_error(grant, error.code.as_str(), error.to_string()),
    }
}

fn response_session_ref(response: &BrokerResponse) -> Option<AgentSessionRef> {
    response
        .data
        .as_ref()
        .and_then(|data| data.get("session"))
        .and_then(|session| serde_json::from_value(session.clone()).ok())
}

fn broker_data_response(grant: &AgentGrantFile, data: Value) -> BrokerResponse {
    BrokerResponse {
        protocol_version: AGENT_BROKER_PROTOCOL_VERSION,
        ok: true,
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
        error: None,
        error_code: None,
        data: Some(data),
        remaining_uses: grant.remaining_uses,
        expires_at: grant.expires_at,
    }
}

fn broker_session_error(
    grant: &AgentGrantFile,
    code: impl Into<String>,
    message: impl Into<String>,
) -> BrokerResponse {
    BrokerResponse {
        protocol_version: AGENT_BROKER_PROTOCOL_VERSION,
        ok: false,
        exit_code: 6,
        stdout: String::new(),
        stderr: String::new(),
        error: Some(message.into()),
        error_code: Some(code.into()),
        data: None,
        remaining_uses: grant.remaining_uses,
        expires_at: grant.expires_at,
    }
}

fn broker_response(
    grant: &AgentGrantFile,
    error: Option<String>,
    exit_code: i32,
    stdout: String,
    stderr: String,
) -> BrokerResponse {
    BrokerResponse {
        protocol_version: AGENT_BROKER_PROTOCOL_VERSION,
        ok: error.is_none() && exit_code == 0,
        exit_code,
        stdout,
        stderr,
        error,
        error_code: None,
        data: None,
        remaining_uses: grant.remaining_uses,
        expires_at: grant.expires_at,
    }
}

#[cfg(unix)]
async fn send_request(
    grant: &AgentGrantFile,
    request: BrokerRequest,
) -> anyhow::Result<BrokerResponse> {
    let mut stream = UnixStream::connect(&grant.socket_path)
        .await
        .context("connect to agent broker")?;
    stream
        .write_all(&serde_json::to_vec(&BrokerWireRequest {
            protocol_version: AGENT_BROKER_PROTOCOL_VERSION,
            request,
        })?)
        .await?;
    stream.shutdown().await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    let response = serde_json::from_slice::<BrokerResponse>(&bytes)?;
    if !is_supported_agent_broker_protocol_version(response.protocol_version) {
        bail!(
            "agent broker selected unsupported protocol version {}",
            response.protocol_version
        );
    }
    Ok(response)
}

#[cfg(not(unix))]
async fn send_request(
    _grant: &AgentGrantFile,
    _request: BrokerRequest,
) -> anyhow::Result<BrokerResponse> {
    bail!("agent broker currently requires a Unix-domain socket platform")
}

async fn shutdown_grant(grant: &AgentGrantFile, recovery_reason: &str) -> anyhow::Result<()> {
    let broker_responded = if grant.socket_path.exists() {
        matches!(
            tokio::time::timeout(
                BROKER_PROBE_TIMEOUT,
                send_request(
                    grant,
                    BrokerRequest::Shutdown {
                        token: grant.token.clone(),
                    },
                ),
            )
            .await,
            Ok(Ok(response)) if response.ok
        )
    } else {
        false
    };
    if broker_responded {
        let started = tokio::time::Instant::now();
        while started.elapsed() < BROKER_PROBE_TIMEOUT
            && (grant.socket_path.exists() || grant_path_for_id(&grant.id)?.exists())
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    } else {
        append_agent_audit(
            grant,
            AuditOperation::CredentialGrantReleased,
            json!({
                "reason": recovery_reason,
                "broker_health": if grant.socket_path.exists() { "stale_socket" } else { "offline" },
            }),
        );
    }
    remove_grant_artifacts(grant)
}

async fn wait_for_socket(socket_path: &Path) -> anyhow::Result<()> {
    let started = tokio::time::Instant::now();
    #[cfg(unix)]
    let mut last_error = None;
    while started.elapsed() < BROKER_READY_TIMEOUT {
        #[cfg(unix)]
        match UnixStream::connect(socket_path).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
        #[cfg(not(unix))]
        if socket_path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    #[cfg(unix)]
    if let Some(error) = last_error {
        bail!("agent broker did not become ready: {error}");
    }
    bail!("agent broker did not become ready")
}

fn grant_directory() -> anyhow::Result<PathBuf> {
    let path = AppConfig::config_dir()?.join("agent-grants");
    fs::create_dir_all(&path)?;
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

fn grant_path_for_id(id: &str) -> anyhow::Result<PathBuf> {
    Ok(grant_directory()?.join(format!("{}.json", id.trim_start_matches("agent-grant:"))))
}

fn load_grants(prune: bool) -> anyhow::Result<Vec<AgentGrantFile>> {
    let directory = grant_directory()?;
    let mut grants = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let grant = match read_grant(&path) {
            Ok(grant) => grant,
            Err(_) => continue,
        };
        if grant.version != GRANT_VERSION {
            continue;
        }
        // A live broker with exhausted data-operation uses must remain
        // addressable long enough for status, wait, cancel, and close requests
        // against calls that were already accepted.
        let terminal = grant.expires_at <= Utc::now()
            || (grant_uses_exhausted(&grant) && !grant.socket_path.exists());
        if terminal && prune {
            let _ = remove_grant_artifacts(&grant);
            let _ = fs::remove_file(path);
            continue;
        }
        grants.push(grant);
    }
    grants.sort_by_key(|grant| grant.expires_at);
    Ok(grants)
}

fn read_grant(path: &Path) -> anyhow::Result<AgentGrantFile> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_grant(path: &Path, grant: &AgentGrantFile) -> anyhow::Result<()> {
    let content = serde_json::to_vec_pretty(grant)?;
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let result = (|| -> anyhow::Result<()> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(&content)?;
        file.sync_all()?;
        #[cfg(unix)]
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        drop(file);
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn remove_grant_artifacts(grant: &AgentGrantFile) -> anyhow::Result<()> {
    let _ = fs::remove_file(&grant.socket_path);
    let _ = fs::remove_file(grant_path_for_id(&grant.id)?);
    Ok(())
}

fn ensure_unix() -> anyhow::Result<()> {
    if cfg!(unix) {
        Ok(())
    } else {
        bail!("agent broker currently requires a Unix-domain socket platform")
    }
}

#[derive(Default)]
struct AgentSessionAuditContext<'a> {
    session: Option<&'a AgentSessionRef>,
    call_id: Option<&'a str>,
    capability: Option<&'a str>,
    purpose: Option<&'a PluginSessionPurpose>,
}

fn build_agent_session_audit_event(
    grant: &AgentGrantFile,
    operation: AuditOperation,
    response: &BrokerResponse,
    context: AgentSessionAuditContext<'_>,
    started_at: DateTime<Utc>,
) -> AuditEvent {
    let status = if response.ok {
        AuditEventStatus::Succeeded
    } else {
        match response.error_code.as_deref() {
            Some("session.timeout")
            | Some("session.expired")
            | Some("session.control_timeout")
            | Some("session.close_timeout") => AuditEventStatus::TimedOut,
            Some("session.cancelled") => AuditEventStatus::Cancelled,
            _ => AuditEventStatus::Failed,
        }
    };
    let mut event = AuditEvent::new(operation, status);
    event.grant_id = Some(grant.id.clone());
    event.profile = Some(ConnectionProfileRef::Id(grant.profile_id.clone()));
    event.plugin_id = Some(grant.plugin_id.clone());
    event.capability_id = context.capability.map(str::to_owned);
    event.duration_ms = Some(
        Utc::now()
            .signed_duration_since(started_at)
            .num_milliseconds()
            .max(0) as u64,
    );
    event.metadata = json!({
        "session_id": context.session.map(|reference| reference.session_id.as_str()),
        "generation": context.session.map(|reference| reference.generation),
        "call_id": context.call_id,
        "protocol_version": response.protocol_version,
        "purpose": context.purpose,
        "remaining_uses": response.remaining_uses,
        "grant_expires_at": response.expires_at,
        "error_code": response.error_code,
    });
    event.redaction = RedactionStatus::Applied;
    event
}

#[cfg(not(test))]
fn append_agent_session_audit(
    grant: &AgentGrantFile,
    operation: AuditOperation,
    response: &BrokerResponse,
    context: AgentSessionAuditContext<'_>,
    started_at: DateTime<Utc>,
) {
    let event = build_agent_session_audit_event(grant, operation, response, context, started_at);
    if let Ok(store) = LocalAuditStore::default_store() {
        let _ = store.append(&event);
    }
}

#[cfg(test)]
fn append_agent_session_audit(
    grant: &AgentGrantFile,
    operation: AuditOperation,
    response: &BrokerResponse,
    context: AgentSessionAuditContext<'_>,
    started_at: DateTime<Utc>,
) {
    let _ = build_agent_session_audit_event(grant, operation, response, context, started_at);
}

#[cfg(not(test))]
fn append_agent_audit(
    grant: &AgentGrantFile,
    operation: AuditOperation,
    metadata: serde_json::Value,
) {
    let mut event = AuditEvent::new(operation, AuditEventStatus::Succeeded);
    event.grant_id = Some(grant.id.clone());
    event.profile = Some(ConnectionProfileRef::Id(grant.profile_id.clone()));
    event.plugin_id = Some(grant.plugin_id.clone());
    event.metadata = metadata;
    event.redaction = RedactionStatus::NotRequired;
    if let Ok(store) = LocalAuditStore::default_store() {
        let _ = store.append(&event);
    }
}

#[cfg(test)]
fn append_agent_audit(
    _grant: &AgentGrantFile,
    _operation: AuditOperation,
    _metadata: serde_json::Value,
) {
}

#[cfg(all(test, feature = "full"))]
#[path = "data_search_live_session_conformance.rs"]
mod data_search_live_session_conformance;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;

    use super::*;

    #[derive(Default)]
    struct BlockingSessionState {
        started: StdMutex<Vec<String>>,
        cancelled: StdMutex<HashSet<String>>,
        started_notify: Notify,
        control_notify: Notify,
        active_notify: Notify,
        active: AtomicUsize,
        max_active: AtomicUsize,
        closed: AtomicBool,
        cleanup_count: AtomicUsize,
    }

    struct BlockingSession {
        state: Arc<BlockingSessionState>,
    }

    struct ActiveCallGuard {
        state: Arc<BlockingSessionState>,
    }

    impl Drop for ActiveCallGuard {
        fn drop(&mut self) {
            self.state.active.fetch_sub(1, Ordering::SeqCst);
            self.state.active_notify.notify_waiters();
        }
    }

    #[async_trait]
    impl voidb_core::PluginAgentSession for BlockingSession {
        async fn call(
            &self,
            request: AgentSessionCallRequest,
        ) -> Result<AgentSessionCallResult, PluginSessionError> {
            let active = self.state.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.state.max_active.fetch_max(active, Ordering::SeqCst);
            let _active = ActiveCallGuard {
                state: Arc::clone(&self.state),
            };
            self.state
                .started
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(request.call_id.clone());
            self.state.started_notify.notify_waiters();
            loop {
                let controlled = self.state.control_notify.notified();
                if self.state.closed.load(Ordering::SeqCst) {
                    return Err(PluginSessionError::new(
                        PluginSessionErrorCode::Aborted,
                        "fixture session closed",
                    ));
                }
                if self
                    .state
                    .cancelled
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .contains(&request.call_id)
                {
                    return Err(PluginSessionError::new(
                        PluginSessionErrorCode::Cancelled,
                        "fixture call cancelled",
                    ));
                }
                controlled.await;
            }
        }

        async fn health(&self) -> Result<voidb_core::PluginSessionHealth, PluginSessionError> {
            Ok(voidb_core::PluginSessionHealth::Ready)
        }

        async fn cancel(&self, call_id: &str) -> Result<(), PluginSessionError> {
            self.state
                .cancelled
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .insert(call_id.to_owned());
            self.state.control_notify.notify_waiters();
            Ok(())
        }

        async fn close(&self, _reason: String) -> Result<(), PluginSessionError> {
            if !self.state.closed.swap(true, Ordering::SeqCst) {
                self.state.cleanup_count.fetch_add(1, Ordering::SeqCst);
            }
            self.state.control_notify.notify_waiters();
            Ok(())
        }
    }

    struct BlockingSessionFactory {
        state: Arc<BlockingSessionState>,
    }

    #[async_trait]
    impl voidb_core::PluginAgentSessionFactory for BlockingSessionFactory {
        fn plugin_id(&self) -> &str {
            "ssh"
        }

        async fn open(
            &self,
            _context: voidb_core::AgentSessionOpenContext,
        ) -> Result<Arc<dyn voidb_core::PluginAgentSession>, PluginSessionError> {
            Ok(Arc::new(BlockingSession {
                state: Arc::clone(&self.state),
            }))
        }
    }

    async fn wait_for_started_calls(state: &BlockingSessionState, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let mut started = Box::pin(state.started_notify.notified());
                started.as_mut().enable();
                if state
                    .started
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .len()
                    >= expected
                {
                    return;
                }
                started.await;
            }
        })
        .await
        .expect("fixture calls start before timeout");
    }

    async fn wait_for_active_calls(state: &BlockingSessionState, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let mut changed = Box::pin(state.active_notify.notified());
                changed.as_mut().enable();
                if state.active.load(Ordering::SeqCst) == expected {
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect("fixture active-call count changes before timeout");
    }

    struct RunningBlockingBroker {
        grant_path: PathBuf,
        grant: AgentGrantFile,
        session: AgentSessionRef,
        state: Arc<BlockingSessionState>,
        task: tokio::task::JoinHandle<anyhow::Result<()>>,
    }

    impl RunningBlockingBroker {
        async fn start(
            directory: &Path,
            mut grant: AgentGrantFile,
            host_generation: u64,
            purpose: PluginSessionPurpose,
        ) -> Self {
            fs::create_dir_all(directory).expect("create blocking broker directory");
            let grant_path = directory.join("grant.json");
            grant.socket_path = directory.join("grant.sock");
            grant.execution_mode = CapabilityExecutionMode::SessionOnly;
            grant.capabilities = vec!["ssh.terminal_read".into()];
            write_grant(&grant_path, &grant).expect("write blocking broker grant");

            let state = Arc::new(BlockingSessionState::default());
            let mut host = AgentSessionHost::new(
                grant.id.clone(),
                grant.profile_id.clone(),
                grant.plugin_id.clone(),
                grant.capabilities.clone(),
                grant.expires_at,
                host_generation,
            );
            host.register_factory(Arc::new(BlockingSessionFactory {
                state: Arc::clone(&state),
            }));
            let session = host
                .open(
                    AgentSessionOpenRequest {
                        purpose,
                        capabilities: grant.capabilities.clone(),
                        lease_seconds: 60,
                        concurrency: AgentSessionConcurrency::Serialized,
                        destructive_acknowledged: false,
                        input: Value::Null,
                    },
                    Utc::now(),
                )
                .await
                .expect("open blocking broker session")
                .session;

            let broker_path = grant_path.clone();
            let broker_grant = grant.clone();
            let task = tokio::spawn(async move {
                broker_loop_with_host(&broker_path, broker_grant, host, "test-password").await
            });
            wait_for_socket(&grant.socket_path)
                .await
                .expect("blocking broker socket ready");

            Self {
                grant_path,
                grant,
                session,
                state,
                task,
            }
        }

        fn call_request(&self, call_id: &str) -> AgentSessionCallRequest {
            AgentSessionCallRequest {
                session: self.session.clone(),
                call_id: call_id.into(),
                capability: "ssh.terminal_read".into(),
                input: json!({ "offset": 0 }),
                destructive_acknowledged: false,
                timeout_ms: Some(5_000),
                output_limit_bytes: 1024,
            }
        }

        async fn shutdown(self) {
            let response = send_request(
                &self.grant,
                BrokerRequest::Shutdown {
                    token: self.grant.token.clone(),
                },
            )
            .await
            .expect("blocking broker shutdown response");
            assert!(response.ok);
            self.task
                .await
                .expect("blocking broker task")
                .expect("blocking broker exits");
        }
    }

    fn grant() -> AgentGrantFile {
        AgentGrantFile {
            version: GRANT_VERSION,
            id: "agent-grant:test".into(),
            token: "token".into(),
            profile_id: "profile:test".into(),
            profile_name: "prod".into(),
            plugin_id: "ssh".into(),
            capabilities: vec!["ssh.sftp_list".into(), "ssh.exec".into()],
            execution_mode: CapabilityExecutionMode::Stateless,
            preset: Some(AgentAuthorizationPresetKind::ReadOnly),
            allow_destructive: false,
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(15),
            remaining_uses: Some(10),
            socket_path: "/tmp/voidb-agent-test.sock".into(),
            authorization_scopes: Vec::new(),
            principal_fingerprint: None,
            grant_revision: None,
        }
    }

    #[test]
    fn resolve_profile_accepts_bare_immutable_profile_id() {
        let profiles = vec![ConnectionProfile {
            id: "profile:test".into(),
            name: "ser7".into(),
            plugin_id: "ssh".into(),
            display_name: None,
            metadata: json!({}),
            default_options: serde_json::Value::Null,
            credential_refs: Vec::new(),
            policy: voidb_core::ConnectionProfilePolicy::default(),
        }];

        let resolved = resolve_profile(&profiles, "profile:test", "ssh")
            .expect("bare profile id should resolve");
        assert_eq!(resolved.name, "ser7");
    }

    #[test]
    fn agent_exec_builds_an_immutable_profile_invocation_without_grant_plumbing() {
        let matches = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "exec",
                "docker.list_containers",
                "--profile",
                "prod-docker",
                "--input-json",
                r#"{"all":true}"#,
                "--page-limit",
                "25",
            ])
            .expect("agent exec command parses");
        let (_, agent) = matches.subcommand().expect("agent command");
        let (_, exec) = agent.subcommand().expect("exec command");
        let input = parse_agent_exec_input(exec).expect("agent exec input");
        let argv = agent_exec_argv(exec, "docker.list_containers", "profile:docker", &input);

        assert_eq!(
            argv,
            vec![
                "invoke",
                "run",
                "docker.list_containers",
                "--profile",
                "id:profile:docker",
                "--input-json",
                r#"{"all":true}"#,
                "--format",
                "json",
                "--page-limit",
                "25",
            ]
        );
        assert!(!argv.iter().any(|argument| argument == "--grant"));
        assert!(!argv.iter().any(|argument| argument == "--plugin"));
    }

    #[cfg(feature = "full")]
    #[test]
    fn agent_exec_accepts_explicit_principal_binding_and_exact_jit_scope() {
        let matches = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "exec",
                "docker.list_containers",
                "--profile",
                "prod-docker",
                "--client-id",
                "agent",
                "--task-id",
                "task-123",
                "--instance-id",
                "desktop",
            ])
            .expect("agent exec principal parses");
        let (_, agent) = matches.subcommand().expect("agent command");
        let (_, exec) = agent.subcommand().expect("exec command");
        let principal = agent_exec_principal(exec)
            .expect("valid principal")
            .expect("explicit principal");
        assert_eq!(principal.client_id, "agent");
        assert_eq!(principal.task_id, "task-123");
        assert_eq!(principal.instance_id.as_deref(), Some("desktop"));

        let (scope, risk) = exact_agent_exec_scope("docker", "docker.list_containers", json!({}))
            .expect("exact Docker scope");
        assert_eq!(risk, voidb_core::CapabilityRiskLevel::ReadOnly);
        assert!(matches!(
            scope,
            AgentAuthorizationScope::ExactInvocation { capability_id, .. }
                if capability_id == "docker.list_containers"
        ));
    }

    #[test]
    fn agent_exec_help_hides_principal_and_grant_plumbing() {
        let mut command = agent_command();
        let agent = command
            .find_subcommand_mut("agent")
            .expect("agent command exists");
        let exec = agent
            .find_subcommand_mut("exec")
            .expect("exec command exists");
        let help = exec.render_long_help().to_string();

        for hidden in [
            "--client-id",
            "--task-id",
            "--instance-id",
            "--grant",
            "--plugin",
        ] {
            assert!(!help.contains(hidden), "exec help exposed {hidden}");
        }
        for visible in [
            "docker.list_containers",
            "--profile",
            "--input-json",
            "--purpose",
            "--no-request",
        ] {
            assert!(help.contains(visible), "exec help omitted {visible}");
        }
    }

    #[test]
    fn jit_request_create_requires_a_reviewable_purpose_and_keeps_reason_alias() {
        let base = [
            "voidb-cli",
            "agent",
            "request",
            "create",
            "--profile",
            "id:profile:test",
            "--plugin",
            "ssh",
            "--capability",
            "ssh.exec",
            "--scope",
            "capability",
            "--client-id",
            "agent",
            "--task-id",
            "task-purpose-test",
        ];
        assert!(agent_command().try_get_matches_from(base).is_err());

        for flag in ["--purpose", "--reason"] {
            let mut args = base.to_vec();
            args.extend([
                flag,
                "Inspect production uptime while triaging incident INC-42",
            ]);
            assert!(
                agent_command().try_get_matches_from(args).is_ok(),
                "{flag} should supply the review purpose"
            );
        }
    }

    #[test]
    fn agent_exec_jit_prompt_exposes_the_interactive_cli_review_path() {
        let prompt = agent_exec_review_prompt(
            "docker",
            "prod\u{1b}[31m",
            "voidb-cli agent request review auth-request:00000000-0000-4000-8000-000000000000",
        );

        assert!(prompt.contains("Authorization required for docker/prod"));
        assert!(prompt.contains("password prompt hides input"));
        assert!(prompt.contains(
            "voidb-cli agent request review auth-request:00000000-0000-4000-8000-000000000000"
        ));
        assert!(prompt.contains("Connection Manager approval inbox (p)"));
        assert!(!prompt.contains('\u{1b}'));
    }

    #[test]
    fn agent_exec_never_reuses_another_principals_jit_grant() {
        let approved = AgentPrincipal {
            client_id: "agent".into(),
            task_id: "task-a".into(),
            instance_id: None,
        };
        let other = AgentPrincipal {
            client_id: "agent".into(),
            task_id: "task-b".into(),
            instance_id: None,
        };
        let mut grant = grant();
        grant.principal_fingerprint = Some(approved.fingerprint().unwrap());

        assert!(grant_matches_agent_exec_principal(&grant, Some(&approved)).unwrap());
        assert!(!grant_matches_agent_exec_principal(&grant, Some(&other)).unwrap());
        assert!(!grant_matches_agent_exec_principal(&grant, None).unwrap());
    }

    #[test]
    fn read_only_grant_accepts_scoped_invoke_and_profile_test() {
        let grant = grant();
        assert!(
            command_allowed(
                &grant,
                &[
                    "invoke".into(),
                    "run".into(),
                    "ssh.sftp_list".into(),
                    "--profile".into(),
                    "id:profile:test".into(),
                    "--input-json".into(),
                    "{}".into(),
                ]
            )
            .is_ok()
        );
        assert_eq!(
            invoked_capability(&["invoke".into(), "run".into(), "ssh.sftp_list".into()]),
            Some("ssh.sftp_list")
        );
        assert!(
            command_allowed(
                &grant,
                &[
                    "profile".into(),
                    "test".into(),
                    "id:profile:test".into(),
                    "--plugin".into(),
                    "ssh".into(),
                ]
            )
            .is_ok()
        );
    }

    #[test]
    fn jit_grant_revalidates_exact_normalized_input_before_execution() {
        let mut grant = grant();
        grant.allow_destructive = true;
        let operation = normalize_agent_operation("ssh.exec", json!({ "command": "uptime" }))
            .expect("normalized operation");
        grant.authorization_scopes = vec![AgentAuthorizationScope::ExactInvocation {
            capability_id: operation.capability_id,
            normalized_input: operation.input,
            invocation_fingerprint: operation.fingerprint,
        }];

        let argv = |input: &str| {
            vec![
                "invoke".into(),
                "run".into(),
                "ssh.exec".into(),
                "--profile".into(),
                "id:profile:test".into(),
                "--input-json".into(),
                input.into(),
                "--yes".into(),
            ]
        };
        assert!(command_allowed(&grant, &argv(r#"{"command":"uptime"}"#)).is_ok());
        assert!(command_allowed(&grant, &argv(r#"{"command":"whoami"}"#)).is_err());
    }

    #[cfg(feature = "full")]
    #[test]
    fn local_filesystem_boundary_rejects_unscoped_proactive_grants() {
        for (plugin_id, capability_id) in [
            ("ssh", "ssh.sftp_get"),
            ("ssh", "ssh.sftp_put"),
        ] {
            let mut scoped_only = grant();
            scoped_only.plugin_id = plugin_id.into();
            let error = ensure_capability_wide_authorization_allowed(&scoped_only, capability_id)
                .expect_err("local filesystem capability must reject capability-wide grants");
            assert!(
                error
                    .to_string()
                    .contains("permission.local_path_scope_required")
            );
        }

        let mut proactive = grant();
        proactive.capabilities.push("ssh.sftp_get".into());
        proactive.allow_destructive = true;
        let input = json!({
            "remote_path": "/remote/file.txt",
            "local_root": "/tmp",
            "local_path": "file.txt",
        });
        let argv = |input: &Value| {
            vec![
                "invoke".into(),
                "run".into(),
                "ssh.sftp_get".into(),
                "--profile".into(),
                "id:profile:test".into(),
                "--input-json".into(),
                input.to_string(),
            ]
        };

        let error = command_allowed(&proactive, &argv(&input)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("permission.local_path_scope_required")
        );

        let operation = normalize_agent_operation("ssh.sftp_get", input.clone()).unwrap();
        proactive.authorization_scopes = vec![AgentAuthorizationScope::ExactInvocation {
            capability_id: operation.capability_id,
            normalized_input: operation.input,
            invocation_fingerprint: operation.fingerprint,
        }];
        assert!(command_allowed(&proactive, &argv(&input)).is_ok());

        let changed = json!({
            "remote_path": "/remote/file.txt",
            "local_root": "/tmp",
            "local_path": "other.txt",
        });
        assert!(command_allowed(&proactive, &argv(&changed)).is_err());
    }

    #[test]
    fn jit_grant_execution_is_bound_to_the_approved_principal() {
        let mut grant = grant();
        let approved = AgentPrincipal {
            client_id: "agent".into(),
            task_id: "task-a".into(),
            instance_id: Some("desktop".into()),
        };
        grant.principal_fingerprint = Some(approved.fingerprint().unwrap());
        let command = |task_id: &str| {
            with_optional_principal_args(Command::new("run"))
                .try_get_matches_from([
                    "run",
                    "--client-id",
                    "agent",
                    "--task-id",
                    task_id,
                    "--instance-id",
                    "desktop",
                ])
                .unwrap()
        };
        assert!(ensure_grant_principal(&grant, &command("task-a")).is_ok());
        assert!(ensure_grant_principal(&grant, &command("task-b")).is_err());
        let missing = with_optional_principal_args(Command::new("run"))
            .try_get_matches_from(["run"])
            .unwrap();
        assert!(ensure_grant_principal(&grant, &missing).is_err());
    }

    #[test]
    fn ssh_reference_jit_flow_covers_scope_revision_session_and_preauthorization() {
        let root = std::env::temp_dir().join(format!("voidb-ssh-jit-{}", Uuid::new_v4()));
        let store = JitAuthorizationStore::with_policy(
            root.clone(),
            "broker-ssh-reference",
            crate::jit_authorization::JitAuthorizationPolicy::default(),
        )
        .expect("temporary JIT store");
        let now = Utc::now();
        let principal = AgentPrincipal {
            client_id: "agent".into(),
            task_id: "ssh-reference".into(),
            instance_id: Some("test".into()),
        };
        let constrained = AgentAuthorizationScope::Constrained {
            capability_id: "ssh.exec".into(),
            constraints: BTreeMap::from([("/command".into(), json!("uptime"))]),
        };
        let first = store
            .create(
                CreateAuthorizationRequest {
                    principal: principal.clone(),
                    profile_id: "profile:test".into(),
                    plugin_id: "ssh".into(),
                    scope: constrained.clone(),
                    risk: voidb_core::CapabilityRiskLevel::Destructive,
                    purpose: "Inspect uptime while triaging the production incident".into(),
                    expires_at: now + chrono::Duration::minutes(5),
                },
                now,
            )
            .expect("request without preauthorization");
        let first_revision = store
            .approve(
                &first.request.id,
                constrained,
                AgentGrantAmendment::Bounded {
                    ttl_seconds: 300,
                    uses: Some(2),
                },
                now + chrono::Duration::seconds(1),
            )
            .expect("bounded approval");
        assert_eq!(first_revision.revision, 1);

        let exact = normalize_agent_operation("ssh.exec", json!({ "command": "whoami" }))
            .expect("exact SSH command");
        let exact_scope = AgentAuthorizationScope::ExactInvocation {
            capability_id: exact.capability_id,
            normalized_input: exact.input,
            invocation_fingerprint: exact.fingerprint,
        };
        let second = store
            .create(
                CreateAuthorizationRequest {
                    principal: principal.clone(),
                    profile_id: "profile:test".into(),
                    plugin_id: "ssh".into(),
                    scope: exact_scope.clone(),
                    risk: voidb_core::CapabilityRiskLevel::Destructive,
                    purpose: "Confirm the remote deployment identity before rollout".into(),
                    expires_at: now + chrono::Duration::minutes(5),
                },
                now + chrono::Duration::seconds(2),
            )
            .expect("amendment request");
        let amended = store
            .approve(
                &second.request.id,
                exact_scope,
                AgentGrantAmendment::AddToGrant {
                    grant_id: first_revision.grant_id.clone(),
                    ttl_delta_seconds: 60,
                    uses_delta: 2,
                },
                now + chrono::Duration::seconds(3),
            )
            .expect("immutable grant amendment");
        assert_eq!(amended.grant_id, first_revision.grant_id);
        assert_eq!(amended.revision, 2);

        let mut jit_grant = grant();
        jit_grant.id = amended.grant_id.clone();
        jit_grant.allow_destructive = true;
        jit_grant.authorization_scopes = store
            .effective_scopes(&amended.grant_id)
            .expect("effective scopes");
        jit_grant.principal_fingerprint = Some(principal.fingerprint().unwrap());
        jit_grant.grant_revision = Some(amended.revision);
        let argv = |command: &str| {
            vec![
                "invoke".into(),
                "run".into(),
                "ssh.exec".into(),
                "--profile".into(),
                "id:profile:test".into(),
                "--input-json".into(),
                json!({ "command": command }).to_string(),
                "--yes".into(),
            ]
        };
        assert!(command_allowed(&jit_grant, &argv("uptime")).is_ok());
        assert!(command_allowed(&jit_grant, &argv("whoami")).is_ok());
        assert!(command_allowed(&jit_grant, &argv("rm -rf /tmp/example")).is_err());

        let session_call = |command: &str| AgentSessionCallRequest {
            session: AgentSessionRef::new("agent-session:ssh", 1),
            call_id: format!("call-{command}"),
            capability: "ssh.exec".into(),
            input: json!({ "command": command }),
            destructive_acknowledged: true,
            timeout_ms: None,
            output_limit_bytes: 1024,
        };
        assert!(session_call_allowed(&jit_grant, &session_call("uptime")).is_err());
        assert!(session_call_allowed(&jit_grant, &session_call("pwd")).is_err());

        let mut proactive_session = grant();
        proactive_session.execution_mode = CapabilityExecutionMode::Both;
        proactive_session.allow_destructive = true;
        assert!(session_call_allowed(&proactive_session, &session_call("uptime")).is_ok());

        let mut capability_wide = grant();
        capability_wide.allow_destructive = true;
        capability_wide.authorization_scopes = vec![AgentAuthorizationScope::Capability {
            capability_id: "ssh.exec".into(),
        }];
        assert!(command_allowed(&capability_wide, &argv("date")).is_ok());

        let mut proactive = grant();
        proactive.allow_destructive = true;
        assert!(proactive.authorization_scopes.is_empty());
        assert!(command_allowed(&proactive, &argv("date")).is_ok());
        fs::remove_dir_all(root).expect("remove temporary JIT store");
    }

    #[test]
    fn request_review_accepts_only_an_opaque_id_and_no_secret_parameters() {
        assert!(
            agent_command()
                .try_get_matches_from([
                    "voidb-cli",
                    "agent",
                    "request",
                    "review",
                    "auth-request:00000000-0000-4000-8000-000000000000",
                ])
                .is_ok()
        );
        for forbidden in ["--master-password", "--password", "--approve", "--command"] {
            assert!(
                agent_command()
                    .try_get_matches_from([
                        "voidb-cli",
                        "agent",
                        "request",
                        "review",
                        "auth-request:00000000-0000-4000-8000-000000000000",
                        forbidden,
                        "secret-or-shell-text",
                    ])
                    .is_err(),
                "review unexpectedly accepted {forbidden}"
            );
        }
    }

    #[test]
    fn tui_decision_accepts_only_non_secret_scope_and_password_stdin_marker() {
        let command = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "request",
                "decide",
                "auth-request:00000000-0000-4000-8000-000000000000",
                "--decision",
                "bounded",
                "--ttl-seconds",
                "300",
                "--uses",
                "2",
                "--constraints-json",
                r#"{"/cwd":"/srv/app"}"#,
                "--password-stdin",
            ])
            .expect("safe TUI decision arguments");
        let encoded = format!("{command:?}");
        for forbidden in ["master_password", "VOIDB_MASTER_PASSWORD", "secret-value"] {
            assert!(!encoded.contains(forbidden));
        }
        for forbidden in ["--master-password", "--password", "--shell"] {
            assert!(
                agent_command()
                    .try_get_matches_from([
                        "voidb-cli",
                        "agent",
                        "request",
                        "decide",
                        "auth-request:00000000-0000-4000-8000-000000000000",
                        "--decision",
                        "once",
                        forbidden,
                        "secret-value",
                    ])
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn request_review_fails_closed_without_a_controlling_tty() {
        if !std::io::stdin().is_terminal() {
            assert_eq!(
                review_jit_request("auth-request:00000000-0000-4000-8000-000000000000")
                    .await
                    .unwrap(),
                JIT_EXIT_INVALID
            );
        }
    }

    #[test]
    fn grant_rejects_other_profiles_plugins_files_and_destructive_ack() {
        let grant = grant();
        for argv in [
            vec!["invoke", "run", "mysql.query", "--profile", "prod"],
            vec!["invoke", "run", "ssh.sftp_list", "--profile", "other"],
            vec!["invoke", "run", "ssh.sftp_list", "--profile", "prod"],
            vec![
                "invoke",
                "run",
                "ssh.sftp_list",
                "--profile",
                "id:profile:test",
                "-pother",
            ],
            vec![
                "invoke",
                "run",
                "ssh.sftp_list",
                "--profile",
                "prod",
                "--input-file",
                "/tmp/input",
            ],
            vec![
                "invoke",
                "run",
                "ssh.sftp_list",
                "--profile=id:profile:test",
                "--input-file=/tmp/input",
            ],
            vec!["invoke", "run", "ssh.exec", "--profile", "prod", "--yes"],
        ] {
            assert!(
                command_allowed(
                    &grant,
                    &argv.into_iter().map(str::to_string).collect::<Vec<_>>()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn default_grant_fails_closed_on_non_read_only_capabilities() {
        assert!(ensure_read_only_capability("ssh.sftp_list").is_ok());
        assert!(ensure_read_only_capability("ssh.exec").is_err());
        assert!(ensure_read_only_capability("missing.capability").is_err());
    }

    #[test]
    fn grant_scope_requires_exact_verified_capabilities() {
        let mode = CapabilityExecutionMode::Stateless;
        assert!(validate_grant_capabilities("ssh", &["*".into()], mode, false).is_err());
        assert!(validate_grant_capabilities("ssh", &["mysql.query".into()], mode, false).is_err());
        assert!(validate_grant_capabilities("ssh", &["ssh.exec".into()], mode, false).is_err());
        assert!(validate_grant_capabilities("ssh", &["ssh.exec".into()], mode, true).is_ok());
        let read_only = read_only_scope("ssh", mode).expect("SSH read-only catalog");
        assert!(read_only.contains(&"ssh.sftp_list".to_string()));
        assert!(!read_only.contains(&"ssh.sftp_get".to_string()));
        assert!(!read_only.contains(&"ssh.exec".to_string()));
        assert!(!read_only.contains(&"*".to_string()));
        let catalog = resolved_authorization_capabilities(Some("ssh"))
            .expect("password-free SSH authorization catalog");
        assert!(
            catalog
                .iter()
                .any(|capability| capability.qualified_id() == "ssh.exec")
        );
        let encoded = serde_json::to_string(&catalog).expect("serialize catalog");
        assert!(!encoded.contains("master_password"));
        assert!(!encoded.contains("socket_path"));
    }

    #[test]
    fn jit_authorization_remains_stateless_only() {
        let definitions = resolved_authorization_capabilities(Some("ssh")).expect("SSH catalog");
        let terminal = definitions
            .iter()
            .find(|definition| definition.qualified_id() == "ssh.terminal_read")
            .expect("terminal capability");
        let error = validate_declared_jit_scope(
            terminal,
            &AgentAuthorizationScope::Capability {
                capability_id: "ssh.terminal_read".into(),
            },
        )
        .expect_err("session-only JIT scope must fail closed");
        assert!(error.to_string().contains("--execution-mode session_only"));

        let stateless = definitions
            .iter()
            .find(|definition| definition.qualified_id() == "ssh.sftp_list")
            .expect("stateless-capable capability");
        assert!(
            validate_declared_jit_scope(
                stateless,
                &AgentAuthorizationScope::Capability {
                    capability_id: "ssh.sftp_list".into(),
                },
            )
            .is_ok()
        );
    }

    #[test]
    fn execution_mode_boundaries_fail_closed_at_invoke_and_session_entrypoints() {
        let invoke = vec![
            "invoke".into(),
            "run".into(),
            "ssh.sftp_list".into(),
            "--profile".into(),
            "id:profile:test".into(),
            "--input-json".into(),
            "{}".into(),
        ];
        let session_call = AgentSessionCallRequest {
            session: AgentSessionRef::new("agent-session:test", 1),
            call_id: "call-mode-boundary".into(),
            capability: "ssh.sftp_list".into(),
            input: json!({}),
            destructive_acknowledged: false,
            timeout_ms: None,
            output_limit_bytes: 1024,
        };

        let stateless = grant();
        assert!(command_allowed(&stateless, &invoke).is_ok());
        assert!(session_call_allowed(&stateless, &session_call).is_err());

        let mut session = grant();
        session.execution_mode = CapabilityExecutionMode::SessionOnly;
        session.capabilities.push("ssh.terminal_read".into());
        assert!(command_allowed(&session, &invoke).is_err());
        assert!(session_call_allowed(&session, &session_call).is_ok());

        let mut open = AgentSessionOpenRequest {
            purpose: PluginSessionPurpose::InteractiveTerminal,
            capabilities: Vec::new(),
            lease_seconds: 300,
            concurrency: AgentSessionConcurrency::Serialized,
            destructive_acknowledged: false,
            input: json!({}),
        };
        assert!(session_open_allowed(&session, &open).is_err());
        open.capabilities = vec!["ssh.terminal_read".into()];
        let mut ungranted = grant();
        ungranted.execution_mode = CapabilityExecutionMode::SessionOnly;
        let error = session_open_allowed(&ungranted, &open)
            .expect_err("ungranted session capability must fail before host open");
        assert!(error.to_string().contains("outside the agent grant scope"));
        assert!(session_open_allowed(&session, &open).is_ok());
        open.capabilities.push("ssh.exec".into());
        assert!(session_open_allowed(&session, &open).is_err());
        open.capabilities = vec!["ssh.terminal_read".into()];
        open.purpose = PluginSessionPurpose::PortForward;
        assert!(session_open_allowed(&session, &open).is_err());

        let mut combined = grant();
        combined.execution_mode = CapabilityExecutionMode::Both;
        assert!(command_allowed(&combined, &invoke).is_ok());
        assert!(session_call_allowed(&combined, &session_call).is_ok());
    }

    #[test]
    fn live_session_start_contract_validates_input_and_side_effect_acknowledgement() {
        let handoff = voidb_core::CapabilitySessionHandoff::new(
            PluginSessionPurpose::LogStream,
            ["docker.logs_follow"],
        )
        .with_live_session(voidb_core::AgentLiveSessionContract {
            protocol_version: voidb_core::AGENT_LIVE_SESSION_PROTOCOL_VERSION,
            kind: voidb_core::AgentLiveSessionKind::Log,
            resource: voidb_core::AgentLiveSessionResourceDescriptor {
                resource_type: "container".into(),
                identity_schema: json!({
                    "type": "object",
                    "required": ["container_id"],
                    "properties": { "container_id": { "type": "string" } },
                    "additionalProperties": false
                }),
                identity_fields: vec!["/container_id".into()],
                audit_identity: voidb_core::AgentLiveSessionAuditIdentity::Fingerprint,
            },
            start_parameters_schema: json!({
                "type": "object",
                "properties": { "follow": { "type": "boolean" } },
                "additionalProperties": false
            }),
            event_schema: json!({ "type": "object" }),
            operations: voidb_core::AgentLiveSessionOperations {
                events: "docker.logs_follow".into(),
                input: None,
                resize: None,
                signal: None,
            },
            buffer: voidb_core::AgentLiveSessionBufferPolicy::default(),
            reconnect: voidb_core::AgentLiveSessionReconnectPolicy::default(),
            delivery: voidb_core::AgentLiveSessionDeliveryPolicy::default(),
            control: voidb_core::AgentLiveSessionControlPolicy::default(),
            start_risk: voidb_core::CapabilityRiskLevel::ExternalSideEffect,
        });
        let mut grant = grant();
        grant.plugin_id = "docker".into();
        grant.capabilities = vec!["docker.logs_follow".into()];
        grant.execution_mode = CapabilityExecutionMode::SessionOnly;
        let mut request = AgentSessionOpenRequest {
            purpose: PluginSessionPurpose::LogStream,
            capabilities: grant.capabilities.clone(),
            lease_seconds: 60,
            concurrency: AgentSessionConcurrency::Serialized,
            destructive_acknowledged: false,
            input: json!({
                "resource": { "container_id": "fixture" },
                "parameters": { "follow": true }
            }),
        };

        let error = live_session_start_allowed(&grant, &request, &handoff)
            .expect_err("read-only grant must reject side-effecting start");
        assert!(error.to_string().contains("grant is read-only"));

        grant.allow_destructive = true;
        let error = live_session_start_allowed(&grant, &request, &handoff)
            .expect_err("start needs per-open acknowledgement");
        assert!(error.to_string().contains("requires --yes"));

        request.destructive_acknowledged = true;
        live_session_start_allowed(&grant, &request, &handoff)
            .expect("valid acknowledged live-session start");
        request.input["parameters"]["follow"] = json!("yes");
        let error = live_session_start_allowed(&grant, &request, &handoff)
            .expect_err("invalid start parameters");
        assert!(error.to_string().contains("does not match"));
        assert!(!error.to_string().contains("fixture"));
    }

    #[test]
    fn legacy_grants_deserialize_as_stateless() {
        let mut encoded = serde_json::to_value(grant()).expect("serialize grant");
        encoded
            .as_object_mut()
            .expect("grant object")
            .remove("execution_mode");
        let legacy: AgentGrantFile = serde_json::from_value(encoded).expect("legacy grant");

        assert_eq!(legacy.execution_mode, CapabilityExecutionMode::Stateless);
        assert!(
            session_call_allowed(
                &legacy,
                &AgentSessionCallRequest {
                    session: AgentSessionRef::new("agent-session:legacy", 1),
                    call_id: "call-legacy".into(),
                    capability: "ssh.sftp_list".into(),
                    input: json!({}),
                    destructive_acknowledged: false,
                    timeout_ms: None,
                    output_limit_bytes: 1024,
                },
            )
            .is_err()
        );
    }

    #[cfg(feature = "full")]
    #[test]
    fn shared_presets_resolve_and_validate_exact_cli_scopes() {
        let stateless = CapabilityExecutionMode::Stateless;
        let (preset, read_only) = resolve_authorization_scope("ssh", stateless, None, None)
            .expect("default read-only scope");
        assert_eq!(preset, AgentAuthorizationPresetKind::ReadOnly);
        assert!(read_only.contains(&"ssh.sftp_list".into()));
        assert!(!read_only.contains(&"ssh.exec".into()));

        let (preset, interactive) =
            resolve_authorization_scope("ssh", stateless, Some("interactive_execute"), None)
                .expect("central interactive scope");
        assert_eq!(preset, AgentAuthorizationPresetKind::InteractiveExecute);
        assert_eq!(interactive, vec!["ssh.exec"]);

        let (preset, full_access) =
            resolve_authorization_scope("ssh", stateless, Some("full_access"), None)
                .expect("central full-access scope");
        assert_eq!(preset, AgentAuthorizationPresetKind::FullAccess);
        assert!(full_access.contains(&"ssh.exec".into()));
        assert!(full_access.contains(&"ssh.sftp_list".into()));
        assert!(!full_access.contains(&"*".into()));
        assert!(validate_grant_capabilities("ssh", &full_access, stateless, false).is_err());
        assert!(validate_grant_capabilities("ssh", &full_access, stateless, true).is_ok());

        let (preset, custom) =
            resolve_authorization_scope("ssh", stateless, None, Some(vec!["ssh.sftp_rm".into()]))
                .expect("explicit capabilities infer Custom");
        assert_eq!(preset, AgentAuthorizationPresetKind::Custom);
        assert_eq!(custom, vec!["ssh.sftp_rm"]);

        assert!(
            resolve_authorization_scope(
                "ssh",
                stateless,
                Some("read_only"),
                Some(vec!["ssh.exec".into()]),
            )
            .is_err()
        );
        assert!(
            resolve_authorization_scope(
                "ssh",
                stateless,
                Some("read_only"),
                Some(vec!["ssh.sftp_list".into()]),
            )
            .is_err()
        );
        assert!(
            resolve_authorization_scope(
                "ssh",
                stateless,
                Some("interactive_execute"),
                Some(vec!["ssh.sftp_rm".into()]),
            )
            .is_err()
        );
        assert!(
            resolve_authorization_scope(
                "ssh",
                stateless,
                Some("full_access"),
                Some(vec!["ssh.sftp_list".into()]),
            )
            .is_err()
        );
        assert!(resolve_authorization_scope("ssh", stateless, Some("custom"), None).is_err());

        let session = CapabilityExecutionMode::SessionOnly;
        let (_, session_read_only) = resolve_authorization_scope("ssh", session, None, None)
            .expect("session read-only scope");
        assert!(session_read_only.contains(&"ssh.terminal_read".into()));
        assert!(session_read_only.contains(&"ssh.forward_status".into()));
        assert!(session_read_only.contains(&"ssh.sftp_list".into()));
        assert!(!session_read_only.contains(&"ssh.diagnostics".into()));
        assert!(
            validate_grant_capabilities("ssh", &["ssh.terminal_read".into()], session, false,)
                .is_ok()
        );
        assert!(
            validate_grant_capabilities("ssh", &["ssh.terminal_read".into()], stateless, false,)
                .is_err()
        );
        assert!(
            validate_grant_capabilities("ssh", &["ssh.diagnostics".into()], session, false,)
                .is_err()
        );

        let (_, combined) = resolve_authorization_scope(
            "ssh",
            CapabilityExecutionMode::Both,
            Some("full_access"),
            None,
        )
        .expect("combined full-access scope");
        assert_eq!(combined.len(), 15);
        assert!(combined.contains(&"ssh.diagnostics".into()));
        assert!(combined.contains(&"ssh.terminal_read".into()));
        assert!(
            validate_grant_capabilities("ssh", &combined, CapabilityExecutionMode::Both, true,)
                .is_ok()
        );
    }

    #[test]
    fn full_access_cli_preset_parses_with_explicit_destructive_acknowledgement() {
        let matches = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "authorize",
                "--profile",
                "docker",
                "--plugin",
                "docker",
                "--preset",
                "full_access",
                "--allow-destructive",
                "--yes",
            ])
            .expect("parse full-access authorization");
        let authorize = matches
            .subcommand_matches("agent")
            .and_then(|matches| matches.subcommand_matches("authorize"))
            .expect("authorize matches");
        assert_eq!(
            authorize.get_one::<String>("preset").map(String::as_str),
            Some("full_access")
        );
        assert_eq!(
            authorize
                .get_one::<String>("execution-mode")
                .map(String::as_str),
            Some("stateless")
        );
        assert!(authorize.get_flag("allow-destructive"));
        assert!(authorize.get_flag("yes"));
        assert_eq!(authorize.get_one::<u32>("uses"), None);

        let session = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "authorize",
                "--profile",
                "ssh-prod",
                "--plugin",
                "ssh",
                "--execution-mode",
                "session_only",
                "--capability",
                "ssh.terminal_read",
            ])
            .expect("parse session authorization");
        let authorize = session
            .subcommand_matches("agent")
            .and_then(|matches| matches.subcommand_matches("authorize"))
            .expect("session authorize matches");
        assert_eq!(
            authorize
                .get_one::<String>("execution-mode")
                .map(String::as_str),
            Some("session_only")
        );
    }

    #[test]
    fn time_bounded_authorization_defaults_to_unlimited_uses_and_keeps_optional_limit() {
        let unlimited = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "authorize",
                "--profile",
                "prod",
                "--plugin",
                "ssh",
            ])
            .expect("parse time-only authorization");
        let unlimited = unlimited
            .subcommand_matches("agent")
            .and_then(|matches| matches.subcommand_matches("authorize"))
            .expect("authorize matches");
        assert_eq!(unlimited.get_one::<u32>("uses"), None);

        let limited = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "authorize",
                "--profile",
                "prod",
                "--plugin",
                "ssh",
                "--uses",
                "3",
            ])
            .expect("parse use-limited authorization");
        let limited = limited
            .subcommand_matches("agent")
            .and_then(|matches| matches.subcommand_matches("authorize"))
            .expect("authorize matches");
        assert_eq!(limited.get_one::<u32>("uses"), Some(&3));
    }

    #[test]
    fn batch_authorization_spec_is_bounded_and_supports_mixed_scopes() {
        let directory =
            PathBuf::from("/tmp").join(format!("vb-agent-batch-spec-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("create batch spec directory");
        let path = directory.join("grants.json");
        fs::write(
            &path,
            br#"{
                "grants": [
                    {
                        "profile":"prod-db",
                        "plugin":"postgres",
                        "purpose":"Inspect replication health during incident INC-42",
                        "preset":"read_only"
                    },
                    {
                        "profile":"prod-ssh",
                        "plugin":"ssh",
                        "purpose":"Verify production uptime during incident INC-42",
                        "execution_mode":"stateless",
                        "capabilities":["ssh.exec"]
                    }
                ]
            }"#,
        )
        .expect("write batch spec");
        let spec = load_batch_authorization_spec(&path).expect("parse batch spec");
        assert_eq!(spec.grants.len(), 2);
        assert_eq!(spec.grants[0].preset.as_deref(), Some("read_only"));
        assert_eq!(
            spec.grants[0].purpose,
            "Inspect replication health during incident INC-42"
        );
        assert_eq!(spec.grants[1].capabilities, vec!["ssh.exec"]);
        assert!(grant_scope_requires_destructive(&spec.grants[1].capabilities).unwrap());
        assert!(validate_review_purpose(&spec.grants[0].purpose).is_ok());
        assert!(validate_review_purpose("   ").is_err());
        assert!(validate_review_purpose(&"x".repeat(1001)).is_err());

        let matches = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "authorize-batch",
                "--spec",
                path.to_str().expect("UTF-8 path"),
                "--ttl-minutes",
                "30",
            ])
            .expect("parse batch authorization");
        let batch = matches
            .subcommand_matches("agent")
            .and_then(|matches| matches.subcommand_matches("authorize-batch"))
            .expect("authorize-batch matches");
        assert_eq!(batch.get_one::<u32>("uses"), None);
        assert_eq!(batch.get_one::<u64>("ttl-minutes"), Some(&30));
        fs::remove_dir_all(directory).expect("remove batch spec directory");
    }

    #[cfg(feature = "full")]
    #[test]
    fn builtin_authorization_metadata_builds_shared_exact_presets() {
        for plugin_id in [
            "sqlite",
            "redis",
            "mysql",
            "postgres",
            "duckdb",
            "ssh",
            "sync",
            "mongodb",
            "elasticsearch",
            "sync",
        ] {
            let definitions = resolved_authorization_capabilities(Some(plugin_id))
                .unwrap_or_else(|error| panic!("{plugin_id} catalog failed: {error}"));
            assert!(
                definitions
                    .iter()
                    .all(|definition| definition.authorization.declared),
                "{plugin_id} has undeclared authorization metadata"
            );
        }

        let definitions = resolved_authorization_capabilities(Some("ssh")).expect("SSH catalog");
        let catalogs = build_authorization_plugin_catalogs(&definitions, Some("ssh"));
        let ssh = catalogs.first().expect("SSH plugin catalog");
        let read_only = ssh
            .presets
            .iter()
            .find(|preset| {
                preset.kind == AgentAuthorizationPresetKind::ReadOnly
                    && preset.execution_mode == CapabilityExecutionMode::Stateless
            })
            .expect("read-only preset");
        assert!(read_only.recommended);
        assert!(read_only.capabilities.contains(&"ssh.sftp_list".into()));
        assert!(!read_only.capabilities.contains(&"ssh.exec".into()));
        let interactive = ssh
            .presets
            .iter()
            .find(|preset| {
                preset.kind == AgentAuthorizationPresetKind::InteractiveExecute
                    && preset.execution_mode == CapabilityExecutionMode::Stateless
            })
            .expect("interactive preset");
        assert_eq!(interactive.capabilities, vec!["ssh.exec"]);
        assert!(interactive.requires_destructive_acknowledgement);
        assert!(interactive.session_purposes.is_empty());

        let session_interactive = ssh
            .presets
            .iter()
            .find(|preset| {
                preset.kind == AgentAuthorizationPresetKind::InteractiveExecute
                    && preset.execution_mode == CapabilityExecutionMode::SessionOnly
            })
            .expect("session interactive preset");
        assert_eq!(session_interactive.capabilities, vec!["ssh.exec"]);
        assert_eq!(
            session_interactive.session_purposes,
            vec![PluginSessionPurpose::InteractiveTerminal]
        );
        let full_access = ssh
            .presets
            .iter()
            .find(|preset| {
                preset.kind == AgentAuthorizationPresetKind::FullAccess
                    && preset.execution_mode == CapabilityExecutionMode::Stateless
            })
            .expect("full-access preset");
        let mut expected = definitions
            .iter()
            .filter(|definition| definition.supports_stateless_execution())
            .map(|definition| definition.qualified_id())
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(full_access.capabilities, expected);
        assert!(!full_access.recommended);
        assert!(full_access.requires_destructive_acknowledgement);

        let combined = ssh
            .presets
            .iter()
            .find(|preset| {
                preset.kind == AgentAuthorizationPresetKind::FullAccess
                    && preset.execution_mode == CapabilityExecutionMode::Both
            })
            .expect("combined full-access preset");
        assert_eq!(combined.capabilities.len(), definitions.len());
        assert!(combined.capabilities.contains(&"ssh.terminal_read".into()));
        assert!(combined.capabilities.contains(&"ssh.diagnostics".into()));
    }

    #[test]
    fn authorization_catalog_filters_supported_modes_and_remains_secret_free() {
        let definitions = resolved_authorization_capabilities(Some("ssh")).expect("SSH catalog");
        let filter = |mode| {
            definitions
                .iter()
                .filter(|definition| capability_matches_execution_modes(definition, &[mode]))
                .map(CapabilityDefinition::qualified_id)
                .collect::<Vec<_>>()
        };
        let stateless = filter(CapabilityExecutionMode::Stateless);
        assert!(stateless.contains(&"ssh.exec".into()));
        assert!(stateless.contains(&"ssh.sftp_list".into()));
        assert!(!stateless.contains(&"ssh.terminal_read".into()));
        let session = filter(CapabilityExecutionMode::SessionOnly);
        assert!(session.contains(&"ssh.exec".into()));
        assert!(session.contains(&"ssh.sftp_list".into()));
        assert!(session.contains(&"ssh.terminal_read".into()));
        assert!(!session.contains(&"ssh.diagnostics".into()));
        let combined = filter(CapabilityExecutionMode::Both);
        assert_eq!(combined.len(), definitions.len());
        assert!(combined.contains(&"ssh.diagnostics".into()));
        assert!(combined.contains(&"ssh.terminal_read".into()));

        let matches = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "catalog",
                "--plugin",
                "ssh",
                "--execution-mode",
                "stateless",
                "--execution-mode",
                "session_only",
                "--format",
                "table",
            ])
            .expect("catalog filters parse");
        let catalog = matches
            .subcommand_matches("agent")
            .and_then(|agent| agent.subcommand_matches("catalog"))
            .expect("catalog matches");
        assert_eq!(
            catalog
                .get_many::<String>("execution-mode")
                .expect("execution filters")
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["stateless", "session_only"]
        );
        assert_eq!(
            catalog.get_one::<String>("format").map(String::as_str),
            Some("table")
        );

        let table = authorization_catalog_table(
            &definitions
                .iter()
                .filter(|definition| definition.plugin_id == "ssh")
                .collect::<Vec<_>>(),
        );
        assert!(table.contains("ssh.terminal_read\tsession_only"));
        assert!(table.contains("interactive_terminal"));

        let encoded = serde_json::to_string(&build_authorization_plugin_catalogs(
            &definitions,
            Some("ssh"),
        ))
        .expect("serialize catalog");
        for forbidden in [
            "master_password",
            "token",
            "socket_path",
            "decrypted_config",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[cfg(feature = "full")]
    #[test]
    fn bundled_plugin_approval_fields_are_real_normalized_input_paths() {
        for plugin_id in [
            "sqlite",
            "redis",
            "mysql",
            "postgres",
            "duckdb",
            "ssh",
            "mongodb",
            "elasticsearch",
        ] {
            let definitions = resolved_authorization_capabilities(Some(plugin_id))
                .unwrap_or_else(|error| panic!("{plugin_id} catalog failed: {error}"));
            let mut schema_count = 0;
            for definition in definitions {
                let Some(schema) = &definition.authorization.approval_schema else {
                    continue;
                };
                schema_count += 1;
                schema.validate().unwrap_or_else(|error| {
                    panic!("{} has invalid schema: {error}", definition.qualified_id())
                });
                for field in &schema.fields {
                    if let Some(contract) = definition
                        .session_handoff
                        .as_ref()
                        .and_then(|handoff| handoff.live_session.as_ref())
                    {
                        let (property, input_schema) = field
                            .path
                            .strip_prefix("/resource/")
                            .map(|property| (property, &contract.resource.identity_schema))
                            .or_else(|| {
                                field
                                    .path
                                    .strip_prefix("/parameters/")
                                    .map(|property| (property, &contract.start_parameters_schema))
                            })
                            .unwrap_or_else(|| {
                                panic!(
                                    "{} declares unsupported live-session approval path {}",
                                    definition.qualified_id(),
                                    field.path
                                )
                            });
                        assert!(
                            input_schema["properties"].get(property).is_some(),
                            "{} declares unenforced or nonexistent session-open field {}",
                            definition.qualified_id(),
                            field.path
                        );
                        continue;
                    }
                    let property = field
                        .path
                        .strip_prefix('/')
                        .expect("approval paths are JSON pointers");
                    assert!(
                        definition.input_schema["properties"]
                            .get(property)
                            .is_some(),
                        "{} declares unenforced or nonexistent input field {}",
                        definition.qualified_id(),
                        field.path
                    );
                }
            }
            assert!(
                schema_count > 0,
                "{plugin_id} has no enforceable structured JIT schema"
            );
        }
    }

    #[cfg(feature = "full")]
    #[test]
    fn incomplete_process_metadata_is_custom_only_and_sync_is_supported() {
        let mut definition = resolved_authorization_capabilities(Some("ssh"))
            .expect("SSH catalog")
            .into_iter()
            .next()
            .expect("SSH capability");
        definition.plugin_id = "example-process".into();
        definition.authorization = Default::default();
        let catalogs = build_authorization_plugin_catalogs(&[definition], None);
        let process = catalogs
            .iter()
            .find(|catalog| catalog.plugin_id == "example-process")
            .expect("process catalog");
        assert_eq!(process.presets.len(), 1);
        assert_eq!(
            process.presets[0].kind,
            AgentAuthorizationPresetKind::Custom
        );
        let sync_definitions =
            resolved_authorization_capabilities(Some("sync")).expect("Sync catalog");
        let sync_catalogs = build_authorization_plugin_catalogs(&sync_definitions, Some("sync"));
        let sync = sync_catalogs.first().expect("sync catalog");
        assert_eq!(
            sync.support.status,
            AgentAuthorizationSupportStatus::Supported
        );
        let read_only = sync
            .presets
            .iter()
            .find(|preset| preset.kind == AgentAuthorizationPresetKind::ReadOnly)
            .expect("Sync read-only preset");
        assert_eq!(
            read_only.capabilities,
            vec!["sync.diagnostics", "sync.diff", "sync.plan", "sync.status"]
        );
        let interactive = sync
            .presets
            .iter()
            .find(|preset| preset.kind == AgentAuthorizationPresetKind::InteractiveExecute)
            .expect("Sync mutation preset");
        assert_eq!(
            interactive.capabilities,
            vec!["sync.conflict_resolve", "sync.recovery"]
        );
        assert!(interactive.requires_destructive_acknowledgement);
    }

    #[test]
    fn lifecycle_cli_requires_explicit_replace_renew_and_profile_revoke() {
        let replace = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "authorize",
                "--profile",
                "id:profile:test",
                "--plugin",
                "ssh",
                "--replace",
            ])
            .expect("parse replace");
        assert!(
            replace
                .subcommand_matches("agent")
                .and_then(|agent| agent.subcommand_matches("authorize"))
                .expect("authorize")
                .get_flag("replace")
        );

        agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "renew",
                "agent-grant:test",
                "--ttl-minutes",
                "5",
                "--uses",
                "3",
            ])
            .expect("parse renew");
        agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "revoke",
                "--profile",
                "id:profile:test",
                "--plugin",
                "ssh",
            ])
            .expect("parse profile revoke");
        assert!(
            agent_command()
                .try_get_matches_from([
                    "voidb-cli",
                    "agent",
                    "revoke",
                    "--profile",
                    "id:profile:test",
                ])
                .is_err()
        );
    }

    #[test]
    fn replacement_and_revoke_selection_are_bound_to_exact_profile_and_plugin() {
        let first = grant();
        let mut other_profile = first.clone();
        other_profile.id = "agent-grant:other-profile".into();
        other_profile.profile_id = "profile:other".into();
        other_profile.profile_name = "other".into();
        let mut other_plugin = first.clone();
        other_plugin.id = "agent-grant:other-plugin".into();
        other_plugin.plugin_id = "mysql".into();
        other_plugin.capabilities = vec!["mysql.query".into()];
        let grants = vec![first.clone(), other_profile, other_plugin];

        let replacements = grants_for_profile(&grants, &first.profile_id, &first.plugin_id);
        assert_eq!(replacements.len(), 1);
        assert_eq!(replacements[0].id, first.id);

        let profile = format!("id:{}", first.profile_id);
        let plugin = first.plugin_id.clone();
        let scoped = select_grants_for_revoke(&grants, false, None, Some(&profile), Some(&plugin));
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].id, first.id);
        assert_eq!(
            select_grants_for_revoke(&grants, true, None, None, None).len(),
            3
        );
    }

    #[tokio::test]
    async fn forged_broker_token_is_denied_without_consuming_use_or_exposing_state() {
        let mut grant = grant();
        grant.token = "broker-secret-6ed71a".into();
        let remaining_uses = grant.remaining_uses;
        let mut host = AgentSessionHost::new(
            grant.id.clone(),
            grant.profile_id.clone(),
            grant.plugin_id.clone(),
            grant.capabilities.clone(),
            grant.expires_at,
            1,
        );
        let (response, terminate) = handle_broker_request(
            &mut grant,
            &mut host,
            "master-password-must-not-escape",
            BrokerRequest::Inspect {
                token: "forged-token".into(),
            },
        )
        .await;
        assert!(!response.ok);
        assert!(!terminate);
        assert_eq!(grant.remaining_uses, remaining_uses);
        assert_eq!(response.data, None);
        let encoded = serde_json::to_string(&response).expect("serialize denial");
        assert!(!encoded.contains(&grant.token));
        assert!(!encoded.contains("master-password-must-not-escape"));
    }

    #[tokio::test]
    async fn grant_inspection_distinguishes_offline_and_stale_socket() {
        let directory = PathBuf::from("/tmp").join(format!("vb-agent-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("create temp directory");
        let mut grant = grant();
        grant.socket_path = directory.join("grant.sock");
        assert_eq!(
            inspect_grant(&grant).await.broker_health,
            AgentBrokerHealth::Offline
        );
        fs::write(&grant.socket_path, b"not-a-socket").expect("write stale socket marker");
        assert_eq!(
            inspect_grant(&grant).await.broker_health,
            AgentBrokerHealth::StaleSocket
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn stale_recovery_removes_orphaned_socket_without_credentials() {
        let directory = PathBuf::from("/tmp").join(format!("vb-agent-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("create temp directory");
        let mut grant = grant();
        grant.id = format!("agent-grant:{}", Uuid::new_v4());
        grant.socket_path = directory.join("grant.sock");
        fs::write(&grant.socket_path, b"orphaned").expect("write stale socket marker");

        shutdown_grant(&grant, "stale_recovery")
            .await
            .expect("recover stale grant");

        assert!(!grant.socket_path.exists());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn public_grant_projection_excludes_token_and_socket_path() {
        let grant = grant();
        let public = grant.public(AgentBrokerHealth::Online, 2);
        let value = frontend_grant_value(&public, Utc::now()).expect("serialize public grant");
        assert_eq!(value["active_session_count"], 2);
        assert_eq!(value["status"], "active");
        assert_eq!(value["active"], true);
        assert_eq!(value["allow_destructive"], false);
        assert_eq!(value["execution_mode"], "stateless");
        assert_eq!(value.get("grant"), None);
        assert_eq!(value.get("token"), None);
        assert_eq!(value.get("socket_path"), None);
    }

    #[test]
    fn session_calls_recheck_capability_and_destructive_policy() {
        let mut grant = grant();
        grant.execution_mode = CapabilityExecutionMode::SessionOnly;
        grant
            .capabilities
            .extend(["ssh.terminal_read".into(), "ssh.terminal_write".into()]);
        let read_only = AgentSessionCallRequest {
            session: AgentSessionRef::new("session-1", 1),
            call_id: "call-1".into(),
            capability: "ssh.sftp_list".into(),
            input: Value::Null,
            destructive_acknowledged: false,
            timeout_ms: None,
            output_limit_bytes: 1024,
        };
        assert!(session_call_allowed(&grant, &read_only).is_ok());
        assert!(
            session_call_allowed(
                &grant,
                &AgentSessionCallRequest {
                    capability: "ssh.terminal_read".into(),
                    ..read_only.clone()
                }
            )
            .is_ok()
        );

        let destructive = AgentSessionCallRequest {
            capability: "ssh.exec".into(),
            ..read_only.clone()
        };
        assert!(session_call_allowed(&grant, &destructive).is_err());
        grant.allow_destructive = true;
        assert!(session_call_allowed(&grant, &destructive).is_err());
        assert!(
            session_call_allowed(
                &grant,
                &AgentSessionCallRequest {
                    destructive_acknowledged: true,
                    ..destructive
                }
            )
            .is_ok()
        );
        assert!(
            session_call_allowed(
                &grant,
                &AgentSessionCallRequest {
                    capability: "ssh.terminal_write".into(),
                    input: json!({ "keys": ["CTRL_C"] }),
                    destructive_acknowledged: true,
                    ..read_only
                }
            )
            .is_ok()
        );
    }

    #[test]
    fn session_cli_parses_machine_readable_operation_envelopes() {
        let open = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "session",
                "open",
                "--grant",
                "agent-grant:test",
                "--purpose",
                "log_stream",
                "--capability",
                "docker.logs_follow",
                "--input-json",
                r#"{"resource":{"container_id":"fixture"}}"#,
                "--yes",
            ])
            .expect("parse session open");
        let open = open
            .subcommand_matches("agent")
            .and_then(|agent| agent.subcommand_matches("session"))
            .and_then(|session| session.subcommand_matches("open"))
            .expect("open matches");
        assert!(open.get_flag("yes"));

        let matches = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "session",
                "call",
                "--grant",
                "agent-grant:test",
                "agent-session:test",
                "--generation",
                "3",
                "--capability",
                "ssh.exec",
                "--call-id",
                "call:known-before-start",
                "--input-json",
                r#"{"command":"pwd"}"#,
                "--yes",
            ])
            .expect("parse session call");
        let operation = matches
            .subcommand_matches("agent")
            .and_then(|agent| agent.subcommand_matches("session"))
            .and_then(|session| session.subcommand_matches("call"))
            .expect("call matches");
        assert_eq!(session_ref(operation).generation, 3);
        assert_eq!(
            parse_session_json(operation, "input-json").expect("input"),
            json!({ "command": "pwd" })
        );
        assert!(operation.get_flag("yes"));
        assert_eq!(
            session_call_id(operation).expect("call ID"),
            "call:known-before-start"
        );
    }

    #[test]
    fn session_cli_exposes_start_status_wait_and_control_lifecycle() {
        let start = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "session",
                "start",
                "--grant",
                "agent-grant:test",
                "agent-session:test",
                "--generation",
                "2",
                "--capability",
                "ssh.terminal_read",
                "--call-id",
                "call:async",
            ])
            .expect("parse start");
        let start = start
            .subcommand_matches("agent")
            .and_then(|agent| agent.subcommand_matches("session"))
            .and_then(|session| session.subcommand_matches("start"))
            .expect("start matches");
        let request = session_call_request(start).expect("start request");
        assert_eq!(request.call_id, "call:async");
        assert_eq!(request.session.generation, 2);

        let status = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "session",
                "status",
                "--grant",
                "agent-grant:test",
                "agent-session:test",
                "--call-id",
                "call:async",
            ])
            .expect("parse call status");
        let status = status
            .subcommand_matches("agent")
            .and_then(|agent| agent.subcommand_matches("session"))
            .and_then(|session| session.subcommand_matches("status"))
            .expect("status matches");
        assert_eq!(
            status.get_one::<String>("call-id").map(String::as_str),
            Some("call:async")
        );

        let wait = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "session",
                "wait",
                "--grant",
                "agent-grant:test",
                "agent-session:test",
                "--call-id",
                "call:async",
                "--wait-timeout-ms",
                "250",
            ])
            .expect("parse wait");
        let wait = wait
            .subcommand_matches("agent")
            .and_then(|agent| agent.subcommand_matches("session"))
            .and_then(|session| session.subcommand_matches("wait"))
            .expect("wait matches");
        assert_eq!(wait.get_one::<u64>("wait-timeout-ms"), Some(&250));
    }

    #[test]
    fn broker_wire_protocol_negotiates_with_legacy_requests_and_responses() {
        let legacy_request: BrokerWireRequest = serde_json::from_value(json!({
            "action": "inspect",
            "token": "opaque"
        }))
        .expect("legacy request");
        assert_eq!(
            legacy_request.protocol_version,
            AGENT_BROKER_LEGACY_PROTOCOL_VERSION
        );

        let current_request = serde_json::to_value(BrokerWireRequest {
            protocol_version: AGENT_BROKER_PROTOCOL_VERSION,
            request: BrokerRequest::Inspect {
                token: "opaque".into(),
            },
        })
        .expect("current request");
        assert_eq!(
            current_request["protocol_version"],
            AGENT_BROKER_PROTOCOL_VERSION
        );
        assert_eq!(current_request["action"], "inspect");
        let legacy_broker_view: BrokerRequest =
            serde_json::from_value(current_request).expect("new request accepted by v1 broker");
        assert!(matches!(legacy_broker_view, BrokerRequest::Inspect { .. }));

        let grant = grant();
        let current_response = broker_data_response(&grant, json!({ "broker": "online" }));
        let mut legacy_response = serde_json::to_value(current_response).expect("response");
        legacy_response
            .as_object_mut()
            .expect("response object")
            .remove("protocol_version");
        let legacy_response: BrokerResponse =
            serde_json::from_value(legacy_response).expect("legacy response");
        assert_eq!(
            legacy_response.protocol_version,
            AGENT_BROKER_LEGACY_PROTOCOL_VERSION
        );
    }

    #[test]
    fn session_cli_rejects_non_public_caller_owned_call_ids() {
        let matches = agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "session",
                "call",
                "--grant",
                "agent-grant:test",
                "agent-session:test",
                "--capability",
                "ssh.exec",
                "--call-id",
                "contains a space",
            ])
            .expect("parse session call");
        let operation = matches
            .subcommand_matches("agent")
            .and_then(|agent| agent.subcommand_matches("session"))
            .and_then(|session| session.subcommand_matches("call"))
            .expect("call matches");
        let error = session_call_id(operation).expect_err("invalid call ID");
        assert!(error.to_string().contains("session.call_id_invalid"));
    }

    #[test]
    fn session_audit_excludes_inputs_outputs_tokens_and_secret_values() {
        let grant = grant();
        let response = BrokerResponse {
            protocol_version: AGENT_BROKER_PROTOCOL_VERSION,
            ok: true,
            exit_code: 0,
            stdout: "secret-stdout".into(),
            stderr: "secret-stderr".into(),
            error: None,
            error_code: None,
            data: Some(json!({
                "session": { "session_id": "agent-session:test", "generation": 1 },
                "output": "top-secret-output"
            })),
            remaining_uses: Some(9),
            expires_at: grant.expires_at,
        };
        let event = build_agent_session_audit_event(
            &grant,
            AuditOperation::SessionCall,
            &response,
            AgentSessionAuditContext {
                session: Some(&AgentSessionRef::new("agent-session:test", 1)),
                call_id: Some("call:audit-safe"),
                capability: Some("ssh.exec"),
                purpose: Some(&PluginSessionPurpose::InteractiveTerminal),
            },
            Utc::now(),
        );
        let encoded = serde_json::to_string(&event).expect("serialize audit");
        assert!(encoded.contains("agent-session:test"));
        assert!(encoded.contains("call:audit-safe"));
        assert!(encoded.contains("ssh.exec"));
        for secret in [
            "secret-stdout",
            "secret-stderr",
            "top-secret-output",
            grant.token.as_str(),
        ] {
            assert!(!encoded.contains(secret));
        }
        assert_eq!(event.redaction, RedactionStatus::Applied);
    }

    #[test]
    fn expired_or_exhausted_grants_are_rejected() {
        let mut grant = grant();
        grant.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(
            command_allowed(
                &grant,
                &[
                    "profile".into(),
                    "test".into(),
                    "id:profile:test".into(),
                    "--plugin".into(),
                    "ssh".into()
                ]
            )
            .is_err()
        );
        grant.expires_at = Utc::now() + chrono::Duration::minutes(1);
        grant.remaining_uses = Some(0);
        assert!(
            command_allowed(
                &grant,
                &[
                    "profile".into(),
                    "test".into(),
                    "id:profile:test".into(),
                    "--plugin".into(),
                    "ssh".into()
                ]
            )
            .is_err()
        );

        grant.remaining_uses = None;
        assert!(
            command_allowed(
                &grant,
                &[
                    "profile".into(),
                    "test".into(),
                    "id:profile:test".into(),
                    "--plugin".into(),
                    "ssh".into()
                ]
            )
            .is_ok()
        );
        consume_agent_use(&mut grant, "profile", "test", None);
        assert_eq!(grant.remaining_uses, None);
    }

    #[tokio::test]
    async fn password_pipe_is_closed_after_the_password_is_written() {
        let (writer, mut reader) = tokio::io::duplex(64);
        let receive = tokio::spawn(async move {
            let mut bytes = Vec::new();
            reader
                .read_to_end(&mut bytes)
                .await
                .expect("read password pipe to EOF");
            bytes
        });

        write_password_and_close(writer, b"test-password")
            .await
            .expect("write and close password pipe");
        assert_eq!(
            receive.await.expect("password reader exits"),
            b"test-password"
        );
    }

    #[cfg(unix)]
    #[test]
    fn grant_rewrites_remain_parseable_during_concurrent_reads() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let directory = PathBuf::from("/tmp").join(format!("vb-agent-write-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("create temp grant directory");
        let grant_path = directory.join("grant.json");
        let mut grant = grant();
        write_grant(&grant_path, &grant).expect("write initial grant");

        let done = Arc::new(AtomicBool::new(false));
        let reader_done = Arc::clone(&done);
        let reader_path = grant_path.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            read_grant(&reader_path).expect("initial atomic grant read");
            ready_tx.send(()).expect("signal reader ready");
            let mut reads = 1;
            while !reader_done.load(Ordering::Acquire) {
                read_grant(&reader_path).expect("an atomic grant read");
                reads += 1;
            }
            reads
        });

        ready_rx.recv().expect("reader becomes ready");
        for remaining_uses in 1..=100 {
            grant.remaining_uses = Some(remaining_uses);
            write_grant(&grant_path, &grant).expect("rewrite grant");
        }
        done.store(true, Ordering::Release);
        assert!(reader.join().expect("reader exits") > 0);
        assert_eq!(
            fs::metadata(&grant_path)
                .expect("grant metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_dir(&directory)
                .expect("read temp directory")
                .count(),
            1
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn broker_accepts_status_cancel_and_serialized_starts_during_a_blocked_call() {
        let directory =
            PathBuf::from("/tmp").join(format!("vb-agent-concurrent-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("create temp grant directory");
        let grant_path = directory.join("grant.json");
        let mut grant = grant();
        grant.socket_path = directory.join("grant.sock");
        grant.execution_mode = CapabilityExecutionMode::SessionOnly;
        grant.capabilities = vec!["ssh.terminal_read".into()];
        grant.remaining_uses = Some(2);
        write_grant(&grant_path, &grant).expect("write grant");

        let fixture = Arc::new(BlockingSessionState::default());
        let mut host = AgentSessionHost::new(
            grant.id.clone(),
            grant.profile_id.clone(),
            grant.plugin_id.clone(),
            grant.capabilities.clone(),
            grant.expires_at,
            1,
        );
        host.register_factory(Arc::new(BlockingSessionFactory {
            state: Arc::clone(&fixture),
        }));
        let session = host
            .open(
                AgentSessionOpenRequest {
                    purpose: PluginSessionPurpose::InteractiveTerminal,
                    capabilities: grant.capabilities.clone(),
                    lease_seconds: 60,
                    concurrency: AgentSessionConcurrency::Serialized,
                    destructive_acknowledged: false,
                    input: Value::Null,
                },
                Utc::now(),
            )
            .await
            .expect("open fixture session")
            .session;

        let broker_path = grant_path.clone();
        let broker_grant = grant.clone();
        let broker = tokio::spawn(async move {
            broker_loop_with_host(&broker_path, broker_grant, host, "test-password").await
        });
        wait_for_socket(&grant.socket_path)
            .await
            .expect("broker socket ready");

        let call_request = |call_id: &str| AgentSessionCallRequest {
            session: session.clone(),
            call_id: call_id.into(),
            capability: "ssh.terminal_read".into(),
            input: json!({ "offset": 0 }),
            destructive_acknowledged: false,
            timeout_ms: Some(5_000),
            output_limit_bytes: 1024,
        };
        let first = send_request(
            &grant,
            BrokerRequest::SessionCallStart {
                token: grant.token.clone(),
                request: call_request("call:first"),
            },
        )
        .await
        .expect("start first call");
        assert!(first.ok);
        wait_for_started_calls(&fixture, 1).await;

        let duplicate = send_request(
            &grant,
            BrokerRequest::SessionCallStart {
                token: grant.token.clone(),
                request: call_request("call:first"),
            },
        )
        .await
        .expect("duplicate start response");
        assert!(!duplicate.ok);
        assert_eq!(
            duplicate.error_code.as_deref(),
            Some("session.call_id_conflict")
        );
        assert_eq!(duplicate.remaining_uses, Some(1));

        let second = send_request(
            &grant,
            BrokerRequest::SessionCallStart {
                token: grant.token.clone(),
                request: call_request("call:second"),
            },
        )
        .await
        .expect("queue second call");
        assert!(second.ok);
        assert_eq!(second.remaining_uses, Some(0));
        let exhausted = send_request(
            &grant,
            BrokerRequest::SessionCallStart {
                token: grant.token.clone(),
                request: call_request("call:exhausted"),
            },
        )
        .await
        .expect("exhausted start response");
        assert!(!exhausted.ok);
        assert_eq!(exhausted.error_code.as_deref(), Some("session.expired"));
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(
            fixture
                .started
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_slice(),
            ["call:first"]
        );

        let status = tokio::time::timeout(
            Duration::from_millis(200),
            send_request(
                &grant,
                BrokerRequest::SessionCallStatus {
                    token: grant.token.clone(),
                    request: AgentSessionCallStatusRequest {
                        session: session.clone(),
                        call_id: "call:first".into(),
                    },
                },
            ),
        )
        .await
        .expect("call status remains responsive")
        .expect("status response");
        let status: AgentSessionCallView =
            serde_json::from_value(status.data.expect("status data")).expect("call status");
        assert_eq!(status.lifecycle.state, AgentSessionCallState::Running);

        let timed_wait = send_request(
            &grant,
            BrokerRequest::SessionCallWait {
                token: grant.token.clone(),
                request: AgentSessionCallWaitRequest {
                    session: session.clone(),
                    call_id: "call:first".into(),
                    timeout_ms: Some(10),
                },
            },
        )
        .await
        .expect("bounded non-terminal wait");
        let timed_wait: AgentSessionCallWaitResult =
            serde_json::from_value(timed_wait.data.expect("timed wait data"))
                .expect("timed wait result");
        assert!(timed_wait.wait_timed_out);
        assert_eq!(
            timed_wait.call.lifecycle.state,
            AgentSessionCallState::Running
        );

        let list = tokio::time::timeout(
            Duration::from_millis(200),
            send_request(
                &grant,
                BrokerRequest::SessionList {
                    token: grant.token.clone(),
                    request: AgentSessionListRequest::default(),
                },
            ),
        )
        .await
        .expect("session list remains responsive")
        .expect("list response");
        assert!(list.ok);
        assert_eq!(list.data.expect("list data")["count"], 1);

        let cancel_first = tokio::time::timeout(
            Duration::from_millis(200),
            send_request(
                &grant,
                BrokerRequest::SessionCancel {
                    token: grant.token.clone(),
                    request: AgentSessionCancelRequest {
                        session: session.clone(),
                        call_id: "call:first".into(),
                        timeout_ms: None,
                    },
                },
            ),
        )
        .await
        .expect("cancel remains responsive")
        .expect("cancel response");
        assert!(cancel_first.ok);
        let first_wait = send_request(
            &grant,
            BrokerRequest::SessionCallWait {
                token: grant.token.clone(),
                request: AgentSessionCallWaitRequest {
                    session: session.clone(),
                    call_id: "call:first".into(),
                    timeout_ms: Some(500),
                },
            },
        )
        .await
        .expect("wait first call");
        let first_wait: AgentSessionCallWaitResult =
            serde_json::from_value(first_wait.data.expect("wait data")).expect("wait result");
        assert!(!first_wait.wait_timed_out);
        assert_eq!(
            first_wait.call.lifecycle.state,
            AgentSessionCallState::Cancelled
        );

        wait_for_started_calls(&fixture, 2).await;
        assert_eq!(fixture.max_active.load(Ordering::SeqCst), 1);
        send_request(
            &grant,
            BrokerRequest::SessionCancel {
                token: grant.token.clone(),
                request: AgentSessionCancelRequest {
                    session: session.clone(),
                    call_id: "call:second".into(),
                    timeout_ms: None,
                },
            },
        )
        .await
        .expect("cancel second call");
        let second_wait = send_request(
            &grant,
            BrokerRequest::SessionCallWait {
                token: grant.token.clone(),
                request: AgentSessionCallWaitRequest {
                    session: session.clone(),
                    call_id: "call:second".into(),
                    timeout_ms: Some(500),
                },
            },
        )
        .await
        .expect("wait second call");
        let second_wait: AgentSessionCallWaitResult =
            serde_json::from_value(second_wait.data.expect("wait data")).expect("wait result");
        assert_eq!(
            second_wait.call.lifecycle.state,
            AgentSessionCallState::Cancelled
        );

        send_request(
            &grant,
            BrokerRequest::SessionClose {
                token: grant.token.clone(),
                request: AgentSessionCloseAgentRequest {
                    session,
                    reason: "test_complete".into(),
                    timeout_ms: None,
                },
            },
        )
        .await
        .expect("close session");
        send_request(
            &grant,
            BrokerRequest::Shutdown {
                token: grant.token.clone(),
            },
        )
        .await
        .expect("shutdown response");
        broker.await.expect("broker task").expect("broker exits");
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn broker_race_cancels_a_queued_call_before_driver_execution() {
        let directory =
            PathBuf::from("/tmp").join(format!("vb-agent-cancel-queued-{}", Uuid::new_v4()));
        let mut grant = grant();
        grant.remaining_uses = Some(2);
        let broker = RunningBlockingBroker::start(
            &directory,
            grant,
            1,
            PluginSessionPurpose::InteractiveTerminal,
        )
        .await;

        let first = send_request(
            &broker.grant,
            BrokerRequest::SessionCallStart {
                token: broker.grant.token.clone(),
                request: broker.call_request("call:running"),
            },
        )
        .await
        .expect("start running call");
        assert!(first.ok);
        wait_for_started_calls(&broker.state, 1).await;

        let queued = send_request(
            &broker.grant,
            BrokerRequest::SessionCallStart {
                token: broker.grant.token.clone(),
                request: broker.call_request("call:queued"),
            },
        )
        .await
        .expect("queue serialized call");
        assert!(queued.ok);

        let cancel = tokio::time::timeout(
            Duration::from_millis(200),
            send_request(
                &broker.grant,
                BrokerRequest::SessionCancel {
                    token: broker.grant.token.clone(),
                    request: AgentSessionCancelRequest {
                        session: broker.session.clone(),
                        call_id: "call:queued".into(),
                        timeout_ms: None,
                    },
                },
            ),
        )
        .await
        .expect("queued cancel remains responsive")
        .expect("queued cancel response");
        assert!(cancel.ok);

        let queued_wait = tokio::time::timeout(
            Duration::from_millis(200),
            send_request(
                &broker.grant,
                BrokerRequest::SessionCallWait {
                    token: broker.grant.token.clone(),
                    request: AgentSessionCallWaitRequest {
                        session: broker.session.clone(),
                        call_id: "call:queued".into(),
                        timeout_ms: Some(150),
                    },
                },
            ),
        )
        .await
        .expect("queued call reaches a terminal state without waiting for the gate")
        .expect("queued wait response");
        let queued_wait: AgentSessionCallWaitResult =
            serde_json::from_value(queued_wait.data.expect("queued wait data"))
                .expect("queued wait result");
        assert!(!queued_wait.wait_timed_out);
        assert_eq!(
            queued_wait.call.lifecycle.state,
            AgentSessionCallState::Cancelled
        );
        assert_eq!(queued_wait.call.lifecycle.started_at, None);
        assert_eq!(
            broker
                .state
                .started
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_slice(),
            ["call:running"]
        );
        assert_eq!(broker.state.active.load(Ordering::SeqCst), 1);

        send_request(
            &broker.grant,
            BrokerRequest::SessionCancel {
                token: broker.grant.token.clone(),
                request: AgentSessionCancelRequest {
                    session: broker.session.clone(),
                    call_id: "call:running".into(),
                    timeout_ms: None,
                },
            },
        )
        .await
        .expect("cancel running call");
        wait_for_active_calls(&broker.state, 0).await;
        broker.shutdown().await;
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn broker_race_close_aborts_an_inflight_transaction_and_cleans_runtime_artifacts() {
        let directory =
            PathBuf::from("/tmp").join(format!("vb-agent-close-race-{}", Uuid::new_v4()));
        let mut grant = grant();
        grant.remaining_uses = Some(1);
        let broker = RunningBlockingBroker::start(
            &directory,
            grant,
            7,
            PluginSessionPurpose::DatabaseTransaction,
        )
        .await;
        let grant_path = broker.grant_path.clone();
        let socket_path = broker.grant.socket_path.clone();

        let started = send_request(
            &broker.grant,
            BrokerRequest::SessionCallStart {
                token: broker.grant.token.clone(),
                request: broker.call_request("call:transaction"),
            },
        )
        .await
        .expect("start transaction call");
        assert!(started.ok);
        wait_for_started_calls(&broker.state, 1).await;

        let closed = tokio::time::timeout(
            Duration::from_millis(200),
            send_request(
                &broker.grant,
                BrokerRequest::SessionClose {
                    token: broker.grant.token.clone(),
                    request: AgentSessionCloseAgentRequest {
                        session: broker.session.clone(),
                        reason: "transaction_owner_closed".into(),
                        timeout_ms: Some(100),
                    },
                },
            ),
        )
        .await
        .expect("close remains responsive during transaction I/O")
        .expect("close response");
        assert!(closed.ok);
        let calls: Vec<AgentSessionCallView> =
            serde_json::from_value(closed.data.expect("close data")["calls"].clone())
                .expect("closed call list");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].lifecycle.state, AgentSessionCallState::Aborted);
        assert_eq!(
            calls[0].lifecycle.control,
            Some(AgentSessionControlKind::Close)
        );
        wait_for_active_calls(&broker.state, 0).await;
        assert!(broker.state.closed.load(Ordering::SeqCst));
        assert_eq!(broker.state.cleanup_count.load(Ordering::SeqCst), 1);

        let repeated = send_request(
            &broker.grant,
            BrokerRequest::SessionClose {
                token: broker.grant.token.clone(),
                request: AgentSessionCloseAgentRequest {
                    session: broker.session.clone(),
                    reason: "repeat".into(),
                    timeout_ms: None,
                },
            },
        )
        .await
        .expect("repeat close response");
        assert!(repeated.ok);
        assert_eq!(broker.state.cleanup_count.load(Ordering::SeqCst), 1);

        broker.shutdown().await;
        assert!(!socket_path.exists());
        assert!(!grant_path.exists());
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn broker_race_restart_rejects_stale_ids_and_reuses_only_the_caller_call_id() {
        let directory = PathBuf::from("/tmp").join(format!("vb-agent-restart-{}", Uuid::new_v4()));
        let mut grant = grant();
        grant.remaining_uses = Some(2);

        let first = RunningBlockingBroker::start(
            &directory,
            grant.clone(),
            11,
            PluginSessionPurpose::InteractiveTerminal,
        )
        .await;
        let old_session = first.session.clone();
        let old_state = Arc::clone(&first.state);
        let grant_path = first.grant_path.clone();
        let socket_path = first.grant.socket_path.clone();
        let started = send_request(
            &first.grant,
            BrokerRequest::SessionCallStart {
                token: first.grant.token.clone(),
                request: first.call_request("call:reused-after-restart"),
            },
        )
        .await
        .expect("start pre-restart call");
        assert!(started.ok);
        wait_for_started_calls(&first.state, 1).await;
        first.shutdown().await;
        wait_for_active_calls(&old_state, 0).await;
        assert_eq!(old_state.cleanup_count.load(Ordering::SeqCst), 1);
        assert!(!socket_path.exists());
        assert!(!grant_path.exists());

        let restarted = RunningBlockingBroker::start(
            &directory,
            grant,
            12,
            PluginSessionPurpose::InteractiveTerminal,
        )
        .await;
        assert_ne!(restarted.session.session_id, old_session.session_id);

        let stale_call = send_request(
            &restarted.grant,
            BrokerRequest::SessionCallStatus {
                token: restarted.grant.token.clone(),
                request: AgentSessionCallStatusRequest {
                    session: old_session.clone(),
                    call_id: "call:reused-after-restart".into(),
                },
            },
        )
        .await
        .expect("stale call response");
        assert_eq!(
            stale_call.error_code.as_deref(),
            Some("session.call_not_found")
        );

        let stale_session = send_request(
            &restarted.grant,
            BrokerRequest::SessionStatus {
                token: restarted.grant.token.clone(),
                request: AgentSessionStatusRequest {
                    session: old_session,
                },
            },
        )
        .await
        .expect("stale session response");
        assert_eq!(
            stale_session.error_code.as_deref(),
            Some("session.not_found")
        );

        let mut wrong_generation = restarted.session.clone();
        wrong_generation.generation += 1;
        let stale_generation = send_request(
            &restarted.grant,
            BrokerRequest::SessionStatus {
                token: restarted.grant.token.clone(),
                request: AgentSessionStatusRequest {
                    session: wrong_generation,
                },
            },
        )
        .await
        .expect("stale generation response");
        assert_eq!(
            stale_generation.error_code.as_deref(),
            Some("session.stale")
        );

        let reused = send_request(
            &restarted.grant,
            BrokerRequest::SessionCallStart {
                token: restarted.grant.token.clone(),
                request: restarted.call_request("call:reused-after-restart"),
            },
        )
        .await
        .expect("reuse caller call ID in the new broker generation");
        assert!(reused.ok);
        wait_for_started_calls(&restarted.state, 1).await;
        send_request(
            &restarted.grant,
            BrokerRequest::SessionCancel {
                token: restarted.grant.token.clone(),
                request: AgentSessionCancelRequest {
                    session: restarted.session.clone(),
                    call_id: "call:reused-after-restart".into(),
                    timeout_ms: None,
                },
            },
        )
        .await
        .expect("cancel post-restart call");
        wait_for_active_calls(&restarted.state, 0).await;
        restarted.shutdown().await;
        assert!(!socket_path.exists());
        assert!(!grant_path.exists());
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn broker_race_concurrent_duplicate_callers_have_one_winner_across_repeated_rounds() {
        const ROUNDS: usize = 6;
        const CALLERS: usize = 8;

        let directory =
            PathBuf::from("/tmp").join(format!("vb-agent-caller-race-{}", Uuid::new_v4()));
        let mut grant = grant();
        grant.remaining_uses = Some(ROUNDS as u32 + 1);
        let broker = RunningBlockingBroker::start(
            &directory,
            grant,
            21,
            PluginSessionPurpose::InteractiveTerminal,
        )
        .await;

        for round in 0..ROUNDS {
            let call_id = format!("call:race:{round}");
            let barrier = Arc::new(tokio::sync::Barrier::new(CALLERS + 1));
            let mut callers = JoinSet::new();
            for _ in 0..CALLERS {
                let barrier = Arc::clone(&barrier);
                let grant = broker.grant.clone();
                let request = broker.call_request(&call_id);
                callers.spawn(async move {
                    barrier.wait().await;
                    send_request(
                        &grant,
                        BrokerRequest::SessionCallStart {
                            token: grant.token.clone(),
                            request,
                        },
                    )
                    .await
                });
            }
            barrier.wait().await;

            let mut accepted = 0;
            let mut conflicts = 0;
            let mut other_errors = Vec::new();
            while let Some(response) = callers.join_next().await {
                let response = response
                    .expect("concurrent caller task")
                    .expect("concurrent caller response");
                if response.ok {
                    accepted += 1;
                } else if response.error_code.as_deref() == Some("session.call_id_conflict") {
                    conflicts += 1;
                } else {
                    other_errors.push((response.error_code, response.error));
                }
            }
            assert_eq!(accepted, 1);
            assert_eq!(conflicts, CALLERS - 1, "other errors: {other_errors:?}");
            assert_eq!(
                read_grant(&broker.grant_path)
                    .expect("persisted use reservation")
                    .remaining_uses,
                Some((ROUNDS - round) as u32)
            );
            wait_for_started_calls(&broker.state, round + 1).await;

            send_request(
                &broker.grant,
                BrokerRequest::SessionCancel {
                    token: broker.grant.token.clone(),
                    request: AgentSessionCancelRequest {
                        session: broker.session.clone(),
                        call_id,
                        timeout_ms: None,
                    },
                },
            )
            .await
            .expect("cancel winning call");
            wait_for_active_calls(&broker.state, 0).await;
        }

        assert_eq!(
            broker
                .state
                .started
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            ROUNDS
        );
        assert_eq!(broker.state.max_active.load(Ordering::SeqCst), 1);
        broker.shutdown().await;
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn broker_shutdown_removes_private_runtime_artifacts() {
        let directory = PathBuf::from("/tmp").join(format!("vb-agent-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("create temp grant directory");
        let grant_path = directory.join("grant.json");
        let mut grant = grant();
        grant.socket_path = directory.join("grant.sock");
        write_grant(&grant_path, &grant).expect("write grant");

        let broker_path = grant_path.clone();
        let broker = tokio::spawn(async move { broker_loop(&broker_path, "test-password").await });
        wait_for_socket(&grant.socket_path)
            .await
            .expect("broker socket ready");
        assert_eq!(
            fs::metadata(&grant_path)
                .expect("grant metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&grant.socket_path)
                .expect("broker socket metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let mut legacy = UnixStream::connect(&grant.socket_path)
            .await
            .expect("connect legacy client");
        legacy
            .write_all(
                &serde_json::to_vec(&BrokerWireRequest {
                    protocol_version: AGENT_BROKER_LEGACY_PROTOCOL_VERSION,
                    request: BrokerRequest::SessionCallStatus {
                        token: grant.token.clone(),
                        request: AgentSessionCallStatusRequest {
                            session: AgentSessionRef::new("agent-session:test", 1),
                            call_id: "call:test".into(),
                        },
                    },
                })
                .expect("serialize legacy async request"),
            )
            .await
            .expect("write legacy async request");
        legacy.shutdown().await.expect("finish legacy request");
        let mut legacy_response = Vec::new();
        legacy
            .read_to_end(&mut legacy_response)
            .await
            .expect("read legacy denial");
        let legacy_response: BrokerResponse =
            serde_json::from_slice(&legacy_response).expect("parse legacy denial");
        assert_eq!(
            legacy_response.error_code.as_deref(),
            Some("session.protocol_unsupported")
        );
        assert_eq!(
            legacy_response.protocol_version,
            AGENT_BROKER_LEGACY_PROTOCOL_VERSION
        );
        let response = send_request(
            &grant,
            BrokerRequest::Shutdown {
                token: grant.token.clone(),
            },
        )
        .await
        .expect("shutdown response");

        assert!(response.ok);
        broker.await.expect("broker task").expect("broker exits");
        assert!(!grant.socket_path.exists());
        assert!(!grant_path.exists());
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn broker_survives_bad_or_abandoned_client_connections() {
        let directory =
            PathBuf::from("/tmp").join(format!("vb-agent-bad-client-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("create temp grant directory");
        let grant_path = directory.join("grant.json");
        let mut grant = grant();
        grant.socket_path = directory.join("grant.sock");
        write_grant(&grant_path, &grant).expect("write grant");

        let broker_path = grant_path.clone();
        let broker = tokio::spawn(async move { broker_loop(&broker_path, "test-password").await });
        wait_for_socket(&grant.socket_path)
            .await
            .expect("broker socket ready");

        let mut malformed = UnixStream::connect(&grant.socket_path)
            .await
            .expect("connect malformed client");
        malformed
            .write_all(b"{")
            .await
            .expect("write malformed request");
        malformed.shutdown().await.expect("close malformed request");
        drop(malformed);

        let mut abandoned = UnixStream::connect(&grant.socket_path)
            .await
            .expect("connect abandoned client");
        abandoned
            .write_all(
                &serde_json::to_vec(&BrokerRequest::Inspect {
                    token: grant.token.clone(),
                })
                .expect("serialize inspect request"),
            )
            .await
            .expect("write abandoned request");
        abandoned.shutdown().await.expect("close abandoned request");
        drop(abandoned);

        let response = send_request(
            &grant,
            BrokerRequest::Inspect {
                token: grant.token.clone(),
            },
        )
        .await
        .expect("broker stays available");
        assert!(response.ok);
        assert_eq!(response.remaining_uses, grant.remaining_uses);

        send_request(
            &grant,
            BrokerRequest::Shutdown {
                token: grant.token.clone(),
            },
        )
        .await
        .expect("shutdown response");
        broker.await.expect("broker task").expect("broker exits");
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn broker_remains_online_after_multiple_run_requests() {
        let directory =
            PathBuf::from("/tmp").join(format!("vb-agent-multi-run-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("create temp grant directory");
        let grant_path = directory.join("grant.json");
        let mut grant = grant();
        grant.socket_path = directory.join("grant.sock");
        write_grant(&grant_path, &grant).expect("write grant");

        let broker_path = grant_path.clone();
        let broker = tokio::spawn(async move { broker_loop(&broker_path, "test-password").await });
        wait_for_socket(&grant.socket_path)
            .await
            .expect("broker socket ready");

        for expected_remaining in [9, 8, 7] {
            let response = send_request(
                &grant,
                BrokerRequest::Run {
                    token: grant.token.clone(),
                    argv: vec![
                        "profile".into(),
                        "test".into(),
                        format!("id:{}", grant.profile_id),
                        "--plugin".into(),
                        grant.plugin_id.clone(),
                        "--format".into(),
                        "json".into(),
                    ],
                },
            )
            .await
            .expect("run response");
            assert_eq!(response.remaining_uses, Some(expected_remaining));
        }

        let inspection = send_request(
            &grant,
            BrokerRequest::Inspect {
                token: grant.token.clone(),
            },
        )
        .await
        .expect("broker remains online");
        assert!(inspection.ok);
        assert_eq!(inspection.remaining_uses, Some(7));

        send_request(
            &grant,
            BrokerRequest::Shutdown {
                token: grant.token.clone(),
            },
        )
        .await
        .expect("shutdown response");
        broker.await.expect("broker task").expect("broker exits");
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn broker_lists_persistent_sessions_with_structured_data() {
        let directory = PathBuf::from("/tmp").join(format!("vb-agent-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("create temp grant directory");
        let grant_path = directory.join("grant.json");
        let mut grant = grant();
        grant.socket_path = directory.join("grant.sock");
        write_grant(&grant_path, &grant).expect("write grant");

        let broker_path = grant_path.clone();
        let broker = tokio::spawn(async move { broker_loop(&broker_path, "test-password").await });
        wait_for_socket(&grant.socket_path)
            .await
            .expect("broker socket ready");
        let response = send_request(
            &grant,
            BrokerRequest::Inspect {
                token: grant.token.clone(),
            },
        )
        .await
        .expect("inspect response");
        assert!(response.ok);
        assert_eq!(
            response.data,
            Some(json!({ "active_session_count": 0, "broker": "online" }))
        );
        assert_eq!(response.remaining_uses, grant.remaining_uses);

        let previous_profile = grant.profile_id.clone();
        let previous_plugin = grant.plugin_id.clone();
        let previous_capabilities = grant.capabilities.clone();
        let renewed_expiry = Utc::now() + chrono::Duration::minutes(5);
        let renewal = send_request(
            &grant,
            BrokerRequest::RenewGrant {
                token: grant.token.clone(),
                expires_at: renewed_expiry,
                remaining_uses: Some(3),
            },
        )
        .await
        .expect("renew response");
        assert!(renewal.ok);
        let renewed = read_grant(&grant_path).expect("renewed grant file");
        assert_eq!(renewed.profile_id, previous_profile);
        assert_eq!(renewed.plugin_id, previous_plugin);
        assert_eq!(renewed.capabilities, previous_capabilities);
        assert_eq!(renewed.remaining_uses, Some(3));
        assert_eq!(renewed.expires_at, renewed_expiry);

        send_request(
            &grant,
            BrokerRequest::Shutdown {
                token: grant.token.clone(),
            },
        )
        .await
        .expect("shutdown response");
        broker.await.expect("broker task").expect("broker exits");
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn review_decision_parsing_and_defaults() {
        assert_eq!(parse_review_decision(""), Some("b"));
        assert_eq!(parse_review_decision("  "), Some("b"));
        assert_eq!(parse_review_decision("b"), Some("b"));
        assert_eq!(parse_review_decision("B"), Some("b"));
        assert_eq!(parse_review_decision("bounded"), Some("b"));
        assert_eq!(parse_review_decision("time-bounded"), Some("b"));
        assert_eq!(parse_review_decision("o"), Some("o"));
        assert_eq!(parse_review_decision("once"), Some("o"));
        assert_eq!(parse_review_decision("a"), Some("a"));
        assert_eq!(parse_review_decision("add"), Some("a"));
        assert_eq!(parse_review_decision("add-to-grant"), Some("a"));
        assert_eq!(parse_review_decision("d"), Some("d"));
        assert_eq!(parse_review_decision("deny"), Some("d"));
        assert_eq!(parse_review_decision("reject"), Some("d"));
        assert_eq!(parse_review_decision("unknown"), None);
    }

    #[test]
    fn review_principal_formatting() {
        let principal = AgentPrincipal {
            client_id: "antigravity".into(),
            task_id: "task-1".into(),
            instance_id: None,
        };
        let formatted = format_review_principal(&principal);
        assert!(formatted.contains("client=antigravity"));
        assert!(formatted.contains("task=task-1"));

        let principal_with_instance = AgentPrincipal {
            client_id: "antigravity".into(),
            task_id: "task-1".into(),
            instance_id: Some("inst-42".into()),
        };
        let formatted2 = format_review_principal(&principal_with_instance);
        assert!(formatted2.contains("instance=inst-42"));
    }

    #[test]
    fn review_scope_and_risk_formatting() {
        assert_eq!(
            format_review_risk(voidb_core::CapabilityRiskLevel::ReadOnly),
            "read_only (safe)"
        );
        assert_eq!(
            format_review_risk(voidb_core::CapabilityRiskLevel::Destructive),
            "destructive (high risk)"
        );

        let scope = AgentAuthorizationScope::ExactInvocation {
            capability_id: "docker.list_containers".into(),
            normalized_input: json!({}),
            invocation_fingerprint: "fingerprint".into(),
        };
        let summary = format_review_scope_summary(&scope);
        assert!(summary.contains("Exact invocation: 'docker.list_containers'"));

        let scope_cap = AgentAuthorizationScope::Capability {
            capability_id: "mysql.query".into(),
        };
        let summary_cap = format_review_scope_summary(&scope_cap);
        assert!(summary_cap.contains("Capability 'mysql.query'"));
    }
}

