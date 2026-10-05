//! Runtime host for stdio JSON-RPC process plugins.
//!
//! Discovery remains read-only. This host starts an already-available candidate
//! only when an invocation path explicitly asks for that plugin.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::Duration as StdDuration;

use chrono::{Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::capability::{
    CapabilityError, CapabilityErrorCategory, CapabilityInvocation, CapabilityInvocationResult,
    CredentialClass, CredentialGrant, CredentialGrantScope, InvocationOutputPage, InvocationStatus,
    InvocationStreamEvent, MAX_INVOCATION_OUTPUT_BYTES, RedactionStatus,
};
use crate::process_plugin::{ProcessPluginCandidate, ProcessPluginCandidateState};
use crate::process_plugin_contract::{
    PROCESS_PLUGIN_ENV_LOG_FORMAT, PROCESS_PLUGIN_ENV_PLUGIN_DIR, PROCESS_PLUGIN_ENV_PLUGIN_ID,
    PROCESS_PLUGIN_ENV_PROTOCOL_VERSION, PROCESS_PLUGIN_JSONRPC_VERSION,
    PROCESS_PLUGIN_LOG_FORMAT_JSON, PROCESS_PLUGIN_METHOD_CANCEL, PROCESS_PLUGIN_METHOD_HEALTH,
    PROCESS_PLUGIN_METHOD_INITIALIZE, PROCESS_PLUGIN_METHOD_INVOKE,
    PROCESS_PLUGIN_METHOD_SESSION_CALL, PROCESS_PLUGIN_METHOD_SESSION_CANCEL,
    PROCESS_PLUGIN_METHOD_SESSION_CLOSE, PROCESS_PLUGIN_METHOD_SESSION_HEALTH,
    PROCESS_PLUGIN_METHOD_SESSION_OPEN, PROCESS_PLUGIN_METHOD_SESSION_RENEW,
    PROCESS_PLUGIN_METHOD_STREAM_END, PROCESS_PLUGIN_METHOD_STREAM_ITEM,
    PROCESS_PLUGIN_METHOD_STREAM_PROGRESS, PROCESS_PLUGIN_PROTOCOL_VERSION,
    PROCESS_PLUGIN_REQUEST_ID_HEALTH, PROCESS_PLUGIN_REQUEST_ID_INITIALIZE,
    PROCESS_PLUGIN_REQUEST_ID_INVOKE, PROCESS_PLUGIN_TRANSPORT_STDIO_JSONRPC,
    is_supported_process_plugin_protocol_version,
};

const DEFAULT_STARTUP_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_STDERR_LIMIT_BYTES: usize = 4096;
const DEFAULT_SHUTDOWN_GRACE_MS: u64 = 500;
const DEFAULT_CANCEL_GRACE_MS: u64 = 1_000;
const PROCESS_PLUGIN_MESSAGE_OVERHEAD_BYTES: u64 = 64 * 1024;
const MAX_PROCESS_PLUGIN_MESSAGE_BYTES: usize =
    (MAX_INVOCATION_OUTPUT_BYTES + PROCESS_PLUGIN_MESSAGE_OVERHEAD_BYTES) as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessPluginRuntimeState {
    Created,
    Starting,
    Initialized,
    Ready,
    Invoking,
    Exited,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessPluginLaunchOptions {
    pub startup_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub stderr_limit_bytes: usize,
}

impl Default for ProcessPluginLaunchOptions {
    fn default() -> Self {
        Self {
            startup_timeout_ms: DEFAULT_STARTUP_TIMEOUT_MS,
            request_timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
            stderr_limit_bytes: DEFAULT_STDERR_LIMIT_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessPluginHealth {
    pub status: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_invocations: Option<u64>,

    #[serde(default)]
    pub details: Value,
}

#[derive(Debug, Clone)]
pub struct ProcessPluginRuntimeHost {
    candidate: ProcessPluginCandidate,
    options: ProcessPluginLaunchOptions,
}

impl ProcessPluginRuntimeHost {
    pub fn new(candidate: ProcessPluginCandidate) -> Self {
        Self::with_options(candidate, ProcessPluginLaunchOptions::default())
    }

    pub fn with_options(
        candidate: ProcessPluginCandidate,
        options: ProcessPluginLaunchOptions,
    ) -> Self {
        Self { candidate, options }
    }

    pub fn candidate(&self) -> &ProcessPluginCandidate {
        &self.candidate
    }

    pub async fn initialize_and_health(&self) -> Result<ProcessPluginHealth, CapabilityError> {
        let mut process = match self.launch().await {
            Ok(process) => process,
            Err(error) => return Err(error),
        };

        let result = async {
            let _ = self.initialize(&mut process).await?;
            self.health(&mut process).await
        }
        .await;

        match result {
            Ok(health) => {
                let _ = process.shutdown().await;
                Ok(health)
            }
            Err(error) => Err(with_stderr_diagnostics(
                error,
                process.shutdown().await,
                self.options.stderr_limit_bytes,
            )),
        }
    }

    pub async fn invoke(
        &self,
        invocation: CapabilityInvocation,
        credential_grant: &CredentialGrant,
    ) -> Result<CapabilityInvocationResult, CapabilityError> {
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        self.invoke_controlled(invocation, credential_grant, cancel_rx, None)
            .await
    }

    /// Invoke with caller-owned cancellation and optional bounded stream-event
    /// delivery. Dropping the event receiver applies backpressure to the
    /// process stdout reader instead of buffering an unbounded stream.
    pub async fn invoke_controlled(
        &self,
        invocation: CapabilityInvocation,
        credential_grant: &CredentialGrant,
        cancellation: watch::Receiver<bool>,
        stream_events: Option<mpsc::Sender<InvocationStreamEvent>>,
    ) -> Result<CapabilityInvocationResult, CapabilityError> {
        let mut process = match self.launch().await {
            Ok(process) => process,
            Err(error) => return Err(error),
        };

        let result = async {
            let _ = self.initialize(&mut process).await?;
            self.health(&mut process).await?;
            self.invoke_initialized(
                &mut process,
                invocation,
                credential_grant,
                cancellation,
                stream_events,
            )
            .await
        }
        .await;

        match result {
            Ok(result) => {
                let _ = process.shutdown().await;
                Ok(result)
            }
            Err(error) => Err(with_stderr_diagnostics(
                error,
                process.shutdown().await,
                self.options.stderr_limit_bytes,
            )),
        }
    }

    /// Launch one process that remains alive while plugin-owned session handles
    /// are active. Protocol 1.0 plugins remain usable through stateless invoke.
    pub async fn open_session_runtime(
        &self,
    ) -> Result<ProcessPluginSessionRuntime, CapabilityError> {
        let mut process = self.launch().await?;
        let initialized = self.initialize(&mut process).await?;
        if initialized.session_protocol.as_deref() != Some("1") {
            let _ = process.shutdown().await;
            return Err(runtime_error(
                CapabilityErrorCategory::Unavailable,
                "unavailable.process_plugin_sessions_unsupported",
                "Process plugin did not negotiate persistent sessions.",
                json!({
                    "plugin_id": self.candidate.id,
                    "compatibility_fallback": "stateless"
                }),
                false,
                RedactionStatus::NotRequired,
            ));
        }
        self.health(&mut process).await?;
        Ok(ProcessPluginSessionRuntime {
            host: self.clone(),
            process: Some(process),
            next_request_id: 1,
        })
    }

    async fn launch(&self) -> Result<RunningProcess, CapabilityError> {
        if self.candidate.state != ProcessPluginCandidateState::Available {
            return Err(runtime_error(
                CapabilityErrorCategory::Unavailable,
                "unavailable.process_plugin_candidate_not_available",
                "Process-plugin candidate is not available for runtime invocation.",
                json!({
                    "plugin_id": self.candidate.id,
                    "state": self.candidate.state,
                }),
                true,
                RedactionStatus::NotRequired,
            ));
        }

        let Some(manifest) = self.candidate.manifest.as_ref() else {
            return Err(runtime_error(
                CapabilityErrorCategory::Unavailable,
                "unavailable.process_plugin_manifest_missing",
                "Process-plugin candidate does not have a decoded manifest.",
                json!({ "plugin_id": self.candidate.id }),
                false,
                RedactionStatus::NotRequired,
            ));
        };
        if manifest.runtime.transport != PROCESS_PLUGIN_TRANSPORT_STDIO_JSONRPC {
            return Err(runtime_error(
                CapabilityErrorCategory::Unavailable,
                "unavailable.process_plugin_transport_unsupported",
                "Process-plugin transport is not supported by this runtime host.",
                json!({
                    "plugin_id": self.candidate.id,
                    "transport": manifest.runtime.transport,
                    "supported_transport": PROCESS_PLUGIN_TRANSPORT_STDIO_JSONRPC,
                }),
                false,
                RedactionStatus::NotRequired,
            ));
        }

        let Some(command_path) = &self.candidate.resolved_runtime_command else {
            return Err(runtime_error(
                CapabilityErrorCategory::Unavailable,
                "unavailable.process_plugin_command_unresolved",
                "Process-plugin runtime command was not resolved during discovery.",
                json!({ "plugin_id": self.candidate.id }),
                false,
                RedactionStatus::NotRequired,
            ));
        };

        let mut command = Command::new(command_path);
        command
            .args(&manifest.runtime.args)
            .current_dir(&self.candidate.source.plugin_dir)
            .env_clear()
            .envs(&manifest.runtime.env)
            .env(PROCESS_PLUGIN_ENV_PLUGIN_ID, &self.candidate.id)
            .env(
                PROCESS_PLUGIN_ENV_PLUGIN_DIR,
                self.candidate.source.plugin_dir.as_os_str(),
            )
            .env(
                PROCESS_PLUGIN_ENV_PROTOCOL_VERSION,
                PROCESS_PLUGIN_PROTOCOL_VERSION,
            )
            .env(
                PROCESS_PLUGIN_ENV_LOG_FORMAT,
                PROCESS_PLUGIN_LOG_FORMAT_JSON,
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.kill_on_drop(true);

        let mut child = command.spawn().map_err(|error| {
            runtime_error(
                CapabilityErrorCategory::Transport,
                "transport.process_plugin_launch_failed",
                "Process-plugin runtime process could not be started.",
                json!({
                    "plugin_id": self.candidate.id,
                    "message": error.to_string(),
                }),
                true,
                RedactionStatus::Applied,
            )
        })?;

        let stdin = child.stdin.take().ok_or_else(|| {
            runtime_error(
                CapabilityErrorCategory::Transport,
                "transport.process_plugin_stdin_unavailable",
                "Process-plugin stdin was not available after launch.",
                json!({ "plugin_id": self.candidate.id }),
                true,
                RedactionStatus::NotRequired,
            )
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            runtime_error(
                CapabilityErrorCategory::Transport,
                "transport.process_plugin_stdout_unavailable",
                "Process-plugin stdout was not available after launch.",
                json!({ "plugin_id": self.candidate.id }),
                true,
                RedactionStatus::NotRequired,
            )
        })?;
        let stderr = child.stderr.take();
        let stderr_task = stderr.map(|stderr| {
            let limit = self.options.stderr_limit_bytes.saturating_add(1);
            tokio::spawn(async move {
                let mut reader = stderr.take(limit as u64);
                let mut bytes = Vec::new();
                let _ = reader.read_to_end(&mut bytes).await;
                bytes
            })
        });

        Ok(RunningProcess {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            stderr_task,
            stderr_limit_bytes: self.options.stderr_limit_bytes,
        })
    }

    async fn initialize(
        &self,
        process: &mut RunningProcess,
    ) -> Result<InitializeResult, CapabilityError> {
        let result = process
            .request(
                PROCESS_PLUGIN_REQUEST_ID_INITIALIZE,
                PROCESS_PLUGIN_METHOD_INITIALIZE,
                json!({
                    "protocol_version": PROCESS_PLUGIN_PROTOCOL_VERSION,
                    "core_version": env!("CARGO_PKG_VERSION"),
                    "plugin_id": self.candidate.id,
                    "manifest_path": self.candidate.manifest_path,
                    "started_at": Utc::now(),
                }),
                self.options.startup_timeout_ms,
                &self.candidate.id,
            )
            .await?;

        let initialized = serde_json::from_value::<InitializeResult>(result).map_err(|error| {
            protocol_error(
                &self.candidate.id,
                "protocol.initialize_result_invalid",
                "Process plugin returned an invalid initialize result.",
                json!({ "message": error.to_string() }),
            )
        })?;

        if initialized.plugin_id != self.candidate.id {
            return Err(protocol_error(
                &self.candidate.id,
                "protocol.initialize_plugin_id_mismatch",
                "Process plugin initialize result did not echo the expected plugin id.",
                json!({
                    "expected_plugin_id": self.candidate.id,
                    "actual_plugin_id": initialized.plugin_id,
                }),
            ));
        }

        if !is_supported_process_plugin_protocol_version(&initialized.protocol_version) {
            return Err(protocol_error(
                &self.candidate.id,
                "protocol.initialize_protocol_mismatch",
                "Process plugin initialize result did not select a supported protocol version.",
                json!({
                    "protocol_version": initialized.protocol_version,
                    "supported_protocol_version": PROCESS_PLUGIN_PROTOCOL_VERSION,
                }),
            ));
        }

        if initialized
            .status
            .as_deref()
            .is_some_and(|status| status != "ready")
        {
            return Err(runtime_error(
                CapabilityErrorCategory::Unavailable,
                "unavailable.process_plugin_not_ready",
                "Process plugin initialized but did not report ready status.",
                json!({
                    "plugin_id": self.candidate.id,
                    "status": initialized.status,
                }),
                true,
                RedactionStatus::NotRequired,
            ));
        }

        Ok(initialized)
    }

    async fn health(
        &self,
        process: &mut RunningProcess,
    ) -> Result<ProcessPluginHealth, CapabilityError> {
        let result = process
            .request(
                PROCESS_PLUGIN_REQUEST_ID_HEALTH,
                PROCESS_PLUGIN_METHOD_HEALTH,
                json!({ "include_runtime": true }),
                self.options.startup_timeout_ms,
                &self.candidate.id,
            )
            .await?;
        let health_result = serde_json::from_value::<HealthResult>(result).map_err(|error| {
            protocol_error(
                &self.candidate.id,
                "protocol.health_result_invalid",
                "Process plugin returned an invalid health result.",
                json!({ "message": error.to_string() }),
            )
        })?;

        if health_result.status != "ready" {
            return Err(runtime_error(
                CapabilityErrorCategory::Unavailable,
                "unavailable.process_plugin_health_not_ready",
                "Process plugin health check did not report ready status.",
                json!({
                    "plugin_id": self.candidate.id,
                    "status": health_result.status,
                }),
                true,
                RedactionStatus::NotRequired,
            ));
        }

        Ok(ProcessPluginHealth {
            status: health_result.status,
            active_invocations: health_result.active_invocations,
            details: Value::Object(health_result.extra.into_iter().collect()),
        })
    }

    async fn invoke_initialized(
        &self,
        process: &mut RunningProcess,
        invocation: CapabilityInvocation,
        credential_grant: &CredentialGrant,
        cancellation: watch::Receiver<bool>,
        stream_events: Option<mpsc::Sender<InvocationStreamEvent>>,
    ) -> Result<CapabilityInvocationResult, CapabilityError> {
        let invocation_id = invocation.id.clone();
        let cancellation_token = invocation.controls.cancellation_token.clone();
        let timeout_ms = invocation
            .controls
            .timeout_ms
            .unwrap_or(self.options.request_timeout_ms);
        let result = process
            .request_invocation(
                PROCESS_PLUGIN_REQUEST_ID_INVOKE,
                PROCESS_PLUGIN_METHOD_INVOKE,
                json!({
                    "invocation": invocation,
                    "credential_grants": credential_grant_descriptors(credential_grant),
                }),
                timeout_ms,
                &self.candidate.id,
                &invocation_id,
                cancellation_token.as_deref(),
                cancellation,
                stream_events,
            )
            .await?;

        let result =
            serde_json::from_value::<CapabilityInvocationResult>(result).map_err(|error| {
                protocol_error(
                    &self.candidate.id,
                    "protocol.invoke_result_invalid",
                    "Process plugin returned an invalid invocation result.",
                    json!({ "message": error.to_string() }),
                )
            })?;
        if result.invocation_id != invocation_id {
            return Err(protocol_error(
                &self.candidate.id,
                "protocol.invocation_id_mismatch",
                "Process plugin result did not match the caller-owned invocation id.",
                json!({
                    "expected_invocation_id": invocation_id,
                    "actual_invocation_id": result.invocation_id,
                }),
            ));
        }
        Ok(result)
    }
}

/// Long-lived protocol 1.1 process runtime. The child is kill-on-drop so a host
/// crash cannot leave a plugin process orphaned; callers should still use
/// `shutdown` for bounded graceful cleanup.
pub struct ProcessPluginSessionRuntime {
    host: ProcessPluginRuntimeHost,
    process: Option<RunningProcess>,
    next_request_id: u64,
}

impl ProcessPluginSessionRuntime {
    pub async fn session_open(&mut self, params: Value) -> Result<Value, CapabilityError> {
        let result = self
            .request(PROCESS_PLUGIN_METHOD_SESSION_OPEN, params)
            .await?;
        validate_secret_free_session_descriptor(&self.host.candidate.id, &result)?;
        Ok(result)
    }

    pub async fn session_call(&mut self, params: Value) -> Result<Value, CapabilityError> {
        self.request(PROCESS_PLUGIN_METHOD_SESSION_CALL, params)
            .await
    }

    pub async fn session_health(&mut self, params: Value) -> Result<Value, CapabilityError> {
        let result = self
            .request(PROCESS_PLUGIN_METHOD_SESSION_HEALTH, params)
            .await?;
        validate_secret_free_session_descriptor(&self.host.candidate.id, &result)?;
        Ok(result)
    }

    pub async fn session_renew(&mut self, params: Value) -> Result<Value, CapabilityError> {
        self.request(PROCESS_PLUGIN_METHOD_SESSION_RENEW, params)
            .await
    }

    pub async fn session_cancel(&mut self, params: Value) -> Result<Value, CapabilityError> {
        self.request(PROCESS_PLUGIN_METHOD_SESSION_CANCEL, params)
            .await
    }

    pub async fn session_close(&mut self, params: Value) -> Result<Value, CapabilityError> {
        self.request(PROCESS_PLUGIN_METHOD_SESSION_CLOSE, params)
            .await
    }

    pub async fn shutdown(mut self) -> Vec<u8> {
        match self.process.take() {
            Some(process) => process.shutdown().await,
            None => Vec::new(),
        }
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<Value, CapabilityError> {
        let id = format!("session:{}", self.next_request_id);
        self.next_request_id = self.next_request_id.saturating_add(1);
        let process = self.process.as_mut().ok_or_else(|| {
            runtime_error(
                CapabilityErrorCategory::Unavailable,
                "unavailable.process_plugin_session_runtime_closed",
                "Process-plugin session runtime is closed.",
                json!({ "plugin_id": self.host.candidate.id }),
                false,
                RedactionStatus::NotRequired,
            )
        })?;
        process
            .request(
                &id,
                method,
                params,
                self.host.options.request_timeout_ms,
                &self.host.candidate.id,
            )
            .await
    }
}

#[allow(clippy::result_large_err)]
fn validate_secret_free_session_descriptor(
    plugin_id: &str,
    result: &Value,
) -> Result<(), CapabilityError> {
    let descriptor = result.get("descriptor").unwrap_or(&Value::Null);
    let bytes = serde_json::to_vec(descriptor).unwrap_or_default();
    if bytes.len() > 4096 || contains_secret_key(descriptor) {
        return Err(protocol_error(
            plugin_id,
            "protocol.session_descriptor_unsafe",
            "Process-plugin session descriptor was too large or contained credential-shaped fields.",
            json!({ "descriptor_bytes": bytes.len() }),
        ));
    }
    Ok(())
}

fn contains_secret_key(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            key.contains("password")
                || key.contains("secret")
                || key.contains("credential")
                || key.contains("token")
                || contains_secret_key(value)
        }),
        Value::Array(values) => values.iter().any(contains_secret_key),
        _ => false,
    }
}

struct RunningProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr_task: Option<JoinHandle<Vec<u8>>>,
    stderr_limit_bytes: usize,
}

impl RunningProcess {
    async fn request(
        &mut self,
        id: &str,
        method: &str,
        params: Value,
        timeout_ms: u64,
        plugin_id: &str,
    ) -> Result<Value, CapabilityError> {
        let request = json!({
            "jsonrpc": PROCESS_PLUGIN_JSONRPC_VERSION,
            "id": id,
            "method": method,
            "params": params,
        });
        let timeout = StdDuration::from_millis(timeout_ms);
        match tokio::time::timeout(timeout, self.request_inner(id, request, plugin_id)).await {
            Ok(result) => result,
            Err(_) => Err(runtime_error(
                CapabilityErrorCategory::Timeout,
                "timeout.process_plugin_request_timed_out",
                "Process-plugin JSON-RPC request timed out.",
                json!({
                    "plugin_id": plugin_id,
                    "method": method,
                    "timeout_ms": timeout_ms,
                }),
                true,
                RedactionStatus::NotRequired,
            )),
        }
    }

    async fn request_inner(
        &mut self,
        id: &str,
        request: Value,
        plugin_id: &str,
    ) -> Result<Value, CapabilityError> {
        self.write_request(&request, plugin_id).await?;
        self.read_response(id, plugin_id).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_invocation(
        &mut self,
        id: &str,
        method: &str,
        params: Value,
        timeout_ms: u64,
        plugin_id: &str,
        invocation_id: &str,
        cancellation_token: Option<&str>,
        mut cancellation: watch::Receiver<bool>,
        stream_events: Option<mpsc::Sender<InvocationStreamEvent>>,
    ) -> Result<Value, CapabilityError> {
        if *cancellation.borrow() {
            return Err(invocation_cancelled_error(
                plugin_id,
                invocation_id,
                false,
                false,
            ));
        }

        let request = json!({
            "jsonrpc": PROCESS_PLUGIN_JSONRPC_VERSION,
            "id": id,
            "method": method,
            "params": params,
        });
        let deadline = tokio::time::Instant::now() + StdDuration::from_millis(timeout_ms);
        let dispatch = tokio::select! {
            biased;
            _ = cancellation_requested(&mut cancellation) => None,
            result = tokio::time::timeout_at(deadline, self.write_request(&request, plugin_id)) => Some(result),
        };
        match dispatch {
            None => {
                return Err(invocation_cancelled_error(
                    plugin_id,
                    invocation_id,
                    false,
                    false,
                ));
            }
            Some(Ok(result)) => result?,
            Some(Err(_)) => {
                return Err(process_invocation_timeout_error(
                    plugin_id, method, timeout_ms,
                ));
            }
        }

        enum RequestOutcome {
            Completed(Result<Value, CapabilityError>),
            Cancelled,
        }
        let outcome = {
            let request_future = async {
                match tokio::time::timeout_at(
                    deadline,
                    self.read_invocation_response(
                        id,
                        plugin_id,
                        invocation_id,
                        stream_events.as_ref(),
                    ),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(process_invocation_timeout_error(
                        plugin_id, method, timeout_ms,
                    )),
                }
            };
            tokio::pin!(request_future);
            tokio::select! {
                biased;
                _ = cancellation_requested(&mut cancellation) => RequestOutcome::Cancelled,
                result = &mut request_future => RequestOutcome::Completed(result),
            }
        };

        match outcome {
            RequestOutcome::Completed(result) => result,
            RequestOutcome::Cancelled => {
                let cancel_id = format!("cancel:{invocation_id}");
                let token = cancellation_token.unwrap_or(invocation_id);
                let cancel_result = self
                    .request(
                        &cancel_id,
                        PROCESS_PLUGIN_METHOD_CANCEL,
                        json!({
                            "invocation_id": invocation_id,
                            "cancellation_token": token,
                            "reason": "caller requested cancellation",
                        }),
                        DEFAULT_CANCEL_GRACE_MS,
                        plugin_id,
                    )
                    .await;
                let accepted = cancel_result
                    .as_ref()
                    .ok()
                    .and_then(|value| value.get("accepted"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                Err(invocation_cancelled_error(
                    plugin_id,
                    invocation_id,
                    true,
                    accepted,
                ))
            }
        }
    }

    async fn write_request(
        &mut self,
        request: &Value,
        plugin_id: &str,
    ) -> Result<(), CapabilityError> {
        let mut encoded = serde_json::to_vec(&request).map_err(|error| {
            runtime_error(
                CapabilityErrorCategory::Internal,
                "internal.process_plugin_request_encode_failed",
                "Process-plugin JSON-RPC request could not be encoded.",
                json!({ "message": error.to_string() }),
                false,
                RedactionStatus::NotRequired,
            )
        })?;
        encoded.push(b'\n');
        self.stdin.write_all(&encoded).await.map_err(|error| {
            runtime_error(
                CapabilityErrorCategory::Transport,
                "transport.process_plugin_stdin_write_failed",
                "Process-plugin stdin write failed.",
                json!({ "plugin_id": plugin_id, "message": error.to_string() }),
                true,
                RedactionStatus::Applied,
            )
        })?;
        self.stdin.flush().await.map_err(|error| {
            runtime_error(
                CapabilityErrorCategory::Transport,
                "transport.process_plugin_stdin_flush_failed",
                "Process-plugin stdin flush failed.",
                json!({ "plugin_id": plugin_id, "message": error.to_string() }),
                true,
                RedactionStatus::Applied,
            )
        })?;
        Ok(())
    }

    async fn read_response(
        &mut self,
        expected_id: &str,
        plugin_id: &str,
    ) -> Result<Value, CapabilityError> {
        loop {
            let message = self.read_protocol_message(plugin_id).await?;

            let Some(id) = message.get("id") else {
                if message.get("method").is_some() {
                    continue;
                }
                return Err(protocol_error(
                    plugin_id,
                    "protocol.response_id_missing",
                    "Process plugin response did not include an id.",
                    json!({ "message_kind": message_kind(&message) }),
                ));
            };

            if id != &Value::String(expected_id.to_string()) {
                continue;
            }

            if let Some(error) = message.get("error") {
                return Err(json_rpc_error_to_capability_error(plugin_id, error));
            }

            return message.get("result").cloned().ok_or_else(|| {
                protocol_error(
                    plugin_id,
                    "protocol.response_result_missing",
                    "Process plugin response did not include result or error.",
                    json!({ "message_kind": message_kind(&message) }),
                )
            });
        }
    }

    async fn read_invocation_response(
        &mut self,
        expected_id: &str,
        plugin_id: &str,
        invocation_id: &str,
        stream_events: Option<&mpsc::Sender<InvocationStreamEvent>>,
    ) -> Result<Value, CapabilityError> {
        let mut expected_sequence = 0_u64;
        loop {
            let message = self.read_protocol_message(plugin_id).await?;
            if message.get("id").is_none() && message.get("method").is_some() {
                if let Some(terminal) = handle_stream_notification(
                    plugin_id,
                    invocation_id,
                    &message,
                    &mut expected_sequence,
                    stream_events,
                )
                .await?
                {
                    return serde_json::to_value(terminal).map_err(|error| {
                        runtime_error(
                            CapabilityErrorCategory::Internal,
                            "internal.process_plugin_stream_end_encode_failed",
                            "Process-plugin stream terminal result could not be encoded.",
                            json!({ "message": error.to_string() }),
                            false,
                            RedactionStatus::NotRequired,
                        )
                    });
                }
                continue;
            }

            if message.get("id") != Some(&Value::String(expected_id.to_string())) {
                continue;
            }
            if let Some(error) = message.get("error") {
                return Err(json_rpc_error_to_capability_error(plugin_id, error));
            }
            return message.get("result").cloned().ok_or_else(|| {
                protocol_error(
                    plugin_id,
                    "protocol.response_result_missing",
                    "Process plugin response did not include result or error.",
                    json!({ "message_kind": message_kind(&message) }),
                )
            });
        }
    }

    #[allow(clippy::result_large_err)]
    async fn read_protocol_message(&mut self, plugin_id: &str) -> Result<Value, CapabilityError> {
        let mut bytes = Vec::with_capacity(8 * 1024);
        loop {
            let available = self.stdout.fill_buf().await.map_err(|error| {
                runtime_error(
                    CapabilityErrorCategory::Transport,
                    "transport.process_plugin_stdout_read_failed",
                    "Process-plugin stdout read failed.",
                    json!({ "plugin_id": plugin_id, "message": error.to_string() }),
                    true,
                    RedactionStatus::Applied,
                )
            })?;
            if available.is_empty() {
                return Err(runtime_error(
                    CapabilityErrorCategory::Transport,
                    "transport.process_plugin_exited",
                    "Process-plugin process exited before returning a JSON-RPC response.",
                    json!({ "plugin_id": plugin_id }),
                    true,
                    RedactionStatus::Applied,
                ));
            }
            let chunk_len = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |position| position + 1);
            if bytes.len().saturating_add(chunk_len) > MAX_PROCESS_PLUGIN_MESSAGE_BYTES {
                return Err(protocol_error(
                    plugin_id,
                    "protocol.stdout_message_too_large",
                    "Process plugin wrote a JSON-RPC message larger than the transport limit.",
                    json!({ "max_message_bytes": MAX_PROCESS_PLUGIN_MESSAGE_BYTES }),
                ));
            }
            let has_newline = available[..chunk_len].ends_with(b"\n");
            bytes.extend_from_slice(&available[..chunk_len]);
            self.stdout.consume(chunk_len);
            if has_newline {
                break;
            }
        }

        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        serde_json::from_slice::<Value>(&bytes)
            .map_err(|error| {
                protocol_error(
                    plugin_id,
                    "protocol.stdout_json_invalid",
                    "Process plugin wrote malformed JSON to stdout.",
                    json!({
                        "message": error.to_string(),
                        "line_bytes": bytes.len(),
                    }),
                )
            })
            .and_then(|message| {
                if message.get("jsonrpc").and_then(Value::as_str)
                    != Some(PROCESS_PLUGIN_JSONRPC_VERSION)
                {
                    return Err(protocol_error(
                        plugin_id,
                        "protocol.jsonrpc_version_invalid",
                        "Process plugin response did not use JSON-RPC 2.0.",
                        json!({ "message_kind": message_kind(&message) }),
                    ));
                }
                Ok(message)
            })
    }

    async fn shutdown(mut self) -> Vec<u8> {
        drop(self.stdin);
        if tokio::time::timeout(
            StdDuration::from_millis(DEFAULT_SHUTDOWN_GRACE_MS),
            self.child.wait(),
        )
        .await
        .is_err()
        {
            let _ = self.child.kill().await;
            let _ = tokio::time::timeout(
                StdDuration::from_millis(DEFAULT_SHUTDOWN_GRACE_MS),
                self.child.wait(),
            )
            .await;
        }

        let Some(stderr_task) = self.stderr_task.take() else {
            return Vec::new();
        };
        match tokio::time::timeout(
            StdDuration::from_millis(DEFAULT_SHUTDOWN_GRACE_MS),
            stderr_task,
        )
        .await
        {
            Ok(Ok(mut bytes)) => {
                let max_len = self.stderr_limit_bytes.saturating_add(1);
                if bytes.len() > max_len {
                    bytes.truncate(max_len);
                }
                bytes
            }
            _ => Vec::new(),
        }
    }
}

async fn cancellation_requested(cancellation: &mut watch::Receiver<bool>) {
    while !*cancellation.borrow() {
        if cancellation.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

async fn handle_stream_notification(
    plugin_id: &str,
    invocation_id: &str,
    message: &Value,
    expected_sequence: &mut u64,
    stream_events: Option<&mpsc::Sender<InvocationStreamEvent>>,
) -> Result<Option<CapabilityInvocationResult>, CapabilityError> {
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return Ok(None);
    };
    if !matches!(
        method,
        PROCESS_PLUGIN_METHOD_STREAM_ITEM
            | PROCESS_PLUGIN_METHOD_STREAM_PROGRESS
            | PROCESS_PLUGIN_METHOD_STREAM_END
    ) {
        return Ok(None);
    }
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let stream_invocation_id = params
        .get("invocation_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let sequence = params
        .get("sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| stream_protocol_error(plugin_id, "Stream notification omitted sequence."))?;
    if stream_invocation_id != invocation_id || sequence != *expected_sequence {
        return Err(stream_protocol_error(
            plugin_id,
            "Stream notification did not match the invocation or expected sequence.",
        ));
    }
    *expected_sequence = expected_sequence.saturating_add(1);

    match method {
        PROCESS_PLUGIN_METHOD_STREAM_ITEM => {
            send_stream_event(
                plugin_id,
                stream_events,
                InvocationStreamEvent::Data {
                    value: params.get("item").cloned().unwrap_or(Value::Null),
                },
            )
            .await?;
            Ok(None)
        }
        PROCESS_PLUGIN_METHOD_STREAM_PROGRESS => {
            send_stream_event(
                plugin_id,
                stream_events,
                InvocationStreamEvent::Progress {
                    message: params
                        .get("message")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    fraction: params.get("progress").and_then(Value::as_f64),
                    current: params.get("current").and_then(Value::as_u64),
                    total: params.get("total").and_then(Value::as_u64),
                },
            )
            .await?;
            Ok(None)
        }
        PROCESS_PLUGIN_METHOD_STREAM_END => {
            let status = serde_json::from_value::<InvocationStatus>(
                params.get("status").cloned().unwrap_or(Value::Null),
            )
            .map_err(|_| stream_protocol_error(plugin_id, "Stream end status was invalid."))?;
            let page = params
                .get("page")
                .cloned()
                .filter(|value| !value.is_null())
                .map(serde_json::from_value::<InvocationOutputPage>)
                .transpose()
                .map_err(|_| stream_protocol_error(plugin_id, "Stream end page was invalid."))?;
            Ok(Some(CapabilityInvocationResult {
                invocation_id: invocation_id.into(),
                status,
                output: Value::Null,
                output_summary: params.get("output_summary").cloned().unwrap_or(Value::Null),
                page,
            }))
        }
        _ => Ok(None),
    }
}

async fn send_stream_event(
    plugin_id: &str,
    stream_events: Option<&mpsc::Sender<InvocationStreamEvent>>,
    event: InvocationStreamEvent,
) -> Result<(), CapabilityError> {
    let Some(stream_events) = stream_events else {
        return Ok(());
    };
    stream_events.send(event).await.map_err(|_| {
        runtime_error(
            CapabilityErrorCategory::Cancellation,
            "cancellation.stream_consumer_closed",
            "Invocation stream consumer closed before the plugin completed.",
            json!({ "plugin_id": plugin_id }),
            false,
            RedactionStatus::NotRequired,
        )
    })
}

fn stream_protocol_error(plugin_id: &str, message: &str) -> CapabilityError {
    runtime_error(
        CapabilityErrorCategory::Plugin,
        "plugin.stream_protocol_violation",
        message,
        json!({ "plugin_id": plugin_id }),
        false,
        RedactionStatus::Applied,
    )
}

fn invocation_cancelled_error(
    plugin_id: &str,
    invocation_id: &str,
    dispatched: bool,
    cooperative_cancel_accepted: bool,
) -> CapabilityError {
    runtime_error(
        CapabilityErrorCategory::Cancellation,
        "cancellation.requested",
        "Caller requested capability invocation cancellation.",
        json!({
            "plugin_id": plugin_id,
            "invocation_id": invocation_id,
            "dispatched": dispatched,
            "cooperative_cancel_accepted": cooperative_cancel_accepted,
        }),
        false,
        RedactionStatus::NotRequired,
    )
}

fn process_invocation_timeout_error(
    plugin_id: &str,
    method: &str,
    timeout_ms: u64,
) -> CapabilityError {
    runtime_error(
        CapabilityErrorCategory::Timeout,
        "timeout.process_plugin_request_timed_out",
        "Process-plugin JSON-RPC request timed out.",
        json!({
            "plugin_id": plugin_id,
            "method": method,
            "timeout_ms": timeout_ms,
        }),
        true,
        RedactionStatus::NotRequired,
    )
}

#[derive(Debug, Deserialize)]
struct InitializeResult {
    plugin_id: String,
    protocol_version: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    session_protocol: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HealthResult {
    status: String,
    #[serde(default)]
    active_invocations: Option<u64>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcErrorEnvelope {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<CapabilityError>,
}

fn json_rpc_error_to_capability_error(plugin_id: &str, value: &Value) -> CapabilityError {
    match serde_json::from_value::<JsonRpcErrorEnvelope>(value.clone()) {
        Ok(error) => error.data.unwrap_or_else(|| {
            runtime_error(
                CapabilityErrorCategory::Plugin,
                "plugin.jsonrpc_error",
                "Process plugin returned a JSON-RPC error.",
                json!({
                    "plugin_id": plugin_id,
                    "jsonrpc_code": error.code,
                    "message": "<redacted>",
                    "message_bytes": error.message.len(),
                }),
                false,
                RedactionStatus::Applied,
            )
        }),
        Err(error) => protocol_error(
            plugin_id,
            "protocol.jsonrpc_error_invalid",
            "Process plugin returned an invalid JSON-RPC error object.",
            json!({ "message": error.to_string() }),
        ),
    }
}

fn credential_grant_descriptors(grant: &CredentialGrant) -> Vec<Value> {
    let expires_at = grant
        .expires_at
        .unwrap_or_else(|| grant.issued_at + ChronoDuration::minutes(5));
    let purpose = match &grant.scope {
        CredentialGrantScope::Invocation { .. } => "capability_invocation",
        CredentialGrantScope::RuntimeInstance { .. } => "runtime_instance",
    };

    grant
        .credential_refs
        .iter()
        .map(|credential_ref| {
            json!({
                "grant_id": grant.id,
                "credential_ref_id": credential_ref.id,
                "class": credential_class_label(&credential_ref.class),
                "expires_at": expires_at,
                "purpose": purpose,
            })
        })
        .collect()
}

fn credential_class_label(class: &CredentialClass) -> String {
    match class {
        CredentialClass::Password => "password".into(),
        CredentialClass::Token => "token".into(),
        CredentialClass::ApiKey => "api_key".into(),
        CredentialClass::PrivateKey => "private_key".into(),
        CredentialClass::ClientCertificate => "client_certificate".into(),
        CredentialClass::CloudAccessKey => "cloud_access_key".into(),
        CredentialClass::CloudSecretKey => "cloud_secret_key".into(),
        CredentialClass::Other(value) => value.clone(),
    }
}

fn message_kind(message: &Value) -> &'static str {
    if message.get("method").is_some() {
        "notification_or_request"
    } else if message.get("error").is_some() {
        "error_response"
    } else if message.get("result").is_some() {
        "success_response"
    } else {
        "unknown"
    }
}

fn protocol_error(plugin_id: &str, code: &str, message: &str, details: Value) -> CapabilityError {
    runtime_error(
        CapabilityErrorCategory::Transport,
        code,
        message,
        with_plugin_id(plugin_id, details),
        true,
        RedactionStatus::Applied,
    )
}

fn runtime_error(
    category: CapabilityErrorCategory,
    code: &str,
    message: &str,
    details: Value,
    retryable: bool,
    redaction: RedactionStatus,
) -> CapabilityError {
    CapabilityError {
        category,
        code: code.into(),
        message: message.into(),
        details,
        target: None,
        retryable,
        redaction,
    }
}

fn with_plugin_id(plugin_id: &str, details: Value) -> Value {
    match details {
        Value::Object(mut map) => {
            map.insert("plugin_id".into(), Value::String(plugin_id.into()));
            Value::Object(map)
        }
        other => json!({
            "plugin_id": plugin_id,
            "details": other,
        }),
    }
}

fn with_stderr_diagnostics(
    mut error: CapabilityError,
    stderr: Vec<u8>,
    stderr_limit_bytes: usize,
) -> CapabilityError {
    if stderr.is_empty() {
        return error;
    }

    error.details = match error.details {
        Value::Object(mut map) => {
            map.insert("stderr".into(), stderr_summary(&stderr, stderr_limit_bytes));
            Value::Object(map)
        }
        other => json!({
            "details": other,
            "stderr": stderr_summary(&stderr, stderr_limit_bytes),
        }),
    };
    if error.redaction == RedactionStatus::NotRequired {
        error.redaction = RedactionStatus::Applied;
    }
    error
}

fn stderr_summary(stderr: &[u8], stderr_limit_bytes: usize) -> Value {
    json!({
        "present": true,
        "bytes": stderr.len(),
        "limit_bytes": stderr_limit_bytes,
        "truncated": stderr.len() > stderr_limit_bytes,
        "content": "<redacted plugin stderr>",
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::capability::{
        ActorRef, ActorType, ConnectionInstancePurpose, ConnectionProfileRef, CredentialRef,
        InstanceReusePolicy, InvocationConnectionTarget, InvocationControls,
    };
    use crate::process_plugin::{
        ProcessPluginRoot, ProcessPluginRootKind, discover_process_plugins_from_roots,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[tokio::test]
    async fn initializes_health_and_invokes_fixture_success() {
        let fixture = RuntimeFixture::new("success");

        let health = fixture.host.initialize_and_health().await.expect("health");
        assert_eq!(health.status, "ready");

        let result = fixture
            .host
            .invoke(sample_invocation(Some(1_000)), &sample_grant())
            .await
            .expect("invoke");

        assert_eq!(result.status, crate::InvocationStatus::Succeeded);
        assert_eq!(result.output["ok"], true);
    }

    #[tokio::test]
    async fn injects_reserved_environment_and_prevents_manifest_override() {
        let fixture = RuntimeFixture::new("health_env");

        let health = fixture.host.initialize_and_health().await.expect("health");
        let expected_plugin_dir = fixture.path().join("fixture");

        assert_eq!(health.status, "ready");
        assert_eq!(health.details["env"]["plugin_id"], "fixture");
        assert_eq!(
            health.details["env"]["plugin_dir"].as_str(),
            Some(expected_plugin_dir.to_string_lossy().as_ref())
        );
        assert_eq!(
            health.details["env"]["protocol_version"],
            PROCESS_PLUGIN_PROTOCOL_VERSION
        );
        assert_eq!(
            health.details["env"]["log_format"],
            PROCESS_PLUGIN_LOG_FORMAT_JSON
        );
    }

    #[tokio::test]
    async fn rejects_unsupported_initialize_protocol_version() {
        let fixture = RuntimeFixture::new("protocol_mismatch");

        let error = fixture
            .host
            .initialize_and_health()
            .await
            .expect_err("protocol mismatch");

        assert_eq!(error.category, CapabilityErrorCategory::Transport);
        assert_eq!(error.code, "protocol.initialize_protocol_mismatch");
        assert_eq!(error.details["protocol_version"], "2");
        assert_eq!(
            error.details["supported_protocol_version"],
            PROCESS_PLUGIN_PROTOCOL_VERSION
        );
    }

    #[tokio::test]
    async fn tolerates_stream_notifications_before_matching_invoke_response() {
        let fixture = RuntimeFixture::new("stream_notification");

        let result = fixture
            .host
            .invoke(sample_invocation(Some(1_000)), &sample_grant())
            .await
            .expect("invoke");

        assert_eq!(result.status, crate::InvocationStatus::Succeeded);
        assert_eq!(result.output["stream_notice"], true);
    }

    #[tokio::test]
    async fn forwards_validated_stream_notifications_through_bounded_channel() {
        let fixture = RuntimeFixture::new("stream_notification");
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        let host = fixture.host.clone();
        let invocation = sample_invocation(Some(1_000));
        let task = tokio::spawn(async move {
            let grant = sample_grant();
            host.invoke_controlled(invocation, &grant, cancel_rx, Some(stream_tx))
                .await
        });
        tokio::time::sleep(StdDuration::from_millis(25)).await;
        let first = stream_rx.recv().await.expect("first progress event");
        let second = stream_rx.recv().await.expect("second progress event");
        let result = task.await.expect("join invoke").expect("invoke");

        assert_eq!(result.invocation_id, "invoke-test");
        assert!(matches!(
            first,
            InvocationStreamEvent::Progress {
                fraction: Some(0.5),
                ..
            }
        ));
        assert!(matches!(second, InvocationStreamEvent::Data { .. }));
    }

    #[tokio::test]
    async fn rejects_out_of_sequence_stream_notifications() {
        let fixture = RuntimeFixture::new("stream_bad_sequence");

        let error = fixture
            .host
            .invoke(sample_invocation(Some(1_000)), &sample_grant())
            .await
            .expect_err("stream protocol violation");

        assert_eq!(error.category, CapabilityErrorCategory::Plugin);
        assert_eq!(error.code, "plugin.stream_protocol_violation");
    }

    #[tokio::test]
    async fn rejects_result_for_different_caller_owned_invocation_id() {
        let fixture = RuntimeFixture::new("invocation_id_mismatch");

        let error = fixture
            .host
            .invoke(sample_invocation(Some(1_000)), &sample_grant())
            .await
            .expect_err("invocation id mismatch");

        assert_eq!(error.category, CapabilityErrorCategory::Transport);
        assert_eq!(error.code, "protocol.invocation_id_mismatch");
        assert_eq!(error.details["expected_invocation_id"], "invoke-test");
        assert_eq!(error.details["actual_invocation_id"], "different-call");
    }

    #[tokio::test]
    async fn cancellation_is_bounded_and_cleans_up_uncooperative_process() {
        let fixture = RuntimeFixture::new("timeout");
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let started = std::time::Instant::now();
        tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(25)).await;
            let _ = cancel_tx.send(true);
        });

        let error = fixture
            .host
            .invoke_controlled(
                sample_invocation(Some(5_000)),
                &sample_grant(),
                cancel_rx,
                None,
            )
            .await
            .expect_err("cancelled invocation");

        assert_eq!(error.category, CapabilityErrorCategory::Cancellation);
        assert_eq!(error.code, "cancellation.requested");
        assert!(started.elapsed() < StdDuration::from_secs(3));
    }

    #[tokio::test]
    async fn maps_structured_target_failure() {
        let fixture = RuntimeFixture::new("target_failure");

        let error = fixture
            .host
            .invoke(sample_invocation(Some(1_000)), &sample_grant())
            .await
            .expect_err("target failure");

        assert_eq!(error.category, CapabilityErrorCategory::TargetSystem);
        assert_eq!(error.code, "fixture.target_failed");
        assert_eq!(error.redaction, RedactionStatus::Applied);
    }

    #[tokio::test]
    async fn redacts_stderr_and_malformed_protocol_diagnostics() {
        let fixture = RuntimeFixture::new("malformed_with_stderr");

        let error = fixture
            .host
            .invoke(sample_invocation(Some(1_000)), &sample_grant())
            .await
            .expect_err("protocol violation");
        let encoded = serde_json::to_string(&error).expect("serialize error");

        assert_eq!(error.category, CapabilityErrorCategory::Transport);
        assert_eq!(error.redaction, RedactionStatus::Applied);
        assert!(encoded.contains("<redacted plugin stderr>"));
        assert!(!encoded.contains("super-secret"));
    }

    #[tokio::test]
    async fn reports_timeout_without_raw_stderr() {
        let fixture = RuntimeFixture::new("timeout");

        let error = fixture
            .host
            .invoke(sample_invocation(Some(50)), &sample_grant())
            .await
            .expect_err("timeout");

        assert_eq!(error.category, CapabilityErrorCategory::Timeout);
        assert_eq!(error.code, "timeout.process_plugin_request_timed_out");
    }

    #[tokio::test]
    async fn reports_crash_as_redacted_transport_error() {
        let fixture = RuntimeFixture::new("crash");

        let error = fixture
            .host
            .invoke(sample_invocation(Some(1_000)), &sample_grant())
            .await
            .expect_err("crash");

        assert_eq!(error.category, CapabilityErrorCategory::Transport);
        assert_eq!(error.code, "transport.process_plugin_exited");
        assert_eq!(error.redaction, RedactionStatus::Applied);
    }

    #[tokio::test]
    async fn shutdown_closes_stdin_and_waits_before_kill() {
        let fixture = RuntimeFixture::new("graceful_shutdown");

        fixture.host.initialize_and_health().await.expect("health");

        assert!(
            fixture
                .path()
                .join("fixture")
                .join("shutdown.marker")
                .exists(),
            "plugin should observe stdin EOF and finish cleanup"
        );
    }

    #[tokio::test]
    async fn stderr_summary_uses_launch_limit_and_redacts_content() {
        let fixture = RuntimeFixture::with_options(
            "malformed_with_stderr",
            ProcessPluginLaunchOptions {
                stderr_limit_bytes: 8,
                ..ProcessPluginLaunchOptions::default()
            },
        );

        let error = fixture
            .host
            .invoke(sample_invocation(Some(1_000)), &sample_grant())
            .await
            .expect_err("protocol violation");
        let encoded = serde_json::to_string(&error).expect("serialize error");

        assert_eq!(error.details["stderr"]["limit_bytes"], 8);
        assert_eq!(error.details["stderr"]["bytes"], 9);
        assert_eq!(error.details["stderr"]["truncated"], true);
        assert!(encoded.contains("<redacted plugin stderr>"));
        assert!(!encoded.contains("super-secret"));
    }

    fn sample_invocation(timeout_ms: Option<u64>) -> CapabilityInvocation {
        CapabilityInvocation {
            id: "invoke-test".into(),
            plugin_id: "fixture".into(),
            capability_id: "echo".into(),
            connection: InvocationConnectionTarget::FromProfile {
                profile: ConnectionProfileRef::Name("fixture-profile".into()),
                purpose: ConnectionInstancePurpose::CapabilityInvocation,
                reuse: InstanceReusePolicy::Allow,
                options: Value::Null,
            },
            input: json!({ "message": "hello" }),
            controls: InvocationControls {
                timeout_ms,
                ..InvocationControls::default()
            },
            actor: Some(ActorRef {
                id: "test-agent".into(),
                actor_type: ActorType::Agent,
            }),
            requested_at: Utc::now(),
        }
    }

    fn sample_grant() -> CredentialGrant {
        CredentialGrant {
            id: "grant-test".into(),
            profile: ConnectionProfileRef::Name("fixture-profile".into()),
            plugin_id: "fixture".into(),
            scope: CredentialGrantScope::Invocation {
                invocation_id: "invoke-test".into(),
            },
            issued_at: Utc::now(),
            expires_at: None,
            credential_refs: vec![CredentialRef {
                id: "cred-password".into(),
                class: CredentialClass::Password,
                label: Some("password".into()),
            }],
            redaction: RedactionStatus::NotRequired,
        }
    }

    struct RuntimeFixture {
        _temp: TempDir,
        host: ProcessPluginRuntimeHost,
    }

    impl RuntimeFixture {
        fn new(mode: &str) -> Self {
            Self::with_options(mode, ProcessPluginLaunchOptions::default())
        }

        fn with_options(mode: &str, options: ProcessPluginLaunchOptions) -> Self {
            let temp = TempDir::new("runtime");
            write_fixture_plugin(temp.path(), mode);
            let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
                temp.path(),
                ProcessPluginRootKind::EnvPath,
                0,
            )]);
            let candidate = discovery
                .candidates
                .into_iter()
                .find(|candidate| candidate.id == "fixture")
                .expect("fixture candidate");
            assert_eq!(candidate.state, ProcessPluginCandidateState::Available);
            Self {
                _temp: temp,
                host: ProcessPluginRuntimeHost::with_options(candidate, options),
            }
        }

        fn path(&self) -> &Path {
            self._temp.path()
        }
    }

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let id = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "voidb-process-runtime-{label}-{}-{id}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn write_fixture_plugin(root: &Path, mode: &str) {
        let plugin_dir = root.join("fixture");
        let schemas = plugin_dir.join("schemas");
        let bin = plugin_dir.join("bin");
        fs::create_dir_all(&schemas).expect("create schemas");
        fs::create_dir_all(&bin).expect("create bin");
        fs::write(schemas.join("profile.schema.json"), r#"{"type":"object"}"#)
            .expect("write profile schema");
        fs::write(
            schemas.join("echo-input.schema.json"),
            r#"{"type":"object"}"#,
        )
        .expect("write input schema");
        fs::write(
            schemas.join("echo-output.schema.json"),
            r#"{"type":"object"}"#,
        )
        .expect("write output schema");

        let script = bin.join("fixture-runtime");
        fs::write(&script, fixture_script()).expect("write script");
        make_executable(&script);

        let runtime_env = if mode == "health_env" {
            r#"
[runtime.env]
VOIDB_PLUGIN_ID = "manifest-spoof"
VOIDB_PLUGIN_DIR = "/tmp/spoof"
VOIDB_PROTOCOL_VERSION = "999"
VOIDB_LOG_FORMAT = "text"
"#
        } else {
            ""
        };

        let manifest = format!(
            r#"
id = "fixture"
name = "Fixture"
version = "0.1.0"
protocol_version = "1"

[runtime]
command = "fixture-runtime"
args = ["{mode}"]
transport = "stdio-jsonrpc"
{runtime_env}

[connections]
profile_schema = "schemas/profile.schema.json"
secret_classes = ["password"]

[[capabilities]]
id = "echo"
description = "Echo input."
input_schema = "schemas/echo-input.schema.json"
output_schema = "schemas/echo-output.schema.json"
permissions = ["connection.read"]
destructive = false
streaming = false
connection_required = true
required_secret_classes = ["password"]
supports_dry_run = false
default_timeout_ms = 1000
"#
        );
        fs::write(plugin_dir.join("plugin.toml"), manifest).expect("write manifest");
    }

    fn fixture_script() -> &'static str {
        r#"#!/bin/sh
mode="$1"
while IFS= read -r line; do
  case "$line" in
    *voidb.initialize*)
      case "$mode" in
        protocol_mismatch)
          echo '{"jsonrpc":"2.0","id":"initialize","result":{"plugin_id":"fixture","protocol_version":"2","status":"ready"}}'
          ;;
        *)
          echo '{"jsonrpc":"2.0","id":"initialize","result":{"plugin_id":"fixture","protocol_version":"1","status":"ready"}}'
          ;;
      esac
      ;;
    *voidb.health*)
      case "$mode" in
        health_env)
          echo "{\"jsonrpc\":\"2.0\",\"id\":\"health\",\"result\":{\"status\":\"ready\",\"active_invocations\":0,\"env\":{\"plugin_id\":\"$VOIDB_PLUGIN_ID\",\"plugin_dir\":\"$VOIDB_PLUGIN_DIR\",\"protocol_version\":\"$VOIDB_PROTOCOL_VERSION\",\"log_format\":\"$VOIDB_LOG_FORMAT\"}}}"
          ;;
        *)
          echo '{"jsonrpc":"2.0","id":"health","result":{"status":"ready","active_invocations":0}}'
          ;;
      esac
      ;;
    *voidb.invoke*)
      case "$mode" in
        success)
          echo '{"jsonrpc":"2.0","id":"invoke","result":{"invocation_id":"invoke-test","status":"succeeded","output":{"ok":true},"output_summary":{"ok":true}}}'
          ;;
        stream_notification)
          echo '{"jsonrpc":"2.0","method":"voidb.stream.progress","params":{"invocation_id":"invoke-test","sequence":0,"message":"working","progress":0.5}}'
          echo '{"jsonrpc":"2.0","method":"voidb.stream.item","params":{"invocation_id":"invoke-test","sequence":1,"item":{"row":1}}}'
          echo '{"jsonrpc":"2.0","id":"invoke","result":{"invocation_id":"invoke-test","status":"succeeded","output":{"stream_notice":true},"output_summary":{"stream_notice":true}}}'
          ;;
        stream_bad_sequence)
          echo '{"jsonrpc":"2.0","method":"voidb.stream.progress","params":{"invocation_id":"invoke-test","sequence":1,"message":"working","progress":0.5}}'
          echo '{"jsonrpc":"2.0","id":"invoke","result":{"invocation_id":"invoke-test","status":"succeeded","output":{},"output_summary":{}}}'
          ;;
        invocation_id_mismatch)
          echo '{"jsonrpc":"2.0","id":"invoke","result":{"invocation_id":"different-call","status":"succeeded","output":{},"output_summary":{}}}'
          ;;
        target_failure)
          echo '{"jsonrpc":"2.0","id":"invoke","error":{"code":-32010,"message":"Target failed","data":{"category":"target_system","code":"fixture.target_failed","message":"Target failed.","details":{},"retryable":false,"redaction":"applied"}}}'
          ;;
        malformed_with_stderr)
          echo 'super-secret from plugin stderr' >&2
          echo 'not-json'
          ;;
        timeout)
          sleep 2
          echo '{"jsonrpc":"2.0","id":"invoke","result":{"invocation_id":"invoke-test","status":"succeeded","output":{},"output_summary":{}}}'
          ;;
        crash)
          exit 42
          ;;
        graceful_shutdown)
          echo '{"jsonrpc":"2.0","id":"invoke","result":{"invocation_id":"invoke-test","status":"succeeded","output":{"ok":true},"output_summary":{"ok":true}}}'
          ;;
      esac
      ;;
  esac
done
if [ "$mode" = "graceful_shutdown" ]; then
  echo "closed" > shutdown.marker
fi
"#
    }

    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("chmod");
    }
}
