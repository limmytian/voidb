use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use serde_json::{Value, json};

use super::{
    AgentAuthorizationPresetKind, AuthorizationStatusView, CapabilityItem, ConnectionProfile,
    GrantRevisionView, JitDecision, PLUGINS, PendingAuthorizationView, ScreenMode,
    format_use_limit,
};
use voidb_core::process_plugin::{ProcessPluginCandidateState, discover_process_plugins};

use super::ConnectionManagerApp;

impl ConnectionManagerApp {
    pub(super) fn poll_background(&mut self) -> bool {
        let mut changed = false;
        if let Some((plugin_id, rx)) = &self.plugin_install_rx {
            let finished = match rx.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("Plugin installer worker stopped".into()))
                }
                Err(mpsc::TryRecvError::Empty) => None,
            };
            if let Some(result) = finished {
                let plugin_id = plugin_id.clone();
                self.plugin_states = installed_plugin_states();
                self.status = match result {
                    Ok(message)
                        if self.plugin_states.get(&plugin_id)
                            == Some(&ProcessPluginCandidateState::Available) =>
                    {
                        message
                    }
                    Ok(_) => format!(
                        "Plugin '{plugin_id}' was installed but is unavailable; inspect with voidb-cli plugin describe {plugin_id}"
                    ),
                    Err(error) => {
                        format!("Install '{plugin_id}' failed: {error} · press i to retry")
                    }
                };
                self.plugin_install_rx = None;
                self.next_authorization_refresh = Instant::now();
                changed = true;
            }
        }
        self.start_authorization_status_refresh();
        if let Some(rx) = &self.test_rx {
            match rx.try_recv() {
                Ok(Ok(message)) => {
                    self.status = message;
                    self.test_rx = None;
                    changed = true;
                }
                Ok(Err(message)) => {
                    self.status = format!("Test failed: {message}");
                    self.test_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.status = "Profile test worker stopped".to_string();
                    self.test_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(rx) = &self.capability_rx {
            match rx.try_recv() {
                Ok(Ok(payload)) => {
                    self.capabilities = parse_capabilities(&payload);
                    self.status = format!("Loaded {} capabilities", self.capabilities.len());
                    self.capability_rx = None;
                    changed = true;
                }
                Ok(Err(message)) => {
                    self.status = format!("Capability discovery failed: {message}");
                    self.capability_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.status = "Capability discovery worker stopped".to_string();
                    self.capability_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(rx) = &self.authorization_catalog_rx {
            match rx.try_recv() {
                Ok(Ok(payload)) => {
                    let capabilities = parse_capabilities(&payload);
                    if let Some(dialog) = &mut self.authorization_dialog {
                        dialog.capabilities = capabilities;
                        dialog.loading = false;
                        dialog.message = if dialog.capabilities.is_empty() {
                            Some("This profile has no agent-ready capabilities".into())
                        } else {
                            None
                        };
                    }
                    self.authorization_catalog_rx = None;
                    changed = true;
                }
                Ok(Err(message)) => {
                    if let Some(dialog) = &mut self.authorization_dialog {
                        dialog.loading = false;
                        dialog.message = Some(format!("Capability catalog unavailable: {message}"));
                    }
                    self.authorization_catalog_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    if let Some(dialog) = &mut self.authorization_dialog {
                        dialog.loading = false;
                        dialog.message = Some("Capability catalog worker stopped".into());
                    }
                    self.authorization_catalog_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(rx) = &self.authorization_operation_rx {
            match rx.try_recv() {
                Ok(Ok(message)) => {
                    self.status = message;
                    self.authorization_operation_rx = None;
                    self.authorization_dialog = None;
                    self.jit_approval_dialog = None;
                    if self.mode != ScreenMode::AuthorizationInbox {
                        self.mode = ScreenMode::Browse;
                    }
                    self.next_authorization_refresh = Instant::now();
                    self.start_authorization_status_refresh();
                    changed = true;
                }
                Ok(Err(message)) => {
                    if let Some(dialog) = &mut self.authorization_dialog {
                        dialog.review_action = None;
                        dialog.message = Some(format!("Authorization operation failed: {message}"));
                    }
                    if let Some(dialog) = &mut self.jit_approval_dialog {
                        dialog.confirm = false;
                        dialog.message = Some(format!("Authorization decision failed: {message}"));
                    }
                    self.authorization_operation_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    if let Some(dialog) = &mut self.authorization_dialog {
                        dialog.review_action = None;
                        dialog.message = Some("Authorization operation worker stopped".into());
                    }
                    if let Some(dialog) = &mut self.jit_approval_dialog {
                        dialog.confirm = false;
                        dialog.message = Some("Authorization decision worker stopped".into());
                    }
                    self.authorization_operation_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(rx) = &self.authorization_status_rx {
            match rx.try_recv() {
                Ok(Ok(payload)) => {
                    self.authorization_statuses = parse_agent_statuses(&payload);
                    self.authorization_supported_plugins = parse_agent_supported_plugins(&payload);
                    self.authorization_capability_catalog = parse_capabilities(&payload)
                        .into_iter()
                        .map(|capability| (capability.id.clone(), capability))
                        .collect();
                    self.pending_authorization_requests = parse_pending_authorizations(&payload);
                    self.grant_revisions = parse_grant_revisions(&payload);
                    self.authorization_observed_at = parse_authorization_observed_at(&payload);
                    self.authorization_snapshot_error = None;
                    self.authorization_inbox_selected = self
                        .authorization_inbox_selected
                        .min(self.pending_authorization_requests.len().saturating_sub(1));
                    self.authorization_status_rx = None;
                    changed = true;
                }
                Ok(Err(message)) => {
                    self.authorization_snapshot_error = Some(message);
                    self.authorization_status_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.authorization_snapshot_error =
                        Some("authorization snapshot worker stopped".into());
                    self.authorization_status_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        changed
    }
}

pub(super) fn installed_plugin_states() -> HashMap<String, ProcessPluginCandidateState> {
    let discovery = discover_process_plugins();
    discovery
        .candidates
        .iter()
        .filter(|candidate| candidate.state != ProcessPluginCandidateState::Shadowed)
        .map(|candidate| (candidate.id.clone(), candidate.state))
        .collect()
}

pub(super) fn can_install_missing_plugin(
    plugin_id: &str,
    state: Option<ProcessPluginCandidateState>,
) -> bool {
    state.is_none() && PLUGINS.iter().any(|(id, _)| *id == plugin_id)
}

pub(super) fn run_plugin_install(plugin_id: &str) -> std::result::Result<String, String> {
    if !can_install_missing_plugin(plugin_id, None) {
        return Err("Only official plugin IDs can be installed here".into());
    }
    let output = std::process::Command::new(resolve_voidb_cli_binary())
        .args(["plugin", "install", plugin_id, "--format", "json"])
        .env_remove(voidb_core::VOIDB_MASTER_PASSWORD_ENV)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    if !output.status.success() {
        return Err(format!("Plugin installer exited with {}", output.status));
    }
    let response: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "Invalid plugin installer response".to_string())?;
    parse_plugin_install_response(plugin_id, &response)
}

pub(super) fn parse_plugin_install_response(
    plugin_id: &str,
    response: &Value,
) -> std::result::Result<String, String> {
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(response
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("Plugin installer reported an error")
            .to_string());
    }
    if response.pointer("/data/plugin/id").and_then(Value::as_str) != Some(plugin_id)
        || response
            .pointer("/data/plugin/candidate_state")
            .and_then(Value::as_str)
            != Some("available")
    {
        return Err("Installer did not return the requested available plugin".into());
    }
    Ok(format!(
        "Plugin '{plugin_id}' installed · press t to test or c for capabilities"
    ))
}

fn resolve_voidb_cli_binary() -> PathBuf {
    if let Ok(path) = std::env::var("VOIDB_CLI_BIN") {
        return path.into();
    }
    if let Ok(current) = std::env::current_exe()
        && let Some(directory) = current.parent()
    {
        let sibling = directory.join(if cfg!(windows) {
            "voidb-cli.exe"
        } else {
            "voidb-cli"
        });
        if sibling.exists() {
            return sibling;
        }
    }
    "voidb-cli".into()
}

pub(super) fn run_profile_test(
    profile: &ConnectionProfile,
    master_password: Option<&str>,
) -> std::result::Result<String, String> {
    let mut command = std::process::Command::new(resolve_voidb_cli_binary());
    command.args([
        "profile",
        "test",
        &format!("id:{}", profile.id),
        "--plugin",
        &profile.plugin_id,
        "--format",
        "json",
    ]);
    if let Some(password) = master_password {
        command.env(voidb_core::VOIDB_MASTER_PASSWORD_ENV, password);
    }
    let output = command
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "voidb-cli did not return structured JSON".to_string())?;
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        let message = value
            .pointer("/data/message")
            .and_then(Value::as_str)
            .unwrap_or("connection succeeded");
        Ok(format!(
            "{}/{} OK: {message}",
            profile.plugin_id, profile.name
        ))
    } else {
        Err(value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("profile test failed")
            .to_string())
    }
}

pub(super) struct AgentAuthorizeRequest {
    pub(super) capabilities: Vec<String>,
    pub(super) ttl_minutes: u64,
    pub(super) uses: Option<u32>,
    pub(super) preset: AgentAuthorizationPresetKind,
    pub(super) allow_destructive: bool,
    pub(super) replace: bool,
}

pub(super) fn run_agent_authorize(
    profile: &ConnectionProfile,
    master_password: Option<&str>,
    request: AgentAuthorizeRequest,
) -> std::result::Result<String, String> {
    let password = master_password.ok_or_else(|| "credentials are locked".to_string())?;
    if request.capabilities.is_empty() {
        return Err("authorization capability scope is empty".into());
    }
    let mut command = std::process::Command::new(resolve_voidb_cli_binary());
    command.args(agent_authorize_args(profile, &request));
    command
        .env_remove(voidb_core::VOIDB_MASTER_PASSWORD_ENV)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "could not open the authorization password pipe".to_string())?
        .write_all(password.as_bytes())
        .map_err(|error| format!("could not send the authorization password: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("could not wait for voidb-cli: {error}"))?;
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| String::from_utf8_lossy(&output.stderr).into_owned())?;
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        let grant_id = value
            .pointer("/data/grant/id")
            .and_then(Value::as_str)
            .unwrap_or("agent grant");
        Ok(format!(
            "Authorized {grant_id} for {}/{} · {} capabilities · {} min · {}",
            profile.plugin_id,
            profile.name,
            request.capabilities.len(),
            request.ttl_minutes,
            format_use_limit(request.uses),
        ))
    } else {
        Err(value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("voidb-cli rejected the authorization")
            .to_string())
    }
}

pub(super) fn agent_authorize_args(
    profile: &ConnectionProfile,
    request: &AgentAuthorizeRequest,
) -> Vec<String> {
    let mut args = vec![
        "agent".into(),
        "authorize".into(),
        "--profile".into(),
        format!("id:{}", profile.id),
        "--plugin".into(),
        profile.plugin_id.clone(),
        "--ttl-minutes".into(),
        request.ttl_minutes.to_string(),
        "--preset".into(),
        match request.preset {
            AgentAuthorizationPresetKind::ReadOnly => "read_only".into(),
            AgentAuthorizationPresetKind::InteractiveExecute => "interactive_execute".into(),
            AgentAuthorizationPresetKind::FullAccess => "full_access".into(),
            AgentAuthorizationPresetKind::Custom => "custom".into(),
        },
        "--password-stdin".into(),
    ];
    if let Some(uses) = request.uses {
        args.extend(["--uses".into(), uses.to_string()]);
    }
    for capability in &request.capabilities {
        args.extend(["--capability".into(), capability.clone()]);
    }
    if request.allow_destructive {
        args.extend(["--allow-destructive".into(), "--yes".into()]);
    }
    if request.replace {
        args.push("--replace".into());
    }
    args
}

pub(super) fn run_agent_renew(
    grant_id: &str,
    ttl_minutes: u64,
    uses: Option<u32>,
) -> std::result::Result<String, String> {
    let mut command = std::process::Command::new(resolve_voidb_cli_binary());
    command
        .args(["agent", "renew", grant_id, "--ttl-minutes"])
        .arg(ttl_minutes.to_string());
    if let Some(uses) = uses {
        command.arg("--uses").arg(uses.to_string());
    }
    let output = command
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| String::from_utf8_lossy(&output.stderr).into_owned())?;
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(format!(
            "Renewed {grant_id} for {ttl_minutes} minutes with {}",
            format_use_limit(uses)
        ))
    } else {
        Err(value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("voidb-cli rejected the renewal")
            .to_string())
    }
}

pub(super) fn run_agent_revoke_profile(
    profile: &ConnectionProfile,
) -> std::result::Result<String, String> {
    let output = std::process::Command::new(resolve_voidb_cli_binary())
        .args(["agent", "revoke", "--profile"])
        .arg(format!("id:{}", profile.id))
        .args(["--plugin", &profile.plugin_id])
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| String::from_utf8_lossy(&output.stderr).into_owned())?;
    value
        .pointer("/data/count")
        .and_then(Value::as_u64)
        .map(|count| {
            format!(
                "Revoked {count} grant{} for {}/{}",
                if count == 1 { "" } else { "s" },
                profile.plugin_id,
                profile.name
            )
        })
        .ok_or_else(|| "voidb-cli did not return a scoped revoke count".to_string())
}

pub(super) fn run_agent_revoke_all() -> std::result::Result<usize, String> {
    let output = std::process::Command::new(resolve_voidb_cli_binary())
        .args(["agent", "revoke", "--all"])
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| String::from_utf8_lossy(&output.stderr).into_owned())?;
    value
        .pointer("/data/count")
        .and_then(Value::as_u64)
        .map(|count| count as usize)
        .ok_or_else(|| "voidb-cli did not return a revoke count".to_string())
}

fn run_agent_list() -> std::result::Result<String, String> {
    let output = std::process::Command::new(resolve_voidb_cli_binary())
        .args(["agent", "list"])
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    if !output.status.success() && output.stdout.is_empty() {
        return Err(format!("voidb-cli exited with {}", output.status));
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

pub(super) fn run_authorization_snapshot() -> std::result::Result<String, String> {
    let grants: Value = serde_json::from_str(&run_agent_list()?)
        .map_err(|_| "voidb-cli agent list returned invalid JSON".to_string())?;
    let output = std::process::Command::new(resolve_voidb_cli_binary())
        .args(["agent", "catalog"])
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    let catalog: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| String::from_utf8_lossy(&output.stderr).into_owned())?;
    let inbox_output = std::process::Command::new(resolve_voidb_cli_binary())
        .args(["agent", "request", "inbox"])
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    let inbox: Value = serde_json::from_slice(&inbox_output.stdout)
        .map_err(|_| String::from_utf8_lossy(&inbox_output.stderr).into_owned())?;
    Ok(json!({ "agent": grants, "catalog": catalog, "inbox": inbox }).to_string())
}

pub(super) fn run_jit_authorization_decision(
    request_id: &str,
    decision: JitDecision,
    ttl_minutes: u64,
    uses: Option<u32>,
    grant_id: Option<&str>,
    constraints_json: Option<&str>,
    master_password: Option<&str>,
) -> std::result::Result<String, String> {
    let mut command = std::process::Command::new(resolve_voidb_cli_binary());
    command
        .args(["agent", "request", "decide", request_id, "--decision"])
        .arg(decision.cli_value());
    if matches!(decision, JitDecision::Bounded) {
        command
            .arg("--ttl-seconds")
            .arg((ttl_minutes * 60).to_string());
        if let Some(uses) = uses {
            command.arg("--uses").arg(uses.to_string());
        }
    }
    if matches!(decision, JitDecision::AddToGrant) {
        let grant_id = grant_id.ok_or_else(|| "No compatible logical grant exists".to_string())?;
        command
            .arg("--grant")
            .arg(grant_id)
            .arg("--ttl-delta-seconds")
            .arg((ttl_minutes * 60).to_string())
            .arg("--uses-delta")
            .arg(uses.unwrap_or(0).to_string());
    }
    if let Some(constraints) = constraints_json {
        command.arg("--constraints-json").arg(constraints);
    }
    if matches!(decision, JitDecision::Deny) {
        command
            .arg("--reason")
            .arg("Denied from Connection Manager");
    }
    let password = master_password.ok_or_else(|| "credentials are locked".to_string())?;
    command.arg("--password-stdin");
    command
        .env_remove(voidb_core::VOIDB_MASTER_PASSWORD_ENV)
        .stdin(std::process::Stdio::piped());
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "could not open decision password pipe".to_string())?
        .write_all(password.as_bytes())
        .map_err(|error| format!("could not send decision password: {error}"))?;
    parse_jit_decision_output(
        child
            .wait_with_output()
            .map_err(|error| format!("could not wait for voidb-cli: {error}"))?,
        request_id,
        decision,
    )
}

fn parse_jit_decision_output(
    output: std::process::Output,
    request_id: &str,
    decision: JitDecision,
) -> std::result::Result<String, String> {
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| String::from_utf8_lossy(&output.stderr).into_owned())?;
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        let revision = value
            .pointer("/data/revision/revision")
            .and_then(Value::as_u64)
            .map(|revision| format!(" · revision {revision}"))
            .unwrap_or_default();
        Ok(format!(
            "{} request {request_id}{revision}",
            decision.label()
        ))
    } else {
        Err(value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("voidb-cli rejected the authorization decision")
            .to_string())
    }
}

pub(super) fn parse_agent_statuses(
    payload: &str,
) -> HashMap<(String, String), AuthorizationStatusView> {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return HashMap::new();
    };
    let agent = value.get("agent").unwrap_or(&value);
    agent
        .pointer("/data/grants")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|grant| {
            let profile_id = grant.get("profile_id")?.as_str()?.to_string();
            let plugin_id = grant.get("plugin_id")?.as_str()?.to_string();
            let view = AuthorizationStatusView {
                grant_id: grant.get("id")?.as_str()?.to_string(),
                profile_id: profile_id.clone(),
                plugin_id: plugin_id.clone(),
                status: grant
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("broker_offline")
                    .to_string(),
                broker_health: grant
                    .get("broker_health")
                    .and_then(Value::as_str)
                    .unwrap_or("offline")
                    .to_string(),
                allow_destructive: grant
                    .get("allow_destructive")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                expires_at: grant
                    .get("expires_at")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                remaining_uses: grant
                    .get("remaining_uses")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok()),
                active_session_count: grant
                    .get("active_session_count")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or(0),
                capabilities: grant
                    .get("capabilities")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect(),
            };
            Some(((profile_id, plugin_id), view))
        })
        .collect()
}

pub(super) fn parse_agent_supported_plugins(payload: &str) -> BTreeSet<String> {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return BTreeSet::new();
    };
    value
        .pointer("/catalog/data/capabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|capability| capability.get("plugin_id").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

pub(super) fn parse_pending_authorizations(payload: &str) -> Vec<PendingAuthorizationView> {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return Vec::new();
    };
    let mut requests = value
        .pointer("/inbox/data/requests")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|request| {
            Some(PendingAuthorizationView {
                id: request.get("id")?.as_str()?.to_string(),
                principal_fingerprint: request.get("principal_fingerprint")?.as_str()?.to_string(),
                profile_id: request.get("profile_id")?.as_str()?.to_string(),
                plugin_id: request.get("plugin_id")?.as_str()?.to_string(),
                scope: request.get("scope")?.clone(),
                risk: request
                    .get("risk")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                purpose: request
                    .get("purpose")
                    .or_else(|| request.get("reason"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                status: request.get("status")?.as_str()?.to_string(),
                created_at: request.get("created_at")?.as_str()?.to_string(),
                expires_at: request.get("expires_at")?.as_str()?.to_string(),
                timed_out: request
                    .get("timed_out")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                decision_reason: request
                    .get("decision_reason")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            })
        })
        .collect::<Vec<_>>();
    requests.sort_by_key(|request| (!request.is_pending(), request.created_at.clone()));
    requests
}

pub(super) fn parse_grant_revisions(payload: &str) -> Vec<GrantRevisionView> {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return Vec::new();
    };
    value
        .pointer("/inbox/data/revisions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|revision| {
            Some(GrantRevisionView {
                grant_id: revision.get("grant_id")?.as_str()?.to_string(),
                revision: revision.get("revision")?.as_u64()?,
                principal_fingerprint: revision.get("principal_fingerprint")?.as_str()?.to_string(),
                profile_id: revision.get("profile_id")?.as_str()?.to_string(),
                plugin_id: revision.get("plugin_id")?.as_str()?.to_string(),
                expires_at: revision.get("expires_at")?.as_str()?.to_string(),
                remaining_uses: revision
                    .get("remaining_uses")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok()),
            })
        })
        .collect()
}

fn parse_authorization_observed_at(payload: &str) -> Option<String> {
    serde_json::from_str::<Value>(payload)
        .ok()?
        .pointer("/inbox/data/observed_at")?
        .as_str()
        .map(str::to_string)
}

pub(super) fn run_capability_list(plugin_id: &str) -> std::result::Result<String, String> {
    let output = std::process::Command::new(resolve_voidb_cli_binary())
        .args(capability_list_args(plugin_id))
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    if !output.status.success() && output.stdout.is_empty() {
        return Err(format!("voidb-cli exited with {}", output.status));
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

pub(super) fn capability_list_args(plugin_id: &str) -> [&str; 6] {
    [
        "agent",
        "catalog",
        "--plugin",
        plugin_id,
        "--execution-mode",
        "stateless",
    ]
}

pub(super) fn parse_capabilities(payload: &str) -> Vec<CapabilityItem> {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return Vec::new();
    };
    let candidates = value
        .pointer("/data/capabilities")
        .or_else(|| value.pointer("/catalog/data/capabilities"))
        .or_else(|| value.pointer("/data/items"))
        .or_else(|| value.get("capabilities"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    candidates
        .into_iter()
        .filter_map(|item| {
            let id = item
                .get("qualified_id")
                .or_else(|| item.get("id"))
                .and_then(Value::as_str)?
                .to_string();
            Some(CapabilityItem {
                id,
                description: item
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("No description")
                    .to_string(),
                risk: item
                    .get("risk")
                    .and_then(Value::as_str)
                    .unwrap_or("read_only")
                    .to_string(),
                interactive_execute: item
                    .pointer("/authorization/interactive_execute")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                capability_wide_allowed: item
                    .pointer("/authorization/capability_wide_allowed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                approval_fields: item
                    .pointer("/authorization/approval_schema/fields")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|field| {
                        let label = field.get("label")?.as_str()?;
                        let path = field.get("path")?.as_str()?;
                        let constraint = field
                            .get("constraint")
                            .and_then(Value::as_str)
                            .unwrap_or("exact");
                        Some(format!("{label} ({path}, {constraint})"))
                    })
                    .collect(),
            })
        })
        .collect()
}
