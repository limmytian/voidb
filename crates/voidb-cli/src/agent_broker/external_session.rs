//! Bridge between the agent authorization broker's session host and external
//! process plugins that negotiate persistent sessions (protocol 1.1).
//!
//! The factory resolves the installed plugin candidate and the granted
//! profile, opens one kill-on-drop plugin child per hosted session through
//! [`ProcessPluginSessionRuntime`], and maps the wire contract
//! (`voidb.session.*`) onto the host's [`PluginAgentSession`] trait. Every
//! live handle stays inside this module; the broker, grant files, and audit
//! records only ever see bounded secret-free descriptors.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use uuid::Uuid;
use voidb_core::capability::{
    CapabilityDefinition, CapabilityError, CapabilityErrorCategory, CapabilityInvocation,
    ConnectionInstancePurpose, ConnectionProfile, CredentialClass, InstanceReusePolicy,
    InvocationConnectionTarget, InvocationControls, CapabilityRiskLevel, RedactionStatus,
    grant_credentials_for_invocation,
};
use voidb_core::process_plugin::ProcessPluginCandidateState;
use voidb_core::process_plugin_runtime::{
    ProcessPluginRuntimeHost, ProcessPluginSessionRuntime, credential_grant_descriptors,
};
use voidb_core::session::{
    AgentSessionCallRequest, AgentSessionCallResult, AgentSessionOpenContext,
    AgentSessionConcurrency, PluginAgentSession, PluginAgentSessionFactory, PluginSessionError,
    PluginSessionErrorCode, PluginSessionHealth, PluginSessionReason,
};
use voidb_core::{
    ConnectionConfig, DatabaseType, LocalProfileStore, redact_text_with_json,
};

/// Built-in plugin IDs that never host persistent agent sessions:
/// `connections` is an observer without protocol state, and Sync remains
/// deferred per the adoption matrix.
pub(crate) const SESSIONLESS_BUILTIN_PLUGIN_IDS: &[&str] = &["connections", "sync"];

pub(crate) fn builtin_plugin_hosts_no_sessions(plugin_id: &str) -> bool {
    SESSIONLESS_BUILTIN_PLUGIN_IDS.contains(&plugin_id)
}

/// Resolved per-grant factory state. Everything here stays in broker process
/// memory; grant files never receive the decrypted connection or credential
/// material.
pub(crate) struct ExternalPluginSessionFactory {
    plugin_id: String,
    runtime_host: ProcessPluginRuntimeHost,
    profile: ConnectionProfile,
    connection: ConnectionConfig,
    capabilities: BTreeMap<String, CapabilityDefinition>,
}

impl ExternalPluginSessionFactory {
    /// Resolves the installed plugin candidate and granted profile for a
    /// session-capable grant. Returns `Ok(None)` when no installed candidate
    /// or matching profile exists so the session host keeps its fail-closed
    /// `Unsupported` behavior for that grant.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn resolve(
        grant_plugin_id: &str,
        grant_profile_id: &str,
        master_password: &str,
    ) -> anyhow::Result<Option<Self>> {
        let discovery = voidb_core::discover_process_plugins();
        let candidate = discovery
            .candidates
            .into_iter()
            .find(|candidate| {
                candidate.id == grant_plugin_id
                    && candidate.state == ProcessPluginCandidateState::Available
            });
        let Some(candidate) = candidate else {
            return Ok(None);
        };

        let store = LocalProfileStore::default_store()?;
        let Some(profile) = store
            .load_profiles()?
            .into_iter()
            .find(|profile| profile.id == grant_profile_id)
        else {
            return Ok(None);
        };

        let connection = if is_local_system_profile(&profile) {
            local_system_connection(&profile)
        } else {
            store.native_connection(&profile, Some(master_password))?
        };

        let mut capabilities = BTreeMap::new();
        if let Some(manifest) = candidate.manifest.as_ref() {
            for capability in &manifest.capabilities {
                // Grant capabilities are qualified as "plugin.capability".
                let definition = capability_definition(manifest.id.clone(), capability);
                capabilities.insert(
                    format!("{}.{}", manifest.id, capability.id),
                    definition,
                );
            }
        }

        Ok(Some(Self {
            plugin_id: candidate.id.clone(),
            runtime_host: ProcessPluginRuntimeHost::new(candidate),
            profile,
            connection,
            capabilities,
        }))
    }

    fn session_credential_grants(
        &self,
        allowed_capabilities: &[String],
        session_id: &str,
    ) -> Result<Vec<Value>, PluginSessionError> {
        let mut descriptors = Vec::new();
        for capability_id in allowed_capabilities {
            let Some(definition) = self.capabilities.get(capability_id) else {
                return Err(PluginSessionError::new(
                    PluginSessionErrorCode::PolicyDenied,
                    format!("Capability '{capability_id}' is not declared by the plugin manifest."),
                ));
            };
            let invocation = CapabilityInvocation {
                id: format!("{session_id}:{}", definition.id),
                plugin_id: definition.plugin_id.clone(),
                capability_id: definition.id.clone(),
                connection: if definition.connection_required {
                    InvocationConnectionTarget::FromProfile {
                        profile: self.profile.profile_ref(),
                        purpose: ConnectionInstancePurpose::CapabilityInvocation,
                        reuse: InstanceReusePolicy::Allow,
                        options: Value::Null,
                    }
                } else {
                    InvocationConnectionTarget::Stateless
                },
                input: Value::Null,
                controls: InvocationControls::default(),
                actor: None,
                requested_at: Utc::now(),
            };
            let grant = grant_credentials_for_invocation(
                &self.profile,
                definition,
                &invocation,
                Utc::now(),
            )
            .map_err(|error| map_capability_error(&error))?;
            descriptors.extend(credential_grant_descriptors(&grant));
        }
        Ok(descriptors)
    }
}

#[async_trait]
impl PluginAgentSessionFactory for ExternalPluginSessionFactory {
    fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    async fn open(
        &self,
        context: AgentSessionOpenContext,
    ) -> Result<Arc<dyn PluginAgentSession>, PluginSessionError> {
        let mut runtime = self
            .runtime_host
            .open_session_runtime()
            .await
            .map_err(|error| map_capability_error(&error))?;

        let plugin_session_id = format!("plugin-session:{}", Uuid::new_v4());
        let purpose = serde_json::to_value(&context.binding.purpose)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "capability_invocation".to_owned());

        let credential_grants =
            self.session_credential_grants(&context.binding.allowed_capabilities, &plugin_session_id)?;

        let open_result = runtime
            .session_open(json!({
                "session_id": plugin_session_id,
                "generation": 1,
                "grant_id": context.binding.grant_id,
                "profile_id": context.binding.profile_id,
                "purpose": purpose,
                "capabilities": context.binding.allowed_capabilities,
                "lease_expires_at": context.lease_expires_at,
                "input": context.request.input,
                "credential_grants": credential_grants,
                "options": self.connection.plugin_config.clone().unwrap_or(Value::Null),
            }))
            .await
            .map_err(|error| map_capability_error(&error))?;

        let handle_id = open_result
            .get("handle_id")
            .and_then(Value::as_str)
            .filter(|handle_id| !handle_id.is_empty())
            .ok_or_else(|| {
                PluginSessionError::new(
                    PluginSessionErrorCode::OwnerUnavailable,
                    "Plugin session open did not return a handle id.",
                )
            })?
            .to_owned();
        let generation = open_result
            .get("generation")
            .and_then(Value::as_u64)
            .filter(|generation| *generation > 0)
            .unwrap_or(1);

        Ok(Arc::new(ExternalPluginSession {
            runtime: Arc::new(Mutex::new(Some(runtime))),
            handle_id,
            generation,
            connection: self.connection.clone(),
        }))
    }
}

/// One hosted plugin-owned session. Calls are serialized by the runtime's
/// `&mut` handle; the host layer adds the grant deadline and output bounds.
struct ExternalPluginSession {
    runtime: Arc<Mutex<Option<ProcessPluginSessionRuntime>>>,
    handle_id: String,
    generation: u64,
    connection: ConnectionConfig,
}

impl ExternalPluginSession {
    fn handle_params(&self) -> Value {
        json!({
            "handle_id": self.handle_id,
            "generation": self.generation,
        })
    }

    /// Redacts plugin output against the decrypted profile connection config,
    /// mirroring the one-shot invoke output redaction.
    fn redact_output(&self, output: &mut Value) -> RedactionStatus {
        let Some(plugin_config) = &self.connection.plugin_config else {
            return RedactionStatus::NotRequired;
        };
        redact_value_with_config(output, plugin_config)
    }
}

#[async_trait]
impl PluginAgentSession for ExternalPluginSession {
    fn concurrency(&self) -> AgentSessionConcurrency {
        AgentSessionConcurrency::Serialized
    }

    async fn call(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        let params = json!({
            "handle_id": self.handle_id,
            "generation": self.generation,
            "call_id": request.call_id,
            "capability": request.capability,
            "input": request.input,
            "output_limit_bytes": request.output_limit_bytes,
            "timeout_ms": request.timeout_ms,
        });
        let result = {
            let mut guard = self.runtime.lock().await;
            let runtime = runtime_guard(&mut guard)?;
            runtime
                .session_call(params)
                .await
                .map_err(|error| map_capability_error(&error))?
        };

        let call_id = result
            .get("call_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let mut output = result.get("output").cloned().unwrap_or(Value::Null);
        let local_redaction = self.redact_output(&mut output);
        let mut redaction = result
            .get("redaction")
            .cloned()
            .map(serde_json::from_value::<RedactionStatus>)
            .transpose()
            .map_err(|error| {
                PluginSessionError::new(
                    PluginSessionErrorCode::RedactionFailed,
                    format!("Plugin session returned an invalid redaction status: {error}"),
                )
            })?
            .unwrap_or(RedactionStatus::NotRequired);
        if local_redaction == RedactionStatus::Applied {
            redaction = RedactionStatus::Applied;
        }
        let output_bytes = serde_json::to_vec(&output)
            .map(|bytes| bytes.len())
            .unwrap_or(0);

        Ok(AgentSessionCallResult {
            call_id,
            output,
            output_bytes,
            redaction,
            truncated: result
                .get("truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }

    async fn health(&self) -> Result<PluginSessionHealth, PluginSessionError> {
        let result = {
            let mut guard = self.runtime.lock().await;
            let runtime = runtime_guard(&mut guard)?;
            runtime
                .session_health(self.handle_params())
                .await
                .map_err(|error| map_capability_error(&error))?
        };
        Ok(map_health_string(
            result
                .get("health")
                .and_then(Value::as_str)
                .unwrap_or("degraded"),
        ))
    }

    async fn renew(
        &self,
        lease_expires_at: chrono::DateTime<Utc>,
    ) -> Result<(), PluginSessionError> {
        let params = json!({
            "handle_id": self.handle_id,
            "generation": self.generation,
            "lease_expires_at": lease_expires_at,
        });
        let mut guard = self.runtime.lock().await;
        let runtime = runtime_guard(&mut guard)?;
        runtime
            .session_renew(params)
            .await
            .map_err(|error| map_capability_error(&error))?;
        Ok(())
    }

    async fn cancel(&self, call_id: &str) -> Result<(), PluginSessionError> {
        let params = json!({
            "handle_id": self.handle_id,
            "generation": self.generation,
            "call_id": call_id,
        });
        let accepted = {
            let mut guard = self.runtime.lock().await;
            let runtime = runtime_guard(&mut guard)?;
            runtime
                .session_cancel(params)
                .await
                .map_err(|error| map_capability_error(&error))?
        };
        if accepted.get("accepted").and_then(Value::as_bool) != Some(true) {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::CallNotFound,
                "Plugin session did not accept the call cancellation.",
            ));
        }
        Ok(())
    }

    async fn close(&self, reason: PluginSessionReason) -> Result<(), PluginSessionError> {
        let params = json!({
            "handle_id": self.handle_id,
            "generation": self.generation,
            "reason": reason,
        });
        let mut guard = self.runtime.lock().await;
        if guard.is_none() {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::OwnerUnavailable,
                "Plugin session runtime is closed.",
            ));
        }
        let close_result = match guard.as_mut().unwrap().session_close(params).await {
            Ok(result) => result,
            Err(error) => {
                // Bounded cleanup still runs: the plugin child is terminated
                // below even when the graceful close RPC fails.
                let stderr = if let Some(runtime) = guard.take() {
                    runtime.shutdown().await
                } else {
                    Vec::new()
                };
                let mut mapped = map_capability_error(&error);
                if !stderr.is_empty() {
                    mapped.message =
                        "Plugin session close failed; the plugin process was terminated."
                            .to_owned();
                }
                return Err(mapped);
            }
        };
        if let Some(runtime) = guard.take() {
            let _stderr = runtime.shutdown().await;
        }
        if close_result.get("closed").and_then(Value::as_bool) == Some(false) {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::CloseTimeout,
                "Plugin session reported an incomplete close.",
            ));
        }
        Ok(())
    }
}

fn runtime_guard(
    guard: &mut Option<ProcessPluginSessionRuntime>,
) -> Result<&mut ProcessPluginSessionRuntime, PluginSessionError> {
    guard.as_mut().ok_or_else(|| {
        PluginSessionError::new(
            PluginSessionErrorCode::OwnerUnavailable,
            "Plugin session runtime is closed.",
        )
    })
}

/// Maps a plugin/transport [`CapabilityError`] onto the stable session error
/// contract. Stable plugin codes win over categories so plugins can express
/// precise session failures.
fn map_capability_error(error: &CapabilityError) -> PluginSessionError {
    if error.redaction == RedactionStatus::FailedClosed {
        return PluginSessionError::new(
            PluginSessionErrorCode::RedactionFailed,
            "Plugin session output failed closed and cannot be returned.",
        );
    }
    if let Ok(code) =
        serde_json::from_value::<PluginSessionErrorCode>(json!(error.code))
    {
        return PluginSessionError::new(code, error.message.clone());
    }
    let code = match error.code.as_str() {
        "plugin.session_unsupported" | "unavailable.process_plugin_sessions_unsupported" => {
            PluginSessionErrorCode::Unsupported
        }
        "unavailable.process_plugin_session_runtime_closed" => PluginSessionErrorCode::Aborted,
        "protocol.session_descriptor_unsafe" => PluginSessionErrorCode::RedactionFailed,
        _ => match error.category {
            CapabilityErrorCategory::Timeout => PluginSessionErrorCode::TimedOut,
            CapabilityErrorCategory::Cancellation => PluginSessionErrorCode::Cancelled,
            CapabilityErrorCategory::Validation
            | CapabilityErrorCategory::Auth
            | CapabilityErrorCategory::Permission
            | CapabilityErrorCategory::Credential
            | CapabilityErrorCategory::Policy
            | CapabilityErrorCategory::Conflict => PluginSessionErrorCode::PolicyDenied,
            CapabilityErrorCategory::Unavailable
            | CapabilityErrorCategory::Transport
            | CapabilityErrorCategory::Plugin
            | CapabilityErrorCategory::TargetSystem
            | CapabilityErrorCategory::Internal => PluginSessionErrorCode::OwnerUnavailable,
        },
    };
    PluginSessionError::new(code, error.message.clone())
}

fn map_health_string(health: &str) -> PluginSessionHealth {
    match health {
        "starting" => PluginSessionHealth::Starting,
        "ready" => PluginSessionHealth::Ready,
        "busy" => PluginSessionHealth::Busy,
        "stale" => PluginSessionHealth::Stale,
        "closing" => PluginSessionHealth::Closing,
        "closed" => PluginSessionHealth::Closed,
        "failed" => PluginSessionHealth::Failed,
        _ => PluginSessionHealth::Degraded,
    }
}

#[cfg_attr(test, allow(dead_code))]
fn is_local_system_profile(profile: &ConnectionProfile) -> bool {
    profile
        .metadata
        .get("scope")
        .and_then(Value::as_str)
        .is_some_and(|scope| scope == "local_system")
}

#[cfg_attr(test, allow(dead_code))]
fn local_system_connection(profile: &ConnectionProfile) -> ConnectionConfig {
    ConnectionConfig {
        name: profile.name.clone(),
        db_type: DatabaseType::Plugin,
        plugin_id: Some(profile.plugin_id.clone()),
        plugin_config: None,
    }
}

/// Minimal manifest-to-definition mapping for grant construction. Session
/// credential grants only use identity, connection requirement, and secret
/// classes, so schema references resolve to `null` instead of reading files.
fn capability_definition(
    manifest_plugin_id: String,
    capability: &voidb_core::ProcessPluginCapability,
) -> CapabilityDefinition {
    CapabilityDefinition {
        plugin_id: manifest_plugin_id,
        id: capability.id.clone(),
        description: capability.description.clone(),
        input_schema: Value::Null,
        output_schema: Value::Null,
        permissions: capability.permissions.clone(),
        authorization: {
            let mut auth = capability.authorization.clone();
            if !auth.declared {
                auth.declared = true;
                auth.capability_wide_allowed = true;
            }
            auth
        },
        risk: capability
            .risk
            .unwrap_or_else(|| CapabilityRiskLevel::from_destructive(capability.destructive)),
        destructive: capability.destructive,
        streaming: capability.streaming,
        execution_mode: capability.execution_mode,
        session_handoff: capability.session_handoff.clone(),
        connection_required: capability.connection_required,
        required_secret_classes: capability
            .required_secret_classes
            .iter()
            .map(|class| credential_class_from_manifest(class))
            .collect(),
        supports_dry_run: capability.supports_dry_run,
        default_timeout_ms: capability.default_timeout_ms,
    }
}

fn credential_class_from_manifest(class: &str) -> CredentialClass {
    match class {
        "password" => CredentialClass::Password,
        "token" => CredentialClass::Token,
        "api_key" | "apikey" | "api-key" => CredentialClass::ApiKey,
        "private_key" | "private-key" => CredentialClass::PrivateKey,
        "client_certificate" | "client-certificate" => CredentialClass::ClientCertificate,
        "cloud_access_key" | "cloud-access-key" => CredentialClass::CloudAccessKey,
        "cloud_secret_key" | "cloud-secret-key" => CredentialClass::CloudSecretKey,
        other => CredentialClass::Other(other.to_owned()),
    }
}

fn redact_value_with_config(value: &mut Value, plugin_config: &Value) -> RedactionStatus {
    match value {
        Value::String(text) => {
            let (redacted, status) = redact_text_with_json(text, plugin_config);
            *text = redacted;
            status
        }
        Value::Array(items) => {
            let mut status = RedactionStatus::NotRequired;
            for item in items.iter_mut() {
                if redact_value_with_config(item, plugin_config) == RedactionStatus::Applied {
                    status = RedactionStatus::Applied;
                }
            }
            status
        }
        Value::Object(map) => {
            let mut status = RedactionStatus::NotRequired;
            for (_, item) in map.iter_mut() {
                if redact_value_with_config(item, plugin_config) == RedactionStatus::Applied {
                    status = RedactionStatus::Applied;
                }
            }
            status
        }
        _ => RedactionStatus::NotRequired,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_session_host::AgentSessionHost;
    use chrono::Duration;
    use voidb_core::process_plugin::{
        ProcessPluginCandidate,
        ProcessPluginPackageSource, ProcessPluginRoot, ProcessPluginRootKind,
        discover_process_plugins_from_roots, validate_process_plugin_package,
        write_process_plugin_install_record, cleanup_process_plugin_package_staging,
    };
    use voidb_core::plugin_provenance::sign_test_candidate;
    use voidb_core::session::{
        AgentSessionBinding, AgentSessionCloseAgentRequest, AgentSessionOpenRequest,
        AgentSessionRef, PluginSessionPurpose,
    };

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let id = uuid::Uuid::new_v4();
            let path = std::env::temp_dir().join(format!(
                "voidb-external-session-{label}-{}-{id}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            let path = std::fs::canonicalize(path).expect("canonical temp dir");
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_session_fixture(root: &std::path::Path, mode: &str) -> ProcessPluginCandidate {
        let plugin_dir = root.join("fixture");
        let schemas = plugin_dir.join("schemas");
        let bin = plugin_dir.join("bin");
        std::fs::create_dir_all(&schemas).expect("create schemas");
        std::fs::create_dir_all(&bin).expect("create bin");
        std::fs::write(schemas.join("profile.schema.json"), r#"{"type":"object"}"#)
            .expect("write profile schema");
        std::fs::write(schemas.join("echo-input.schema.json"), r#"{"type":"object"}"#)
            .expect("write input schema");
        std::fs::write(schemas.join("echo-output.schema.json"), r#"{"type":"object"}"#)
            .expect("write output schema");

        let script = bin.join("fixture-runtime");
        std::fs::write(&script, fixture_script()).expect("write script");
        let mut permissions = std::fs::metadata(&script).expect("metadata").permissions();
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).expect("chmod");

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

[connections]
profile_schema = "schemas/profile.schema.json"
secret_classes = ["password"]

[[capabilities]]
id = "echo"
description = "Echo capability for session tests."
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
        std::fs::write(plugin_dir.join("plugin.toml"), manifest).expect("write manifest");

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            root,
            ProcessPluginRootKind::EnvPath,
            0,
        )]);
        let candidate = discovery
            .candidates
            .into_iter()
            .find(|candidate| candidate.id == "fixture")
            .expect("fixture candidate");
        assert_eq!(candidate.state, ProcessPluginCandidateState::Available);
        let validation = validate_process_plugin_package(
            ProcessPluginPackageSource::local_directory(&candidate.source.plugin_dir),
            root,
        )
        .expect("fixture validation");
        write_process_plugin_install_record(&validation.install_record).expect("install record");
        cleanup_process_plugin_package_staging(&validation.staging_root).expect("cleanup staging");
        sign_test_candidate(&candidate);
        candidate
    }

    fn fixture_script() -> &'static str {
        r#"#!/bin/sh
mode="$1"
while IFS= read -r line; do
  request_id=$(printf '%s' "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  call_id=$(printf '%s' "$line" | sed -n 's/.*"call_id":"\([^"]*\)".*/\1/p')
  case "$line" in
    *voidb.initialize*)
      case "$mode" in
        nosession)
          echo '{"jsonrpc":"2.0","id":"initialize","result":{"plugin_id":"fixture","protocol_version":"1","status":"ready"}}'
          ;;
        *)
          echo '{"jsonrpc":"2.0","id":"initialize","result":{"plugin_id":"fixture","protocol_version":"1.1","status":"ready","session_protocol":"1"}}'
          ;;
      esac
      ;;
    *voidb.health*)
      echo '{"jsonrpc":"2.0","id":"health","result":{"status":"ready","active_invocations":0}}'
      ;;
    *voidb.session.open*)
      echo "{\"jsonrpc\":\"2.0\",\"id\":\"$request_id\",\"result\":{\"handle_id\":\"fixture-handle-1\",\"generation\":1,\"health\":\"ready\",\"descriptor\":{\"plugin\":\"fixture\"}}}"
      ;;
    *voidb.session.call*)
      echo "{\"jsonrpc\":\"2.0\",\"id\":\"$request_id\",\"result\":{\"call_id\":\"$call_id\",\"output\":{\"echo\":true},\"output_bytes\":13,\"redaction\":\"not_required\",\"truncated\":false}}"
      ;;
    *voidb.session.health*)
      echo "{\"jsonrpc\":\"2.0\",\"id\":\"$request_id\",\"result\":{\"handle_id\":\"fixture-handle-1\",\"generation\":1,\"health\":\"ready\",\"descriptor\":{}}}"
      ;;
    *voidb.session.renew*)
      echo "{\"jsonrpc\":\"2.0\",\"id\":\"$request_id\",\"result\":{\"handle_id\":\"fixture-handle-1\",\"generation\":1,\"health\":\"ready\",\"descriptor\":{}}}"
      ;;
    *voidb.session.cancel*)
      echo "{\"jsonrpc\":\"2.0\",\"id\":\"$request_id\",\"result\":{\"handle_id\":\"fixture-handle-1\",\"call_id\":\"$call_id\",\"accepted\":true}}"
      ;;
    *voidb.session.close*)
      echo "{\"jsonrpc\":\"2.0\",\"id\":\"$request_id\",\"result\":{\"handle_id\":\"fixture-handle-1\",\"closed\":true}}"
      ;;
  esac
done
"#
    }

    fn test_profile() -> ConnectionProfile {
        ConnectionProfile {
            id: "profile-fixture".into(),
            name: "fixture".into(),
            plugin_id: "fixture".into(),
            display_name: Some("Fixture profile".into()),
            metadata: Value::Null,
            default_options: Value::Null,
            credential_refs: vec![voidb_core::capability::CredentialRef {
                id: "cred-fixture-password".into(),
                class: CredentialClass::Password,
                label: None,
            }],
            policy: Default::default(),
        }
    }

    fn test_factory(candidate: ProcessPluginCandidate) -> ExternalPluginSessionFactory {
        let profile = test_profile();
        let mut capabilities = BTreeMap::new();
        if let Some(manifest) = candidate.manifest.as_ref() {
            for capability in &manifest.capabilities {
                // Grant capabilities are qualified as "plugin.capability".
                let definition = capability_definition(manifest.id.clone(), capability);
                capabilities.insert(
                    format!("{}.{}", manifest.id, capability.id),
                    definition,
                );
            }
        }
        ExternalPluginSessionFactory {
            plugin_id: candidate.id.clone(),
            runtime_host: ProcessPluginRuntimeHost::new(candidate),
            connection: ConnectionConfig {
                name: "fixture".into(),
                db_type: DatabaseType::Plugin,
                plugin_id: Some("fixture".into()),
                plugin_config: Some(json!({"host": "fixture.internal"})),
            },
            profile,
            capabilities,
        }
    }

    fn open_context() -> AgentSessionOpenContext {
        let now = Utc::now();
        AgentSessionOpenContext {
            binding: AgentSessionBinding {
                grant_id: "grant-test".into(),
                profile_id: "profile-fixture".into(),
                plugin_id: "fixture".into(),
                purpose: PluginSessionPurpose::CapabilityInvocation,
                allowed_capabilities: vec!["fixture.echo".into()],
                host_generation: 1,
            },
            request: AgentSessionOpenRequest {
                purpose: PluginSessionPurpose::CapabilityInvocation,
                capabilities: vec!["fixture.echo".into()],
                lease_seconds: 300,
                concurrency: AgentSessionConcurrency::Serialized,
                destructive_acknowledged: false,
                input: Value::Null,
            },
            lease_expires_at: now + Duration::minutes(5),
        }
    }

    #[tokio::test]
    async fn opens_calls_and_closes_a_fixture_plugin_session() {
        let dir = TestDir::new("session-ok");
        let candidate = write_session_fixture(dir.path(), "session");
        let factory = test_factory(candidate);
        let context = open_context();

        let handle = factory.open(context.clone()).await.expect("session open");
        assert_eq!(handle.concurrency(), AgentSessionConcurrency::Serialized);
        assert!(matches!(handle.health().await.expect("health"), PluginSessionHealth::Ready));

        let reference = AgentSessionRef::new("agent-session:test", 1);
        let result = handle
            .call(AgentSessionCallRequest {
                session: reference.clone(),
                call_id: "call-1".into(),
                capability: "echo".into(),
                input: json!({"ping": 1}),
                destructive_acknowledged: false,
                timeout_ms: None,
                output_limit_bytes: 64 * 1024,
            })
            .await
            .expect("session call");
        assert_eq!(result.call_id, "call-1");
        assert_eq!(result.output, json!({"echo": true}));
        assert_eq!(result.redaction, RedactionStatus::NotRequired);
        assert!(!result.truncated);

        handle.renew(context.lease_expires_at).await.expect("renew");
        handle.cancel("call-1").await.expect("cancel");
        handle.close("test_close".into()).await.expect("close");
    }

    #[tokio::test]
    async fn plugin_without_session_negotiation_fails_closed_as_unsupported() {
        let dir = TestDir::new("session-unsupported");
        let candidate = write_session_fixture(dir.path(), "nosession");
        let factory = test_factory(candidate);
        let error = match factory.open(open_context()).await {
            Ok(_) => panic!("session open must fail closed for non-session plugins"),
            Err(error) => error,
        };
        assert_eq!(error.code, PluginSessionErrorCode::Unsupported);
    }

    #[test]
    fn builtin_plugins_never_host_sessions() {
        assert!(builtin_plugin_hosts_no_sessions("connections"));
        assert!(builtin_plugin_hosts_no_sessions("sync"));
        assert!(!builtin_plugin_hosts_no_sessions("postgres"));
    }

    #[tokio::test]
    async fn host_end_to_end_open_call_close_through_the_bridge() {
        let dir = TestDir::new("session-host");
        let candidate = write_session_fixture(dir.path(), "session");
        let factory = Arc::new(test_factory(candidate));
        let expires_at = Utc::now() + Duration::minutes(15);
        let mut host = AgentSessionHost::new(
            "grant-test",
            "profile-fixture",
            "fixture",
            vec!["fixture.echo".into()],
            expires_at,
            1,
        );
        host.register_factory(factory);

        let view = host
            .open(
                AgentSessionOpenRequest {
                    purpose: PluginSessionPurpose::CapabilityInvocation,
                    capabilities: vec!["fixture.echo".into()],
                    lease_seconds: 120,
                    concurrency: AgentSessionConcurrency::Serialized,
                    destructive_acknowledged: false,
                    input: Value::Null,
                },
                Utc::now(),
            )
            .await
            .expect("host open");
        assert_eq!(view.binding.plugin_id, "fixture");

        let result = host
            .call(
                AgentSessionCallRequest {
                    session: view.session.clone(),
                    call_id: "call-2".into(),
                    capability: "fixture.echo".into(),
                    input: Value::Null,
                    destructive_acknowledged: false,
                    timeout_ms: None,
                    output_limit_bytes: 64 * 1024,
                },
                Utc::now(),
            )
            .await
            .expect("host call");
        assert_eq!(result.output, json!({"echo": true}));

        host.close(
            AgentSessionCloseAgentRequest {
                session: view.session.clone(),
                reason: "test_close".into(),
                timeout_ms: None,
            },
            Utc::now(),
        )
        .await
        .expect("host close");
    }
}
