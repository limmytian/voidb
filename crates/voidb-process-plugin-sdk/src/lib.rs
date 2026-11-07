//! Minimal Rust SDK for external VoidB process plugins.
//!
//! The SDK intentionally stays transport-focused: it helps plugin authors build
//! manifests, dispatch `stdio-jsonrpc` requests, return structured errors, and
//! keep output summaries redacted. Plugins own their target clients and any
//! async runtime they need behind these synchronous handler boundaries.

#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
// Public contract types: re-exported so simple plugins can depend on the SDK
// alone. `voidb-core` remains available with `default-features = false` for
// advanced use beyond these re-exports.
pub use voidb_core::{
    AgentSessionBinding, AgentSessionCallRequest, AgentSessionCallResult, AgentSessionConcurrency,
    AgentSessionOpenContext, AgentSessionOpenRequest, AgentSessionRef,
    CapabilityAuthorizationMetadata, CapabilityError, CapabilityErrorCategory,
    CapabilityExecutionMode, CapabilityInvocation, CapabilityInvocationResult, CapabilityRiskLevel,
    CapabilitySessionHandoff, CredentialClass, InvocationStatus, PROCESS_PLUGIN_JSONRPC_VERSION,
    PROCESS_PLUGIN_METHOD_CANCEL, PROCESS_PLUGIN_METHOD_HEALTH, PROCESS_PLUGIN_METHOD_INITIALIZE,
    PROCESS_PLUGIN_METHOD_INVOKE, PROCESS_PLUGIN_METHOD_SESSION_CALL,
    PROCESS_PLUGIN_METHOD_SESSION_CANCEL, PROCESS_PLUGIN_METHOD_SESSION_CLOSE,
    PROCESS_PLUGIN_METHOD_SESSION_HEALTH, PROCESS_PLUGIN_METHOD_SESSION_OPEN,
    PROCESS_PLUGIN_METHOD_SESSION_RENEW, PROCESS_PLUGIN_PROTOCOL_VERSION,
    PROCESS_PLUGIN_TRANSPORT_STDIO_JSONRPC, PluginAgentSession, PluginAgentSessionFactory,
    PluginSessionError, PluginSessionErrorCode, PluginSessionHealth, PluginSessionPurpose,
    PluginSessionReason, ProcessPluginCapability, ProcessPluginConnections, ProcessPluginManifest,
    ProcessPluginRequirements, ProcessPluginRuntime, ProcessPluginUi, RedactionStatus,
    TargetSystemFailure, is_supported_process_plugin_protocol_version,
    parse_process_plugin_protocol_version, redact_text_with_json,
};

pub use voidb_core::{
    PROCESS_PLUGIN_BUNDLED_ROOT_ENV, PROCESS_PLUGIN_DEVELOPMENT_PATH_ENV,
    PROCESS_PLUGIN_ENV_LOG_FORMAT, PROCESS_PLUGIN_ENV_PLUGIN_DIR, PROCESS_PLUGIN_ENV_PLUGIN_ID,
    PROCESS_PLUGIN_ENV_PROTOCOL_VERSION, PROCESS_PLUGIN_MANIFEST_SCHEMA_URI,
    PROCESS_PLUGIN_METHOD_STREAM_END, PROCESS_PLUGIN_METHOD_STREAM_ITEM,
    PROCESS_PLUGIN_METHOD_STREAM_PROGRESS, PROCESS_PLUGIN_RESERVED_ENV_VARS,
    PROCESS_PLUGIN_SUPPORTED_PROTOCOL_VERSIONS, PROCESS_PLUGIN_SUPPORTED_TRANSPORTS,
};

pub use voidb_core::plugin_provenance::{
    PROVENANCE_DOMAIN, PROVENANCE_FILE, PluginProvenance, PluginProvenancePayload,
};

pub mod sql;

pub use sql::{
    GenericSqlBackend, SqlCatalogItem, SqlExecResult, SqlQueryResult, SqlTableDescription,
    SqlTableItem, SqlValue, generic_sql_capabilities, mount_generic_sql_router,
};

pub type SdkResult<T> = Result<T, ProcessPluginSdkError>;

#[derive(Debug, Error)]
pub enum ProcessPluginSdkError {
    #[error("I/O error while serving process-plugin protocol: {0}")]
    Io(#[from] io::Error),

    #[error("JSON encode/decode error while serving process-plugin protocol: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct ManifestBuilder {
    manifest: ProcessPluginManifest,
}

impl ManifestBuilder {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        runtime_command: impl Into<String>,
    ) -> Self {
        Self {
            manifest: ProcessPluginManifest {
                schema: Some(PROCESS_PLUGIN_MANIFEST_SCHEMA_URI.into()),
                id: id.into(),
                name: name.into(),
                version: version.into(),
                protocol_version: PROCESS_PLUGIN_PROTOCOL_VERSION.into(),
                description: None,
                license: None,
                homepage: None,
                runtime: ProcessPluginRuntime {
                    command: runtime_command.into(),
                    args: Vec::new(),
                    transport: PROCESS_PLUGIN_TRANSPORT_STDIO_JSONRPC.into(),
                    env: BTreeMap::new(),
                },
                connections: ProcessPluginConnections {
                    profile_schema: "schemas/profile.schema.json".into(),
                    secret_classes: Vec::new(),
                },
                capabilities: Vec::new(),
                ui: Some(ProcessPluginUi {
                    tui: false,
                    entrypoint_capability: None,
                    raw_input: false,
                }),
                requirements: None,
            },
        }
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.manifest.description = Some(description.into());
        self
    }

    pub fn license(mut self, license: impl Into<String>) -> Self {
        self.manifest.license = Some(license.into());
        self
    }

    pub fn homepage(mut self, homepage: impl Into<String>) -> Self {
        self.manifest.homepage = Some(homepage.into());
        self
    }

    pub fn runtime_arg(mut self, arg: impl Into<String>) -> Self {
        self.manifest.runtime.args.push(arg.into());
        self
    }

    pub fn runtime_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.manifest.runtime.env.insert(key.into(), value.into());
        self
    }

    pub fn profile_schema(mut self, schema_ref: impl Into<String>) -> Self {
        self.manifest.connections.profile_schema = schema_ref.into();
        self
    }

    pub fn secret_class(mut self, class: impl Into<String>) -> Self {
        self.manifest.connections.secret_classes.push(class.into());
        self
    }

    pub fn capability(mut self, capability: ProcessPluginCapability) -> Self {
        self.manifest.capabilities.push(capability);
        self
    }

    pub fn core_requirement(mut self, requirement: impl Into<String>) -> Self {
        self.manifest
            .requirements
            .get_or_insert_with(default_requirements)
            .voidb_core = Some(requirement.into());
        self
    }

    pub fn platforms(mut self, platforms: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.manifest
            .requirements
            .get_or_insert_with(default_requirements)
            .platforms = Some(platforms.into_iter().map(Into::into).collect());
        self
    }

    pub fn build(self) -> ProcessPluginManifest {
        self.manifest
    }
}

#[derive(Debug, Clone)]
pub struct CapabilityBuilder {
    capability: ProcessPluginCapability,
}

impl CapabilityBuilder {
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        input_schema: impl Into<String>,
        output_schema: impl Into<String>,
    ) -> Self {
        Self {
            capability: ProcessPluginCapability {
                id: id.into(),
                description: description.into(),
                input_schema: input_schema.into(),
                output_schema: output_schema.into(),
                permissions: Vec::new(),
                authorization: CapabilityAuthorizationMetadata::default(),
                risk: Some(CapabilityRiskLevel::ReadOnly),
                destructive: false,
                streaming: false,
                execution_mode: CapabilityExecutionMode::Stateless,
                session_handoff: None,
                connection_required: true,
                required_secret_classes: Vec::new(),
                supports_dry_run: false,
                default_timeout_ms: None,
            },
        }
    }

    pub fn permission(mut self, permission: impl Into<String>) -> Self {
        self.capability.permissions.push(permission.into());
        self
    }

    pub fn authorization(mut self, metadata: CapabilityAuthorizationMetadata) -> Self {
        self.capability.authorization = metadata;
        self
    }

    pub fn risk(mut self, risk: CapabilityRiskLevel) -> Self {
        self.capability.risk = Some(risk);
        self
    }

    pub fn destructive(mut self, destructive: bool) -> Self {
        self.capability.destructive = destructive;
        self
    }

    pub fn streaming(mut self, streaming: bool) -> Self {
        self.capability.streaming = streaming;
        self
    }

    pub fn execution_mode(mut self, execution_mode: CapabilityExecutionMode) -> Self {
        self.capability.execution_mode = execution_mode;
        self
    }

    pub fn session_handoff(mut self, session_handoff: CapabilitySessionHandoff) -> Self {
        self.capability.session_handoff = Some(session_handoff);
        self
    }

    pub fn connection_required(mut self, connection_required: bool) -> Self {
        self.capability.connection_required = connection_required;
        self
    }

    pub fn required_secret_class(mut self, class: impl Into<String>) -> Self {
        self.capability.required_secret_classes.push(class.into());
        self
    }

    pub fn supports_dry_run(mut self, supports_dry_run: bool) -> Self {
        self.capability.supports_dry_run = supports_dry_run;
        self
    }

    pub fn default_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.capability.default_timeout_ms = Some(timeout_ms);
        self
    }

    pub fn build(self) -> ProcessPluginCapability {
        self.capability
    }
}

fn default_requirements() -> ProcessPluginRequirements {
    ProcessPluginRequirements {
        voidb_core: None,
        platforms: None,
    }
}

pub fn object_schema(
    properties: impl IntoIterator<Item = (impl Into<String>, Value)>,
    required: impl IntoIterator<Item = impl Into<String>>,
) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect::<serde_json::Map<_, _>>(),
        "required": required.into_iter().map(Into::into).collect::<Vec<String>>(),
    })
}

pub fn string_schema(description: impl Into<String>) -> Value {
    json!({
        "type": "string",
        "description": description.into(),
    })
}

pub fn boolean_schema(description: impl Into<String>) -> Value {
    json!({
        "type": "boolean",
        "description": description.into(),
    })
}

pub fn integer_schema(description: impl Into<String>) -> Value {
    json!({
        "type": "integer",
        "description": description.into(),
    })
}

pub trait ProcessPluginHandler {
    fn plugin_id(&self) -> &str;

    fn initialize(
        &mut self,
        params: InitializeParams,
    ) -> Result<InitializeResult, CapabilityError> {
        if params.plugin_id != self.plugin_id() {
            return Err(plugin_error(
                "plugin.initialize_id_mismatch",
                "Initialize request targeted a different plugin id.",
                json!({
                    "expected_plugin_id": self.plugin_id(),
                    "actual_plugin_id": params.plugin_id,
                }),
            ));
        }

        if !is_supported_process_plugin_protocol_version(&params.protocol_version) {
            return Err(plugin_error(
                "plugin.protocol_unsupported",
                "Requested VoidB process-plugin protocol version is not supported.",
                json!({ "protocol_version": params.protocol_version }),
            ));
        }

        Ok(InitializeResult {
            plugin_id: self.plugin_id().into(),
            protocol_version: params.protocol_version.clone(),
            status: Some("ready".into()),
            session_protocol: parse_process_plugin_protocol_version(&params.protocol_version)
                .filter(|(_, minor)| *minor >= 1)
                .map(|_| "1".into()),
        })
    }

    fn health(&mut self, _params: HealthParams) -> Result<HealthResult, CapabilityError> {
        Ok(HealthResult::ready())
    }

    fn invoke(
        &mut self,
        invocation: CapabilityInvocation,
        credential_grants: Vec<CredentialGrantDescriptor>,
    ) -> Result<CapabilityInvocationResult, CapabilityError>;

    fn cancel(&mut self, params: CancelParams) -> Result<CancelResult, CapabilityError> {
        Ok(CancelResult {
            invocation_id: params.invocation_id,
            accepted: false,
            status: "not_supported".into(),
        })
    }

    fn session_open(
        &mut self,
        _params: SessionOpenParams,
    ) -> Result<SessionOpenResult, CapabilityError> {
        Err(plugin_error(
            "plugin.session_unsupported",
            "Plugin does not expose persistent sessions.",
            json!({}),
        ))
    }

    fn session_call(
        &mut self,
        _params: SessionCallParams,
    ) -> Result<SessionCallResult, CapabilityError> {
        Err(plugin_error(
            "plugin.session_unsupported",
            "Plugin does not expose persistent sessions.",
            json!({}),
        ))
    }

    fn session_health(
        &mut self,
        _params: SessionHandleParams,
    ) -> Result<SessionHealthResult, CapabilityError> {
        Err(plugin_error(
            "plugin.session_unsupported",
            "Plugin does not expose persistent sessions.",
            json!({}),
        ))
    }

    fn session_renew(
        &mut self,
        _params: SessionRenewParams,
    ) -> Result<SessionHealthResult, CapabilityError> {
        Err(plugin_error(
            "plugin.session_unsupported",
            "Plugin does not expose persistent sessions.",
            json!({}),
        ))
    }

    fn session_cancel(
        &mut self,
        _params: SessionCancelParams,
    ) -> Result<SessionCancelResult, CapabilityError> {
        Err(plugin_error(
            "plugin.session_unsupported",
            "Plugin does not expose persistent sessions.",
            json!({}),
        ))
    }

    fn session_close(
        &mut self,
        _params: SessionCloseParams,
    ) -> Result<SessionCloseResult, CapabilityError> {
        Err(plugin_error(
            "plugin.session_unsupported",
            "Plugin does not expose persistent sessions.",
            json!({}),
        ))
    }
}

pub type CapabilityHandler = Box<
    dyn FnMut(
            CapabilityInvocation,
            &[CredentialGrantDescriptor],
        ) -> Result<CapabilityInvocationResult, CapabilityError>
        + Send,
>;

pub struct CapabilityRouter {
    plugin_id: String,
    handlers: BTreeMap<String, CapabilityHandler>,
    health_extra: BTreeMap<String, Value>,
    session_bridge: Option<Arc<dyn SessionBridge>>,
}

impl CapabilityRouter {
    pub fn new(plugin_id: impl Into<String>) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            handlers: BTreeMap::new(),
            health_extra: BTreeMap::new(),
            session_bridge: None,
        }
    }

    /// Registers the persistent-session bridge. Plugins that register one
    /// advertise the `voidb.session.*` sub-protocol to the host; without a
    /// bridge the plugin fails sessions closed.
    pub fn session_bridge(mut self, bridge: Arc<dyn SessionBridge>) -> Self {
        self.session_bridge = Some(bridge);
        self
    }

    pub fn with_health_detail(mut self, key: impl Into<String>, value: Value) -> Self {
        self.health_extra.insert(key.into(), value);
        self
    }

    pub fn capability<F>(mut self, capability_id: impl Into<String>, handler: F) -> Self
    where
        F: FnMut(
                CapabilityInvocation,
                &[CredentialGrantDescriptor],
            ) -> Result<CapabilityInvocationResult, CapabilityError>
            + Send
            + 'static,
    {
        self.handlers
            .insert(capability_id.into(), Box::new(handler));
        self
    }
}

impl ProcessPluginHandler for CapabilityRouter {
    fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    fn health(&mut self, _params: HealthParams) -> Result<HealthResult, CapabilityError> {
        Ok(HealthResult {
            status: "ready".into(),
            active_invocations: Some(0),
            extra: self.health_extra.clone(),
        })
    }

    fn invoke(
        &mut self,
        invocation: CapabilityInvocation,
        credential_grants: Vec<CredentialGrantDescriptor>,
    ) -> Result<CapabilityInvocationResult, CapabilityError> {
        let Some(handler) = self.handlers.get_mut(&invocation.capability_id) else {
            return Err(plugin_error(
                "plugin.capability_not_found",
                "Plugin does not expose the requested capability.",
                json!({
                    "plugin_id": self.plugin_id,
                    "capability_id": invocation.capability_id,
                }),
            ));
        };

        handler(invocation, &credential_grants)
    }

    fn initialize(
        &mut self,
        params: InitializeParams,
    ) -> Result<InitializeResult, CapabilityError> {
        if params.plugin_id != self.plugin_id {
            return Err(plugin_error(
                "plugin.initialize_id_mismatch",
                "Initialize request targeted a different plugin id.",
                json!({
                    "expected_plugin_id": self.plugin_id,
                    "actual_plugin_id": params.plugin_id,
                }),
            ));
        }

        if !is_supported_process_plugin_protocol_version(&params.protocol_version) {
            return Err(plugin_error(
                "plugin.protocol_unsupported",
                "Requested VoidB process-plugin protocol version is not supported.",
                json!({ "protocol_version": params.protocol_version }),
            ));
        }

        // Advertise the persistent-session sub-protocol only when a session
        // bridge is registered; otherwise the host fails closed with
        // `unavailable.process_plugin_sessions_unsupported` instead of
        // opening a runtime the plugin cannot answer.
        let session_protocol = if self.session_bridge.is_some() {
            parse_process_plugin_protocol_version(&params.protocol_version)
                .filter(|(_, minor)| *minor >= 1)
                .map(|_| "1".into())
        } else {
            None
        };

        Ok(InitializeResult {
            plugin_id: self.plugin_id.clone(),
            protocol_version: params.protocol_version.clone(),
            status: Some("ready".into()),
            session_protocol,
        })
    }

    fn session_open(
        &mut self,
        params: SessionOpenParams,
    ) -> Result<SessionOpenResult, CapabilityError> {
        match &self.session_bridge {
            Some(bridge) => bridge.open(params),
            None => Err(session_unsupported()),
        }
    }

    fn session_call(
        &mut self,
        params: SessionCallParams,
    ) -> Result<SessionCallResult, CapabilityError> {
        match &self.session_bridge {
            Some(bridge) => bridge.call(params),
            None => Err(session_unsupported()),
        }
    }

    fn session_health(
        &mut self,
        params: SessionHandleParams,
    ) -> Result<SessionHealthResult, CapabilityError> {
        match &self.session_bridge {
            Some(bridge) => bridge.health(params),
            None => Err(session_unsupported()),
        }
    }

    fn session_renew(
        &mut self,
        params: SessionRenewParams,
    ) -> Result<SessionHealthResult, CapabilityError> {
        match &self.session_bridge {
            Some(bridge) => bridge.renew(params),
            None => Err(session_unsupported()),
        }
    }

    fn session_cancel(
        &mut self,
        params: SessionCancelParams,
    ) -> Result<SessionCancelResult, CapabilityError> {
        match &self.session_bridge {
            Some(bridge) => bridge.cancel(params),
            None => Err(session_unsupported()),
        }
    }

    fn session_close(
        &mut self,
        params: SessionCloseParams,
    ) -> Result<SessionCloseResult, CapabilityError> {
        match &self.session_bridge {
            Some(bridge) => bridge.close(params),
            None => Err(session_unsupported()),
        }
    }
}

fn session_unsupported() -> CapabilityError {
    plugin_error(
        "plugin.session_unsupported",
        "Plugin does not expose persistent sessions.",
        json!({}),
    )
}

/// Sync bridge between the stdio serve loop and a plugin's persistent
/// sessions. Implement this to answer the `voidb.session.*` RPCs; the
/// [`CoreSessionAdapter`] provides the ready-made implementation over a
/// [`PluginAgentSessionFactory`] from `voidb-core`.
pub trait SessionBridge: Send + Sync {
    fn open(&self, params: SessionOpenParams) -> Result<SessionOpenResult, CapabilityError>;
    fn call(&self, params: SessionCallParams) -> Result<SessionCallResult, CapabilityError>;
    fn health(&self, params: SessionHandleParams) -> Result<SessionHealthResult, CapabilityError>;
    fn renew(&self, params: SessionRenewParams) -> Result<SessionHealthResult, CapabilityError>;
    fn cancel(&self, params: SessionCancelParams) -> Result<SessionCancelResult, CapabilityError>;
    fn close(&self, params: SessionCloseParams) -> Result<SessionCloseResult, CapabilityError>;
}

/// Ready-made [`SessionBridge`] over a `voidb-core`
/// [`PluginAgentSessionFactory`]. The factory constructor receives each open
/// request so plugin-side factories that need the profile's decrypted
/// configuration can build it from `params.options`; the adapter drives the
/// async factory/session through the provided tokio runtime handle and keeps
/// the handle registry.
pub struct CoreSessionAdapter {
    runtime: tokio::runtime::Handle,
    factory: Box<
        dyn Fn(&SessionOpenParams) -> Result<Arc<dyn PluginAgentSessionFactory>, CapabilityError>
            + Send
            + Sync,
    >,
    handles:
        std::sync::Mutex<std::collections::BTreeMap<String, (u64, Arc<dyn PluginAgentSession>)>>,
}

impl CoreSessionAdapter {
    pub fn new(
        runtime: tokio::runtime::Handle,
        factory: impl Fn(
            &SessionOpenParams,
        ) -> Result<Arc<dyn PluginAgentSessionFactory>, CapabilityError>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            runtime,
            factory: Box::new(factory),
            handles: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    fn lookup(
        &self,
        handle_id: &str,
        generation: u64,
    ) -> Result<Arc<dyn PluginAgentSession>, CapabilityError> {
        let handles = self.handles.lock().expect("session handle registry");
        let Some((registered_generation, session)) = handles.get(handle_id) else {
            return Err(bridge_capability_error(
                "session.not_found",
                "Plugin session handle does not exist or is already closed.",
            ));
        };
        if *registered_generation != generation {
            return Err(bridge_capability_error(
                "session.stale",
                "Plugin session handle generation no longer matches.",
            ));
        }
        Ok(Arc::clone(session))
    }
}

fn bridge_capability_error(code: impl Into<String>, message: impl Into<String>) -> CapabilityError {
    CapabilityError {
        category: CapabilityErrorCategory::Plugin,
        code: code.into(),
        message: message.into(),
        details: json!({}),
        target: None,
        retryable: false,
        redaction: RedactionStatus::NotRequired,
    }
}

/// Maps a core [`PluginSessionError`] onto the wire [`CapabilityError`]. The
/// stable session error code (`session.unsupported`, `session.not_found`, …)
/// is preserved so the host can restore the typed error.
pub fn session_error_to_capability(error: PluginSessionError) -> CapabilityError {
    let category = match error.code {
        PluginSessionErrorCode::PolicyDenied
        | PluginSessionErrorCode::BindingMismatch
        | PluginSessionErrorCode::Expired
        | PluginSessionErrorCode::CallIdInvalid
        | PluginSessionErrorCode::CallIdMismatch
        | PluginSessionErrorCode::CallIdConflict => CapabilityErrorCategory::Permission,
        PluginSessionErrorCode::TimedOut => CapabilityErrorCategory::Timeout,
        PluginSessionErrorCode::Cancelled => CapabilityErrorCategory::Cancellation,
        PluginSessionErrorCode::OutputLimit | PluginSessionErrorCode::RedactionFailed => {
            CapabilityErrorCategory::Validation
        }
        _ => CapabilityErrorCategory::Plugin,
    };
    CapabilityError {
        category,
        code: error.code.as_str().to_string(),
        message: error.message,
        details: error
            .session_id
            .as_ref()
            .map(|session_id| json!({ "session_id": session_id }))
            .unwrap_or_else(|| json!({})),
        target: None,
        retryable: false,
        redaction: RedactionStatus::NotRequired,
    }
}

fn health_string(health: &PluginSessionHealth) -> String {
    serde_json::to_value(health)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "degraded".into())
}

impl SessionBridge for CoreSessionAdapter {
    fn open(&self, params: SessionOpenParams) -> Result<SessionOpenResult, CapabilityError> {
        let factory = (self.factory)(&params)?;
        let purpose: PluginSessionPurpose = serde_json::from_value(json!(params.purpose))
            .or_else(|_| serde_json::from_value(json!({ "kind": params.purpose })))
            .map_err(|error| {
                bridge_capability_error(
                    "validation.session_purpose_invalid",
                    format!("Invalid session purpose: {error}"),
                )
            })?;
        let lease_seconds = (params.lease_expires_at - chrono::Utc::now())
            .num_seconds()
            .clamp(1, 86_400) as u64;
        let context = AgentSessionOpenContext {
            binding: AgentSessionBinding {
                grant_id: params.grant_id.clone(),
                profile_id: params.profile_id.clone(),
                plugin_id: factory.plugin_id().to_string(),
                purpose: purpose.clone(),
                allowed_capabilities: params.capabilities.clone(),
                host_generation: params.generation.max(1),
            },
            request: AgentSessionOpenRequest {
                purpose,
                capabilities: params.capabilities.clone(),
                lease_seconds,
                concurrency: AgentSessionConcurrency::default(),
                destructive_acknowledged: false,
                input: params.input.clone(),
            },
            lease_expires_at: params.lease_expires_at,
        };
        let session = self
            .runtime
            .block_on(factory.open(context))
            .map_err(session_error_to_capability)?;
        let health = self
            .runtime
            .block_on(session.health())
            .map_err(session_error_to_capability)?;
        let handle_id = params.session_id.clone();
        let generation = params.generation.max(1);
        self.handles
            .lock()
            .expect("session handle registry")
            .insert(handle_id.clone(), (generation, Arc::clone(&session)));
        Ok(SessionOpenResult {
            handle_id,
            generation,
            health: health_string(&health),
            descriptor: Value::Null,
        })
    }

    fn call(&self, params: SessionCallParams) -> Result<SessionCallResult, CapabilityError> {
        let session = self.lookup(&params.handle_id, params.generation)?;
        let request = AgentSessionCallRequest {
            session: AgentSessionRef::new(
                format!("plugin-session:{}", params.handle_id),
                params.generation,
            ),
            call_id: params.call_id.clone(),
            capability: params.capability.clone(),
            input: params.input.clone(),
            destructive_acknowledged: false,
            timeout_ms: params.timeout_ms,
            output_limit_bytes: params.output_limit_bytes,
        };
        let result = self
            .runtime
            .block_on(session.call(request))
            .map_err(session_error_to_capability)?;
        Ok(SessionCallResult {
            call_id: result.call_id,
            output: result.output,
            output_bytes: result.output_bytes,
            redaction: result.redaction,
            truncated: result.truncated,
        })
    }

    fn health(&self, params: SessionHandleParams) -> Result<SessionHealthResult, CapabilityError> {
        let session = self.lookup(&params.handle_id, params.generation)?;
        let health = self
            .runtime
            .block_on(session.health())
            .map_err(session_error_to_capability)?;
        Ok(SessionHealthResult {
            handle_id: params.handle_id,
            generation: params.generation,
            health: health_string(&health),
            descriptor: Value::Null,
        })
    }

    fn renew(&self, params: SessionRenewParams) -> Result<SessionHealthResult, CapabilityError> {
        let session = self.lookup(&params.handle_id, params.generation)?;
        self.runtime
            .block_on(session.renew(params.lease_expires_at))
            .map_err(session_error_to_capability)?;
        let health = self
            .runtime
            .block_on(session.health())
            .map_err(session_error_to_capability)?;
        Ok(SessionHealthResult {
            handle_id: params.handle_id,
            generation: params.generation,
            health: health_string(&health),
            descriptor: Value::Null,
        })
    }

    fn cancel(&self, params: SessionCancelParams) -> Result<SessionCancelResult, CapabilityError> {
        let session = self.lookup(&params.handle_id, params.generation)?;
        self.runtime
            .block_on(session.cancel(&params.call_id))
            .map_err(session_error_to_capability)?;
        Ok(SessionCancelResult {
            handle_id: params.handle_id,
            call_id: params.call_id,
            accepted: true,
        })
    }

    fn close(&self, params: SessionCloseParams) -> Result<SessionCloseResult, CapabilityError> {
        let session = self.lookup(&params.handle_id, params.generation)?;
        self.runtime
            .block_on(session.close(params.reason.clone()))
            .map_err(session_error_to_capability)?;
        self.handles
            .lock()
            .expect("session handle registry")
            .remove(&params.handle_id);
        Ok(SessionCloseResult {
            handle_id: params.handle_id,
            closed: true,
        })
    }
}

pub fn serve_stdio(handler: impl ProcessPluginHandler) -> SdkResult<()> {
    serve_reader_writer(handler, io::stdin().lock(), io::stdout().lock())
}

pub fn serve_reader_writer<H, R, W>(mut handler: H, reader: R, mut writer: W) -> SdkResult<()>
where
    H: ProcessPluginHandler,
    R: BufRead,
    W: Write,
{
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<JsonRpcRequest>(&line) {
            Ok(request) => handle_request(&mut handler, request),
            Err(error) => json_rpc_error(
                Value::Null,
                -32700,
                "Parse error.",
                protocol_error(
                    "protocol.json_parse_failed",
                    "JSON-RPC message could not be decoded.",
                    json!({ "message": error.to_string() }),
                ),
            ),
        };
        serde_json::to_writer(&mut writer, &response)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

fn handle_request(handler: &mut impl ProcessPluginHandler, request: JsonRpcRequest) -> Value {
    let id = request.id.unwrap_or(Value::Null);
    if request.jsonrpc != PROCESS_PLUGIN_JSONRPC_VERSION {
        return json_rpc_error(
            id,
            -32600,
            "Invalid Request.",
            protocol_error(
                "protocol.jsonrpc_version_invalid",
                "JSON-RPC message must use version 2.0.",
                json!({ "jsonrpc": request.jsonrpc }),
            ),
        );
    }

    match request.method.as_str() {
        PROCESS_PLUGIN_METHOD_INITIALIZE => {
            dispatch_params(id, request.params, |params| handler.initialize(params))
        }
        PROCESS_PLUGIN_METHOD_HEALTH => {
            dispatch_params(id, request.params, |params| handler.health(params))
        }
        PROCESS_PLUGIN_METHOD_INVOKE => {
            dispatch_params(id, request.params, |params: InvokeParams| {
                handler.invoke(params.invocation, params.credential_grants)
            })
        }
        PROCESS_PLUGIN_METHOD_CANCEL => {
            dispatch_params(id, request.params, |params| handler.cancel(params))
        }
        PROCESS_PLUGIN_METHOD_SESSION_OPEN => {
            dispatch_params(id, request.params, |params| handler.session_open(params))
        }
        PROCESS_PLUGIN_METHOD_SESSION_CALL => {
            dispatch_params(id, request.params, |params| handler.session_call(params))
        }
        PROCESS_PLUGIN_METHOD_SESSION_HEALTH => {
            dispatch_params(id, request.params, |params| handler.session_health(params))
        }
        PROCESS_PLUGIN_METHOD_SESSION_RENEW => {
            dispatch_params(id, request.params, |params| handler.session_renew(params))
        }
        PROCESS_PLUGIN_METHOD_SESSION_CANCEL => {
            dispatch_params(id, request.params, |params| handler.session_cancel(params))
        }
        PROCESS_PLUGIN_METHOD_SESSION_CLOSE => {
            dispatch_params(id, request.params, |params| handler.session_close(params))
        }
        _ => json_rpc_error(
            id,
            -32601,
            "Method not found.",
            protocol_error(
                "protocol.method_not_found",
                "JSON-RPC method is not supported by this plugin.",
                json!({ "method": request.method }),
            ),
        ),
    }
}

fn dispatch_params<T, R>(
    id: Value,
    params: Option<Value>,
    dispatch: impl FnOnce(T) -> Result<R, CapabilityError>,
) -> Value
where
    T: for<'de> Deserialize<'de>,
    R: Serialize,
{
    let params = params.unwrap_or_else(|| json!({}));
    match serde_json::from_value::<T>(params) {
        Ok(params) => match dispatch(params) {
            Ok(result) => json_rpc_success(id, result),
            Err(error) => {
                let code = json_rpc_code_for_capability_error(&error);
                let message = error.message.clone();
                json_rpc_error(id, code, &message, error)
            }
        },
        Err(error) => json_rpc_error(
            id,
            -32602,
            "Invalid params.",
            protocol_error(
                "protocol.invalid_params",
                "JSON-RPC params did not match the VoidB process-plugin contract.",
                json!({ "message": error.to_string() }),
            ),
        ),
    }
}

fn json_rpc_success(id: Value, result: impl Serialize) -> Value {
    json!({
        "jsonrpc": PROCESS_PLUGIN_JSONRPC_VERSION,
        "id": id,
        "result": result,
    })
}

fn json_rpc_error(id: Value, code: i64, message: &str, error: CapabilityError) -> Value {
    json!({
        "jsonrpc": PROCESS_PLUGIN_JSONRPC_VERSION,
        "id": id,
        "error": {
            "code": code,
            "message": message,
            "data": error,
        }
    })
}

fn json_rpc_code_for_capability_error(error: &CapabilityError) -> i64 {
    match error.category {
        CapabilityErrorCategory::Cancellation => -32020,
        CapabilityErrorCategory::Plugin | CapabilityErrorCategory::Unavailable => -32040,
        _ => -32010,
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitializeParams {
    pub protocol_version: String,
    #[serde(default)]
    pub core_version: Option<String>,
    pub plugin_id: String,
    #[serde(default)]
    pub manifest_path: Option<String>,
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitializeResult {
    pub plugin_id: String,
    pub protocol_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_protocol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionOpenParams {
    pub session_id: String,
    pub generation: u64,
    pub grant_id: String,
    pub profile_id: String,
    pub purpose: String,
    pub capabilities: Vec<String>,
    pub lease_expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub input: Value,
    #[serde(default)]
    pub credential_grants: Vec<CredentialGrantDescriptor>,
    /// Decrypted profile plugin configuration for this scoped session,
    /// filled by Core from the granted profile. Plugins treat it as
    /// write-only operational input per the secret-brokering policy.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub options: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionOpenResult {
    pub handle_id: String,
    pub generation: u64,
    pub health: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub descriptor: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionCallParams {
    pub handle_id: String,
    pub generation: u64,
    pub call_id: String,
    pub capability: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub input: Value,
    pub output_limit_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionCallResult {
    pub call_id: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub output: Value,
    pub output_bytes: usize,
    pub redaction: RedactionStatus,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionHandleParams {
    pub handle_id: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionHealthResult {
    pub handle_id: String,
    pub generation: u64,
    pub health: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub descriptor: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRenewParams {
    pub handle_id: String,
    pub generation: u64,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCancelParams {
    pub handle_id: String,
    pub generation: u64,
    pub call_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCancelResult {
    pub handle_id: String,
    pub call_id: String,
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCloseParams {
    pub handle_id: String,
    pub generation: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCloseResult {
    pub handle_id: String,
    pub closed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthParams {
    #[serde(default)]
    pub include_runtime: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthResult {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_invocations: Option<u64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl HealthResult {
    pub fn ready() -> Self {
        Self {
            status: "ready".into(),
            active_invocations: Some(0),
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InvokeParams {
    pub invocation: CapabilityInvocation,
    #[serde(default)]
    pub credential_grants: Vec<CredentialGrantDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialGrantDescriptor {
    pub grant_id: String,
    pub credential_ref_id: String,
    pub class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CancelParams {
    pub invocation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CancelResult {
    pub invocation_id: String,
    pub accepted: bool,
    pub status: String,
}

pub fn succeeded(
    invocation_id: impl Into<String>,
    output: Value,
    output_summary: Value,
) -> CapabilityInvocationResult {
    CapabilityInvocationResult {
        invocation_id: invocation_id.into(),
        status: InvocationStatus::Succeeded,
        output,
        output_summary,
        page: None,
    }
}

pub fn redacted_output_summary(value: Value) -> Value {
    match value {
        Value::Object(mut map) => {
            map.insert("redaction".into(), json!("applied"));
            Value::Object(map)
        }
        other => json!({
            "summary": other,
            "redaction": "applied",
        }),
    }
}

pub fn capability_error(
    category: CapabilityErrorCategory,
    code: impl Into<String>,
    message: impl Into<String>,
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

pub fn validation_error(
    code: impl Into<String>,
    message: impl Into<String>,
    details: Value,
) -> CapabilityError {
    capability_error(
        CapabilityErrorCategory::Validation,
        code,
        message,
        details,
        false,
        RedactionStatus::Applied,
    )
}

pub fn plugin_error(
    code: impl Into<String>,
    message: impl Into<String>,
    details: Value,
) -> CapabilityError {
    capability_error(
        CapabilityErrorCategory::Plugin,
        code,
        message,
        details,
        false,
        RedactionStatus::Applied,
    )
}

pub fn protocol_error(
    code: impl Into<String>,
    message: impl Into<String>,
    details: Value,
) -> CapabilityError {
    capability_error(
        CapabilityErrorCategory::Transport,
        code,
        message,
        details,
        true,
        RedactionStatus::Applied,
    )
}

pub fn target_error(
    code: impl Into<String>,
    message: impl Into<String>,
    target_system: impl Into<String>,
    target_code: impl Into<String>,
    target_message: impl Into<String>,
    details: Value,
) -> CapabilityError {
    CapabilityError {
        category: CapabilityErrorCategory::TargetSystem,
        code: code.into(),
        message: message.into(),
        details,
        target: Some(TargetSystemFailure {
            system: Some(target_system.into()),
            code: Some(target_code.into()),
            message: Some(target_message.into()),
        }),
        retryable: false,
        redaction: RedactionStatus::Applied,
    }
}

pub fn redact_text_with_context(text: &str, context: &Value) -> (String, RedactionStatus) {
    redact_text_with_json(text, context)
}

pub fn credential_class_label(class: &CredentialClass) -> &'static str {
    match class {
        CredentialClass::Password => "password",
        CredentialClass::Token => "token",
        CredentialClass::ApiKey => "api_key",
        CredentialClass::PrivateKey => "private_key",
        CredentialClass::ClientCertificate => "client_certificate",
        CredentialClass::CloudAccessKey => "cloud_access_key",
        CredentialClass::CloudSecretKey => "cloud_secret_key",
        CredentialClass::Other(_) => "other",
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use voidb_core::{
        ActorRef, ActorType, ConnectionInstancePurpose, ConnectionProfileRef, InstanceReusePolicy,
        InvocationConnectionTarget, InvocationControls,
    };

    struct SessionFixture;

    impl ProcessPluginHandler for SessionFixture {
        fn plugin_id(&self) -> &str {
            "fixture"
        }

        fn invoke(
            &mut self,
            _invocation: CapabilityInvocation,
            _credential_grants: Vec<CredentialGrantDescriptor>,
        ) -> Result<CapabilityInvocationResult, CapabilityError> {
            Err(plugin_error("unused", "unused", json!({})))
        }

        fn session_open(
            &mut self,
            params: SessionOpenParams,
        ) -> Result<SessionOpenResult, CapabilityError> {
            Ok(SessionOpenResult {
                handle_id: format!("handle:{}", params.session_id),
                generation: params.generation,
                health: "ready".into(),
                descriptor: json!({ "buffered_items": 0 }),
            })
        }

        fn session_close(
            &mut self,
            params: SessionCloseParams,
        ) -> Result<SessionCloseResult, CapabilityError> {
            Ok(SessionCloseResult {
                handle_id: params.handle_id,
                closed: true,
            })
        }
    }

    #[test]
    fn manifest_builder_declares_capability_contracts() {
        let manifest = ManifestBuilder::new("hello-sql", "Hello SQL", "0.1.0", "hello-sql")
            .description("Example SQL process plugin.")
            .profile_schema("schemas/profile.schema.json")
            .capability(
                CapabilityBuilder::new(
                    "query",
                    "Run a bounded read-only query.",
                    "schemas/query-input.schema.json",
                    "schemas/query-output.schema.json",
                )
                .permission("connection.read")
                .risk(CapabilityRiskLevel::ReadOnly)
                .execution_mode(CapabilityExecutionMode::Both)
                .session_handoff(CapabilitySessionHandoff::new(
                    voidb_core::PluginSessionPurpose::DatabaseQuery,
                    ["hello-sql.query"],
                ))
                .default_timeout_ms(1_000)
                .build(),
            )
            .capability(
                CapabilityBuilder::new(
                    "exec",
                    "Plan or execute a mutating statement.",
                    "schemas/exec-input.schema.json",
                    "schemas/exec-output.schema.json",
                )
                .permission("sql.exec")
                .risk(CapabilityRiskLevel::Mutating)
                .destructive(true)
                .supports_dry_run(true)
                .build(),
            )
            .build();

        assert_eq!(manifest.id, "hello-sql");
        assert_eq!(manifest.protocol_version, PROCESS_PLUGIN_PROTOCOL_VERSION);
        assert_eq!(
            manifest.runtime.transport,
            PROCESS_PLUGIN_TRANSPORT_STDIO_JSONRPC
        );
        assert_eq!(manifest.capabilities.len(), 2);
        assert_eq!(
            manifest.capabilities[0].execution_mode,
            CapabilityExecutionMode::Both
        );
        assert_eq!(
            manifest.capabilities[0]
                .session_handoff
                .as_ref()
                .map(|handoff| handoff.capabilities.as_slice()),
            Some(["hello-sql.query".to_string()].as_slice())
        );
        assert_eq!(
            manifest.capabilities[1].risk,
            Some(CapabilityRiskLevel::Mutating)
        );
        assert!(manifest.capabilities[1].supports_dry_run);
    }

    #[test]
    fn stdio_server_negotiates_and_dispatches_session_lifecycle() {
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":\"init\",\"method\":\"voidb.initialize\",\"params\":{\"protocol_version\":\"1.1\",\"plugin_id\":\"fixture\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"open\",\"method\":\"voidb.session.open\",\"params\":{\"session_id\":\"s1\",\"generation\":1,\"grant_id\":\"g1\",\"profile_id\":\"p1\",\"purpose\":\"log_stream\",\"capabilities\":[\"fixture.logs\"],\"lease_expires_at\":\"2099-01-01T00:00:00Z\",\"input\":{},\"credential_grants\":[]}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"close\",\"method\":\"voidb.session.close\",\"params\":{\"handle_id\":\"handle:s1\",\"generation\":1,\"reason\":\"test\"}}\n"
        );
        let mut output = Vec::new();
        serve_reader_writer(SessionFixture, Cursor::new(input), &mut output).expect("serve");
        let responses = String::from_utf8(output).unwrap();
        assert!(responses.contains("\"session_protocol\":\"1\""));
        assert!(responses.contains("\"handle_id\":\"handle:s1\""));
        assert!(responses.contains("\"closed\":true"));
        assert!(!responses.contains("credential_grants"));
    }

    #[test]
    fn stdio_server_initializes_health_checks_and_invokes() {
        let router = CapabilityRouter::new("fixture").capability("echo", |invocation, grants| {
            assert_eq!(grants.len(), 1);
            Ok(succeeded(
                invocation.id,
                json!({ "echo": invocation.input }),
                redacted_output_summary(json!({ "credential_grants": grants.len() })),
            ))
        });
        let input = format!(
            "{}\n{}\n{}\n",
            json!({
                "jsonrpc": "2.0",
                "id": "initialize",
                "method": "voidb.initialize",
                "params": {
                    "protocol_version": "1",
                    "plugin_id": "fixture",
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": "health",
                "method": "voidb.health",
                "params": { "include_runtime": true }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": "invoke",
                "method": "voidb.invoke",
                "params": {
                    "invocation": sample_invocation(),
                    "credential_grants": [{
                        "grant_id": "grant-1",
                        "credential_ref_id": "cred-1",
                        "class": "password",
                        "purpose": "capability_invocation"
                    }]
                }
            }),
        );
        let mut output = Vec::new();

        serve_reader_writer(router, Cursor::new(input), &mut output).expect("serve");

        let lines = String::from_utf8(output).expect("utf8");
        let responses = lines
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("json response"))
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0]["result"]["plugin_id"], "fixture");
        assert_eq!(responses[1]["result"]["status"], "ready");
        assert_eq!(responses[2]["result"]["status"], "succeeded");
        assert_eq!(responses[2]["result"]["output"]["echo"]["message"], "hello");
        assert_eq!(
            responses[2]["result"]["output_summary"]["redaction"],
            "applied"
        );
    }

    #[test]
    fn stdio_server_returns_structured_error_for_unknown_capability() {
        let router = CapabilityRouter::new("fixture");
        let input = format!(
            "{}\n",
            json!({
                "jsonrpc": "2.0",
                "id": "invoke",
                "method": "voidb.invoke",
                "params": {
                    "invocation": sample_invocation(),
                    "credential_grants": []
                }
            }),
        );
        let mut output = Vec::new();

        serve_reader_writer(router, Cursor::new(input), &mut output).expect("serve");

        let response = serde_json::from_slice::<Value>(&output).expect("json response");
        assert_eq!(response["error"]["code"], -32040);
        assert_eq!(
            response["error"]["data"]["code"],
            "plugin.capability_not_found"
        );
        assert_eq!(response["error"]["data"]["redaction"], "applied");
    }

    #[test]
    fn redaction_helper_reuses_core_redaction_targets() {
        let context = json!({ "password": "secret-value" });
        let (redacted, status) = redact_text_with_context("target returned secret-value", &context);

        assert_eq!(status, RedactionStatus::Applied);
        assert!(!redacted.contains("secret-value"));
        assert!(redacted.contains("<redacted:password>"));
    }

    fn sample_invocation() -> CapabilityInvocation {
        CapabilityInvocation {
            id: "invoke-1".into(),
            plugin_id: "fixture".into(),
            capability_id: "echo".into(),
            connection: InvocationConnectionTarget::FromProfile {
                profile: ConnectionProfileRef::Name("fixture".into()),
                purpose: ConnectionInstancePurpose::CapabilityInvocation,
                reuse: InstanceReusePolicy::Allow,
                options: Value::Null,
            },
            input: json!({ "message": "hello" }),
            controls: InvocationControls::default(),
            actor: Some(ActorRef {
                id: "agent:test".into(),
                actor_type: ActorType::Agent,
            }),
            requested_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod session_bridge_tests {
    use super::*;

    struct MockFactory;

    #[async_trait::async_trait]
    impl PluginAgentSessionFactory for MockFactory {
        fn plugin_id(&self) -> &str {
            "fixture"
        }

        async fn open(
            &self,
            context: AgentSessionOpenContext,
        ) -> Result<Arc<dyn PluginAgentSession>, PluginSessionError> {
            assert_eq!(context.binding.plugin_id, "fixture");
            assert_eq!(context.binding.allowed_capabilities, ["fixture.echo"]);
            Ok(Arc::new(MockSession))
        }
    }

    struct MockSession;

    #[async_trait::async_trait]
    impl PluginAgentSession for MockSession {
        fn concurrency(&self) -> AgentSessionConcurrency {
            AgentSessionConcurrency::Serialized
        }

        async fn call(
            &self,
            request: AgentSessionCallRequest,
        ) -> Result<AgentSessionCallResult, PluginSessionError> {
            Ok(AgentSessionCallResult {
                call_id: request.call_id,
                output: json!({ "echo": true }),
                output_bytes: 15,
                redaction: RedactionStatus::NotRequired,
                truncated: false,
            })
        }

        async fn health(&self) -> Result<PluginSessionHealth, PluginSessionError> {
            Ok(PluginSessionHealth::Ready)
        }

        async fn close(&self, _reason: PluginSessionReason) -> Result<(), PluginSessionError> {
            Ok(())
        }
    }

    fn open_params() -> SessionOpenParams {
        SessionOpenParams {
            session_id: "plugin-session:1".into(),
            generation: 1,
            grant_id: "grant-test".into(),
            profile_id: "profile-fixture".into(),
            purpose: "capability_invocation".into(),
            capabilities: vec!["fixture.echo".into()],
            lease_expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            input: Value::Null,
            credential_grants: vec![],
            options: json!({ "host": "fixture.internal" }),
        }
    }

    fn adapter(runtime: tokio::runtime::Handle) -> CoreSessionAdapter {
        CoreSessionAdapter::new(runtime, |params| {
            assert_eq!(params.options["host"], "fixture.internal");
            Ok(Arc::new(MockFactory))
        })
    }

    #[test]
    fn open_call_health_close_round_trip_through_the_adapter() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let adapter = adapter(runtime.handle().clone());

        let opened = adapter.open(open_params()).expect("open");
        assert_eq!(opened.handle_id, "plugin-session:1");
        assert_eq!(opened.health, "ready");

        let called = adapter
            .call(SessionCallParams {
                handle_id: opened.handle_id.clone(),
                generation: 1,
                call_id: "call-1".into(),
                capability: "fixture.echo".into(),
                input: Value::Null,
                output_limit_bytes: 64 * 1024,
                timeout_ms: None,
            })
            .expect("call");
        assert_eq!(called.output, json!({ "echo": true }));

        let health = adapter
            .health(SessionHandleParams {
                handle_id: opened.handle_id.clone(),
                generation: 1,
            })
            .expect("health");
        assert_eq!(health.health, "ready");

        let closed = adapter
            .close(SessionCloseParams {
                handle_id: opened.handle_id,
                generation: 1,
                reason: "test_close".into(),
            })
            .expect("close");
        assert!(closed.closed);

        // The handle registry dropped the session with the close.
        assert!(
            adapter
                .health(SessionHandleParams {
                    handle_id: "plugin-session:1".into(),
                    generation: 1,
                })
                .is_err()
        );
    }

    #[test]
    fn unknown_or_stale_handles_fail_closed() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let adapter = adapter(runtime.handle().clone());

        let stale = adapter.call(SessionCallParams {
            handle_id: "plugin-session:missing".into(),
            generation: 1,
            call_id: "call-1".into(),
            capability: "fixture.echo".into(),
            input: Value::Null,
            output_limit_bytes: 64 * 1024,
            timeout_ms: None,
        });
        let error = stale.expect_err("missing handle");
        assert_eq!(error.code, "session.not_found");
    }

    #[test]
    fn router_advertises_sessions_only_with_a_bridge() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let mut bridged = CapabilityRouter::new("fixture")
            .session_bridge(Arc::new(adapter(runtime.handle().clone())));
        let result = bridged
            .initialize(InitializeParams {
                plugin_id: "fixture".into(),
                protocol_version: "1.1".into(),
                core_version: None,
                manifest_path: None,
                started_at: None,
            })
            .expect("initialize");
        assert_eq!(result.session_protocol.as_deref(), Some("1"));

        let mut plain = CapabilityRouter::new("fixture");
        let result = plain
            .initialize(InitializeParams {
                plugin_id: "fixture".into(),
                protocol_version: "1.1".into(),
                core_version: None,
                manifest_path: None,
                started_at: None,
            })
            .expect("initialize");
        assert_eq!(result.session_protocol, None);
    }
}
