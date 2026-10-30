use clap::ArgMatches;
use serde::Serialize;
use serde_json::Value;
use std::io::Write;
use voidb_core::VoidbError;
use voidb_core::capability::{
    CapabilityAuthorizationMetadata, CapabilityDefinition, CapabilityError,
    CapabilityErrorCategory, CapabilityExecutionMode, CapabilityRiskLevel, CredentialClass,
    InvocationStatus, InvocationStreamEnvelope, InvocationStreamEvent, RedactionStatus,
    TargetSystemFailure,
};

use super::INVOKE_CLI_SCHEMA_VERSION;
use super::execution::InvokeRunData;
use crate::builtin::json_output::print_json;

pub(super) fn capability_error(
    category: CapabilityErrorCategory,
    code: &str,
    message: &str,
    details: Value,
    target: Option<TargetSystemFailure>,
    retryable: bool,
) -> CapabilityError {
    CapabilityError {
        category,
        code: code.to_string(),
        message: message.to_string(),
        details,
        target,
        retryable,
        redaction: RedactionStatus::NotRequired,
    }
}

pub(super) fn exit_code_for_error(error: &CapabilityError) -> u8 {
    match error.category {
        CapabilityErrorCategory::Validation => 2,
        CapabilityErrorCategory::Auth
        | CapabilityErrorCategory::Credential
        | CapabilityErrorCategory::Permission
        | CapabilityErrorCategory::Policy => 3,
        CapabilityErrorCategory::Unavailable => 4,
        CapabilityErrorCategory::Timeout | CapabilityErrorCategory::Transport => 5,
        CapabilityErrorCategory::TargetSystem => 6,
        CapabilityErrorCategory::Conflict => 7,
        CapabilityErrorCategory::Cancellation => 8,
        CapabilityErrorCategory::Plugin | CapabilityErrorCategory::Internal => 1,
    }
}

pub(super) fn success_envelope<T: Serialize>(data: T) -> JsonSuccessEnvelope<T> {
    JsonSuccessEnvelope {
        ok: true,
        schema_version: INVOKE_CLI_SCHEMA_VERSION,
        command: "invoke",
        data,
        warnings: Vec::new(),
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InvokeOutputFormat {
    Json,
    Ndjson,
}

pub(super) fn run_output_format(matches: &ArgMatches) -> InvokeOutputFormat {
    match matches.get_one::<String>("format").map(String::as_str) {
        Some("ndjson") => InvokeOutputFormat::Ndjson,
        Some("json") | None => InvokeOutputFormat::Json,
        Some(_) => unreachable!("format is constrained by clap"),
    }
}

pub(super) struct NdjsonEmitter<W> {
    pub(super) writer: W,
    pub(super) invocation_id: String,
    pub(super) next_sequence: u64,
}

impl<W: Write> NdjsonEmitter<W> {
    pub(super) fn new(writer: W, invocation_id: String) -> Self {
        Self {
            writer,
            invocation_id,
            next_sequence: 0,
        }
    }

    pub(super) fn emit(&mut self, event: InvocationStreamEvent) -> Result<(), VoidbError> {
        let envelope =
            InvocationStreamEnvelope::new(self.next_sequence, self.invocation_id.clone(), event);
        serde_json::to_writer(&mut self.writer, &envelope).map_err(|error| {
            VoidbError::Plugin(format!("Failed to serialize NDJSON output: {error}"))
        })?;
        self.writer.write_all(b"\n").map_err(|error| {
            VoidbError::Plugin(format!("Failed to write NDJSON output: {error}"))
        })?;
        self.writer.flush().map_err(|error| {
            VoidbError::Plugin(format!("Failed to flush NDJSON output: {error}"))
        })?;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| VoidbError::Plugin("NDJSON sequence number overflowed".into()))?;
        Ok(())
    }
}

pub(super) fn print_run_success<W: Write>(
    output_format: InvokeOutputFormat,
    ndjson: Option<&mut NdjsonEmitter<W>>,
    data: InvokeRunData,
) -> Result<(), VoidbError> {
    if output_format == InvokeOutputFormat::Json {
        return print_json(&success_envelope(data));
    }

    let emitter = ndjson.expect("NDJSON emitter exists for NDJSON output");
    for warning in &data.warnings {
        emitter.emit(InvocationStreamEvent::Warning {
            warning: serialize_output_value(warning)?,
        })?;
    }
    let status = data.status;
    let duration_ms = data.timing.duration_ms;
    emitter.emit(InvocationStreamEvent::Data {
        value: serialize_output_value(&data)?,
    })?;
    emitter.emit(InvocationStreamEvent::End {
        status,
        duration_ms: Some(duration_ms),
    })
}

pub(super) fn print_run_error<W: Write>(
    output_format: InvokeOutputFormat,
    ndjson: Option<&mut NdjsonEmitter<W>>,
    envelope: JsonErrorEnvelope,
) -> Result<(), VoidbError> {
    if output_format == InvokeOutputFormat::Json {
        return print_json(&envelope);
    }

    let status = invocation_status_for_error(&envelope.error);
    let emitter = ndjson.expect("NDJSON emitter exists for NDJSON output");
    emitter.emit(InvocationStreamEvent::Error {
        error: envelope.error,
    })?;
    emitter.emit(InvocationStreamEvent::End {
        status,
        duration_ms: None,
    })
}

fn serialize_output_value(value: &impl Serialize) -> Result<Value, VoidbError> {
    serde_json::to_value(value)
        .map_err(|error| VoidbError::Plugin(format!("Failed to serialize invoke output: {error}")))
}

fn invocation_status_for_error(error: &CapabilityError) -> InvocationStatus {
    match error.category {
        CapabilityErrorCategory::Timeout => InvocationStatus::TimedOut,
        CapabilityErrorCategory::Cancellation => InvocationStatus::Cancelled,
        _ => InvocationStatus::Failed,
    }
}

#[derive(Debug, Serialize)]
pub(super) struct JsonSuccessEnvelope<T> {
    ok: bool,
    schema_version: u32,
    command: &'static str,
    data: T,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct JsonErrorEnvelope {
    pub(super) ok: bool,
    pub(super) schema_version: u32,
    pub(super) command: &'static str,
    pub(super) exit_code: u8,
    pub(super) error: CapabilityError,
}

#[derive(Debug, Serialize)]
pub(super) struct InvokeListData {
    pub(super) capabilities: Vec<CapabilitySummary>,
}

#[derive(Debug, Serialize)]
pub(super) struct InvokeDescribeData {
    pub(super) capability: CapabilityDefinition,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CapabilitySummary {
    pub(super) qualified_id: String,
    pub(super) plugin_id: String,
    pub(super) id: String,
    pub(super) description: String,
    pub(super) permissions: Vec<String>,
    pub(super) authorization: CapabilityAuthorizationMetadata,
    pub(super) risk: CapabilityRiskLevel,
    pub(super) destructive: bool,
    pub(super) streaming: bool,
    pub(super) execution_mode: CapabilityExecutionMode,
    pub(super) supports_stateless: bool,
    pub(super) supports_session: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) session_handoff: Option<voidb_core::CapabilitySessionHandoff>,
    pub(super) connection_required: bool,
    pub(super) required_secret_classes: Vec<CredentialClass>,
    pub(super) supports_dry_run: bool,
    pub(super) default_timeout_ms: Option<u64>,
}

impl From<CapabilityDefinition> for CapabilitySummary {
    fn from(capability: CapabilityDefinition) -> Self {
        let risk = capability.effective_risk();
        let supports_stateless = capability.supports_stateless_execution();
        let supports_session = capability.supports_session_execution();
        Self {
            qualified_id: capability.qualified_id(),
            plugin_id: capability.plugin_id,
            id: capability.id,
            description: capability.description,
            permissions: capability.permissions,
            authorization: capability.authorization,
            risk,
            destructive: capability.destructive,
            streaming: capability.streaming,
            execution_mode: capability.execution_mode,
            supports_stateless,
            supports_session,
            session_handoff: capability.session_handoff,
            connection_required: capability.connection_required,
            required_secret_classes: capability.required_secret_classes,
            supports_dry_run: capability.supports_dry_run,
            default_timeout_ms: capability.default_timeout_ms,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InvokeCatalogOutputFormat {
    Json,
    Table,
}

pub(super) fn capability_list_table(capabilities: &[CapabilitySummary]) -> String {
    let mut lines = vec!["Capability\tMode\tRisk\tStream\tProfile\tSession purpose".to_string()];
    for capability in capabilities {
        let purpose = capability
            .session_handoff
            .as_ref()
            .map(|handoff| session_purpose_cli_name(&handoff.purpose))
            .unwrap_or_else(|| "-".into());
        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            table_cell(&capability.qualified_id),
            execution_mode_name(capability.execution_mode),
            risk_name(capability.risk),
            capability.streaming,
            capability.connection_required,
            table_cell(&purpose),
        ));
    }
    lines.join("\n")
}

pub(super) fn capability_description_table(capability: &CapabilityDefinition) -> String {
    let handoff = capability
        .session_handoff
        .as_ref()
        .map(|handoff| {
            format!(
                "{} [{}]",
                session_purpose_cli_name(&handoff.purpose),
                handoff.capabilities.join(",")
            )
        })
        .unwrap_or_else(|| "-".into());
    [
        "Field\tValue".to_string(),
        format!("capability\t{}", table_cell(&capability.qualified_id())),
        format!("description\t{}", table_cell(&capability.description)),
        format!(
            "execution_mode\t{}",
            execution_mode_name(capability.execution_mode)
        ),
        format!("risk\t{}", risk_name(capability.effective_risk())),
        format!("streaming\t{}", capability.streaming),
        format!("connection_required\t{}", capability.connection_required),
        format!("supports_dry_run\t{}", capability.supports_dry_run),
        format!(
            "default_timeout_ms\t{}",
            capability
                .default_timeout_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into())
        ),
        format!(
            "permissions\t{}",
            table_cell(&capability.permissions.join(","))
        ),
        format!("session_handoff\t{}", table_cell(&handoff)),
    ]
    .join("\n")
}

fn table_cell(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ")
}

fn execution_mode_name(mode: CapabilityExecutionMode) -> &'static str {
    match mode {
        CapabilityExecutionMode::Stateless => "stateless",
        CapabilityExecutionMode::SessionOnly => "session_only",
        CapabilityExecutionMode::Both => "both",
    }
}

fn risk_name(risk: CapabilityRiskLevel) -> &'static str {
    match risk {
        CapabilityRiskLevel::ReadOnly => "read_only",
        CapabilityRiskLevel::Mutating => "mutating",
        CapabilityRiskLevel::Destructive => "destructive",
        CapabilityRiskLevel::ExternalSideEffect => "external_side_effect",
    }
}

pub(crate) fn session_purpose_cli_name(purpose: &voidb_core::PluginSessionPurpose) -> String {
    use voidb_core::PluginSessionPurpose;

    match purpose {
        PluginSessionPurpose::InteractiveTerminal => "interactive_terminal".into(),
        PluginSessionPurpose::FileTransfer => "file_transfer".into(),
        PluginSessionPurpose::PortForward => "port_forward".into(),
        PluginSessionPurpose::DatabaseQuery => "database_query".into(),
        PluginSessionPurpose::DatabaseTransaction => "database_transaction".into(),
        PluginSessionPurpose::CacheCommand => "cache_command".into(),
        PluginSessionPurpose::LogStream => "log_stream".into(),
        PluginSessionPurpose::WatchStream => "watch_stream".into(),
        PluginSessionPurpose::InfrastructureClient => "infrastructure_client".into(),
        PluginSessionPurpose::SyncClient => "sync_client".into(),
        PluginSessionPurpose::CapabilityInvocation => "capability_invocation".into(),
        PluginSessionPurpose::PluginDefined(value) => format!("plugin_defined:{value}"),
    }
}
