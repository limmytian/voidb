#![allow(clippy::result_large_err)]

use serde_json::{Value, json};
use voidb_core::{
    CapabilityDefinition, CapabilityError, CapabilityErrorCategory, CapabilityInvocation,
    CapabilityInvocationResult, CapabilityRiskLevel, CredentialClass, InvocationOutputPage,
    InvocationStatus, LocalPathError, LocalPathScope, Pagination, RedactionStatus,
    TargetSystemFailure,
};

use crate::config::{SshAuthMethod, SshConfig};
use crate::service::{SshService, direct_connection_error_code};

const PLUGIN_ID: &str = "ssh";
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_TEXT_LIMIT_BYTES: usize = 64 * 1024;
const MAX_TEXT_LIMIT_BYTES: usize = 1024 * 1024;
const DEFAULT_LIST_LIMIT: usize = 100;
const MAX_LIST_LIMIT: usize = 1_000;

pub fn ssh_capabilities() -> Vec<CapabilityDefinition> {
    vec![
        capability(
            "test",
            "Connect and authenticate to an SSH target without opening an interactive shell.",
            empty_input_schema(),
            json!({
                "type": "object",
                "required": ["reachable", "auth_method"],
                "properties": {
                    "reachable": { "type": "boolean" },
                    "auth_method": { "type": "string" }
                },
                "additionalProperties": false
            }),
            vec!["connection.test", "ssh.test"],
            false,
            false,
            false,
        ),
        capability(
            "exec",
            "Execute a remote SSH command and return bounded stdout, stderr, and exit status.",
            json!({
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command": { "type": "string", "minLength": 1 },
                    "max_stdout_bytes": text_limit_schema(),
                    "max_stderr_bytes": text_limit_schema()
                },
                "additionalProperties": false
            }),
            exec_output_schema(),
            vec!["connection.read", "ssh.exec"],
            true,
            false,
            true,
        ),
        capability(
            "terminal_read",
            "Read a bounded incremental output window from an agent-owned interactive SSH PTY.",
            json!({
                "type": "object",
                "properties": {
                    "after_offset": { "type": "integer", "minimum": 0, "default": 0 },
                    "max_bytes": { "type": "integer", "minimum": 1, "maximum": 131072, "default": 32768 },
                    "wait_ms": { "type": "integer", "minimum": 0, "maximum": 1000, "default": 0 }
                },
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "required": ["text", "next_offset", "end_offset", "gap", "more", "closed"],
                "properties": {
                    "text": { "type": "string" },
                    "source_bytes": { "type": "integer", "minimum": 0 },
                    "requested_offset": { "type": "integer", "minimum": 0 },
                    "start_offset": { "type": "integer", "minimum": 0 },
                    "next_offset": { "type": "integer", "minimum": 0 },
                    "retained_start_offset": { "type": "integer", "minimum": 0 },
                    "end_offset": { "type": "integer", "minimum": 0 },
                    "gap": { "type": "boolean" },
                    "more": { "type": "boolean" },
                    "timed_out": { "type": "boolean" },
                    "closed": { "type": "boolean" }
                },
                "additionalProperties": false
            }),
            vec!["connection.read", "ssh.terminal.read"],
            false,
            true,
            false,
        ),
        capability(
            "terminal_snapshot",
            "Return a bounded plain-text screen snapshot and terminal mode metadata for an agent-owned SSH PTY.",
            empty_input_schema(),
            json!({
                "type": "object",
                "required": ["lines", "cursor", "size", "modes", "end_offset", "health"],
                "properties": {
                    "lines": { "type": "array", "items": { "type": "string" } },
                    "cursor": { "type": "object" },
                    "size": { "type": "object" },
                    "modes": { "type": "object" },
                    "title": { "type": "string" },
                    "retained_start_offset": { "type": "integer", "minimum": 0 },
                    "end_offset": { "type": "integer", "minimum": 0 },
                    "exit_code": { "type": ["integer", "null"] },
                    "health": { "type": "string" }
                },
                "additionalProperties": false
            }),
            vec!["connection.read", "ssh.terminal.read"],
            false,
            false,
            false,
        ),
        capability(
            "terminal_write",
            "Write bounded text or named keys to an agent-owned interactive SSH PTY.",
            json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string", "maxLength": 16384 },
                    "keys": {
                        "type": "array",
                        "maxItems": 256,
                        "items": { "type": "string" }
                    },
                    "paste": { "type": "boolean", "default": false },
                    "enter": { "type": "boolean", "default": false }
                },
                "anyOf": [
                    { "required": ["text"] },
                    { "required": ["keys"] },
                    { "required": ["enter"] }
                ],
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "required": ["written_bytes", "text_bytes", "key_count", "paste", "enter"],
                "properties": {
                    "written_bytes": { "type": "integer", "minimum": 1 },
                    "text_bytes": { "type": "integer", "minimum": 0 },
                    "key_count": { "type": "integer", "minimum": 0 },
                    "paste": { "type": "boolean" },
                    "enter": { "type": "boolean" }
                },
                "additionalProperties": false
            }),
            vec!["connection.write", "ssh.terminal.control"],
            true,
            false,
            false,
        ),
        capability(
            "terminal_resize",
            "Resize an agent-owned interactive SSH PTY and its terminal parser.",
            terminal_size_schema(),
            terminal_size_schema(),
            vec!["connection.write", "ssh.terminal.control"],
            true,
            false,
            false,
        ),
        capability(
            "terminal_signal",
            "Send a named process signal to an agent-owned interactive SSH PTY.",
            json!({
                "type": "object",
                "required": ["signal"],
                "properties": {
                    "signal": { "type": "string", "enum": ["INT", "TERM", "HUP", "QUIT", "KILL"] }
                },
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "required": ["signal"],
                "properties": {
                    "signal": { "type": "string" }
                },
                "additionalProperties": false
            }),
            vec!["connection.write", "ssh.terminal.control"],
            true,
            false,
            false,
        ),
        capability(
            "forward_open",
            "Open a local TCP forward inside a persistent SSH agent session.",
            json!({
                "type": "object",
                "required": ["bind_port", "remote_host", "remote_port"],
                "properties": {
                    "bind_addr": { "type": "string", "default": "127.0.0.1" },
                    "bind_port": { "type": "integer", "minimum": 0, "maximum": 65535 },
                    "remote_host": { "type": "string", "minLength": 1 },
                    "remote_port": { "type": "integer", "minimum": 1, "maximum": 65535 }
                },
                "additionalProperties": false
            }),
            json!({ "type": "object" }),
            vec!["connection.forward", "ssh.forward"],
            true,
            false,
            true,
        ),
        capability(
            "forward_status",
            "Inspect a local forward inside a persistent SSH agent session.",
            empty_input_schema(),
            json!({ "type": "object" }),
            vec!["connection.read", "ssh.forward"],
            false,
            false,
            false,
        ),
        capability(
            "sftp_list",
            "List a remote SFTP directory with bounded, cursor-based output.",
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "minLength": 1, "default": "." }
                },
                "additionalProperties": false
            }),
            list_output_schema(),
            vec!["connection.read", "sftp.list"],
            false,
            false,
            false,
        ),
        mutating_capability(
            "sftp_get",
            "Download a remote SFTP file to a local path and return transfer metadata.",
            json!({
                "type": "object",
                "required": ["remote_path", "local_root", "local_path"],
                "properties": {
                    "remote_path": { "type": "string", "minLength": 1 },
                    "local_root": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Human-approved absolute local root; never returned in output."
                    },
                    "local_path": {
                        "type": "string",
                        "minLength": 1,
                        "description": "New destination path relative to local_root."
                    }
                },
                "additionalProperties": false
            }),
            transfer_output_schema("downloaded"),
            vec!["connection.read", "sftp.read", "local.write"],
            false,
            false,
        ),
        capability(
            "sftp_put",
            "Upload a local file to a remote SFTP path and return transfer metadata.",
            json!({
                "type": "object",
                "required": ["local_root", "local_path", "remote_path"],
                "properties": {
                    "local_root": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Human-approved absolute local root; never returned in output."
                    },
                    "local_path": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Existing source path relative to local_root."
                    },
                    "remote_path": { "type": "string", "minLength": 1 }
                },
                "additionalProperties": false
            }),
            transfer_output_schema("uploaded"),
            vec!["connection.write", "sftp.write", "local.read"],
            true,
            false,
            true,
        ),
        capability(
            "sftp_mkdir",
            "Create a remote SFTP directory.",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "minLength": 1 }
                },
                "additionalProperties": false
            }),
            mutation_output_schema("mkdir"),
            vec!["connection.write", "sftp.write"],
            true,
            false,
            true,
        ),
        capability(
            "sftp_rm",
            "Remove a remote SFTP file.",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "minLength": 1 }
                },
                "additionalProperties": false
            }),
            mutation_output_schema("rm"),
            vec!["connection.write", "sftp.delete"],
            true,
            false,
            true,
        ),
        capability(
            "diagnostics",
            "Return agent-safe SSH profile diagnostics without opening a network connection.",
            empty_input_schema(),
            json!({
                "type": "object",
                "required": ["auth_method", "connect_timeout_secs", "keep_alive_interval_secs"],
                "properties": {
                    "auth_method": { "type": "string" },
                    "connect_timeout_secs": { "type": "integer", "minimum": 0 },
                    "keep_alive_interval_secs": { "type": "integer", "minimum": 0 }
                },
                "additionalProperties": false
            }),
            vec!["connection.read", "ssh.diagnostics"],
            false,
            false,
            false,
        ),
    ]
}

pub async fn invoke_ssh_capability(
    config: &SshConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    if invocation.plugin_id != PLUGIN_ID {
        return Err(validation_error(
            "validation.plugin_mismatch",
            "Invocation plugin_id does not match SSH.",
            json!({ "expected": PLUGIN_ID, "actual": invocation.plugin_id }),
        ));
    }

    match invocation.capability_id.as_str() {
        "test" => invoke_test(config, invocation).await,
        "exec" => invoke_exec(config, invocation).await,
        "forward_open" if invocation.controls.dry_run => Ok(dry_run_result(
            invocation.id,
            "forward_open",
            json!({ "session_required": true }),
        )),
        "forward_open" | "forward_status" => Err(unavailable_error(
            "unavailable.session_required",
            "SSH forwarding capabilities require a persistent agent session.",
            json!({ "capability_id": invocation.capability_id }),
        )),
        "terminal_read" | "terminal_snapshot" | "terminal_write" | "terminal_resize"
        | "terminal_signal" => Err(unavailable_error(
            "unavailable.session_required",
            "SSH terminal capabilities require an agent-owned interactive PTY session.",
            json!({ "capability_id": invocation.capability_id }),
        )),
        "sftp_list" => invoke_sftp_list(config, invocation).await,
        "sftp_get" => invoke_sftp_get(config, invocation).await,
        "sftp_put" => invoke_sftp_put(config, invocation).await,
        "sftp_mkdir" => invoke_sftp_mkdir(config, invocation).await,
        "sftp_rm" => invoke_sftp_rm(config, invocation).await,
        "diagnostics" => Ok(diagnostics_result(config, invocation.id)),
        other => Err(unavailable_error(
            "unavailable.capability_not_found",
            "SSH capability was not found.",
            json!({ "capability_id": other }),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn capability(
    id: &str,
    description: &str,
    input_schema: Value,
    output_schema: Value,
    permissions: Vec<&str>,
    destructive: bool,
    streaming: bool,
    supports_dry_run: bool,
) -> CapabilityDefinition {
    let (execution_mode, session_handoff) = ssh_execution_metadata(id);
    CapabilityDefinition {
        plugin_id: PLUGIN_ID.to_string(),
        id: id.to_string(),
        description: description.to_string(),
        input_schema,
        output_schema,
        permissions: permissions.into_iter().map(str::to_string).collect(),
        authorization: ssh_authorization_metadata(id),
        risk: CapabilityRiskLevel::from_destructive(destructive),
        destructive,
        streaming,
        execution_mode,
        session_handoff,
        connection_required: true,
        required_secret_classes: Vec::<CredentialClass>::new(),
        supports_dry_run,
        default_timeout_ms: Some(DEFAULT_TIMEOUT_MS),
    }
}

fn ssh_execution_metadata(
    id: &str,
) -> (
    voidb_core::CapabilityExecutionMode,
    Option<voidb_core::CapabilitySessionHandoff>,
) {
    use voidb_core::{CapabilityExecutionMode, CapabilitySessionHandoff, PluginSessionPurpose};

    let metadata = match id {
        "exec" => (
            CapabilityExecutionMode::Both,
            CapabilitySessionHandoff::new(PluginSessionPurpose::InteractiveTerminal, ["ssh.exec"]),
        ),
        "terminal_read" | "terminal_snapshot" | "terminal_write" | "terminal_resize"
        | "terminal_signal" => (
            CapabilityExecutionMode::SessionOnly,
            CapabilitySessionHandoff::new(
                PluginSessionPurpose::InteractiveTerminal,
                [
                    "ssh.terminal_read",
                    "ssh.terminal_snapshot",
                    "ssh.terminal_write",
                    "ssh.terminal_resize",
                    "ssh.terminal_signal",
                ],
            ),
        ),
        "forward_open" | "forward_status" => (
            CapabilityExecutionMode::SessionOnly,
            CapabilitySessionHandoff::new(
                PluginSessionPurpose::PortForward,
                ["ssh.forward_open", "ssh.forward_status"],
            ),
        ),
        "sftp_list" => (
            CapabilityExecutionMode::Both,
            CapabilitySessionHandoff::new(PluginSessionPurpose::FileTransfer, ["ssh.sftp_list"]),
        ),
        _ => return (CapabilityExecutionMode::Stateless, None),
    };

    (metadata.0, Some(metadata.1))
}

#[allow(clippy::too_many_arguments)]
fn mutating_capability(
    id: &str,
    description: &str,
    input_schema: Value,
    output_schema: Value,
    permissions: Vec<&str>,
    streaming: bool,
    supports_dry_run: bool,
) -> CapabilityDefinition {
    let mut definition = capability(
        id,
        description,
        input_schema,
        output_schema,
        permissions,
        false,
        streaming,
        supports_dry_run,
    );
    definition.risk = CapabilityRiskLevel::Mutating;
    definition
}

fn ssh_authorization_metadata(id: &str) -> voidb_core::CapabilityAuthorizationMetadata {
    match id {
        "exec" => voidb_core::CapabilityAuthorizationMetadata::declared()
            .with_interactive_execute()
            .with_session_purposes(vec![voidb_core::PluginSessionPurpose::InteractiveTerminal])
            .with_approval_schema(voidb_core::CapabilityApprovalSchema::v1(vec![
                voidb_core::CapabilityApprovalField::new(
                    "/command",
                    "Remote command",
                    voidb_core::CapabilityApprovalValueType::String,
                )
                .required()
                .with_description(
                    "Exact shell command string; argv-style execution is not currently exposed.",
                )
                .with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::Destructive),
            ])),
        "terminal_read" | "terminal_snapshot" => {
            voidb_core::CapabilityAuthorizationMetadata::declared()
                .with_session_purposes(vec![voidb_core::PluginSessionPurpose::InteractiveTerminal])
        }
        "terminal_write" => voidb_core::CapabilityAuthorizationMetadata::declared()
            .with_session_purposes(vec![voidb_core::PluginSessionPurpose::InteractiveTerminal])
            .with_note(
                "Interactive PTY control is intentionally Custom-only and requires a short-lived destructive grant.",
            ),
        "terminal_resize" => voidb_core::CapabilityAuthorizationMetadata::declared()
            .with_session_purposes(vec![voidb_core::PluginSessionPurpose::InteractiveTerminal]),
        "terminal_signal" => voidb_core::CapabilityAuthorizationMetadata::declared()
            .with_session_purposes(vec![voidb_core::PluginSessionPurpose::InteractiveTerminal])
            .with_approval_schema(voidb_core::CapabilityApprovalSchema::v1(vec![
                voidb_core::CapabilityApprovalField::new(
                    "/signal",
                    "Terminal signal",
                    voidb_core::CapabilityApprovalValueType::String,
                )
                .required()
                .with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::Destructive),
            ])),
        "forward_open" => voidb_core::CapabilityAuthorizationMetadata::declared()
            .with_session_purposes(vec![voidb_core::PluginSessionPurpose::PortForward])
            .with_approval_schema(voidb_core::CapabilityApprovalSchema::v1(vec![
                voidb_core::CapabilityApprovalField::new(
                    "/remote_host",
                    "Remote host",
                    voidb_core::CapabilityApprovalValueType::ResourceId,
                )
                .required(),
                voidb_core::CapabilityApprovalField::new(
                    "/remote_port",
                    "Remote port",
                    voidb_core::CapabilityApprovalValueType::Integer,
                )
                .required(),
            ])),
        "forward_status" => voidb_core::CapabilityAuthorizationMetadata::declared()
            .with_session_purposes(vec![voidb_core::PluginSessionPurpose::PortForward]),
        "sftp_list" => voidb_core::CapabilityAuthorizationMetadata::declared()
            .with_session_purposes(vec![voidb_core::PluginSessionPurpose::FileTransfer])
            .with_approval_schema(path_approval_schema("/path", "Remote path", false)),
        "sftp_get" | "sftp_put" => voidb_core::CapabilityAuthorizationMetadata::declared()
            .with_session_purposes(vec![voidb_core::PluginSessionPurpose::FileTransfer])
            .with_approval_schema(local_transfer_approval_schema(
                "/remote_path",
                "Remote path",
                id == "sftp_put",
                id == "sftp_get",
            ))
            .without_capability_wide(),
        "sftp_mkdir" | "sftp_rm" => voidb_core::CapabilityAuthorizationMetadata::declared()
            .with_session_purposes(vec![voidb_core::PluginSessionPurpose::FileTransfer])
            .with_approval_schema(path_approval_schema("/path", "Remote path", true)),
        _ => voidb_core::CapabilityAuthorizationMetadata::declared(),
    }
}

fn local_transfer_approval_schema(
    remote_path: &str,
    remote_label: &str,
    remote_destructive: bool,
    local_write: bool,
) -> voidb_core::CapabilityApprovalSchema {
    let mut fields = path_approval_schema(remote_path, remote_label, remote_destructive).fields;
    fields.push(
        voidb_core::CapabilityApprovalField::new(
            "/local_root",
            "Approved local root",
            voidb_core::CapabilityApprovalValueType::Path,
        )
        .required()
        .with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::PrivilegeEscalation),
    );
    let mut local_path = voidb_core::CapabilityApprovalField::new(
        "/local_path",
        "Relative local path",
        voidb_core::CapabilityApprovalValueType::Path,
    )
    .required();
    if local_write {
        local_path =
            local_path.with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::Destructive);
    }
    fields.push(local_path);
    voidb_core::CapabilityApprovalSchema::v1(fields)
}

fn path_approval_schema(
    path: &str,
    label: &str,
    destructive: bool,
) -> voidb_core::CapabilityApprovalSchema {
    let mut field = voidb_core::CapabilityApprovalField::new(
        path,
        label,
        voidb_core::CapabilityApprovalValueType::Path,
    )
    .required()
    .with_constraint(voidb_core::CapabilityConstraintKind::Prefix);
    if destructive {
        field = field.with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::Destructive);
    }
    voidb_core::CapabilityApprovalSchema::v1(vec![field])
}

fn terminal_size_schema() -> Value {
    json!({
        "type": "object",
        "required": ["cols", "rows"],
        "properties": {
            "cols": { "type": "integer", "minimum": 20, "maximum": 240 },
            "rows": { "type": "integer", "minimum": 5, "maximum": 100 }
        },
        "additionalProperties": false
    })
}

async fn invoke_test(
    config: &SshConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let service = SshService::new_direct(config.clone())
        .await
        .map_err(|error| target_error(direct_connection_error_code(&error), error.to_string()))?;
    service.disconnect().await;

    let output = json!({
        "reachable": true,
        "auth_method": auth_method(config),
    });
    let summary = output.clone();
    Ok(result(invocation.id, output, summary, None))
}

async fn invoke_exec(
    config: &SshConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let command = required_string(&invocation.input, "command")?;
    let max_stdout_bytes = requested_text_limit(&invocation.input, "max_stdout_bytes")?;
    let max_stderr_bytes = requested_text_limit(&invocation.input, "max_stderr_bytes")?;

    if invocation.controls.dry_run {
        return Ok(dry_run_result(
            invocation.id,
            "exec",
            json!({
                "max_stdout_bytes": max_stdout_bytes,
                "max_stderr_bytes": max_stderr_bytes,
            }),
        ));
    }

    let mut service = SshService::new_direct(config.clone())
        .await
        .map_err(|error| target_error(direct_connection_error_code(&error), error.to_string()))?;
    let output = service
        .exec_output(&command)
        .await
        .map_err(|error| target_error("ssh.exec_failed", error.to_string()))?;
    service.disconnect().await;

    let stdout = bounded_text(&output.stdout, max_stdout_bytes);
    let stderr = bounded_text(&output.stderr, max_stderr_bytes);
    let response = json!({
        "stdout": stdout.value,
        "stderr": stderr.value,
        "exit_code": output.exit_code,
        "stdout_bytes": stdout.source_bytes,
        "stderr_bytes": stderr.source_bytes,
        "stdout_truncated": stdout.truncated,
        "stderr_truncated": stderr.truncated,
        "max_stdout_bytes": max_stdout_bytes,
        "max_stderr_bytes": max_stderr_bytes,
    });
    let summary = json!({
        "exit_code": output.exit_code,
        "stdout_bytes": stdout.source_bytes,
        "stderr_bytes": stderr.source_bytes,
        "stdout_truncated": stdout.truncated,
        "stderr_truncated": stderr.truncated,
    });
    Ok(result(invocation.id, response, summary, None))
}

async fn invoke_sftp_list(
    config: &SshConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let path = optional_string(&invocation.input, "path")?.unwrap_or_else(|| ".".to_string());
    let page = page_request(invocation.controls.page.as_ref())?;

    let mut service = SshService::new_direct(config.clone())
        .await
        .map_err(|error| target_error(direct_connection_error_code(&error), error.to_string()))?;
    let mut entries = service
        .sftp_ls(&path)
        .await
        .map_err(|error| target_error("ssh.sftp_list_failed", error.to_string()))?;
    service.disconnect().await;

    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let source_entry_count = entries.len();
    let end = page.offset.saturating_add(page.limit).min(entries.len());
    let page_entries = if page.offset >= entries.len() {
        Vec::new()
    } else {
        entries[page.offset..end].to_vec()
    };
    let next_cursor = (end < entries.len()).then(|| end.to_string());
    let output_entries = page_entries
        .into_iter()
        .map(|(name, is_dir, size)| {
            json!({
                "name": name,
                "entry_type": if is_dir { "directory" } else { "file" },
                "size": size,
            })
        })
        .collect::<Vec<_>>();
    let entry_count = output_entries.len();
    let truncated = next_cursor.is_some();
    let output = json!({
        "path": path,
        "entries": output_entries,
        "limit": page.limit,
        "cursor": page.cursor,
        "next_cursor": next_cursor,
        "entry_count": entry_count,
        "source_entry_count": source_entry_count,
        "truncated": truncated,
    });
    let summary = json!({
        "entry_count": entry_count,
        "source_entry_count": source_entry_count,
        "truncated": truncated,
        "next_cursor": output["next_cursor"],
    });
    let output_page = truncated.then(|| InvocationOutputPage {
        next_cursor: output["next_cursor"].as_str().map(str::to_string),
    });
    Ok(result(invocation.id, output, summary, output_page))
}

async fn invoke_sftp_get(
    config: &SshConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let remote_path = required_string(&invocation.input, "remote_path")?;
    let local_root = required_string(&invocation.input, "local_root")?;
    let local_path = required_string(&invocation.input, "local_path")?;
    let local_scope_id = format!("local-scope:{}", invocation.id);
    let local_scope = LocalPathScope::new(&local_root)
        .map_err(|error| local_path_error(&local_scope_id, "create_file", error))?;
    local_scope
        .validate_new_file(&local_path)
        .map_err(|error| local_path_error(&local_scope_id, "create_file", error))?;

    let mut service = SshService::new_direct(config.clone())
        .await
        .map_err(|error| target_error(direct_connection_error_code(&error), error.to_string()))?;
    let data = service
        .sftp_read_remote(&remote_path)
        .await
        .map_err(|error| target_error("ssh.sftp_get_failed", error.to_string()))?;
    service.disconnect().await;
    local_scope
        .write_new_file(&local_path, &data)
        .map_err(|error| local_path_error(&local_scope_id, "create_file", error))?;

    Ok(transfer_result(
        invocation.id,
        "downloaded",
        data.len(),
        json!({ "remote_path": remote_path, "local_scope_id": local_scope_id }),
    ))
}

async fn invoke_sftp_put(
    config: &SshConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let local_root = required_string(&invocation.input, "local_root")?;
    let local_path = required_string(&invocation.input, "local_path")?;
    let remote_path = required_string(&invocation.input, "remote_path")?;
    let local_scope_id = format!("local-scope:{}", invocation.id);
    let local_scope = LocalPathScope::new(&local_root)
        .map_err(|error| local_path_error(&local_scope_id, "read_file", error))?;

    if invocation.controls.dry_run {
        local_scope
            .resolve_existing_file(&local_path)
            .map_err(|error| local_path_error(&local_scope_id, "read_file", error))?;
        return Ok(dry_run_result(
            invocation.id,
            "sftp_put",
            json!({ "local_scope_id": local_scope_id, "remote_path": remote_path }),
        ));
    }

    let data = local_scope
        .read_file(&local_path)
        .map_err(|error| local_path_error(&local_scope_id, "read_file", error))?;
    let mut service = SshService::new_direct(config.clone())
        .await
        .map_err(|error| target_error(direct_connection_error_code(&error), error.to_string()))?;
    let bytes = service
        .sftp_write_remote(&remote_path, &data)
        .await
        .map_err(|error| target_error("ssh.sftp_put_failed", error.to_string()))?;
    service.disconnect().await;

    Ok(transfer_result(
        invocation.id,
        "uploaded",
        bytes,
        json!({ "local_scope_id": local_scope_id, "remote_path": remote_path }),
    ))
}

async fn invoke_sftp_mkdir(
    config: &SshConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let path = required_string(&invocation.input, "path")?;

    if invocation.controls.dry_run {
        return Ok(dry_run_result(
            invocation.id,
            "sftp_mkdir",
            json!({ "path": path }),
        ));
    }

    let mut service = SshService::new_direct(config.clone())
        .await
        .map_err(|error| target_error(direct_connection_error_code(&error), error.to_string()))?;
    service
        .sftp_mkdir(&path)
        .await
        .map_err(|error| target_error("ssh.sftp_mkdir_failed", error.to_string()))?;
    service.disconnect().await;

    Ok(mutation_result(
        invocation.id,
        "mkdir",
        json!({ "path": path }),
    ))
}

async fn invoke_sftp_rm(
    config: &SshConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let path = required_string(&invocation.input, "path")?;

    if invocation.controls.dry_run {
        return Ok(dry_run_result(
            invocation.id,
            "sftp_rm",
            json!({ "path": path }),
        ));
    }

    let mut service = SshService::new_direct(config.clone())
        .await
        .map_err(|error| target_error(direct_connection_error_code(&error), error.to_string()))?;
    service
        .sftp_rm(&path)
        .await
        .map_err(|error| target_error("ssh.sftp_rm_failed", error.to_string()))?;
    service.disconnect().await;

    Ok(mutation_result(
        invocation.id,
        "rm",
        json!({ "path": path }),
    ))
}

fn diagnostics_result(config: &SshConfig, invocation_id: String) -> CapabilityInvocationResult {
    let output = json!({
        "auth_method": auth_method(config),
        "connect_timeout_secs": config.options.connect_timeout,
        "keep_alive_interval_secs": config.options.keep_alive_interval,
    });
    result(invocation_id, output.clone(), output, None)
}

fn transfer_result(
    invocation_id: String,
    operation: &str,
    bytes: usize,
    paths: Value,
) -> CapabilityInvocationResult {
    let output = json!({
        "operation": operation,
        "bytes": bytes,
        "paths": paths,
    });
    let summary = json!({
        "operation": operation,
        "bytes": bytes,
    });
    result(invocation_id, output, summary, None)
}

fn mutation_result(
    invocation_id: String,
    operation: &str,
    metadata: Value,
) -> CapabilityInvocationResult {
    let output = json!({
        "operation": operation,
        "completed": true,
        "metadata": metadata,
    });
    let summary = json!({
        "operation": operation,
        "completed": true,
    });
    result(invocation_id, output, summary, None)
}

fn dry_run_result(
    invocation_id: String,
    operation: &str,
    metadata: Value,
) -> CapabilityInvocationResult {
    let output = json!({
        "operation": operation,
        "dry_run": true,
        "would_execute": true,
        "metadata": metadata,
    });
    let summary = json!({
        "operation": operation,
        "dry_run": true,
        "would_execute": true,
    });
    result(invocation_id, output, summary, None)
}

fn result(
    invocation_id: String,
    output: Value,
    output_summary: Value,
    page: Option<InvocationOutputPage>,
) -> CapabilityInvocationResult {
    CapabilityInvocationResult {
        invocation_id,
        status: InvocationStatus::Succeeded,
        output,
        output_summary,
        page,
    }
}

fn empty_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false
    })
}

fn text_limit_schema() -> Value {
    json!({
        "type": "integer",
        "minimum": 1,
        "maximum": MAX_TEXT_LIMIT_BYTES,
        "default": DEFAULT_TEXT_LIMIT_BYTES
    })
}

fn exec_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "stdout",
            "stderr",
            "exit_code",
            "stdout_bytes",
            "stderr_bytes",
            "stdout_truncated",
            "stderr_truncated",
            "max_stdout_bytes",
            "max_stderr_bytes"
        ],
        "properties": {
            "stdout": { "type": "string" },
            "stderr": { "type": "string" },
            "exit_code": { "type": ["integer", "null"], "minimum": 0 },
            "stdout_bytes": { "type": "integer", "minimum": 0 },
            "stderr_bytes": { "type": "integer", "minimum": 0 },
            "stdout_truncated": { "type": "boolean" },
            "stderr_truncated": { "type": "boolean" },
            "max_stdout_bytes": text_limit_schema(),
            "max_stderr_bytes": text_limit_schema()
        },
        "additionalProperties": false
    })
}

fn list_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "path",
            "entries",
            "limit",
            "cursor",
            "next_cursor",
            "entry_count",
            "source_entry_count",
            "truncated"
        ],
        "properties": {
            "path": { "type": "string" },
            "entries": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["name", "entry_type", "size"],
                    "properties": {
                        "name": { "type": "string" },
                        "entry_type": { "type": "string", "enum": ["file", "directory"] },
                        "size": { "type": "integer", "minimum": 0 }
                    },
                    "additionalProperties": false
                }
            },
            "limit": { "type": "integer", "minimum": 1, "maximum": MAX_LIST_LIMIT },
            "cursor": { "type": ["string", "null"] },
            "next_cursor": { "type": ["string", "null"] },
            "entry_count": { "type": "integer", "minimum": 0 },
            "source_entry_count": { "type": "integer", "minimum": 0 },
            "truncated": { "type": "boolean" }
        },
        "additionalProperties": false
    })
}

fn transfer_output_schema(operation: &str) -> Value {
    json!({
        "type": "object",
        "required": ["operation", "bytes", "paths"],
        "properties": {
            "operation": { "type": "string", "const": operation },
            "bytes": { "type": "integer", "minimum": 0 },
            "paths": { "type": "object" }
        },
        "additionalProperties": false
    })
}

fn mutation_output_schema(operation: &str) -> Value {
    json!({
        "type": "object",
        "required": ["operation", "completed", "metadata"],
        "properties": {
            "operation": { "type": "string", "const": operation },
            "completed": { "type": "boolean" },
            "metadata": { "type": "object" }
        },
        "additionalProperties": false
    })
}

fn required_string(input: &Value, field: &str) -> Result<String, CapabilityError> {
    optional_string(input, field)?.ok_or_else(|| {
        validation_error(
            "validation.input_field_required",
            "Required string input field is missing.",
            json!({ "field": field }),
        )
    })
}

fn optional_string(input: &Value, field: &str) -> Result<Option<String>, CapabilityError> {
    match input.get(field) {
        Some(value) if !value.is_string() => Err(validation_error(
            "validation.input_field_invalid",
            "Input field must be a string.",
            json!({ "field": field }),
        )),
        Some(value) => value
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(|value| Some(value.to_string()))
            .ok_or_else(|| {
                validation_error(
                    "validation.input_field_required",
                    "String input field cannot be empty.",
                    json!({ "field": field }),
                )
            }),
        None => Ok(None),
    }
}

fn requested_text_limit(input: &Value, field: &str) -> Result<usize, CapabilityError> {
    let Some(value) = input.get(field) else {
        return Ok(DEFAULT_TEXT_LIMIT_BYTES);
    };
    let Some(limit) = value.as_u64() else {
        return Err(validation_error(
            "validation.input_field_invalid",
            "Text limit must be an integer.",
            json!({ "field": field }),
        ));
    };
    if limit == 0 || limit > MAX_TEXT_LIMIT_BYTES as u64 {
        return Err(validation_error(
            "validation.input_field_out_of_range",
            "Text limit is outside the supported range.",
            json!({
                "field": field,
                "minimum": 1,
                "maximum": MAX_TEXT_LIMIT_BYTES,
            }),
        ));
    }
    Ok(limit as usize)
}

#[derive(Debug)]
struct PageRequest {
    limit: usize,
    offset: usize,
    cursor: Option<String>,
}

fn page_request(page: Option<&Pagination>) -> Result<PageRequest, CapabilityError> {
    let Some(page) = page else {
        return Ok(PageRequest {
            limit: DEFAULT_LIST_LIMIT,
            offset: 0,
            cursor: None,
        });
    };
    let limit = (page.limit as usize).clamp(1, MAX_LIST_LIMIT);
    let offset = match &page.cursor {
        Some(cursor) => cursor.parse::<usize>().map_err(|_| {
            validation_error(
                "validation.cursor_invalid",
                "SFTP list cursor must be a numeric offset.",
                json!({ "cursor": cursor }),
            )
        })?,
        None => 0,
    };
    Ok(PageRequest {
        limit,
        offset,
        cursor: page.cursor.clone(),
    })
}

struct BoundedText {
    value: String,
    source_bytes: usize,
    truncated: bool,
}

fn bounded_text(value: &str, limit: usize) -> BoundedText {
    let source_bytes = value.len();
    if source_bytes <= limit {
        return BoundedText {
            value: value.to_string(),
            source_bytes,
            truncated: false,
        };
    }

    let mut end = limit;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }

    BoundedText {
        value: value[..end].to_string(),
        source_bytes,
        truncated: true,
    }
}

fn auth_method(config: &SshConfig) -> &'static str {
    match &config.auth {
        SshAuthMethod::Password { .. } => "password",
        SshAuthMethod::PublicKey { .. } => "public_key",
        SshAuthMethod::Agent => "agent",
    }
}

fn validation_error(code: &str, message: &str, details: Value) -> CapabilityError {
    capability_error(
        CapabilityErrorCategory::Validation,
        code,
        message,
        details,
        None,
        false,
    )
}

fn unavailable_error(code: &str, message: &str, details: Value) -> CapabilityError {
    capability_error(
        CapabilityErrorCategory::Unavailable,
        code,
        message,
        details,
        None,
        true,
    )
}

fn target_error(code: &str, message: String) -> CapabilityError {
    capability_error(
        CapabilityErrorCategory::TargetSystem,
        code,
        "SSH target operation failed.",
        Value::Null,
        Some(TargetSystemFailure {
            system: Some(PLUGIN_ID.to_string()),
            code: Some(code.to_string()),
            message: Some(message),
        }),
        false,
    )
}

fn local_path_error(local_scope_id: &str, access: &str, error: LocalPathError) -> CapabilityError {
    let category = error.category();
    let code = error.code();
    let message = error.safe_message();
    let retryable = error.retryable();
    CapabilityError {
        category,
        code: code.to_string(),
        message: message.to_string(),
        details: json!({
            "local_scope_id": local_scope_id,
            "access": access,
        }),
        target: None,
        retryable,
        redaction: RedactionStatus::Applied,
    }
}

fn capability_error(
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::fs;
    use std::path::PathBuf;
    use voidb_core::{
        ActorRef, ActorType, ConnectionInstancePurpose, ConnectionProfileRef, InstanceReusePolicy,
        InvocationConnectionTarget, InvocationControls,
    };

    struct LocalFixture(PathBuf);

    impl LocalFixture {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("voidb-ssh-local-boundary-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).expect("create SSH local fixture");
            Self(path)
        }

        fn display(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
    }

    impl Drop for LocalFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn exposes_ssh_capability_metadata() {
        let capabilities = ssh_capabilities();

        assert_eq!(capabilities.len(), 15);
        assert!(
            capabilities
                .iter()
                .any(|capability| capability.qualified_id() == "ssh.exec"
                    && capability.destructive
                    && capability.supports_dry_run)
        );
        assert!(capabilities.iter().any(
            |capability| capability.qualified_id() == "ssh.sftp_list" && !capability.streaming
        ));
        assert!(capabilities.iter().any(|capability| {
            capability.qualified_id() == "ssh.forward_open"
                && capability.destructive
                && capability.supports_dry_run
        }));
        assert!(capabilities.iter().any(|capability| {
            capability.qualified_id() == "ssh.forward_status" && !capability.destructive
        }));
        assert!(capabilities.iter().any(|capability| {
            capability.qualified_id() == "ssh.terminal_read"
                && capability.streaming
                && !capability.destructive
        }));
        assert!(capabilities.iter().any(|capability| {
            capability.qualified_id() == "ssh.terminal_write"
                && capability.destructive
                && !capability.supports_dry_run
        }));
        assert!(capabilities.iter().any(|capability| {
            capability.qualified_id() == "ssh.terminal_signal"
                && capability.destructive
                && capability
                    .authorization
                    .session_purposes
                    .contains(&voidb_core::PluginSessionPurpose::InteractiveTerminal)
        }));

        let sftp_get = capabilities
            .iter()
            .find(|capability| capability.id == "sftp_get")
            .expect("sftp_get capability");
        assert_eq!(sftp_get.effective_risk(), CapabilityRiskLevel::Mutating);
        assert!(!sftp_get.authorization.capability_wide_allowed);
        assert!(
            sftp_get
                .authorization
                .approval_schema
                .as_ref()
                .unwrap()
                .fields
                .iter()
                .any(|field| field.path == "/local_root" && field.required)
        );

        let sftp_put = capabilities
            .iter()
            .find(|capability| capability.id == "sftp_put")
            .expect("sftp_put capability");
        assert!(!sftp_put.authorization.capability_wide_allowed);
        assert_eq!(
            sftp_put.input_schema["required"],
            json!(["local_root", "local_path", "remote_path"])
        );
    }

    #[test]
    fn local_path_errors_are_redacted_and_auditable() {
        let error = local_path_error(
            "local-scope:invoke-test",
            "read_file",
            LocalPathError::OutsideScope,
        );

        assert_eq!(error.code, "permission.local_path_outside_scope");
        assert_eq!(error.redaction, RedactionStatus::Applied);
        assert_eq!(error.details["local_scope_id"], "local-scope:invoke-test");
        assert!(
            !serde_json::to_string(&error)
                .unwrap()
                .contains("/Users/secret")
        );
    }

    #[tokio::test]
    async fn local_filesystem_boundary_fixture_rejects_download_and_upload_escape_before_connect() {
        let fixture = LocalFixture::new();
        fs::write(fixture.0.join("existing.txt"), b"existing").unwrap();
        fs::write(fixture.0.join("数据.txt"), b"unicode").unwrap();

        for local_path in ["../escape.txt", "existing.txt"] {
            let error = invoke_ssh_capability(
                &config(),
                invocation(
                    "sftp_get",
                    json!({
                        "remote_path": "/remote/file.txt",
                        "local_root": fixture.display(),
                        "local_path": local_path,
                    }),
                ),
            )
            .await
            .expect_err("download destination must fail before SSH connection");
            assert!(matches!(
                error.code.as_str(),
                "permission.local_path_outside_scope" | "conflict.local_path_exists"
            ));
            assert_eq!(error.redaction, RedactionStatus::Applied);
            assert!(
                !serde_json::to_string(&error)
                    .unwrap()
                    .contains(&fixture.display())
            );
        }

        let mut escaped_upload = invocation(
            "sftp_put",
            json!({
                "local_root": fixture.display(),
                "local_path": "../escape.txt",
                "remote_path": "/remote/file.txt",
            }),
        );
        escaped_upload.controls.dry_run = true;
        let error = invoke_ssh_capability(&config(), escaped_upload)
            .await
            .expect_err("upload source escape must fail before SSH connection");
        assert_eq!(error.code, "permission.local_path_outside_scope");

        let mut unicode_upload = invocation(
            "sftp_put",
            json!({
                "local_root": fixture.display(),
                "local_path": "数据.txt",
                "remote_path": "/remote/unicode.txt",
            }),
        );
        unicode_upload.controls.dry_run = true;
        let result = invoke_ssh_capability(&config(), unicode_upload)
            .await
            .expect("in-scope Unicode source remains valid");
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("数据.txt"));
        assert!(!encoded.contains(&fixture.display()));
    }

    #[test]
    fn local_filesystem_boundary_capability_policy_declares_exact_access_modes() {
        let capabilities = ssh_capabilities();
        let get = capabilities
            .iter()
            .find(|capability| capability.id == "sftp_get")
            .unwrap();
        let put = capabilities
            .iter()
            .find(|capability| capability.id == "sftp_put")
            .unwrap();

        assert!(get.permissions.contains(&"local.write".to_string()));
        assert!(put.permissions.contains(&"local.read".to_string()));
        for capability in [get, put] {
            assert!(!capability.authorization.capability_wide_allowed);
            let fields = &capability
                .authorization
                .approval_schema
                .as_ref()
                .expect("local approval schema")
                .fields;
            assert!(fields.iter().any(|field| field.path == "/local_root"));
            assert!(fields.iter().any(|field| field.path == "/local_path"));
        }
    }

    #[tokio::test]
    async fn terminal_capabilities_require_persistent_agent_session() {
        let error = invoke_ssh_capability(&config(), invocation("terminal_snapshot", json!({})))
            .await
            .expect_err("terminal snapshot must not open through generic invoke");

        assert_eq!(error.code, "unavailable.session_required");
    }

    #[test]
    fn exec_schema_exposes_bounded_output_contract() {
        let capabilities = ssh_capabilities();
        let exec = capabilities
            .iter()
            .find(|capability| capability.id == "exec")
            .expect("exec capability");

        assert_eq!(exec.input_schema["required"][0], "command");
        assert_eq!(
            exec.input_schema["properties"]["max_stdout_bytes"]["maximum"],
            json!(MAX_TEXT_LIMIT_BYTES)
        );
        assert_eq!(
            exec.output_schema["properties"]["stdout_truncated"]["type"],
            "boolean"
        );
        assert!(
            !serde_json::to_string(exec)
                .unwrap()
                .contains("super-secret")
        );
    }

    #[test]
    fn sftp_list_schema_exposes_cursor_contract() {
        let capabilities = ssh_capabilities();
        let list = capabilities
            .iter()
            .find(|capability| capability.id == "sftp_list")
            .expect("sftp list capability");

        assert_eq!(
            list.output_schema["properties"]["limit"]["maximum"],
            json!(MAX_LIST_LIMIT)
        );
        assert_eq!(
            list.output_schema["properties"]["next_cursor"]["type"][0],
            "string"
        );
    }

    #[test]
    fn bounded_text_preserves_utf8_boundaries() {
        let bounded = bounded_text("aé日", 3);

        assert_eq!(bounded.value, "aé");
        assert_eq!(bounded.source_bytes, "aé日".len());
        assert!(bounded.truncated);
    }

    #[test]
    fn invalid_cursor_is_validation_error() {
        let page = Pagination {
            limit: 10,
            cursor: Some("not-a-number".into()),
        };
        let error = page_request(Some(&page)).expect_err("invalid cursor");

        assert_eq!(error.category, CapabilityErrorCategory::Validation);
        assert_eq!(error.code, "validation.cursor_invalid");
    }

    #[tokio::test]
    async fn destructive_exec_dry_run_does_not_connect() {
        let mut invocation = invocation("exec", json!({ "command": "rm -rf /tmp/nope" }));
        invocation.controls.dry_run = true;

        let result = invoke_ssh_capability(&config(), invocation)
            .await
            .expect("dry run succeeds");

        assert_eq!(result.status, InvocationStatus::Succeeded);
        assert_eq!(result.output["dry_run"], true);
        assert_eq!(result.output["operation"], "exec");
    }

    #[tokio::test]
    async fn diagnostics_do_not_expose_secret_material() {
        let result = invoke_ssh_capability(&config(), invocation("diagnostics", json!({})))
            .await
            .expect("diagnostics");
        let encoded = serde_json::to_string(&result).expect("serialize result");

        assert_eq!(result.output["auth_method"], "password");
        assert!(!encoded.contains("super-secret"));
    }

    #[tokio::test]
    async fn diagnostics_do_not_expose_public_key_material() {
        let mut config = config();
        config.auth = SshAuthMethod::PublicKey {
            private_key_path: "/home/user/.ssh/id_ed25519".into(),
            passphrase: Some("key-passphrase".into()),
        };

        let result = invoke_ssh_capability(&config, invocation("diagnostics", json!({})))
            .await
            .expect("diagnostics");
        let encoded = serde_json::to_string(&result).expect("serialize result");

        assert_eq!(result.output["auth_method"], "public_key");
        assert!(!encoded.contains("/home/user/.ssh/id_ed25519"));
        assert!(!encoded.contains("key-passphrase"));
    }

    #[tokio::test]
    async fn rejects_wrong_plugin_id() {
        let mut invocation = invocation("exec", json!({ "command": "true" }));
        invocation.plugin_id = "redis".into();

        let error = invoke_ssh_capability(&config(), invocation)
            .await
            .expect_err("plugin mismatch");

        assert_eq!(error.code, "validation.plugin_mismatch");
    }

    fn invocation(capability_id: &str, input: Value) -> CapabilityInvocation {
        CapabilityInvocation {
            id: format!("invoke-{capability_id}"),
            plugin_id: PLUGIN_ID.into(),
            capability_id: capability_id.into(),
            connection: InvocationConnectionTarget::FromProfile {
                profile: ConnectionProfileRef::name("ssh-test"),
                purpose: ConnectionInstancePurpose::CapabilityInvocation,
                reuse: InstanceReusePolicy::Never,
                options: Value::Null,
            },
            input,
            controls: InvocationControls::default(),
            actor: Some(ActorRef {
                id: "test".into(),
                actor_type: ActorType::Agent,
            }),
            requested_at: Utc::now(),
        }
    }

    fn config() -> SshConfig {
        SshConfig::new("192.0.2.1".into(), 22, "user".into(), "super-secret".into())
    }
}
