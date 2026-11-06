//! MCP (Model Context Protocol) wire types for `vb mcp serve`.
//!
//! The server speaks the MCP stdio transport pinned by the gateway ADR:
//! newline-delimited JSON-RPC 2.0 on stdin/stdout, one frame per line, no
//! embedded newlines, and nothing except protocol frames on stdout. Logging
//! stays on stderr.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The MCP spec revision this server implements (last revision with the
/// `initialize` lifecycle handshake).
pub(crate) const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// Revisions this server can negotiate.
pub(crate) const SUPPORTED_PROTOCOL_VERSIONS: [&str; 1] = [MCP_PROTOCOL_VERSION];

/// Maximum inbound frame size. A larger line is rejected as a parse error
/// instead of buffering without bound.
pub(crate) const MAX_FRAME_BYTES: usize = 1024 * 1024;

pub(crate) const PARSE_ERROR: i64 = -32700;
pub(crate) const INVALID_REQUEST: i64 = -32600;
pub(crate) const METHOD_NOT_FOUND: i64 = -32601;
pub(crate) const INVALID_PARAMS: i64 = -32602;
pub(crate) const INTERNAL_ERROR: i64 = -32603;
pub(crate) const RESOURCE_NOT_FOUND: i64 = -32002;

#[derive(Debug, Deserialize)]
pub(crate) struct JsonRpcFrame {
    pub(crate) jsonrpc: Option<String>,
    pub(crate) id: Option<Value>,
    pub(crate) method: String,
    #[serde(default)]
    pub(crate) params: Value,
}

impl JsonRpcFrame {
    /// Notifications carry no id and get no response.
    pub(crate) fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonRpcSuccess {
    pub(crate) jsonrpc: &'static str,
    pub(crate) id: Value,
    pub(crate) result: Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonRpcErrorBody {
    pub(crate) code: i64,
    pub(crate) message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<Value>,
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonRpcFailure {
    pub(crate) jsonrpc: &'static str,
    pub(crate) id: Value,
    pub(crate) error: JsonRpcErrorBody,
}

pub(crate) fn success(id: &Value, result: Value) -> String {
    serde_json::to_string(&JsonRpcSuccess {
        jsonrpc: "2.0",
        id: id.clone(),
        result,
    })
    .unwrap_or_else(|_| internal_error(id, "serialize MCP response"))
}

pub(crate) fn failure(id: &Value, code: i64, message: impl Into<String>) -> String {
    failure_with_data(id, code, message, None)
}

pub(crate) fn failure_with_data(
    id: &Value,
    code: i64,
    message: impl Into<String>,
    data: Option<Value>,
) -> String {
    serde_json::to_string(&JsonRpcFailure {
        jsonrpc: "2.0",
        id: id.clone(),
        error: JsonRpcErrorBody {
            code,
            message: message.into(),
            data,
        },
    })
    .unwrap_or_else(|_| internal_error(id, "serialize MCP error response"))
}

fn internal_error(id: &Value, message: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":{INTERNAL_ERROR},\"message\":\"{message}\"}}}}",
        id
    )
}
