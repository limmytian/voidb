//! Shared JSON output helpers for built-in CLI commands.
//!
//! Every built-in command group prints the same pretty-printed JSON
//! envelope shape on stdout, so the serializer and its error mapping live
//! here instead of being copied per module.

use serde::Serialize;
use voidb_core::VoidbError;

/// Serialize `value` as pretty-printed JSON on stdout.
pub(crate) fn print_json(value: &impl Serialize) -> Result<(), VoidbError> {
    let output = serde_json::to_string_pretty(value)
        .map_err(|e| VoidbError::Plugin(format!("Failed to serialize JSON output: {}", e)))?;
    println!("{output}");
    Ok(())
}
