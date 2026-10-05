//! Stable process-plugin protocol constants shared by discovery, runtime, and SDK helpers.

pub const PROCESS_PLUGIN_MANIFEST_SCHEMA_URI: &str =
    "https://voidb.dev/schemas/plugin-manifest.schema.json";
pub const PROCESS_PLUGIN_PROTOCOL_VERSION: &str = "1.1";
pub const PROCESS_PLUGIN_SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] =
    [PROCESS_PLUGIN_PROTOCOL_VERSION, "1", "1.0"];
pub const PROCESS_PLUGIN_TRANSPORT_STDIO_JSONRPC: &str = "stdio-jsonrpc";
pub const PROCESS_PLUGIN_SUPPORTED_TRANSPORTS: [&str; 1] = [PROCESS_PLUGIN_TRANSPORT_STDIO_JSONRPC];

pub const PROCESS_PLUGIN_DEVELOPMENT_PATH_ENV: &str = "VOIDB_PLUGIN_PATH";
pub const PROCESS_PLUGIN_BUNDLED_ROOT_ENV: &str = "VOIDB_BUNDLED_PLUGIN_ROOT";

pub const PROCESS_PLUGIN_ENV_PLUGIN_ID: &str = "VOIDB_PLUGIN_ID";
pub const PROCESS_PLUGIN_ENV_PLUGIN_DIR: &str = "VOIDB_PLUGIN_DIR";
pub const PROCESS_PLUGIN_ENV_PROTOCOL_VERSION: &str = "VOIDB_PROTOCOL_VERSION";
pub const PROCESS_PLUGIN_ENV_LOG_FORMAT: &str = "VOIDB_LOG_FORMAT";
pub const PROCESS_PLUGIN_LOG_FORMAT_JSON: &str = "json";
pub const PROCESS_PLUGIN_RESERVED_ENV_VARS: [&str; 4] = [
    PROCESS_PLUGIN_ENV_PLUGIN_ID,
    PROCESS_PLUGIN_ENV_PLUGIN_DIR,
    PROCESS_PLUGIN_ENV_PROTOCOL_VERSION,
    PROCESS_PLUGIN_ENV_LOG_FORMAT,
];

pub const PROCESS_PLUGIN_JSONRPC_VERSION: &str = "2.0";
pub const PROCESS_PLUGIN_REQUEST_ID_INITIALIZE: &str = "initialize";
pub const PROCESS_PLUGIN_REQUEST_ID_HEALTH: &str = "health";
pub const PROCESS_PLUGIN_REQUEST_ID_INVOKE: &str = "invoke";

pub const PROCESS_PLUGIN_METHOD_INITIALIZE: &str = "voidb.initialize";
pub const PROCESS_PLUGIN_METHOD_HEALTH: &str = "voidb.health";
pub const PROCESS_PLUGIN_METHOD_INVOKE: &str = "voidb.invoke";
pub const PROCESS_PLUGIN_METHOD_CANCEL: &str = "voidb.cancel";
pub const PROCESS_PLUGIN_METHOD_SESSION_OPEN: &str = "voidb.session.open";
pub const PROCESS_PLUGIN_METHOD_SESSION_CALL: &str = "voidb.session.call";
pub const PROCESS_PLUGIN_METHOD_SESSION_HEALTH: &str = "voidb.session.health";
pub const PROCESS_PLUGIN_METHOD_SESSION_RENEW: &str = "voidb.session.renew";
pub const PROCESS_PLUGIN_METHOD_SESSION_CANCEL: &str = "voidb.session.cancel";
pub const PROCESS_PLUGIN_METHOD_SESSION_CLOSE: &str = "voidb.session.close";
pub const PROCESS_PLUGIN_METHOD_STREAM_ITEM: &str = "voidb.stream.item";
pub const PROCESS_PLUGIN_METHOD_STREAM_PROGRESS: &str = "voidb.stream.progress";
pub const PROCESS_PLUGIN_METHOD_STREAM_END: &str = "voidb.stream.end";

pub fn is_supported_process_plugin_protocol_version(version: &str) -> bool {
    parse_process_plugin_protocol_version(version)
        .is_some_and(|(major, minor)| major == 1 && minor <= 1)
}

pub fn parse_process_plugin_protocol_version(version: &str) -> Option<(u64, u64)> {
    let mut parts = version.split('.');
    let major = parse_protocol_version_part(parts.next()?)?;
    let minor = match parts.next() {
        Some(minor) => parse_protocol_version_part(minor)?,
        None => 0,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor))
}

fn parse_protocol_version_part(value: &str) -> Option<u64> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return None;
    }
    value.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_accepts_only_supported_major_minor() {
        assert!(is_supported_process_plugin_protocol_version("1"));
        assert!(is_supported_process_plugin_protocol_version("1.0"));
        assert!(is_supported_process_plugin_protocol_version("1.1"));
        assert!(!is_supported_process_plugin_protocol_version("01"));
        assert!(!is_supported_process_plugin_protocol_version("1.2"));
        assert!(!is_supported_process_plugin_protocol_version("2"));
        assert!(!is_supported_process_plugin_protocol_version("1.0.0"));
    }

    #[test]
    fn reserved_runtime_environment_is_named_stably() {
        assert_eq!(
            PROCESS_PLUGIN_RESERVED_ENV_VARS,
            [
                "VOIDB_PLUGIN_ID",
                "VOIDB_PLUGIN_DIR",
                "VOIDB_PROTOCOL_VERSION",
                "VOIDB_LOG_FORMAT",
            ]
        );
    }
}
