use thiserror::Error;

#[derive(Debug, Error)]
pub enum VoidbError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Query error: {0}")]
    Query(String),

    #[error("Schema error: {0}")]
    Schema(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Plugin error: {0}")]
    Plugin(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Plugin incompatible: {0}")]
    IncompatiblePlugin(String),

    #[error("Runtime error: {0}")]
    Runtime(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    /// The command already emitted a structured error and requests a stable
    /// process status without printing a second, unstructured message.
    #[error("CLI exit status {code}")]
    CliExit { code: u8 },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}
