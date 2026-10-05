//! SSH plugin configuration structures

use serde::{Deserialize, Serialize};

/// SSH connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    /// SSH server hostname
    pub host: String,
    /// SSH server port
    pub port: u16,
    /// Username for authentication
    pub username: String,
    /// Authentication method
    pub auth: SshAuthMethod,
    /// Terminal configuration
    #[serde(default)]
    pub terminal: TerminalConfig,
    /// Advanced options
    #[serde(default)]
    pub options: SshOptions,
}

/// SSH authentication method
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SshAuthMethod {
    /// Password authentication
    Password { password: String },
    /// Public key authentication
    PublicKey {
        private_key_path: String,
        passphrase: Option<String>,
    },
    /// SSH agent authentication (uses SSH_AUTH_SOCK)
    Agent,
}

/// Terminal emulation settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalConfig {
    /// Terminal type (default: xterm-256color)
    #[serde(default = "default_term_type")]
    pub term_type: String,
    /// Scrollback buffer size in lines
    #[serde(default = "default_scrollback")]
    pub scrollback: usize,
}

impl Default for TerminalConfig {
    fn default() -> Self {
        Self {
            term_type: default_term_type(),
            scrollback: default_scrollback(),
        }
    }
}

/// Advanced SSH options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshOptions {
    /// Keep-alive interval in seconds (0 = disabled)
    #[serde(default = "default_keepalive")]
    pub keep_alive_interval: u64,
    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub connect_timeout: u64,
    /// Maximum auto-reconnect attempts (0 = disabled)
    #[serde(default = "default_max_reconnect")]
    pub max_reconnect_attempts: u32,
    /// Base delay for reconnect backoff in seconds
    #[serde(default = "default_reconnect_delay")]
    pub reconnect_base_delay: u64,
}

impl Default for SshOptions {
    fn default() -> Self {
        Self {
            keep_alive_interval: default_keepalive(),
            connect_timeout: default_timeout(),
            max_reconnect_attempts: default_max_reconnect(),
            reconnect_base_delay: default_reconnect_delay(),
        }
    }
}

impl SshConfig {
    pub fn new(host: String, port: u16, username: String, password: String) -> Self {
        Self {
            host,
            port,
            username,
            auth: SshAuthMethod::Password { password },
            terminal: TerminalConfig::default(),
            options: SshOptions::default(),
        }
    }
}

fn default_term_type() -> String {
    "xterm-256color".to_string()
}

fn default_scrollback() -> usize {
    1000
}

fn default_keepalive() -> u64 {
    30
}

fn default_timeout() -> u64 {
    10
}

fn default_max_reconnect() -> u32 {
    5
}

fn default_reconnect_delay() -> u64 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_password_auth() {
        let json = r#"{
            "host": "example.com",
            "port": 22,
            "username": "root",
            "auth": { "type": "Password", "password": "secret" }
        }"#;
        let config: SshConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.host, "example.com");
        assert_eq!(config.port, 22);
        assert_eq!(config.username, "root");
        assert!(matches!(config.auth, SshAuthMethod::Password { ref password } if password == "secret"));
    }

    #[test]
    fn deserialize_public_key_auth() {
        let json = r#"{
            "host": "server.local",
            "port": 2222,
            "username": "deploy",
            "auth": { "type": "PublicKey", "private_key_path": "/home/deploy/.ssh/id_ed25519", "passphrase": null }
        }"#;
        let config: SshConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.port, 2222);
        assert!(matches!(config.auth, SshAuthMethod::PublicKey { ref private_key_path, ref passphrase }
            if private_key_path == "/home/deploy/.ssh/id_ed25519" && passphrase.is_none()));
    }

    #[test]
    fn deserialize_agent_auth() {
        let json = r#"{
            "host": "bastion",
            "port": 22,
            "username": "ops",
            "auth": { "type": "Agent" }
        }"#;
        let config: SshConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(config.auth, SshAuthMethod::Agent));
    }

    #[test]
    fn defaults_applied() {
        let json = r#"{
            "host": "localhost",
            "port": 22,
            "username": "test",
            "auth": { "type": "Agent" }
        }"#;
        let config: SshConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.terminal.term_type, "xterm-256color");
        assert_eq!(config.terminal.scrollback, 1000);
        assert_eq!(config.options.keep_alive_interval, 30);
        assert_eq!(config.options.connect_timeout, 10);
        assert_eq!(config.options.max_reconnect_attempts, 5);
        assert_eq!(config.options.reconnect_base_delay, 1);
    }

    #[test]
    fn custom_options_override_defaults() {
        let json = r#"{
            "host": "localhost",
            "port": 22,
            "username": "test",
            "auth": { "type": "Agent" },
            "terminal": { "term_type": "vt100", "scrollback": 5000 },
            "options": { "keep_alive_interval": 60, "connect_timeout": 30, "max_reconnect_attempts": 10, "reconnect_base_delay": 2 }
        }"#;
        let config: SshConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.terminal.term_type, "vt100");
        assert_eq!(config.terminal.scrollback, 5000);
        assert_eq!(config.options.keep_alive_interval, 60);
        assert_eq!(config.options.connect_timeout, 30);
        assert_eq!(config.options.max_reconnect_attempts, 10);
        assert_eq!(config.options.reconnect_base_delay, 2);
    }

    #[test]
    fn new_creates_password_config() {
        let config = SshConfig::new("host".into(), 22, "user".into(), "pass".into());
        assert_eq!(config.host, "host");
        assert!(matches!(config.auth, SshAuthMethod::Password { ref password } if password == "pass"));
    }

    #[test]
    fn roundtrip_serialization() {
        let config = SshConfig::new("test.host".into(), 2222, "admin".into(), "pw".into());
        let json = serde_json::to_string(&config).unwrap();
        let restored: SshConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.host, "test.host");
        assert_eq!(restored.port, 2222);
    }
}
