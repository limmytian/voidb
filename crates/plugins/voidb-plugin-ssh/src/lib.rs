//! VoidB SSH Plugin - SSH service, SFTP, and forwarding capability surface.
//! Author: Limmy

mod agent_session;
mod assist_broker;
mod capabilities;
mod cli_plugin;
mod config;
pub mod service;
mod tui;

pub use agent_session::SshAgentSessionFactory;
pub use assist_broker::{
    SSH_AGENT_SESSION_STORE_DIR_ENV, SSH_ASSIST_STORE_DIR_ENV, SshAssistStore,
    ssh_agent_context_store_root,
};
pub use capabilities::{invoke_ssh_capability, ssh_capabilities};
pub use cli_plugin::create_ssh_cli_plugin;
pub use config::{SshAuthMethod, SshConfig, SshOptions, TerminalConfig};

/// Test an SSH connection by connecting and authenticating without opening a shell.
/// Used by ConnectionManager for the "Test Connection" feature.
pub async fn test_connection(
    conn: &voidb_core::connection::ConnectionConfig,
) -> anyhow::Result<String> {
    use anyhow::anyhow;
    use async_trait::async_trait;
    use russh::client;
    use std::sync::Arc;

    let ssh_config: crate::config::SshConfig = conn
        .plugin_config
        .as_ref()
        .ok_or_else(|| anyhow!("Missing plugin_config"))
        .and_then(|v| {
            serde_json::from_value(v.clone()).map_err(|e| anyhow!("Invalid SSH config: {}", e))
        })?;

    // A non-interactive handler: accepts known hosts, rejects unknown ones
    struct TestHandler {
        host: String,
        port: u16,
    }

    #[async_trait]
    impl client::Handler for TestHandler {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            server_public_key: &ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            match russh_keys::check_known_hosts(&self.host, self.port, server_public_key) {
                Ok(true) => Ok(true),
                Ok(false) => {
                    // Unknown host — refuse rather than hang waiting for user input
                    Err(russh::Error::WrongServerSig)
                }
                Err(russh_keys::Error::KeyChanged { .. }) => Err(russh::Error::WrongServerSig),
                Err(_) => Err(russh::Error::WrongServerSig),
            }
        }
    }

    let client_config = client::Config {
        keepalive_interval: None,
        ..Default::default()
    };

    let handler = TestHandler {
        host: ssh_config.host.clone(),
        port: ssh_config.port,
    };
    let addr = (ssh_config.host.as_str(), ssh_config.port);

    let timeout = std::time::Duration::from_secs(ssh_config.options.connect_timeout);
    let mut session = tokio::time::timeout(
        timeout,
        client::connect(Arc::new(client_config), addr, handler),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "Connection timed out after {}s",
            ssh_config.options.connect_timeout
        )
    })??;

    // Authenticate
    match &ssh_config.auth {
        crate::config::SshAuthMethod::Password { password } => {
            let ok = session
                .authenticate_password(&ssh_config.username, password)
                .await?;
            if !ok {
                return Err(anyhow!(
                    "Authentication failed: invalid username or password"
                ));
            }
        }
        crate::config::SshAuthMethod::PublicKey {
            private_key_path,
            passphrase,
        } => {
            let key = russh_keys::load_secret_key(private_key_path, passphrase.as_deref())
                .map_err(|e| anyhow!("Failed to load key '{}': {}", private_key_path, e))?;
            let ok = session
                .authenticate_publickey(&ssh_config.username, Arc::new(key))
                .await?;
            if !ok {
                return Err(anyhow!("Public key authentication failed"));
            }
        }
        crate::config::SshAuthMethod::Agent => {
            #[cfg(unix)]
            {
                let mut agent = russh_keys::agent::client::AgentClient::connect_env()
                    .await
                    .map_err(|e| anyhow!("SSH agent not available: {}", e))?;
                let identities = agent
                    .request_identities()
                    .await
                    .map_err(|e| anyhow!("Agent list failed: {}", e))?;
                if identities.is_empty() {
                    return Err(anyhow!("SSH agent has no keys (run ssh-add first)"));
                }
                let mut ok = false;
                for key in &identities {
                    if let Ok(true) = session
                        .authenticate_publickey_with(&ssh_config.username, key.clone(), &mut agent)
                        .await
                    {
                        ok = true;
                        break;
                    }
                }
                if !ok {
                    return Err(anyhow!("SSH agent authentication failed"));
                }
            }
            #[cfg(not(unix))]
            {
                return Err(anyhow!("SSH agent authentication is not supported on Windows yet"));
            }
        }
    }

    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;

    Ok(format!(
        "{}@{}:{}",
        ssh_config.username, ssh_config.host, ssh_config.port
    ))
}
