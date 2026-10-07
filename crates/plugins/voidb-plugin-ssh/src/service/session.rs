//! SSH session background task.
//!
//! Manages the russh client connection, PTY shell, and bridges I/O between
//! the service background task and the remote host. All russh protocol
//! details are contained here.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use russh::client;
use russh::client::Msg;
use russh::{Channel, ChannelMsg};
use russh_sftp::client::SftpSession;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::config::{SshAuthMethod, SshConfig};

/// Events produced by the SSH session background task (internal to service)
pub(super) enum SshSessionEvent {
    /// Connection established successfully
    Connected,
    /// Data received from remote PTY
    Data(Vec<u8>),
    /// Connection error
    Error(String),
    /// Remote side sent EOF
    Eof,
    /// Session disconnected
    Disconnected,
    /// Host key verification needed -- caller must respond via the oneshot
    HostKeyVerify {
        host: String,
        port: u16,
        fingerprint: String,
        /// `true` if key exists in known_hosts but does NOT match (danger)
        key_changed: bool,
        reply: oneshot::Sender<bool>,
    },
}

/// Commands sent to the SSH session from the service background task
pub(super) enum SshInput {
    /// Raw data to send to the remote PTY
    Data(Vec<u8>),
    /// Terminal was resized (cols, rows)
    Resize(u16, u16),
    /// Open an SFTP subsystem channel; result sent back via oneshot
    OpenSftp(oneshot::Sender<Result<SftpSession, String>>),
    /// Open a direct-tcpip channel for local port forwarding
    OpenDirectTcpip {
        host: String,
        port: u32,
        originator_addr: String,
        originator_port: u32,
        reply: oneshot::Sender<Result<Channel<Msg>, String>>,
    },
    /// Request remote port forwarding (tcpip-forward)
    TcpipForward {
        address: String,
        port: u32,
        reply: oneshot::Sender<Result<u32, String>>,
    },
    /// Cancel remote port forwarding
    CancelTcpipForward {
        address: String,
        port: u32,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Execute a command on a separate channel (non-PTY) and return stdout
    Exec {
        command: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
}

/// Client handler for russh -- verifies server keys against known_hosts
struct SshClientHandler {
    host: String,
    port: u16,
    /// Channel to ask the UI for verification decisions
    verify_tx: mpsc::UnboundedSender<SshSessionEvent>,
    /// Channel to forward incoming remote-forwarded connections
    forwarded_tx: mpsc::UnboundedSender<ForwardedChannel>,
}

/// An incoming forwarded TCP/IP channel from the server (for -R forwarding)
#[allow(dead_code)]
pub(super) struct ForwardedChannel {
    pub channel: Channel<Msg>,
    pub connected_address: String,
    pub connected_port: u32,
    pub originator_address: String,
    pub originator_port: u32,
}

#[async_trait]
impl client::Handler for SshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Check known_hosts
        match russh_keys::check_known_hosts(&self.host, self.port, server_public_key) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(russh_keys::Error::KeyChanged { line }) => {
                warn!(
                    "Host key changed for {}:{} (known_hosts line {})",
                    self.host, self.port, line
                );
                let fingerprint = format_fingerprint(server_public_key);
                let (reply_tx, reply_rx) = oneshot::channel();
                if self
                    .verify_tx
                    .send(SshSessionEvent::HostKeyVerify {
                        host: self.host.clone(),
                        port: self.port,
                        fingerprint,
                        key_changed: true,
                        reply: reply_tx,
                    })
                    .is_err()
                {
                    warn!("Host key verify event dropped: UI receiver gone");
                    return Ok(false);
                }
                return match reply_rx.await {
                    Ok(accepted) => {
                        if accepted {
                            let _ = russh_keys::known_hosts::learn_known_hosts(
                                &self.host,
                                self.port,
                                server_public_key,
                            );
                        }
                        Ok(accepted)
                    }
                    Err(_) => Ok(false),
                };
            }
            Err(_) => {}
        }

        // Unknown host -- ask user
        let fingerprint = format_fingerprint(server_public_key);
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .verify_tx
            .send(SshSessionEvent::HostKeyVerify {
                host: self.host.clone(),
                port: self.port,
                fingerprint,
                key_changed: false,
                reply: reply_tx,
            })
            .is_err()
        {
            warn!("Host key verify event dropped: UI receiver gone");
            return Ok(false);
        }

        match reply_rx.await {
            Ok(accepted) => {
                if accepted {
                    let _ = russh_keys::known_hosts::learn_known_hosts(
                        &self.host,
                        self.port,
                        server_public_key,
                    );
                }
                Ok(accepted)
            }
            Err(_) => Ok(false),
        }
    }

    /// Called when the server opens a forwarded-tcpip channel (for -R forwarding)
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let _ = self.forwarded_tx.send(ForwardedChannel {
            channel,
            connected_address: connected_address.to_string(),
            connected_port,
            originator_address: originator_address.to_string(),
            originator_port,
        });
        Ok(())
    }
}

/// Format a public key fingerprint for display (SHA-256)
fn format_fingerprint(key: &ssh_key::PublicKey) -> String {
    let fp = key.fingerprint(ssh_key::HashAlg::Sha256);
    format!("{} {}", key.algorithm(), fp)
}

/// Manages an SSH session with background I/O
pub(super) struct SshSession;

impl SshSession {
    /// Spawn a background task that connects, authenticates, opens a PTY shell,
    /// and bridges data between `input_rx` and `event_tx`.
    ///
    /// Returns a receiver for incoming remote-forwarded channels and the task handle.
    pub fn spawn(
        config: SshConfig,
        cols: u16,
        rows: u16,
        event_tx: mpsc::UnboundedSender<SshSessionEvent>,
        mut input_rx: mpsc::UnboundedReceiver<SshInput>,
    ) -> (
        mpsc::UnboundedReceiver<ForwardedChannel>,
        tokio::task::JoinHandle<()>,
    ) {
        let (forwarded_tx, forwarded_rx) = mpsc::unbounded_channel();
        let handle = tokio::spawn(async move {
            if let Err(e) =
                Self::run(config, cols, rows, &event_tx, &mut input_rx, forwarded_tx).await
                && event_tx
                    .send(SshSessionEvent::Error(e.to_string()))
                    .is_err()
            {
                warn!("SSH error event dropped: UI receiver gone: {}", e);
            }
            let _ = event_tx.send(SshSessionEvent::Disconnected);
        });
        (forwarded_rx, handle)
    }

    async fn run(
        config: SshConfig,
        cols: u16,
        rows: u16,
        event_tx: &mpsc::UnboundedSender<SshSessionEvent>,
        input_rx: &mut mpsc::UnboundedReceiver<SshInput>,
        forwarded_tx: mpsc::UnboundedSender<ForwardedChannel>,
    ) -> Result<()> {
        let client_config = client::Config {
            keepalive_interval: if config.options.keep_alive_interval > 0 {
                Some(std::time::Duration::from_secs(
                    config.options.keep_alive_interval,
                ))
            } else {
                None
            },
            ..Default::default()
        };

        let handler = SshClientHandler {
            host: config.host.clone(),
            port: config.port,
            verify_tx: event_tx.clone(),
            forwarded_tx,
        };
        let addr = (config.host.as_str(), config.port);

        let timeout = std::time::Duration::from_secs(config.options.connect_timeout);
        let mut session = tokio::time::timeout(
            timeout,
            client::connect(Arc::new(client_config), addr, handler),
        )
        .await
        .map_err(|_| anyhow!("Connection timed out"))??;

        Self::authenticate(&mut session, &config).await?;

        if event_tx.send(SshSessionEvent::Connected).is_err() {
            warn!("Connected event dropped: UI receiver gone");
        }

        let mut channel = session.channel_open_session().await?;

        channel
            .request_pty(
                false,
                &config.terminal.term_type,
                cols as u32,
                rows as u32,
                0,
                0,
                &[],
            )
            .await?;

        channel.request_shell(false).await?;

        // Bridge I/O between channel and plugin
        loop {
            tokio::select! {
                msg = channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) => {
                            let _ = event_tx.send(SshSessionEvent::Data(data.to_vec()));
                        }
                        Some(ChannelMsg::ExitStatus { .. }) => break,
                        Some(ChannelMsg::Eof) => {
                            let _ = event_tx.send(SshSessionEvent::Eof);
                            break;
                        }
                        None => break,
                        _ => {}
                    }
                }
                input = input_rx.recv() => {
                    match input {
                        Some(SshInput::Data(data)) => {
                            channel.data(&data[..]).await?;
                        }
                        Some(SshInput::Resize(cols, rows)) => {
                            channel.window_change(cols as u32, rows as u32, 0, 0).await?;
                        }
                        Some(SshInput::OpenSftp(reply)) => {
                            let result = Self::open_sftp_channel(&mut session).await;
                            let _ = reply.send(result.map_err(|e| e.to_string()));
                        }
                        Some(SshInput::OpenDirectTcpip { host, port, originator_addr, originator_port, reply }) => {
                            let result = session
                                .channel_open_direct_tcpip(&host, port, &originator_addr, originator_port)
                                .await;
                            let _ = reply.send(result.map_err(|e| e.to_string()));
                        }
                        Some(SshInput::TcpipForward { address, port, reply }) => {
                            let result = session.tcpip_forward(&address, port).await;
                            let _ = reply.send(result.map_err(|e| e.to_string()));
                        }
                        Some(SshInput::CancelTcpipForward { address, port, reply }) => {
                            let result = session.cancel_tcpip_forward(&address, port).await;
                            let _ = reply.send(result.map_err(|e| e.to_string()));
                        }
                        Some(SshInput::Exec { command, reply }) => {
                            let result = Self::exec_command(&mut session, &command).await;
                            let _ = reply.send(result.map_err(|e| e.to_string()));
                        }
                        None => break,
                    }
                }
            }
        }

        session
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await?;

        Ok(())
    }

    /// Authenticate using the configured method
    async fn authenticate(
        session: &mut client::Handle<SshClientHandler>,
        config: &SshConfig,
    ) -> Result<()> {
        match &config.auth {
            SshAuthMethod::Password { password } => {
                let authenticated = session
                    .authenticate_password(&config.username, password)
                    .await?;
                if !authenticated {
                    return Err(anyhow!("Authentication failed: invalid username or password"));
                }
            }
            SshAuthMethod::PublicKey {
                private_key_path,
                passphrase,
            } => {
                let key = russh_keys::load_secret_key(private_key_path, passphrase.as_deref())
                    .map_err(|e| {
                        anyhow!("Failed to load private key '{}': {}", private_key_path, e)
                    })?;

                let authenticated = session
                    .authenticate_publickey(&config.username, Arc::new(key))
                    .await?;
                if !authenticated {
                    return Err(anyhow!("Public key authentication failed"));
                }
            }
            SshAuthMethod::Agent => {
                #[cfg(unix)]
                {
                    let mut agent = russh_keys::agent::client::AgentClient::connect_env()
                        .await
                        .map_err(|e| anyhow!("Failed to connect to SSH agent: {}", e))?;

                    let identities = agent
                        .request_identities()
                        .await
                        .map_err(|e| anyhow!("Failed to list agent identities: {}", e))?;

                    if identities.is_empty() {
                        return Err(anyhow!(
                            "SSH agent has no identities. Add a key with ssh-add first."
                        ));
                    }

                    let mut authenticated = false;
                    for key in &identities {
                        match session
                            .authenticate_publickey_with(&config.username, key.clone(), &mut agent)
                            .await
                        {
                            Ok(true) => {
                                authenticated = true;
                                break;
                            }
                            Ok(false) => continue,
                            Err(_) => continue,
                        }
                    }

                    if !authenticated {
                        return Err(anyhow!(
                            "SSH agent authentication failed: none of the {} keys were accepted",
                            identities.len()
                        ));
                    }
                }
                #[cfg(not(unix))]
                {
                    return Err(anyhow!("SSH agent authentication is not supported on Windows yet"));
                }
            }
        }

        Ok(())
    }

    /// Execute a command on a separate channel (non-PTY) and collect stdout
    async fn exec_command(
        session: &mut client::Handle<SshClientHandler>,
        command: &str,
    ) -> Result<String> {
        let mut channel = session.channel_open_session().await?;
        channel.exec(true, command.as_bytes()).await?;

        let mut stdout = Vec::new();
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    stdout.extend_from_slice(&data);
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::ExitStatus { .. }) => {}
                Some(ChannelMsg::Close) | None => break,
                _ => {}
            }
        }

        Ok(String::from_utf8_lossy(&stdout).into_owned())
    }

    /// Open a new SFTP subsystem channel on the existing SSH connection
    async fn open_sftp_channel(
        session: &mut client::Handle<SshClientHandler>,
    ) -> Result<SftpSession> {
        let sftp_channel = session.channel_open_session().await?;
        sftp_channel.request_subsystem(true, "sftp").await?;
        let stream = sftp_channel.into_stream();
        let sftp = SftpSession::new(stream)
            .await
            .map_err(|e| anyhow!("SFTP init failed: {}", e))?;
        Ok(sftp)
    }
}
