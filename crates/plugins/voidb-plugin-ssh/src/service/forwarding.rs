//! Port forwarding manager -- coordinates local, remote, and SOCKS5 forwarding.
//!
//! Internal to the service module. The service background task creates a
//! ForwardingManager and spawns it when an SSH session connects. External
//! code interacts via `SshCommand::Forward(...)`.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use russh::client::Msg;
use russh::{Channel, ChannelMsg};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

use super::session::{ForwardedChannel, SshInput};
use super::types::{ForwardRule, ForwardStats, ForwardStatus, ForwardType};

/// Events from the forwarding manager to the service (internal)
pub(super) enum ForwardEvent {
    /// A rule's status changed
    StatusChanged { id: u32, status: ForwardStatus },
}

/// Commands from the service to the forwarding manager (internal)
pub(super) enum ForwardCommand {
    /// Add a new forwarding rule
    Add(ForwardType),
    /// Remove a forwarding rule by ID
    Remove(u32),
}

/// Manages all port forwarding rules
pub(super) struct ForwardingManager {
    rules: Vec<ForwardRule>,
    next_id: u32,
    /// Channel to send SSH commands (shared with session)
    ssh_tx: mpsc::UnboundedSender<SshInput>,
    /// Events back to the service
    event_tx: mpsc::UnboundedSender<ForwardEvent>,
    /// Commands from the service
    cmd_rx: mpsc::UnboundedReceiver<ForwardCommand>,
    /// Incoming remote-forwarded channels from the SSH handler
    forwarded_rx: mpsc::UnboundedReceiver<ForwardedChannel>,
    /// Shutdown senders for each rule's listener task
    shutdown_txs: Vec<(u32, oneshot::Sender<()>)>,
}

impl ForwardingManager {
    pub fn new(
        ssh_tx: mpsc::UnboundedSender<SshInput>,
        event_tx: mpsc::UnboundedSender<ForwardEvent>,
        cmd_rx: mpsc::UnboundedReceiver<ForwardCommand>,
        forwarded_rx: mpsc::UnboundedReceiver<ForwardedChannel>,
    ) -> Self {
        Self {
            rules: Vec::new(),
            next_id: 1,
            ssh_tx,
            event_tx,
            cmd_rx,
            forwarded_rx,
            shutdown_txs: Vec::new(),
        }
    }

    /// Run the forwarding manager as a background task
    pub fn spawn(mut self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(ForwardCommand::Add(ft)) => self.add_rule(ft).await,
                        Some(ForwardCommand::Remove(id)) => self.remove_rule(id).await,
                        None => break, // channel closed
                    }
                }
                fwd = self.forwarded_rx.recv() => {
                    match fwd {
                        Some(fwd_channel) => self.handle_forwarded_channel(fwd_channel).await,
                        None => break,
                    }
                }
            }
        }
    }

    async fn add_rule(&mut self, forward_type: ForwardType) {
        let id = self.next_id;
        self.next_id += 1;

        let stats = Arc::new(ForwardStats::default());
        let rule = ForwardRule {
            id,
            forward_type: forward_type.clone(),
            status: ForwardStatus::Starting,
            stats: stats.clone(),
        };
        self.rules.push(rule);

        match &forward_type {
            ForwardType::Local {
                bind_addr,
                bind_port,
                remote_host,
                remote_port,
            } => {
                self.start_local_forward(
                    id,
                    bind_addr.clone(),
                    *bind_port,
                    remote_host.clone(),
                    *remote_port,
                    stats,
                )
                .await;
            }
            ForwardType::Remote {
                remote_addr,
                remote_port,
                local_host,
                local_port,
            } => {
                self.start_remote_forward(
                    id,
                    remote_addr.clone(),
                    *remote_port,
                    local_host.clone(),
                    *local_port,
                    stats,
                )
                .await;
            }
            ForwardType::Dynamic {
                bind_addr,
                bind_port,
            } => {
                self.start_dynamic_forward(id, bind_addr.clone(), *bind_port, stats)
                    .await;
            }
        }
    }

    async fn remove_rule(&mut self, id: u32) {
        // Send shutdown signal to the listener task
        if let Some(pos) = self.shutdown_txs.iter().position(|(rid, _)| *rid == id) {
            let (_, tx) = self.shutdown_txs.remove(pos);
            let _ = tx.send(());
        }

        // For remote forwarding, cancel the tcpip-forward request
        if let Some(rule) = self.rules.iter().find(|r| r.id == id)
            && let ForwardType::Remote {
                remote_addr,
                remote_port,
                ..
            } = &rule.forward_type
        {
            let (reply_tx, _reply_rx) = oneshot::channel();
            if self
                .ssh_tx
                .send(SshInput::CancelTcpipForward {
                    address: remote_addr.clone(),
                    port: *remote_port as u32,
                    reply: reply_tx,
                })
                .is_err()
            {
                warn!("Cannot cancel remote forward: SSH session closed");
            }
        }

        self.rules.retain(|r| r.id != id);
        let _ = self.event_tx.send(ForwardEvent::StatusChanged {
            id,
            status: ForwardStatus::Stopped,
        });
    }

    async fn start_local_forward(
        &mut self,
        id: u32,
        bind_addr: String,
        bind_port: u16,
        remote_host: String,
        remote_port: u16,
        stats: Arc<ForwardStats>,
    ) {
        let listener = match TcpListener::bind(format!("{}:{}", bind_addr, bind_port)).await {
            Ok(l) => l,
            Err(e) => {
                self.set_rule_status(id, ForwardStatus::Error(e.to_string()));
                return;
            }
        };

        self.set_rule_status(id, ForwardStatus::Active);

        let ssh_tx = self.ssh_tx.clone();
        let event_tx = self.event_tx.clone();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        self.shutdown_txs.push((id, shutdown_tx));

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, peer)) => {
                                if !stats.enabled.load(Ordering::Relaxed) {
                                    continue;
                                }
                                stats.total_connections.fetch_add(1, Ordering::Relaxed);
                                stats.active_connections.fetch_add(1, Ordering::Relaxed);

                                let ssh_tx = ssh_tx.clone();
                                let stats = stats.clone();
                                let rh = remote_host.clone();
                                let rp = remote_port;

                                tokio::spawn(async move {
                                    if let Err(e) = handle_local_connection(
                                        stream, &ssh_tx, &rh, rp,
                                        &peer.to_string(), peer.port(),
                                        &stats,
                                    ).await {
                                        warn!("Local forward connection error: {}", e);
                                    }
                                    stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                                });
                            }
                            Err(e) => {
                                error!("Local forward accept error: {}", e);
                                break;
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        info!("Local forward {} shutting down", id);
                        break;
                    }
                }
            }
            let _ = event_tx.send(ForwardEvent::StatusChanged {
                id,
                status: ForwardStatus::Stopped,
            });
        });
    }

    async fn start_remote_forward(
        &mut self,
        id: u32,
        remote_addr: String,
        remote_port: u16,
        local_host: String,
        local_port: u16,
        _stats: Arc<ForwardStats>,
    ) {
        // Request the SSH server to forward the port
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .ssh_tx
            .send(SshInput::TcpipForward {
                address: remote_addr.clone(),
                port: remote_port as u32,
                reply: reply_tx,
            })
            .is_err()
        {
            warn!("Cannot request remote forward: SSH session closed");
            self.set_rule_status(id, ForwardStatus::Error("SSH session closed".into()));
            return;
        }

        let event_tx = self.event_tx.clone();
        let id_copy = id;

        // Store local target for incoming connections
        // The ForwardedChannel handler will use rule matching to find the target
        tokio::spawn(async move {
            match reply_rx.await {
                Ok(Ok(allocated_port)) => {
                    info!(
                        "Remote forward active: remote {}:{} -> local {}:{}",
                        remote_addr, allocated_port, local_host, local_port
                    );
                    let _ = event_tx.send(ForwardEvent::StatusChanged {
                        id: id_copy,
                        status: ForwardStatus::Active,
                    });
                }
                Ok(Err(e)) => {
                    let _ = event_tx.send(ForwardEvent::StatusChanged {
                        id: id_copy,
                        status: ForwardStatus::Error(e),
                    });
                }
                Err(_) => {
                    let _ = event_tx.send(ForwardEvent::StatusChanged {
                        id: id_copy,
                        status: ForwardStatus::Error("Channel closed".into()),
                    });
                }
            }
        });

        self.set_rule_status(id, ForwardStatus::Starting);
    }

    async fn start_dynamic_forward(
        &mut self,
        id: u32,
        bind_addr: String,
        bind_port: u16,
        stats: Arc<ForwardStats>,
    ) {
        let listener = match TcpListener::bind(format!("{}:{}", bind_addr, bind_port)).await {
            Ok(l) => l,
            Err(e) => {
                self.set_rule_status(id, ForwardStatus::Error(e.to_string()));
                return;
            }
        };

        self.set_rule_status(id, ForwardStatus::Active);

        let ssh_tx = self.ssh_tx.clone();
        let event_tx = self.event_tx.clone();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        self.shutdown_txs.push((id, shutdown_tx));

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, peer)) => {
                                if !stats.enabled.load(Ordering::Relaxed) {
                                    continue;
                                }
                                stats.total_connections.fetch_add(1, Ordering::Relaxed);
                                stats.active_connections.fetch_add(1, Ordering::Relaxed);

                                let ssh_tx = ssh_tx.clone();
                                let stats = stats.clone();

                                tokio::spawn(async move {
                                    if let Err(e) = handle_socks5_connection(
                                        stream, &ssh_tx,
                                        &peer.to_string(), peer.port(),
                                        &stats,
                                    ).await {
                                        warn!("SOCKS5 connection error: {}", e);
                                    }
                                    stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                                });
                            }
                            Err(e) => {
                                error!("SOCKS5 accept error: {}", e);
                                break;
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        info!("Dynamic forward {} shutting down", id);
                        break;
                    }
                }
            }
            let _ = event_tx.send(ForwardEvent::StatusChanged {
                id,
                status: ForwardStatus::Stopped,
            });
        });
    }

    /// Handle an incoming forwarded channel from the server (-R)
    async fn handle_forwarded_channel(&self, fwd: ForwardedChannel) {
        // Find the matching remote forwarding rule
        let target = self.rules.iter().find_map(|rule| {
            if let ForwardType::Remote {
                remote_port,
                local_host,
                local_port,
                ..
            } = &rule.forward_type
                && fwd.connected_port == *remote_port as u32
            {
                return Some((local_host.clone(), *local_port, rule.stats.clone()));
            }
            None
        });

        let (local_host, local_port, stats) = match target {
            Some(t) => t,
            None => {
                warn!(
                    "No rule found for forwarded channel on port {}",
                    fwd.connected_port
                );
                return;
            }
        };

        stats.total_connections.fetch_add(1, Ordering::Relaxed);
        stats.active_connections.fetch_add(1, Ordering::Relaxed);

        tokio::spawn(async move {
            if let Err(e) =
                handle_remote_connection(fwd.channel, &local_host, local_port, &stats).await
            {
                warn!("Remote forward connection error: {}", e);
            }
            stats.active_connections.fetch_sub(1, Ordering::Relaxed);
        });
    }

    fn set_rule_status(&mut self, id: u32, status: ForwardStatus) {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == id) {
            rule.status = status.clone();
        }
        let _ = self.event_tx.send(ForwardEvent::StatusChanged { id, status });
    }
}

/// Handle a single local port forwarding connection
async fn handle_local_connection(
    mut tcp: TcpStream,
    ssh_tx: &mpsc::UnboundedSender<SshInput>,
    remote_host: &str,
    remote_port: u16,
    originator_addr: &str,
    originator_port: u16,
    stats: &ForwardStats,
) -> anyhow::Result<()> {
    // Open a direct-tcpip channel through SSH
    let (reply_tx, reply_rx) = oneshot::channel();
    ssh_tx.send(SshInput::OpenDirectTcpip {
        host: remote_host.to_string(),
        port: remote_port as u32,
        originator_addr: originator_addr.to_string(),
        originator_port: originator_port as u32,
        reply: reply_tx,
    })?;

    let channel: Channel<Msg> = reply_rx
        .await
        .map_err(|_| anyhow::anyhow!("Channel closed"))?
        .map_err(|e| anyhow::anyhow!("Failed to open direct-tcpip channel: {}", e))?;

    bridge_tcp_channel(&mut tcp, channel, stats).await
}

/// Handle an incoming remote-forwarded connection
async fn handle_remote_connection(
    channel: Channel<Msg>,
    local_host: &str,
    local_port: u16,
    stats: &ForwardStats,
) -> anyhow::Result<()> {
    let mut tcp = TcpStream::connect(format!("{}:{}", local_host, local_port)).await?;
    bridge_tcp_channel(&mut tcp, channel, stats).await
}

/// Handle a SOCKS5 connection: handshake, then open direct-tcpip
async fn handle_socks5_connection(
    mut tcp: TcpStream,
    ssh_tx: &mpsc::UnboundedSender<SshInput>,
    originator_addr: &str,
    originator_port: u16,
    stats: &ForwardStats,
) -> anyhow::Result<()> {
    // SOCKS5 greeting
    let mut buf = [0u8; 258];
    let n = tcp.read(&mut buf).await?;
    if n < 2 || buf[0] != 0x05 {
        return Err(anyhow::anyhow!("Invalid SOCKS5 greeting"));
    }

    // Reply: no auth required
    tcp.write_all(&[0x05, 0x00]).await?;

    // SOCKS5 connect request
    let n = tcp.read(&mut buf).await?;
    if n < 4 || buf[0] != 0x05 || buf[1] != 0x01 {
        // Only CONNECT (0x01) supported
        tcp.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(anyhow::anyhow!("Unsupported SOCKS5 command"));
    }

    // Parse target address
    let (target_host, target_port) = match buf[3] {
        0x01 => {
            // IPv4
            if n < 10 {
                return Err(anyhow::anyhow!("SOCKS5 request too short"));
            }
            let host = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (host, port)
        }
        0x03 => {
            // Domain name
            let domain_len = buf[4] as usize;
            if n < 5 + domain_len + 2 {
                return Err(anyhow::anyhow!("SOCKS5 request too short"));
            }
            let host = String::from_utf8_lossy(&buf[5..5 + domain_len]).to_string();
            let port = u16::from_be_bytes([buf[5 + domain_len], buf[5 + domain_len + 1]]);
            (host, port)
        }
        0x04 => {
            // IPv6
            if n < 22 {
                return Err(anyhow::anyhow!("SOCKS5 request too short"));
            }
            let mut segments = [0u16; 8];
            for i in 0..8 {
                segments[i] = u16::from_be_bytes([buf[4 + i * 2], buf[5 + i * 2]]);
            }
            let host = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7]
            );
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            (host, port)
        }
        _ => {
            tcp.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(anyhow::anyhow!("Unsupported SOCKS5 address type"));
        }
    };

    // Open direct-tcpip channel to the target
    let (reply_tx, reply_rx) = oneshot::channel();
    ssh_tx.send(SshInput::OpenDirectTcpip {
        host: target_host,
        port: target_port as u32,
        originator_addr: originator_addr.to_string(),
        originator_port: originator_port as u32,
        reply: reply_tx,
    })?;

    match reply_rx.await {
        Ok(Ok(channel)) => {
            // Success reply
            tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            bridge_tcp_channel(&mut tcp, channel, stats).await
        }
        Ok(Err(e)) => {
            // Connection refused
            tcp.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            Err(anyhow::anyhow!("SOCKS5 connect failed: {}", e))
        }
        Err(_) => {
            tcp.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            Err(anyhow::anyhow!("SOCKS5 channel closed"))
        }
    }
}

/// Bridge a TCP stream with an SSH channel bidirectionally
async fn bridge_tcp_channel(
    tcp: &mut TcpStream,
    mut channel: Channel<Msg>,
    stats: &ForwardStats,
) -> anyhow::Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.split();
    let mut buf = vec![0u8; 32768];

    loop {
        tokio::select! {
            // TCP -> SSH channel
            n = tcp_read.read(&mut buf) => {
                match n {
                    Ok(0) => break, // TCP closed
                    Ok(n) => {
                        channel.data(&buf[..n]).await?;
                        stats.add_sent(n as u64);
                    }
                    Err(e) => return Err(anyhow::Error::from(e)),
                }
            }
            // SSH channel -> TCP
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        tcp_write.write_all(&data).await?;
                        stats.add_received(data.len() as u64);
                    }
                    Some(ChannelMsg::Eof) | None => break,
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
