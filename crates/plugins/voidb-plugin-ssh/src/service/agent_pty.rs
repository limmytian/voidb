//! Agent-owned interactive SSH PTY sessions.
//!
//! The SSH channel and terminal parser remain inside the SSH service layer.
//! Agent-facing code receives bounded byte windows and plain screen snapshots,
//! never the underlying `russh` handle.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::{ChannelMsg, Sig, client};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};

use super::DirectCliHandler;
use voidb_core::{PluginSessionHealth, VoidbError};

const COMMAND_QUEUE_CAPACITY: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistentPtySignal {
    Interrupt,
    Terminate,
    Hangup,
    Quit,
    Kill,
}

impl PersistentPtySignal {
    fn into_russh(self) -> Sig {
        match self {
            Self::Interrupt => Sig::INT,
            Self::Terminate => Sig::TERM,
            Self::Hangup => Sig::HUP,
            Self::Quit => Sig::QUIT,
            Self::Kill => Sig::KILL,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentPtyRead {
    pub data: Vec<u8>,
    pub requested_offset: u64,
    pub start_offset: u64,
    pub next_offset: u64,
    pub retained_start_offset: u64,
    pub end_offset: u64,
    pub gap: bool,
    pub more: bool,
    pub timed_out: bool,
    pub closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentPtySnapshot {
    pub lines: Vec<String>,
    pub cursor_row: u16,
    pub cursor_col: u16,
    pub cols: u16,
    pub rows: u16,
    pub alternate_screen: bool,
    pub application_cursor: bool,
    pub application_keypad: bool,
    pub bracketed_paste: bool,
    pub hide_cursor: bool,
    pub title: String,
    pub retained_start_offset: u64,
    pub end_offset: u64,
    pub exit_code: Option<u32>,
    pub health: PluginSessionHealth,
}

enum PersistentPtyCommand {
    Write {
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Resize {
        cols: u16,
        rows: u16,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Signal {
        signal: PersistentPtySignal,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Close {
        reply: oneshot::Sender<()>,
    },
}

struct PersistentPtyState {
    output: VecDeque<u8>,
    output_capacity: usize,
    retained_start_offset: u64,
    end_offset: u64,
    parser: vt100::Parser,
    cols: u16,
    rows: u16,
    exit_code: Option<u32>,
    health: PluginSessionHealth,
}

impl PersistentPtyState {
    fn new(cols: u16, rows: u16, scrollback_rows: usize, output_capacity: usize) -> Self {
        Self {
            output: VecDeque::with_capacity(output_capacity),
            output_capacity,
            retained_start_offset: 0,
            end_offset: 0,
            parser: vt100::Parser::new(rows, cols, scrollback_rows),
            cols,
            rows,
            exit_code: None,
            health: PluginSessionHealth::Ready,
        }
    }

    fn append(&mut self, data: &[u8]) {
        self.parser.process(data);
        self.end_offset = self.end_offset.saturating_add(data.len() as u64);

        if data.len() >= self.output_capacity {
            self.output.clear();
            self.output
                .extend(data[data.len() - self.output_capacity..].iter().copied());
            self.retained_start_offset =
                self.end_offset.saturating_sub(self.output_capacity as u64);
            return;
        }

        self.output.extend(data.iter().copied());
        let overflow = self.output.len().saturating_sub(self.output_capacity);
        if overflow > 0 {
            self.output.drain(..overflow);
            self.retained_start_offset = self.retained_start_offset.saturating_add(overflow as u64);
        }
    }

    fn read(&self, requested_offset: u64, max_bytes: usize, timed_out: bool) -> PersistentPtyRead {
        let start_offset = requested_offset
            .max(self.retained_start_offset)
            .min(self.end_offset);
        let skip = start_offset.saturating_sub(self.retained_start_offset) as usize;
        let data = self
            .output
            .iter()
            .skip(skip)
            .take(max_bytes)
            .copied()
            .collect::<Vec<_>>();
        let next_offset = start_offset.saturating_add(data.len() as u64);
        PersistentPtyRead {
            data,
            requested_offset,
            start_offset,
            next_offset,
            retained_start_offset: self.retained_start_offset,
            end_offset: self.end_offset,
            gap: requested_offset < self.retained_start_offset,
            more: next_offset < self.end_offset,
            timed_out,
            closed: self.health.is_terminal(),
        }
    }

    fn snapshot(&self) -> PersistentPtySnapshot {
        let screen = self.parser.screen();
        let (cursor_row, cursor_col) = screen.cursor_position();
        PersistentPtySnapshot {
            lines: screen.rows(0, self.cols).collect(),
            cursor_row,
            cursor_col,
            cols: self.cols,
            rows: self.rows,
            alternate_screen: screen.alternate_screen(),
            application_cursor: screen.application_cursor(),
            application_keypad: screen.application_keypad(),
            bracketed_paste: screen.bracketed_paste(),
            hide_cursor: screen.hide_cursor(),
            title: screen.title().to_string(),
            retained_start_offset: self.retained_start_offset,
            end_offset: self.end_offset,
            exit_code: self.exit_code,
            health: self.health,
        }
    }
}

/// A plugin-owned interactive terminal backed by one SSH PTY channel.
pub struct PersistentPtySession {
    commands: mpsc::Sender<PersistentPtyCommand>,
    state: Arc<Mutex<PersistentPtyState>>,
    output_notify: Arc<Notify>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl PersistentPtySession {
    pub(super) async fn open(
        handle: client::Handle<DirectCliHandler>,
        term_type: &str,
        cols: u16,
        rows: u16,
        scrollback_rows: usize,
        output_capacity: usize,
    ) -> Result<Self, VoidbError> {
        let channel = handle.channel_open_session().await.map_err(|error| {
            VoidbError::Plugin(format!("Failed to open interactive SSH channel: {error}"))
        })?;
        channel
            .request_pty(true, term_type, u32::from(cols), u32::from(rows), 0, 0, &[])
            .await
            .map_err(|error| {
                VoidbError::Plugin(format!("Failed to request interactive SSH PTY: {error}"))
            })?;
        channel.request_shell(true).await.map_err(|error| {
            VoidbError::Plugin(format!("Failed to start interactive SSH shell: {error}"))
        })?;

        let state = Arc::new(Mutex::new(PersistentPtyState::new(
            cols,
            rows,
            scrollback_rows,
            output_capacity,
        )));
        let output_notify = Arc::new(Notify::new());
        let (commands, command_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let task_state = Arc::clone(&state);
        let task_notify = Arc::clone(&output_notify);
        let task = tokio::spawn(async move {
            run_pty_task(handle, channel, command_rx, task_state, task_notify).await;
        });

        Ok(Self {
            commands,
            state,
            output_notify,
            task: Mutex::new(Some(task)),
        })
    }

    pub async fn read(
        &self,
        after_offset: u64,
        max_bytes: usize,
        wait: Duration,
    ) -> PersistentPtyRead {
        let started = Instant::now();
        loop {
            let notified = self.output_notify.notified();
            {
                let state = self.state.lock().await;
                if state.end_offset > after_offset || state.health.is_terminal() || wait.is_zero() {
                    return state.read(after_offset, max_bytes, false);
                }
            }

            let remaining = wait.saturating_sub(started.elapsed());
            if remaining.is_zero() || tokio::time::timeout(remaining, notified).await.is_err() {
                return self.state.lock().await.read(after_offset, max_bytes, true);
            }
        }
    }

    pub async fn snapshot(&self) -> PersistentPtySnapshot {
        self.state.lock().await.snapshot()
    }

    pub async fn write(&self, data: Vec<u8>) -> Result<(), VoidbError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(PersistentPtyCommand::Write { data, reply })
            .await
            .map_err(|_| VoidbError::Plugin("Interactive SSH terminal is closed".into()))?;
        response
            .await
            .map_err(|_| VoidbError::Plugin("Interactive SSH terminal is closed".into()))?
            .map_err(VoidbError::Plugin)
    }

    pub async fn resize(&self, cols: u16, rows: u16) -> Result<(), VoidbError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(PersistentPtyCommand::Resize { cols, rows, reply })
            .await
            .map_err(|_| VoidbError::Plugin("Interactive SSH terminal is closed".into()))?;
        response
            .await
            .map_err(|_| VoidbError::Plugin("Interactive SSH terminal is closed".into()))?
            .map_err(VoidbError::Plugin)
    }

    pub async fn signal(&self, signal: PersistentPtySignal) -> Result<(), VoidbError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(PersistentPtyCommand::Signal { signal, reply })
            .await
            .map_err(|_| VoidbError::Plugin("Interactive SSH terminal is closed".into()))?;
        response
            .await
            .map_err(|_| VoidbError::Plugin("Interactive SSH terminal is closed".into()))?
            .map_err(VoidbError::Plugin)
    }

    pub async fn health(&self) -> PluginSessionHealth {
        self.state.lock().await.health
    }

    pub async fn close(&self) {
        let (reply, response) = oneshot::channel();
        if self
            .commands
            .send(PersistentPtyCommand::Close { reply })
            .await
            .is_ok()
        {
            let _ = response.await;
        }
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        }
    }
}

async fn run_pty_task(
    handle: client::Handle<DirectCliHandler>,
    mut channel: russh::Channel<client::Msg>,
    mut commands: mpsc::Receiver<PersistentPtyCommand>,
    state: Arc<Mutex<PersistentPtyState>>,
    output_notify: Arc<Notify>,
) {
    let mut failed = false;
    loop {
        tokio::select! {
            message = channel.wait() => {
                match message {
                    Some(ChannelMsg::Data { data })
                    | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        state.lock().await.append(&data);
                        output_notify.notify_waiters();
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        state.lock().await.exit_code = Some(exit_status);
                    }
                    Some(ChannelMsg::ExitSignal { .. }) => {
                        failed = true;
                        break;
                    }
                    Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
                    _ => {}
                }
            }
            command = commands.recv() => {
                match command {
                    Some(PersistentPtyCommand::Write { data, reply }) => {
                        let result = channel.data(&data[..]).await.map_err(|error| error.to_string());
                        let _ = reply.send(result);
                    }
                    Some(PersistentPtyCommand::Resize { cols, rows, reply }) => {
                        let result = channel
                            .window_change(u32::from(cols), u32::from(rows), 0, 0)
                            .await
                            .map_err(|error| error.to_string());
                        if result.is_ok() {
                            let mut state = state.lock().await;
                            state.cols = cols;
                            state.rows = rows;
                            state.parser.set_size(rows, cols);
                        }
                        let _ = reply.send(result);
                    }
                    Some(PersistentPtyCommand::Signal { signal, reply }) => {
                        let result = channel
                            .signal(signal.into_russh())
                            .await
                            .map_err(|error| error.to_string());
                        let _ = reply.send(result);
                    }
                    Some(PersistentPtyCommand::Close { reply }) => {
                        {
                            let mut state = state.lock().await;
                            state.health = PluginSessionHealth::Closing;
                        }
                        let _ = channel.eof().await;
                        let _ = channel.close().await;
                        let _ = reply.send(());
                        break;
                    }
                    None => break,
                }
            }
        }
    }

    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;
    {
        let mut state = state.lock().await;
        state.health = if failed {
            PluginSessionHealth::Failed
        } else {
            PluginSessionHealth::Closed
        };
    }
    output_notify.notify_waiters();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_reports_gaps_and_monotonic_offsets() {
        let mut state = PersistentPtyState::new(8, 2, 4, 5);
        state.append(b"abc");
        state.append(b"defg");

        let read = state.read(0, 16, false);
        assert_eq!(read.data, b"cdefg");
        assert_eq!(read.retained_start_offset, 2);
        assert_eq!(read.start_offset, 2);
        assert_eq!(read.next_offset, 7);
        assert!(read.gap);
        assert!(!read.more);
    }

    #[test]
    fn snapshot_tracks_screen_modes_and_resize() {
        let mut state = PersistentPtyState::new(12, 3, 4, 64);
        state.append(b"hello\r\nworld");
        state.parser.set_size(4, 20);
        state.cols = 20;
        state.rows = 4;

        let snapshot = state.snapshot();
        assert_eq!(snapshot.cols, 20);
        assert_eq!(snapshot.rows, 4);
        assert!(snapshot.lines.join("\n").contains("hello"));
        assert!(snapshot.lines.join("\n").contains("world"));
        assert_eq!(snapshot.end_offset, 12);
    }
}
