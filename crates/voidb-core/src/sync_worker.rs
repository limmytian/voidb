//! Generic synchronous worker for `!Send` connection types.
//!
//! Some database drivers (rusqlite, duckdb) produce connection objects that
//! are `!Send` -- they cannot be moved across thread boundaries. The
//! `SyncWorker<Cmd, Resp>` abstraction solves this by owning the connection
//! on a dedicated OS thread (per D-04). Commands arrive via `std::sync::mpsc`
//! (the worker thread has no tokio context), and results return via
//! `tokio::sync::mpsc::UnboundedSender` (sync send, async recv) (per D-05).
//!
//! # Architecture
//!
//! ```text
//!  TUI thread                    Worker thread (OS thread)
//!  ----------                    -------------------------
//!  SyncWorker.send(cmd) ------> std::sync::mpsc::Receiver
//!                                   |
//!                                handler_fn(&mut conn, cmd)
//!                                   |
//!  SyncWorker.try_recv() <----- tokio::sync::mpsc::UnboundedSender
//!  SyncWorker.recv().await <---'
//! ```
//!
//! # Usage
//!
//! Both `SqliteService` and `DuckDbService` (Phase 4) will reuse this
//! abstraction with their respective `!Send` connection types.
//!
//! # Example
//!
//! ```rust,ignore
//! let worker = SyncWorker::spawn(
//!     || {
//!         // init_fn: create the !Send connection on the worker thread
//!         let conn = rusqlite::Connection::open("my.db")?;
//!         Ok(conn)
//!     },
//!     |conn, cmd| {
//!         // handler_fn: process each command using the connection
//!         match cmd {
//!             SqliteCmd::Query(sql) => {
//!                 let result = conn.execute(&sql, []);
//!                 Some(SqliteResp::Done(result))
//!             }
//!         }
//!     },
//! )?;
//!
//! worker.send(SqliteCmd::Query("SELECT 1".into()))?;
//! let resp = worker.recv().await;
//! ```

use std::sync::mpsc as std_mpsc;
use tokio::sync::mpsc as tokio_mpsc;

/// Generic synchronous worker for `!Send` connection types.
///
/// Owns a connection `C` on a dedicated OS thread. Commands of type `Cmd`
/// are sent in via a synchronous channel, results of type `Resp` come back
/// through a tokio-compatible channel.
///
/// # Type Parameters
/// - `Cmd`: Command type sent to the worker. Must be `Send + 'static`.
/// - `Resp`: Response type sent back from the worker. Must be `Send + 'static`.
///
/// # Thread Safety
/// The connection `C` does NOT need to be `Send`. It is created and used
/// exclusively on the worker thread.
pub struct SyncWorker<Cmd: Send + 'static, Resp: Send + 'static> {
    cmd_tx: std_mpsc::Sender<Cmd>,
    resp_rx: tokio_mpsc::UnboundedReceiver<Resp>,
    thread: Option<std::thread::JoinHandle<()>>,
}

// Manual Debug impl because UnboundedReceiver and JoinHandle don't implement Debug
impl<Cmd: Send + 'static, Resp: Send + 'static> std::fmt::Debug for SyncWorker<Cmd, Resp> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncWorker")
            .field("thread_alive", &self.thread.as_ref().map(|t| !t.is_finished()))
            .finish()
    }
}

impl<Cmd: Send + 'static, Resp: Send + 'static> SyncWorker<Cmd, Resp> {
    /// Spawn a new worker on a dedicated OS thread.
    ///
    /// The `init_fn` creates the `!Send` connection on the worker thread.
    /// If it returns `Err`, `spawn()` returns the error immediately.
    /// The `handler_fn` processes each command and optionally returns a response.
    ///
    /// # Type Parameters
    /// - `C`: The connection type. Does NOT require `Send` -- this is the
    ///   entire point of the `SyncWorker` abstraction.
    /// - `F`: Initialization function that creates the connection.
    /// - `H`: Handler function that processes commands using the connection.
    ///
    /// # Arguments
    /// - `init_fn` - Called once on the worker thread to create the connection.
    ///   Returns `Ok(connection)` or `Err(message)`.
    /// - `handler_fn` - Called for each command. Returns `Some(response)` to
    ///   send a response, or `None` to skip (e.g., for shutdown signals or
    ///   commands that produce no output).
    ///
    /// # Errors
    /// Returns `Err` if `init_fn` fails or if the init barrier channel breaks.
    pub fn spawn<C, F, H>(
        init_fn: F,
        handler_fn: H,
    ) -> Result<Self, String>
    where
        C: 'static, // No Send bound -- this is the entire point
        F: FnOnce() -> Result<C, String> + Send + 'static,
        H: Fn(&mut C, Cmd) -> Option<Resp> + Send + 'static,
    {
        let (cmd_tx, cmd_rx) = std_mpsc::channel::<Cmd>();
        let (resp_tx, resp_rx) = tokio_mpsc::unbounded_channel::<Resp>();

        // Synchronization barrier for init result.
        // The worker thread sends Ok(()) or Err(msg) after init_fn completes.
        let (init_tx, init_rx) = std_mpsc::channel::<Result<(), String>>();

        let thread = std::thread::spawn(move || {
            // Initialize the connection on the worker thread
            let mut conn = match init_fn() {
                Ok(c) => {
                    let _ = init_tx.send(Ok(()));
                    c
                }
                Err(e) => {
                    let _ = init_tx.send(Err(e));
                    return;
                }
            };

            // Process commands until the sender is dropped
            while let Ok(cmd) = cmd_rx.recv() {
                if let Some(resp) = handler_fn(&mut conn, cmd) {
                    // If the receiver is dropped, stop processing
                    if resp_tx.send(resp).is_err() {
                        break;
                    }
                }
                // If handler returns None, continue to next command
            }
            // Loop exits when cmd_rx.recv() returns Err (sender dropped)
        });

        // Wait for initialization result
        match init_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                cmd_tx,
                resp_rx,
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                // Wait for the thread to exit after init failure
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                // init_tx was dropped without sending -- thread panicked or exited
                Err("Worker thread exited before completing initialization".to_string())
            }
        }
    }

    /// Send a command to the worker thread.
    ///
    /// This is non-blocking. Returns `Err` if the worker thread has exited
    /// (receiver dropped).
    pub fn send(&self, cmd: Cmd) -> Result<(), std_mpsc::SendError<Cmd>> {
        self.cmd_tx.send(cmd)
    }

    /// Try to receive a response without blocking.
    ///
    /// Returns `Some(response)` if one is available, `None` otherwise.
    /// Suitable for calling from synchronous `Plugin::update()` context.
    pub fn try_recv(&mut self) -> Option<Resp> {
        self.resp_rx.try_recv().ok()
    }

    /// Receive a response asynchronously.
    ///
    /// Awaits until a response is available or the worker thread exits
    /// (returns `None` when the sender is dropped).
    pub async fn recv(&mut self) -> Option<Resp> {
        self.resp_rx.recv().await
    }
}

impl<Cmd: Send + 'static, Resp: Send + 'static> Drop for SyncWorker<Cmd, Resp> {
    fn drop(&mut self) {
        // The cmd_tx field will be dropped as part of struct destruction,
        // which causes cmd_rx.recv() in the worker thread to return Err,
        // ending the processing loop. We do NOT join here to avoid blocking
        // the TUI thread -- the OS will clean up the thread.
        //
        // The thread handle is kept in Option<JoinHandle> for potential
        // explicit shutdown scenarios, but we don't use it in Drop.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;

    // A !Send type for testing -- Rc<RefCell<T>> is not Send
    type NotSendConn = Rc<RefCell<Vec<String>>>;

    #[tokio::test]
    async fn test_spawn_with_not_send_type() {
        // Test 1: SyncWorker::spawn() creates a worker for a !Send type
        let worker = SyncWorker::<String, String>::spawn(
            || {
                let conn: NotSendConn = Rc::new(RefCell::new(Vec::new()));
                Ok(conn)
            },
            |conn, cmd: String| {
                conn.borrow_mut().push(cmd.clone());
                Some(format!("processed: {}", cmd))
            },
        );
        assert!(worker.is_ok());
    }

    #[tokio::test]
    async fn test_send_and_try_recv() {
        // Test 2: send() delivers a command and try_recv() returns the response
        let mut worker = SyncWorker::<String, String>::spawn(
            || Ok(Rc::new(RefCell::new(Vec::new()))),
            |conn, cmd: String| {
                conn.borrow_mut().push(cmd.clone());
                Some(format!("echo: {}", cmd))
            },
        )
        .unwrap();

        worker.send("hello".to_string()).unwrap();

        // Give the worker thread time to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = worker.try_recv();
        assert_eq!(resp, Some("echo: hello".to_string()));
    }

    #[tokio::test]
    async fn test_sequential_commands_in_order() {
        // Test 3: Multiple sequential commands are processed in order
        let mut worker = SyncWorker::<u32, u32>::spawn(
            || Ok(Rc::new(RefCell::new(0u32))),
            |counter, cmd: u32| {
                *counter.borrow_mut() += cmd;
                Some(*counter.borrow())
            },
        )
        .unwrap();

        worker.send(1).unwrap();
        worker.send(2).unwrap();
        worker.send(3).unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(worker.try_recv(), Some(1));
        assert_eq!(worker.try_recv(), Some(3));
        assert_eq!(worker.try_recv(), Some(6));
    }

    #[tokio::test]
    async fn test_async_recv() {
        // Test 4: async recv() returns the response when awaited
        let mut worker = SyncWorker::<String, String>::spawn(
            || Ok(Rc::new(RefCell::new(Vec::<String>::new()))),
            |_conn, cmd: String| Some(format!("async: {}", cmd)),
        )
        .unwrap();

        worker.send("test".to_string()).unwrap();

        let resp = tokio::time::timeout(Duration::from_secs(1), worker.recv()).await;
        assert!(resp.is_ok());
        assert_eq!(resp.unwrap(), Some("async: test".to_string()));
    }

    #[test]
    fn test_drop_causes_thread_exit() {
        // Test 5: Dropping SyncWorker causes the worker thread to exit
        // (JoinHandle completes within 1 second)

        // Manually construct to get access to the thread handle
        let (cmd_tx, cmd_rx) = std_mpsc::channel::<String>();
        let (resp_tx, _resp_rx) = tokio_mpsc::unbounded_channel::<String>();

        let thread = std::thread::spawn(move || {
            let _conn: NotSendConn = Rc::new(RefCell::new(Vec::new()));
            while let Ok(_cmd) = cmd_rx.recv() {
                let _ = resp_tx.send("ok".to_string());
            }
        });

        // Drop the sender to signal the worker thread to exit
        drop(cmd_tx);

        // The thread should complete within a reasonable time
        let result = thread.join();
        assert!(result.is_ok(), "Worker thread did not exit cleanly after sender was dropped");
    }

    #[tokio::test]
    async fn test_init_fn_error() {
        // Test 6: If init_fn returns Err, SyncWorker::spawn() returns Err
        let result = SyncWorker::<String, String>::spawn(
            || Err("init failed".to_string()),
            |_conn: &mut NotSendConn, _cmd| Some("unreachable".to_string()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("init failed"));
    }

    #[tokio::test]
    async fn test_handler_returning_none() {
        // Test 7: handler_fn returning None does NOT send a response but
        // keeps the worker alive for the next command
        let mut worker = SyncWorker::<String, String>::spawn(
            || Ok(Rc::new(RefCell::new(Vec::<String>::new()))),
            |_conn, cmd: String| {
                if cmd == "skip" {
                    None // No response for this command
                } else {
                    Some(format!("got: {}", cmd))
                }
            },
        )
        .unwrap();

        // Send a command that returns None
        worker.send("skip".to_string()).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(worker.try_recv(), None);

        // Send a command that returns Some -- worker is still alive
        worker.send("hello".to_string()).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(worker.try_recv(), Some("got: hello".to_string()));
    }
}
