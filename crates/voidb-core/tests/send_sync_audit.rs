//! Compile-time Send+Sync audit for service-layer types (ARCH-03).
//!
//! These tests verify that all types involved in the service-layer pattern
//! satisfy the thread-safety bounds required by `Plugin: Send + Sync`.
//!
//! # Background
//!
//! The `Plugin` trait requires `Send + Sync` (see `plugin_trait.rs`). This
//! means any struct implementing Plugin -- and therefore any fields it holds --
//! must compose to be Send + Sync.
//!
//! Service structs (e.g., MySqlService) contain `UnboundedReceiver` which is
//! Send but NOT Sync. To satisfy `Plugin: Send + Sync`, plugin structs must
//! wrap their service in `std::sync::Mutex<Service>`.
//!
//! The same pattern applies to `SyncWorker`: it contains `UnboundedReceiver`
//! and `std::sync::mpsc::Sender`, making it Send but NOT Sync. Plugin structs
//! wrap it in `Mutex<SyncWorker<Cmd, Resp>>`.
//!
//! # Convention for Plugin Structs
//!
//! ```rust,ignore
//! struct MySqlPlugin {
//!     service: std::sync::Mutex<MySqlService>,
//!     // ... other fields
//! }
//! ```
//!
//! `Plugin::update(&mut self, ...)` has `&mut self`, so `Mutex::lock()` in
//! update() is always uncontested (only one caller at a time). The Mutex
//! exists purely to provide `Sync` at the type level.

/// Compile-time assertion that T: Send.
fn assert_send<T: Send>() {}

/// Compile-time assertion that T: Send + Sync.
fn assert_send_sync<T: Send + Sync>() {}

/// Compile-time assertion that T: Clone.
fn assert_clone<T: Clone>() {}

// === Test 1: SyncWorker handle is Send ===

#[test]
fn sync_worker_handle_is_send() {
    // SyncWorker handle must be Send so it can be stored in Plugin structs
    // which are moved into Tab objects on the shell thread.
    assert_send::<voidb_core::sync_worker::SyncWorker<String, String>>();
}

// === Test 2: SyncWorker is NOT Sync (and that is acceptable) ===

#[test]
fn sync_worker_not_sync_is_acceptable() {
    // SyncWorker is NOT Sync because it contains:
    // - std::sync::mpsc::Sender<Cmd> -- Send but NOT Sync
    // - tokio::sync::mpsc::UnboundedReceiver<Resp> -- Send but NOT Sync
    //
    // This is acceptable because SyncWorker is owned by a single service
    // struct, not shared via Arc. The service struct itself achieves Sync
    // through wrapping in std::sync::Mutex.
    assert_send::<voidb_core::sync_worker::SyncWorker<String, String>>();
}

// === Test 3: ShellCapabilities is Clone + Send ===

#[test]
fn shell_capabilities_is_clone_send() {
    // ShellCapabilities is passed to plugins via Plugin::init(caps).
    // It must be Clone (shared across plugins) and Send (passed across threads).
    assert_clone::<voidb_core::ShellCapabilities>();
    assert_send::<voidb_core::ShellCapabilities>();
}

// === Test 4: Mutex-wrapped SyncWorker satisfies Send+Sync ===

#[test]
fn mutex_wrapped_sync_worker_is_send_sync() {
    use std::sync::Mutex;

    // Proves that wrapping SyncWorker in Mutex provides Send + Sync,
    // which is the pattern used by SQLite and DuckDB plugins.
    assert_send_sync::<Mutex<voidb_core::sync_worker::SyncWorker<String, String>>>();
}

// === Test 5: UnboundedSender is Send+Sync ===

#[test]
fn unbounded_sender_is_send_sync() {
    // tokio::sync::mpsc::UnboundedSender::send() does not require .await,
    // making it safe to call from any thread context (including sync Plugin::update()).
    assert_send_sync::<tokio::sync::mpsc::UnboundedSender<String>>();
}
