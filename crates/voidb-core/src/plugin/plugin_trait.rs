//! Core Plugin trait for autonomous plugins
//!
//! This module defines the minimal interface for plugins in VoidB v3.0.
//! Plugins are autonomous applications that run within the VoidB shell.

use anyhow::Result;
use ratatui::{layout::Rect, Frame};

use crate::{Event, ShellCapabilities};

/// Plugin trait - autonomous application within VoidB shell
///
/// # Philosophy
///
/// In VoidB v4.0, plugins are **fully autonomous applications** that run within
/// the VoidB shell. The shell is a **pure router** that provides:
/// - Tab management (switching, creation, closing)
/// - Event routing to active plugin
/// - Shared connection registry
///
/// Plugins have **complete autonomy**:
/// - Own UI rendering (full screen control)
/// - Own event handling
/// - Own state management
/// - Own keybindings
/// - Own layout (can include their own sidebar/tree if needed)
///
/// # Communication Protocol
///
/// - **Events (VoidB → Plugin)**: The shell sends events (keyboard, mouse,
///   focus changes, ticks, resize) to the active plugin via `update()`.
///   Key events pass through a two-layer global shortcut filter before reaching
///   the plugin — see [Key Event Routing](#key-event-routing) below.
///
/// - **Capabilities (VoidB → Plugin)**: The shell provides `ShellCapabilities`
///   at initialization, allowing plugins to:
///   - Open new tabs (`caps.tabs.open()`)
///   - Close current tab (`caps.tabs.close_current()`)
///   - Access connection registry (`caps.connections.read()`)
///
/// # Key Event Routing
///
/// The shell uses a two-layer shortcut system:
///
/// 1. **Hard globals** (always intercepted, even when `wants_raw_input() == true`):
///    - `Ctrl+Q` — quit VoidB
///    - `Ctrl+\` — open shell escape menu (Tab Manager)
///
/// 2. **Soft globals** (only intercepted when `wants_raw_input() == false`):
///    - `q` — return to home tab
///    - `Q` — close current tab
///    - `Ctrl+L` — open Tab Manager
///
/// Plugins that need full keyboard control (e.g., terminal emulators) override
/// `wants_raw_input()` to return `true`, which skips the soft global layer.
///
/// # Example
///
/// ```rust,no_run
/// use anyhow::Result;
/// use ratatui::{Frame, layout::Rect};
/// use voidb_core::{Plugin, Event, ShellCapabilities};
///
/// struct MyPlugin {
///     caps: Option<ShellCapabilities>,
/// }
///
/// impl Plugin for MyPlugin {
///     fn id(&self) -> &str {
///         "my-plugin"
///     }
///
///     fn name(&self) -> &str {
///         "My Plugin"
///     }
///
///     fn init(&mut self, caps: ShellCapabilities) -> Result<()> {
///         self.caps = Some(caps);
///         Ok(())
///     }
///
///     fn update(
///         &mut self,
///         frame: &mut Frame,
///         area: Rect,
///         event: Option<Event>,
///     ) -> Result<()> {
///         // Handle events, render UI
///         // Use caps.tabs.open() to open new tabs
///         Ok(())
///     }
/// }
/// ```
pub trait Plugin: Send + Sync {
    /// Unique plugin identifier
    ///
    /// Used for plugin registration and tab routing.
    /// Should be lowercase with hyphens (e.g., "mysql", "ssh-client").
    fn id(&self) -> &str;

    /// Human-readable plugin name
    ///
    /// Displayed in the UI (e.g., "MySQL", "SSH Client").
    fn name(&self) -> &str;

    /// Initialize plugin with shell capabilities
    ///
    /// Called once when the plugin is first instantiated, before any `update()` calls.
    /// Plugins receive `ShellCapabilities` to interact with the shell.
    ///
    /// Use this to:
    /// - Store the capabilities for later use
    /// - Set up connections (using connection info from `caps.connections`)
    /// - Load resources
    /// - Initialize state
    ///
    /// # Arguments
    ///
    /// - `caps`: Shell capabilities (tab management, connection registry)
    ///
    /// Default implementation does nothing (plugins should override this).
    fn init(&mut self, _caps: ShellCapabilities) -> Result<()> {
        Ok(())
    }

    /// Update and render plugin
    ///
    /// This is the **core method** of the plugin lifecycle. It's called:
    /// - When events occur (keyboard, mouse, resize)
    /// - Only when an event happens (no periodic ticks)
    ///
    /// # Arguments
    ///
    /// - `frame`: Rendering frame to draw to
    /// - `area`: Allocated screen rectangle for this plugin (usually full screen minus tab bar)
    /// - `event`: Optional event (None during passive renders)
    ///
    /// # Returns
    ///
    /// `Result<()>` - The plugin handles errors internally or returns them.
    ///
    /// # Plugin Autonomy
    ///
    /// The plugin is **fully autonomous**:
    /// - **Full screen control**: The plugin gets the entire area (minus tab bar)
    /// - **Event handling**: Decides how to handle or ignore events
    /// - **State management**: Manages its own state (mode, cursor, data)
    /// - **UI rendering**: Renders its own UI (can include sidebar, status bar, etc.)
    /// - **Keybindings**: Chooses its own keybindings
    /// - **Actions**: Can open/close tabs via `self.caps.tabs.open/close_current()`
    ///
    /// The shell does **not** dictate:
    /// - Input modes (vim/emacs/custom)
    /// - Rendering style
    /// - Layout (sidebar/no sidebar)
    /// - State management patterns
    /// - Error handling approaches
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// fn update(&mut self, frame: &mut Frame, area: Rect, event: Option<Event>) -> Result<()> {
    ///     // Handle events
    ///     if let Some(Event::Key(key)) = event {
    ///         match key.code {
    ///             KeyCode::Char('q') => {
    ///                 self.caps.as_ref().unwrap().tabs.close_current()?;
    ///             }
    ///             KeyCode::Char('o') => {
    ///                 self.caps.as_ref().unwrap().tabs.open(
    ///                     "New Tab".into(),
    ///                     "plugin-id".into(),
    ///                     json!({}),
    ///                 )?;
    ///             }
    ///             _ => {}
    ///         }
    ///     }
    ///
    ///     // Render UI (full control over area)
    ///     self.render_my_ui(frame, area)?;
    ///     Ok(())
    /// }
    /// ```
    fn update(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        event: Option<Event>,
    ) -> Result<()>;

    /// Whether this plugin currently wants raw keyboard input.
    ///
    /// When `true`, the shell only intercepts **hard global shortcuts** (`Ctrl+Q` to quit,
    /// `Ctrl+\` to open the shell escape menu) and forwards all other key events — including
    /// plain character keys like `q`, `Q`, and modifier combos like `Ctrl+L` — directly to
    /// the plugin.
    ///
    /// When `false` (the default), the shell also intercepts **soft global shortcuts**
    /// (`q` → go home, `Q` → close tab, `Ctrl+L` → tab manager) before the plugin sees them.
    ///
    /// This value is checked on every key event, so plugins can dynamically toggle it based
    /// on internal state (e.g., SSH returns `true` while connected to a terminal, but could
    /// return `false` when showing a local settings dialog).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Terminal-oriented plugin: always wants raw input when connected
    /// fn wants_raw_input(&self) -> bool {
    ///     self.state == ConnectionState::Connected
    ///         && self.view_mode == ViewMode::Terminal
    /// }
    ///
    /// // Database browser: never needs raw input (default)
    /// // fn wants_raw_input(&self) -> bool { false }
    /// ```
    fn wants_raw_input(&self) -> bool {
        false
    }
}
