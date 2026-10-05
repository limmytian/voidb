//! Events sent from VoidB to plugins
//!
//! Events represent user input and system events that are dispatched
//! from the VoidB shell to active plugins.

use crossterm::event::{KeyEvent, MouseEvent};

/// Events sent from VoidB shell to plugins
///
/// Plugins receive events through the `Plugin::update()` method.
/// Plugins can choose to handle or ignore events based on their current state.
#[derive(Debug, Clone)]
pub enum Event {
    /// Keyboard event
    ///
    /// Contains key code and modifiers (Ctrl, Shift, Alt, etc.)
    Key(KeyEvent),

    /// Mouse event
    ///
    /// Contains mouse button, position, and event type (click, drag, etc.)
    Mouse(MouseEvent),

    /// Plugin gained focus
    ///
    /// Sent when the tab containing this plugin becomes active
    FocusGained,

    /// Plugin lost focus
    ///
    /// Sent when the user switches to a different tab
    FocusLost,

    /// Periodic tick event
    ///
    /// Sent at regular intervals (typically every 100ms) to allow
    /// plugins to perform animations, polling, or other periodic tasks
    Tick,

    /// Paste event (bracketed paste)
    ///
    /// Contains the full pasted text as a single string, allowing
    /// plugins to handle it as a batch instead of character-by-character.
    Paste(String),

    /// Plugin's rendering area was resized
    ///
    /// Sent when the terminal is resized or the plugin's allocated
    /// area changes due to sidebar/statusbar visibility changes
    Resize {
        /// New width in terminal cells
        width: u16,
        /// New height in terminal cells
        height: u16,
    },
}
