//! Connection dialog component interface for plugins
//!
//! Plugins can provide their own connection configuration UI by implementing
//! the ConnectionDialogComponent trait. This allows full control over the
//! form layout, field validation, and interaction logic.

use anyhow::Result;
use ratatui::{Frame, layout::Rect};

use crate::{Event, ConnectionConfig};

/// Plugin-provided connection dialog component
///
/// Plugins implement this trait to provide a custom connection configuration
/// dialog. The plugin has full control over rendering, event handling, and
/// validation. The ConnectionManager handles saving/loading the final config.
pub trait ConnectionDialogComponent: Send + Sync {
    /// Render the dialog to the given frame area
    ///
    /// The plugin should render its entire dialog UI within the provided area.
    /// Typically this includes a popup/modal with form fields, help text, etc.
    fn render(&mut self, frame: &mut Frame, area: Rect);

    /// Handle an input event
    ///
    /// Returns a DialogAction indicating what the manager should do:
    /// - Continue: keep dialog open
    /// - Save: close and save the config (calls build_config)
    /// - Cancel: close without saving
    /// - TestConnection: test the connection without closing
    fn handle_event(&mut self, event: Event) -> DialogAction;

    /// Build a ConnectionConfig from the current form state
    ///
    /// Called when the user confirms the dialog (DialogAction::Save).
    /// Returns Err with a user-friendly message if validation fails.
    fn build_config(&self) -> Result<ConnectionConfig, String>;

    /// Set a status message to display in the dialog (e.g. test result)
    fn set_status_message(&mut self, _msg: Option<String>) {}
}

/// Action returned by ConnectionDialogComponent::handle_event
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogAction {
    /// Keep the dialog open, continue editing
    Continue,
    /// Close the dialog and save the configuration
    Save,
    /// Close the dialog without saving
    Cancel,
    /// Test the connection without closing the dialog
    TestConnection,
}
