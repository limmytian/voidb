//! Shared TUI building blocks for VoidB standalone process plugins.
//!
//! The plugin TUI template duplicated these helpers verbatim across every
//! official plugin repository and they drifted occasionally. This crate is
//! the single home for the plugin-agnostic pieces: layout math, bounded
//! status/log buffers, and error summarization. Plugin-specific views and
//! deliberate local divergences stay plugin-owned (see the crate README and
//! `docs/adr-tui-shared-kit.md`).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
/// Collapse a diagnostic message into a single line that is safe to render in
/// a status bar or an overlay, truncating long messages with an ellipsis.
///
/// The 180-character budget keeps one-line summaries readable in the narrow
/// status strip the plugin TUIs share.
pub fn safe_error_summary(message: &str) -> String {
    let mut summary = message.replace('\n', " ");
    if summary.len() > 180 {
        summary.truncate(177);
        summary.push_str("...");
    }
    summary
}

/// First visible row index for a list of `len` items with `visible` rows on
/// screen and `selected` under the cursor, so the selection stays in view.
pub fn window_start(selected: usize, visible: usize, len: usize) -> usize {
    if visible == 0 || len <= visible {
        0
    } else if selected >= visible {
        (selected + 1).saturating_sub(visible)
    } else {
        0
    }
}

/// A centered sub-rectangle covering `percent_x` by `percent_y` of `area`,
/// used by every popup and confirmation overlay in the plugin TUIs.
pub fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// A bounded line buffer for streamed TUI output (logs, exec transcripts,
/// inspect payloads): keeps the most recent lines under both a line-count and
/// a byte budget so a chatty container cannot grow the TUI without bound.
#[derive(Debug, Clone)]
pub struct BoundedLines {
    lines: std::collections::VecDeque<String>,
    bytes: usize,
    dropped_lines: usize,
    max_lines: usize,
    max_bytes: usize,
}

impl BoundedLines {
    pub fn new(max_lines: usize, max_bytes: usize) -> Self {
        Self {
            lines: std::collections::VecDeque::new(),
            bytes: 0,
            dropped_lines: 0,
            max_lines,
            max_bytes,
        }
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Number of lines dropped by the line or byte budget.
    pub fn dropped_lines(&self) -> usize {
        self.dropped_lines
    }

    /// Approximate in-memory size of the retained lines.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn clear(&mut self) {
        self.lines.clear();
        self.bytes = 0;
        self.dropped_lines = 0;
    }

    /// Append every line of a (possibly multi-line) chunk of streamed text.
    pub fn push_text(&mut self, text: &str) {
        for line in text.lines() {
            self.push_line(line.to_string());
        }
        if text.ends_with('\n') && text.lines().next().is_none() {
            self.push_line(String::new());
        }
    }

    pub fn push_line(&mut self, mut line: String) {
        if line.len() > self.max_bytes {
            line.truncate(self.max_bytes);
        }
        self.bytes = self.bytes.saturating_add(line.len());
        self.lines.push_back(line);
        while self.lines.len() > self.max_lines || self.bytes > self.max_bytes {
            if let Some(removed) = self.lines.pop_front() {
                self.bytes = self.bytes.saturating_sub(removed.len());
                self.dropped_lines = self.dropped_lines.saturating_add(1);
            } else {
                break;
            }
        }
    }

    /// The most recent `count` lines in display order.
    pub fn tail(&self, count: usize) -> Vec<String> {
        self.lines
            .iter()
            .rev()
            .take(count)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    /// Lines `[start, end)` in display order.
    pub fn range(&self, start: usize, end: usize) -> Vec<String> {
        self.lines
            .iter()
            .skip(start)
            .take(end.saturating_sub(start))
            .cloned()
            .collect()
    }
}

/// The shared startup auto-load rule lives in the run loop of each plugin
/// TUI (queue the initial refresh before the first draw when a live service
/// is attached) and is locked by a fixture-mode regression test per plugin;
/// it is documented here because it is contract, not a helper worth wrapping
/// in callbacks.
///
/// The companion regression test in each adopting plugin locks the 0.4.1
/// acceptance criterion (the docker TUI showed no data until a manual
/// refresh) by asserting the initial refresh command is queued before the
/// first draw.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_error_summary_flattens_and_truncates() {
        assert_eq!(safe_error_summary("a\nb"), "a b");
        assert_eq!(safe_error_summary("short"), "short");

        let long = "x".repeat(300);
        let summary = safe_error_summary(&long);
        assert_eq!(summary.len(), 180);
        assert!(summary.ends_with("..."));
    }

    #[test]
    fn window_start_keeps_selection_visible() {
        assert_eq!(window_start(0, 10, 5), 0);
        assert_eq!(window_start(0, 10, 20), 0);
        assert_eq!(window_start(9, 10, 20), 0);
        assert_eq!(window_start(10, 10, 20), 1);
        assert_eq!(window_start(19, 10, 20), 10);
        assert_eq!(window_start(5, 0, 20), 0);
    }

    #[test]
    fn centered_rect_fits_inside_area() {
        let area = Rect::new(0, 0, 100, 60);
        let inner = centered_rect(80, 60, area);
        assert!(inner.x > area.x);
        assert!(inner.width < area.width);
        assert!(inner.height < area.height);
        assert!(inner.right() <= area.right());
        assert!(inner.bottom() <= area.bottom());
    }

    #[test]
    fn bounded_lines_enforce_line_and_byte_budgets() {
        let mut lines = BoundedLines::new(3, 100);
        for index in 0..5 {
            lines.push_line(format!("line-{index}"));
        }
        assert_eq!(lines.len(), 3);
        assert_eq!(lines.dropped_lines(), 2);
        assert_eq!(lines.tail(10), vec!["line-2", "line-3", "line-4"]);

        lines.clear();
        assert!(lines.is_empty());
        assert_eq!(lines.dropped_lines(), 0);
    }

    #[test]
    fn bounded_lines_truncates_oversized_single_lines() {
        let mut lines = BoundedLines::new(4, 10);
        lines.push_line("0123456789abcdef".to_string());
        assert_eq!(lines.tail(1), vec!["0123456789"]);
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn bounded_lines_push_text_splits_and_preserves_trailing_blank() {
        let mut lines = BoundedLines::new(10, 1000);
        lines.push_text("a\nb\n");
        assert_eq!(lines.tail(10), vec!["a", "b"]);
        lines.push_text("\n");
        assert_eq!(lines.tail(1), vec![""]);
    }

    #[test]
    fn bounded_lines_range_slices_in_display_order() {
        let mut lines = BoundedLines::new(10, 1000);
        for index in 0..4 {
            lines.push_line(format!("line-{index}"));
        }
        assert_eq!(lines.range(1, 3), vec!["line-1", "line-2"]);
        assert_eq!(lines.range(3, 10), vec!["line-3"]);
    }
}
