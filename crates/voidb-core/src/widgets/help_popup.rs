use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Widget, Wrap},
    Frame,
};

pub struct HelpEntry {
    pub key: &'static str,
    pub desc: &'static str,
}

pub struct HelpSection {
    pub title: &'static str,
    pub entries: Vec<HelpEntry>,
}

pub struct HelpPopup {
    sections: Vec<HelpSection>,
    scroll: u16,
}

impl HelpPopup {
    pub fn new(sections: Vec<HelpSection>) -> Self {
        Self { sections, scroll: 0 }
    }

    pub fn scroll_down(&mut self, n: u16) {
        self.scroll = self.scroll.saturating_add(n);
    }

    pub fn scroll_up(&mut self, n: u16) {
        self.scroll = self.scroll.saturating_sub(n);
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let popup_w = (area.width * 3 / 4).max(50).min(area.width);
        let popup_h = (area.height * 3 / 4).max(15).min(area.height);
        let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
        let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
        let popup_area = Rect::new(x, y, popup_w, popup_h);

        Clear.render(popup_area, frame.buffer_mut());

        let key_style = Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD);
        let desc_style = Style::default().fg(Color::White);
        let section_style = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
        let sep_style = Style::default().fg(Color::DarkGray);

        let mut lines: Vec<Line> = Vec::new();

        for (si, section) in self.sections.iter().enumerate() {
            if si > 0 {
                lines.push(Line::from(""));
            }
            lines.push(Line::from(vec![
                Span::styled(format!("── {} ", section.title), section_style),
                Span::styled("─".repeat(30), sep_style),
            ]));

            let max_key_width = section.entries.iter()
                .map(|e| e.key.len())
                .max()
                .unwrap_or(0);

            for entry in &section.entries {
                let padding = " ".repeat(max_key_width.saturating_sub(entry.key.len()) + 2);
                lines.push(Line::from(vec![
                    Span::styled(format!("  {}", entry.key), key_style),
                    Span::raw(padding),
                    Span::styled(entry.desc, desc_style),
                ]));
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Press ? or Esc to close",
            Style::default().fg(Color::DarkGray),
        )));

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Help (↑↓ scroll) ")
            .border_style(Style::default().fg(Color::Cyan))
            .style(Style::default().bg(Color::Black));

        let paragraph = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((self.scroll, 0));

        frame.render_widget(paragraph, popup_area);
    }
}

// Pre-built help sections for common modes
pub fn grid_help() -> Vec<HelpSection> {
    vec![
        HelpSection {
            title: "Global Shortcuts",
            entries: vec![
                HelpEntry { key: "q", desc: "Return to Home (Connection Manager)" },
                HelpEntry { key: "Ctrl+L", desc: "Open Tab Manager (view/switch/close tabs)" },
                HelpEntry { key: "Ctrl+Q", desc: "Quit application" },
            ],
        },
        HelpSection {
            title: "Navigation",
            entries: vec![
                HelpEntry { key: "h/j/k/l", desc: "Move left/down/up/right" },
                HelpEntry { key: "Arrow keys", desc: "Move cursor" },
                HelpEntry { key: "PageUp/Down", desc: "Scroll page" },
                HelpEntry { key: "Mouse drag", desc: "Drag column header border to resize" },
                HelpEntry { key: "Home/End", desc: "First/last row" },
                HelpEntry { key: "g / G", desc: "Jump to first/last row" },
                HelpEntry { key: "[ / ]", desc: "Previous/next database page" },
                HelpEntry { key: "{ / }", desc: "First/last database page" },
            ],
        },
        HelpSection {
            title: "Editing",
            entries: vec![
                HelpEntry { key: "e / Enter", desc: "Edit current cell" },
                HelpEntry { key: "i", desc: "Insert new row" },
                HelpEntry { key: "d", desc: "Mark row(s) for deletion" },
                HelpEntry { key: "u", desc: "Undo last change" },
                HelpEntry { key: "U (Shift)", desc: "Discard all pending changes" },
                HelpEntry { key: "Ctrl+S", desc: "Save all changes (edits + deletes)" },
            ],
        },
        HelpSection {
            title: "Query Editor",
            entries: vec![
                HelpEntry { key: ":", desc: "Open query editor" },
                HelpEntry { key: "F5", desc: "Execute query (or selected text)" },
                HelpEntry { key: "Ctrl+E", desc: "EXPLAIN current query" },
                HelpEntry { key: "Ctrl+S", desc: "Save query to bookmarks" },
                HelpEntry { key: "Ctrl+O", desc: "Open saved queries" },
                HelpEntry { key: "Ctrl+A", desc: "Select all text" },
                HelpEntry { key: "Shift+←/→", desc: "Extend text selection" },
                HelpEntry { key: "Tab", desc: "Accept autocomplete / indent" },
                HelpEntry { key: "↑ / ↓", desc: "History / autocomplete navigate" },
                HelpEntry { key: "Esc", desc: "Close autocomplete / exit query" },
            ],
        },
        HelpSection {
            title: "Search, Sort & Filter",
            entries: vec![
                HelpEntry { key: "/", desc: "Search in current data" },
                HelpEntry { key: "n / N", desc: "Next/previous match" },
                HelpEntry { key: "f", desc: "Filter by column value" },
                HelpEntry { key: "Ctrl+F", desc: "Clear filter" },
                HelpEntry { key: "S (Shift)", desc: "Cycle sort on current column" },
            ],
        },
        HelpSection {
            title: "Selection & Clipboard",
            entries: vec![
                HelpEntry { key: "Space", desc: "Toggle row selection" },
                HelpEntry { key: "v", desc: "Enter Visual mode (range select)" },
                HelpEntry { key: "Esc", desc: "Clear selection / exit Visual" },
                HelpEntry { key: "y", desc: "Copy current cell" },
                HelpEntry { key: "Y (Shift)", desc: "Copy row(s) — selected or current" },
                HelpEntry { key: "p", desc: "Paste rows (INSERT new)" },
                HelpEntry { key: "P (Shift)", desc: "Paste rows (OVERWRITE current)" },
            ],
        },
        HelpSection {
            title: "Tools",
            entries: vec![
                HelpEntry { key: "s", desc: "View table structure" },
                HelpEntry { key: "D (Shift)", desc: "Show DDL (CREATE TABLE)" },
                HelpEntry { key: "m", desc: "View long cell content (memo)" },
                HelpEntry { key: "A (Shift)", desc: "Open schema editor (ALTER TABLE)" },
                HelpEntry { key: "Ctrl+E", desc: "Export data (CSV/JSON/SQL)" },
                HelpEntry { key: "Ctrl+I", desc: "Import CSV into current table" },
                HelpEntry { key: "Ctrl+R", desc: "Refresh data" },
                HelpEntry { key: "?", desc: "Toggle this help" },
            ],
        },
    ]
}

pub fn browser_help() -> Vec<HelpSection> {
    vec![
        HelpSection {
            title: "Global Shortcuts",
            entries: vec![
                HelpEntry { key: "q", desc: "Return to Home (Connection Manager)" },
                HelpEntry { key: "Ctrl+L", desc: "Open Tab Manager (view/switch/close tabs)" },
                HelpEntry { key: "Ctrl+Q", desc: "Quit application" },
            ],
        },
        HelpSection {
            title: "Tree Navigation",
            entries: vec![
                HelpEntry { key: "j / ↓", desc: "Move down" },
                HelpEntry { key: "k / ↑", desc: "Move up" },
                HelpEntry { key: "Enter", desc: "Expand/collapse or open table" },
                HelpEntry { key: "Tab", desc: "Switch pane (tree ↔ preview)" },
                HelpEntry { key: "Ctrl+R", desc: "Refresh tree" },
            ],
        },
        HelpSection {
            title: "Database Management",
            entries: vec![
                HelpEntry { key: "C (Shift)", desc: "Create new database" },
                HelpEntry { key: "D (Shift)", desc: "Drop selected database" },
            ],
        },
        HelpSection {
            title: "Table Management",
            entries: vec![
                HelpEntry { key: "N (Shift)", desc: "Create new table wizard" },
                HelpEntry { key: "d", desc: "Duplicate selected table" },
                HelpEntry { key: "R (Shift)", desc: "Rename selected table" },
                HelpEntry { key: "X (Shift)", desc: "Drop selected table" },
            ],
        },
        HelpSection {
            title: "Copy / Paste",
            entries: vec![
                HelpEntry { key: "Space", desc: "Toggle table selection (multi-select)" },
                HelpEntry { key: "v", desc: "Enter Visual mode (range select)" },
                HelpEntry { key: "Esc", desc: "Clear selection / exit Visual" },
                HelpEntry { key: "Y (Shift)", desc: "Copy table/database (structure or +data)" },
                HelpEntry { key: "p", desc: "Paste table(s)/database into selected db" },
            ],
        },
        HelpSection {
            title: "Preview Pane",
            entries: vec![
                HelpEntry { key: "h/j/k/l", desc: "Navigate data grid" },
                HelpEntry { key: "Enter", desc: "Open table in new tab" },
                HelpEntry { key: "?", desc: "Toggle this help" },
            ],
        },
    ]
}
