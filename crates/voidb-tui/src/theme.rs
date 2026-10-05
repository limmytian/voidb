use ratatui::style::{Color, Modifier, Style};

/// Application color theme.
#[allow(dead_code)]
pub struct Theme;

#[allow(dead_code)]
impl Theme {
    // --- Mode indicator colors ---
    pub fn mode_normal() -> Style {
        Style::default()
            .fg(Color::White)
            .bg(Color::Blue)
            .add_modifier(Modifier::BOLD)
    }

    pub fn mode_insert() -> Style {
        Style::default()
            .fg(Color::White)
            .bg(Color::Green)
            .add_modifier(Modifier::BOLD)
    }

    pub fn mode_visual() -> Style {
        Style::default()
            .fg(Color::White)
            .bg(Color::Magenta)
            .add_modifier(Modifier::BOLD)
    }

    pub fn mode_command() -> Style {
        Style::default()
            .fg(Color::White)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    }

    // --- General UI ---
    pub fn border_focused() -> Style {
        Style::default().fg(Color::Cyan)
    }

    pub fn border_unfocused() -> Style {
        Style::default().fg(Color::DarkGray)
    }

    pub fn title() -> Style {
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD)
    }

    pub fn status_bar() -> Style {
        Style::default().fg(Color::White).bg(Color::DarkGray)
    }

    pub fn status_error() -> Style {
        Style::default().fg(Color::Red).bg(Color::DarkGray)
    }

    // --- Tab bar ---
    pub fn tab_active() -> Style {
        Style::default()
            .fg(Color::White)
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD)
    }

    pub fn tab_inactive() -> Style {
        Style::default().fg(Color::Gray).bg(Color::Black)
    }

    // --- Tree ---
    pub fn tree_selected() -> Style {
        Style::default().fg(Color::White).bg(Color::DarkGray)
    }

    pub fn tree_database() -> Style {
        Style::default().fg(Color::Cyan)
    }

    pub fn tree_table() -> Style {
        Style::default().fg(Color::Green)
    }

    pub fn tree_connection() -> Style {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    }

    // --- Command palette ---
    pub fn command_prompt() -> Style {
        Style::default().fg(Color::Yellow).bg(Color::Black)
    }

    pub fn command_input() -> Style {
        Style::default().fg(Color::White).bg(Color::Black)
    }

    // --- Placeholder / hint text ---
    pub fn placeholder() -> Style {
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::ITALIC)
    }

    // --- Structure Designer ---
    pub fn structure_header() -> Style {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    }

    pub fn structure_cursor() -> Style {
        Style::default().fg(Color::White).bg(Color::DarkGray)
    }

    pub fn structure_cursor_row() -> Style {
        Style::default().fg(Color::White).bg(Color::Indexed(236))
    }

    pub fn structure_editing() -> Style {
        Style::default()
            .fg(Color::White)
            .bg(Color::Blue)
    }

    pub fn structure_deleted() -> Style {
        Style::default()
            .fg(Color::Red)
            .add_modifier(Modifier::CROSSED_OUT)
    }

    pub fn structure_sub_tab_active() -> Style {
        Style::default()
            .fg(Color::White)
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD)
    }

    pub fn structure_sub_tab_inactive() -> Style {
        Style::default().fg(Color::Gray)
    }

    // --- Dialog ---
    pub fn dialog_border() -> Style {
        Style::default().fg(Color::Cyan)
    }

    pub fn dialog_bg() -> Style {
        Style::default().bg(Color::Black)
    }
}
