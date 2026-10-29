use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};

use super::{centered_rect, render_input};
use crate::connection_manager_app::{ConnectionManagerApp, EditorView};

impl ConnectionManagerApp {
    pub(super) fn render_editor(&self, frame: &mut Frame, area: Rect) {
        let Some(editor) = &self.editor else {
            return;
        };
        let popup = centered_rect(86, 86, area);
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Block::default()
                .title(if editor.existing_profile_id.is_some() {
                    " Edit native profile "
                } else {
                    " New native profile "
                })
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
            popup,
        );
        let inner = popup.inner(ratatui::layout::Margin {
            horizontal: 2,
            vertical: 1,
        });
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(8),
                Constraint::Length(3),
            ])
            .split(inner);
        render_input(
            frame,
            rows[0],
            if editor.existing_profile_id.is_some() {
                "Connection type (fixed)"
            } else {
                "Connection type (←/→)"
            },
            &format!("{} · {}", editor.plugin_id(), editor.plugin_label()),
            editor.active_field == 0,
            false,
        );
        render_input(
            frame,
            rows[1],
            "Name (required)",
            &editor.name,
            editor.active_field == 1,
            false,
        );
        render_input(
            frame,
            rows[2],
            "Display name (optional)",
            &editor.display_name,
            editor.active_field == 2,
            false,
        );
        let default_message = match editor.view {
            EditorView::Form => {
                let visible = editor.schema.visible_fields(&editor.config);
                let active_index = editor.active_field.saturating_sub(3);
                let visible_height = rows[3].height.saturating_sub(2) as usize;
                let scroll = active_index.saturating_sub(visible_height.saturating_sub(1));
                let items = visible
                    .iter()
                    .enumerate()
                    .skip(scroll)
                    .take(visible_height)
                    .map(|(index, field)| {
                        let marker = if field.required { "*" } else { " " };
                        let label = format!("{marker} {:<24}", field.label);
                        ListItem::new(Line::from(vec![
                            Span::styled(label, Style::default().fg(Color::Cyan)),
                            Span::raw(editor.form_field_display(field)),
                        ]))
                        .style(if editor.active_field == index + 3 {
                            Style::default().bg(Color::Rgb(45, 55, 75)).fg(Color::White)
                        } else {
                            Style::default()
                        })
                    })
                    .collect::<Vec<_>>();
                frame.render_widget(
                    List::new(items).block(
                        Block::default()
                            .title(" Interactive configuration · F2 advanced JSON ")
                            .borders(Borders::ALL)
                            .border_style(if editor.active_field >= 3 {
                                Style::default().fg(Color::Yellow)
                            } else {
                                Style::default().fg(Color::DarkGray)
                            }),
                    ),
                    rows[3],
                );
                editor
                    .active_form_field()
                    .map(|field| {
                        format!(
                            "{} · Tab/↑↓ move · ←/→ choices · Ctrl+S save · F2 JSON",
                            editor.form_field_help(field)
                        )
                    })
                    .unwrap_or_else(|| match editor.active_field {
                        0 if editor.existing_profile_id.is_some() => {
                            "Connection type is fixed for an existing profile · Tab continues"
                                .to_string()
                        }
                        0 => "Choose the connection type first with ←/→ · Tab continues"
                            .to_string(),
                        1 => "Stable name used by CLI commands · unique within this connection type, ignoring case"
                            .to_string(),
                        2 => "Optional human-facing label · may be repeated".to_string(),
                        _ => {
                            "Tab fields · Ctrl+S save · F2 advanced JSON · Esc cancel".to_string()
                        }
                    })
            }
            EditorView::Json => {
                let visible_height = rows[3].height.saturating_sub(2) as usize;
                let scroll = editor
                    .cursor_line
                    .saturating_sub(visible_height.saturating_sub(1));
                let config = editor
                    .config_lines
                    .iter()
                    .skip(scroll)
                    .take(visible_height)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n");
                frame.render_widget(
                    Paragraph::new(config)
                        .block(
                            Block::default()
                                .title(" Advanced plugin configuration JSON · F2 form ")
                                .borders(Borders::ALL)
                                .border_style(if editor.active_field == 3 {
                                    Style::default().fg(Color::Yellow)
                                } else {
                                    Style::default().fg(Color::DarkGray)
                                }),
                        )
                        .wrap(Wrap { trim: false }),
                    rows[3],
                );
                if editor.active_field == 3 {
                    let x = rows[3]
                        .x
                        .saturating_add(1)
                        .saturating_add(editor.cursor_col as u16)
                        .min(rows[3].right().saturating_sub(2));
                    let y = rows[3]
                        .y
                        .saturating_add(1)
                        .saturating_add(editor.cursor_line.saturating_sub(scroll) as u16)
                        .min(rows[3].bottom().saturating_sub(2));
                    frame.set_cursor_position((x, y));
                }
                "Raw JSON mode · F2 validate and return to form · Ctrl+S save · Esc cancel"
                    .to_string()
            }
        };
        let message = editor.message.as_deref().unwrap_or(&default_message);
        frame.render_widget(
            Paragraph::new(message)
                .wrap(Wrap { trim: true })
                .style(Style::default().fg(if editor.message.is_some() {
                    Color::Red
                } else {
                    Color::DarkGray
                })),
            rows[4],
        );
    }
}
