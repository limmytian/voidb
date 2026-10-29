use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};

use super::{centered_rect, render_input};
use crate::connection_manager_app::{ConnectionManagerApp, CredentialMode};

impl ConnectionManagerApp {
    pub(super) fn render_plugin_install_confirmation(&self, frame: &mut Frame, area: Rect) {
        let plugin_id = self
            .plugin_install_target
            .as_deref()
            .unwrap_or("selected plugin");
        let popup = centered_rect(86, 60, area);
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(format!(
                "Download and install official plugin '{plugin_id}' from the registry?\n\nOnly this plugin will be installed in your user plugin directory.\nConnection settings and credentials stay unchanged.\n\nEnter/y install · n/Esc cancel"
            ))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(Block::default().title(" Install plugin ").borders(Borders::ALL)),
            popup,
        );
    }

    pub(super) fn render_delete_confirmation(&self, frame: &mut Frame, area: Rect) {
        let popup = centered_rect(58, 24, area);
        frame.render_widget(Clear, popup);
        let name = self
            .selected_profile()
            .map(|profile| profile.name.as_str())
            .unwrap_or("selected profile");
        frame.render_widget(
            Paragraph::new(format!(
                "Delete native profile '{name}' and its encrypted configuration?\n\nEnter/y confirm · n/Esc cancel"
            ))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(
                Block::default()
                    .title(" Confirm delete ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red)),
            ),
            popup,
        );
    }

    pub(super) fn render_help(&self, frame: &mut Frame, area: Rect) {
        let popup = centered_rect(76, 84, area);
        frame.render_widget(Clear, popup);
        let text = Text::from(vec![
            Line::raw("j/k or ↑/↓     Move selection"),
            Line::raw("n               Create native profile"),
            Line::raw("e               Edit selected profile"),
            Line::raw("Tab / Shift+Tab Navigate profile form fields"),
            Line::raw("←/→             Change enum, boolean, or authentication choice"),
            Line::raw("Ctrl+U          Clear the active text or numeric field"),
            Line::raw("F2              Toggle interactive form / advanced JSON"),
            Line::raw("Ctrl+S          Validate and save the profile"),
            Line::raw("d               Delete selected profile"),
            Line::raw("i               Install the selected profile’s missing official plugin"),
            Line::raw("t               Test through voidb-cli profile test"),
            Line::raw("c               Browse plugin capabilities"),
            Line::raw("a               Quick read-only access for the selected profile"),
            Line::raw("p               Open canonical JIT approval inbox"),
            Line::raw("x               Review explicit revoke-all action"),
            Line::raw("a in access     Toggle simple and advanced authorization controls"),
            Line::raw("Advanced access Presets, TTL, uses, capabilities, renew/revoke"),
            Line::raw("/               Filter profiles"),
            Line::raw("m               Unlock or set master password"),
            Line::raw("r               Reload profile store"),
            Line::raw("Enter           Show copyable CLI guidance"),
            Line::raw("Ctrl+Q          Quit"),
            Line::raw(""),
            Line::styled(
                "Grant status is authorization; active sessions are counted separately.",
                Style::default().fg(Color::Green),
            ),
        ]);
        frame.render_widget(
            Paragraph::new(text).block(Block::default().title(" Help ").borders(Borders::ALL)),
            popup,
        );
    }

    pub(super) fn render_credentials(&self, frame: &mut Frame, area: Rect) {
        let Some(dialog) = &self.credential_dialog else {
            return;
        };
        let popup = centered_rect(
            62,
            if dialog.mode == CredentialMode::Set {
                42
            } else {
                30
            },
            area,
        );
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Block::default()
                .title(if dialog.mode == CredentialMode::Set {
                    " Protect native profile credentials "
                } else {
                    " Unlock native profile credentials "
                })
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
            popup,
        );
        let inner = popup.inner(ratatui::layout::Margin {
            horizontal: 2,
            vertical: 1,
        });
        let mut constraints = vec![Constraint::Length(3)];
        if dialog.mode == CredentialMode::Set {
            constraints.push(Constraint::Length(3));
        }
        constraints.push(Constraint::Min(2));
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(inner);
        render_input(
            frame,
            rows[0],
            "Master password",
            &dialog.password,
            dialog.active_field == 0,
            true,
        );
        if dialog.mode == CredentialMode::Set {
            render_input(
                frame,
                rows[1],
                "Confirm password",
                &dialog.confirmation,
                dialog.active_field == 1,
                true,
            );
        }
        let message_area = rows[rows.len() - 1];
        frame.render_widget(
            Paragraph::new(
                dialog
                    .message
                    .as_deref()
                    .unwrap_or("Enter submit · Tab switch field · Esc cancel"),
            )
            .style(Style::default().fg(if dialog.message.is_some() {
                Color::Red
            } else {
                Color::DarkGray
            })),
            message_area,
        );
    }

    pub(super) fn render_capabilities(&mut self, frame: &mut Frame, area: Rect) {
        let popup = centered_rect(82, 76, area);
        frame.render_widget(Clear, popup);
        let items = if self.capability_rx.is_some() {
            vec![ListItem::new("Loading capability catalog...")]
        } else if self.capabilities.is_empty() {
            vec![ListItem::new("No capabilities reported for this plugin")]
        } else {
            self.capabilities
                .iter()
                .map(|capability| {
                    ListItem::new(vec![
                        Line::styled(
                            format!("{}  [{}]", capability.id, capability.risk),
                            Style::default().fg(Color::Cyan),
                        ),
                        Line::styled(&capability.description, Style::default().fg(Color::Gray)),
                    ])
                })
                .collect()
        };
        let mut state = ListState::default();
        if !self.capabilities.is_empty() {
            state.select(Some(self.capability_selected));
        }
        frame.render_stateful_widget(
            List::new(items)
                .highlight_symbol("▶ ")
                .highlight_style(Style::default().bg(Color::Rgb(30, 50, 65)))
                .block(
                    Block::default()
                        .title(" Capabilities · Enter command guidance · Esc close ")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan)),
                ),
            popup,
            &mut state,
        );
    }
}
