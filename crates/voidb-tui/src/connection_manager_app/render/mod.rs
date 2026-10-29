use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use super::background::can_install_missing_plugin;
use super::{AuthorizationStatusView, MIN_HEIGHT, MIN_WIDTH, ScreenMode, plural};
use voidb_core::process_plugin::ProcessPluginCandidateState;

use super::ConnectionManagerApp;

mod authorization;
mod editor;
mod overlays;

impl ConnectionManagerApp {
    pub(super) fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
            frame.render_widget(
                Paragraph::new(format!(
                    "VoidB Connection Manager\n\nTerminal too small\nMinimum: {MIN_WIDTH}x{MIN_HEIGHT}\nCurrent: {}x{}",
                    area.width, area.height
                ))
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Yellow)),
                area,
            );
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(area);
        self.render_header(frame, chunks[0]);
        self.render_main(frame, chunks[1]);
        self.render_footer(frame, chunks[2]);

        match self.mode {
            ScreenMode::Edit => self.render_editor(frame, area),
            ScreenMode::ConfirmDelete => self.render_delete_confirmation(frame, area),
            ScreenMode::ConfirmPluginInstall => {
                self.render_plugin_install_confirmation(frame, area)
            }
            ScreenMode::Help => self.render_help(frame, area),
            ScreenMode::Credentials => self.render_credentials(frame, area),
            ScreenMode::Capabilities => self.render_capabilities(frame, area),
            ScreenMode::Authorization => self.render_authorization(frame, area),
            ScreenMode::AuthorizationInbox => self.render_authorization_inbox(frame, area),
            _ => {}
        }
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let protection = if self.config.requires_master_password() {
            if self.active_master_password.is_some() {
                Span::styled("UNLOCKED", Style::default().fg(Color::Green))
            } else {
                Span::styled("LOCKED", Style::default().fg(Color::Yellow))
            }
        } else {
            Span::styled("DEFAULT KEY", Style::default().fg(Color::Yellow))
        };
        let title = Line::from(vec![
            Span::styled(
                " VoidB · Native Connection Manager ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  {} profile{}  ·  ",
                self.profiles.len(),
                plural(self.profiles.len())
            )),
            protection,
        ]);
        frame.render_widget(
            Paragraph::new(title).block(Block::default().borders(Borders::ALL)),
            area,
        );
    }

    fn render_main(&mut self, frame: &mut Frame, area: Rect) {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(area);
        let items = self
            .filtered_indices
            .iter()
            .map(|index| {
                let profile = &self.profiles[*index];
                let authorization = self
                    .authorization_statuses
                    .get(&(profile.id.clone(), profile.plugin_id.clone()))
                    .map(AuthorizationStatusView::badge)
                    .unwrap_or_else(|| {
                        if self
                            .authorization_supported_plugins
                            .contains(&profile.plugin_id)
                        {
                            "OFF"
                        } else {
                            "UNSUPPORTED"
                        }
                    });
                let installing = self
                    .plugin_install_rx
                    .as_ref()
                    .is_some_and(|(id, _)| id == &profile.plugin_id);
                let plugin_badge = if installing {
                    "INSTALLING"
                } else {
                    match self.plugin_states.get(&profile.plugin_id) {
                        None if columns[0].width < 40 => "MISSING",
                        None => "NOT INSTALLED",
                        Some(ProcessPluginCandidateState::Available) => authorization,
                        Some(state) => state.as_str(),
                    }
                };
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{} ", protocol_icon(&profile.plugin_id)),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(&profile.name, Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        format!("  {}", profile.plugin_id),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("  [{plugin_badge}]"),
                        Style::default().fg(if plugin_badge == "OFF" {
                            Color::DarkGray
                        } else {
                            Color::Yellow
                        }),
                    ),
                ]))
            })
            .collect::<Vec<_>>();
        let title = if self.mode == ScreenMode::Search {
            format!(" Profiles · filter: {} ", self.search)
        } else {
            " Profiles ".to_string()
        };
        let list = List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_symbol("▶ ")
            .highlight_style(Style::default().bg(Color::Rgb(30, 50, 65)).fg(Color::White));
        frame.render_stateful_widget(list, columns[0], &mut self.list_state);

        let details = if let Some(profile) = self.selected_profile() {
            let display = profile.display_name.as_deref().unwrap_or(&profile.name);
            let authorization = self
                .authorization_statuses
                .get(&(profile.id.clone(), profile.plugin_id.clone()));
            let authorization_detail = authorization
                .map(AuthorizationStatusView::detail)
                .unwrap_or_else(|| {
                    if self
                        .authorization_supported_plugins
                        .contains(&profile.plugin_id)
                    {
                        "OFF · no active grant".to_string()
                    } else {
                        "UNSUPPORTED · no agent-ready capabilities".to_string()
                    }
                });
            let authorization_detail = if !self.plugin_states.contains_key(&profile.plugin_id) {
                "Unavailable until this plugin is installed".to_string()
            } else {
                authorization_detail
            };
            Text::from(vec![
                Line::from(Span::styled(
                    display,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::raw(""),
                detail_line("Name", &profile.name),
                detail_line("Plugin", &profile.plugin_id),
                detail_line("Profile ID", &profile.id),
                detail_line("Storage", "native profile + encrypted local config"),
                detail_line(
                    "Credential refs",
                    &profile.credential_refs.len().to_string(),
                ),
                detail_line(
                    "Plugin status",
                    self.plugin_states
                        .get(&profile.plugin_id)
                        .map_or("Not installed · press i to install", |state| {
                            state.as_str()
                        }),
                ),
                detail_line("Agent access", &authorization_detail),
                Line::raw(""),
                Line::styled(
                    "This profile resolves directly from profiles.json and credentials.json.",
                    Style::default().fg(Color::Green),
                ),
                Line::raw(""),
                Line::styled("Next steps", Style::default().add_modifier(Modifier::BOLD)),
                Line::raw(format!(
                    "Test: voidb-cli profile test id:{} --plugin {}",
                    profile.id, profile.plugin_id
                )),
                Line::raw(format!(
                    "TUI:  voidb-cli {} tui --profile id:{}",
                    profile.plugin_id, profile.id
                )),
                Line::raw(
                    if can_install_missing_plugin(
                        &profile.plugin_id,
                        self.plugin_states.get(&profile.plugin_id).copied(),
                    ) {
                        "Install this plugin: press i (confirmation required)"
                    } else {
                        "Authorize/manage: press a"
                    },
                ),
            ])
        } else if self.profiles.is_empty() {
            Text::from(vec![
                Line::styled(
                    "Create your first native profile",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::raw("Press n, choose a plugin, and complete its interactive form."),
                Line::raw("Authentication choices reveal only the fields they require."),
                Line::raw("Connection details are encrypted in credentials.json."),
                Line::raw("The old config.toml connection list is not used here."),
            ])
        } else {
            Text::from("No profiles match the current filter")
        };
        frame.render_widget(
            Paragraph::new(details).wrap(Wrap { trim: false }).block(
                Block::default()
                    .title(" Profile details ")
                    .borders(Borders::ALL),
            ),
            columns[1],
        );
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let help = match self.mode {
            ScreenMode::Search => "Type to filter · Enter/Esc finish · ↑↓ navigate",
            _ => {
                "n/e/d profile · i install plugin · t test · c capabilities · a manage agent access · x review revoke-all · m credentials · ? help"
            }
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(&self.status, Style::default().fg(Color::Yellow)),
                Line::styled(help, Style::default().fg(Color::DarkGray)),
            ])
            .block(Block::default().borders(Borders::TOP)),
            area,
        );
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
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
        .split(vertical[1])[1]
}

fn render_input(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    value: &str,
    active: bool,
    secret: bool,
) {
    let rendered = if secret {
        "•".repeat(value.chars().count())
    } else {
        value.to_string()
    };
    frame.render_widget(
        Paragraph::new(rendered).block(
            Block::default()
                .title(format!(" {title} "))
                .borders(Borders::ALL)
                .border_style(if active {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        ),
        area,
    );
}

fn detail_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(Color::DarkGray)),
        Span::raw(value.to_string()),
    ])
}

fn protocol_icon(plugin_id: &str) -> &'static str {
    match plugin_id {
        "mysql" => "🐬",
        "postgres" => "🐘",
        "sqlite" => "▣",
        "redis" => "◆",
        "ssh" => "⌘",
        "docker" => "◫",
        "kubernetes" => "☸",
        "s3" => "▱",
        "email" => "✉",
        _ => "•",
    }
}
