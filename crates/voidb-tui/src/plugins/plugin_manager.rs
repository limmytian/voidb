//! Plugin Manager & Marketplace View for VoidB TUI
//!
//! Provides interactive browsing of installed and official registry plugins,
//! search filtering, detail inspection, and asynchronous installation/uninstallation
//! lifecycle operations with status feedback.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use voidb_core::plugin_registry_metadata::PluginRegistryIndex;
use voidb_core::process_plugin::{
    discover_process_plugins, ProcessPluginCandidate,
};

/// High-level active tab in the plugin manager modal
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginManagerTab {
    Installed,
    Marketplace,
}

/// Unified plugin representation for the manager list
#[derive(Debug, Clone)]
pub struct PluginDisplayItem {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub category: String,
    pub is_installed: bool,
    pub is_enabled: bool,
    pub homepage: Option<String>,
    pub capabilities: Vec<String>,
    pub platforms: Vec<String>,
}

/// Asynchronous operation result
pub enum PluginOperationResult {
    Success(String),
    Error(String),
}

type AsyncOpReceiver = Arc<Mutex<Receiver<PluginOperationResult>>>;

/// State for the Plugin Manager modal dialog
pub struct PluginManagerState {
    pub active_tab: PluginManagerTab,
    pub selected_index: usize,
    pub list_state: ListState,
    pub search_active: bool,
    pub search_query: String,
    pub installed_plugins: Vec<ProcessPluginCandidate>,
    pub registry_index: Option<PluginRegistryIndex>,
    pub items: Vec<PluginDisplayItem>,
    pub filtered_indices: Vec<usize>,
    pub status_message: Option<String>,
    pub is_loading: bool,
    pub is_operating: bool,
    pub async_op_rx: Option<AsyncOpReceiver>,
}

impl PluginManagerState {
    pub fn new() -> Self {
        let mut state = Self {
            active_tab: PluginManagerTab::Installed,
            selected_index: 0,
            list_state: ListState::default(),
            search_active: false,
            search_query: String::new(),
            installed_plugins: Vec::new(),
            registry_index: None,
            items: Vec::new(),
            filtered_indices: Vec::new(),
            status_message: None,
            is_loading: false,
            is_operating: false,
            async_op_rx: None,
        };
        state.refresh_installed();
        state
    }

    /// Refresh installed plugins from local discovery
    pub fn refresh_installed(&mut self) {
        let discovery = discover_process_plugins();
        self.installed_plugins = discovery.candidates;
        self.rebuild_items();
    }

    /// Set fetched registry index and rebuild items
    pub fn set_registry_index(&mut self, index: PluginRegistryIndex) {
        self.registry_index = Some(index);
        self.rebuild_items();
    }

    /// Rebuild display items based on current active tab and registries
    pub fn rebuild_items(&mut self) {
        self.items.clear();

        match self.active_tab {
            PluginManagerTab::Installed => {
                for installed in &self.installed_plugins {
                    let manifest = installed.manifest.as_ref();
                    let caps = manifest
                        .map(|m| m.capabilities.iter().map(|c| c.id.clone()).collect())
                        .unwrap_or_default();
                    let platforms = manifest
                        .and_then(|m| m.requirements.as_ref())
                        .and_then(|r| r.platforms.clone())
                        .unwrap_or_default();

                    let desc = manifest
                        .and_then(|m| m.description.clone())
                        .unwrap_or_default();

                    self.items.push(PluginDisplayItem {
                        id: installed.id.clone(),
                        name: installed.name.clone().unwrap_or_else(|| installed.id.clone()),
                        description: desc,
                        version: installed.version.clone().unwrap_or_else(|| "unknown".into()),
                        category: "Installed".into(),
                        is_installed: true,
                        is_enabled: installed.state.as_str() == "available",
                        homepage: None,
                        capabilities: caps,
                        platforms,
                    });
                }
            }
            PluginManagerTab::Marketplace => {
                if let Some(registry) = &self.registry_index {
                    for entry in &registry.plugins {
                        let is_installed = self.installed_plugins.iter().any(|i| i.id == entry.id);
                        let is_enabled = self
                            .installed_plugins
                            .iter()
                            .find(|i| i.id == entry.id)
                            .map(|i| i.state.as_str() == "available")
                            .unwrap_or(false);

                        let platforms = entry
                            .versions
                            .first()
                            .map(|v| v.platforms.clone())
                            .unwrap_or_default();

                        self.items.push(PluginDisplayItem {
                            id: entry.id.clone(),
                            name: entry.name.clone(),
                            description: entry.description.clone().unwrap_or_default(),
                            version: entry.latest_version.clone(),
                            category: entry
                                .category
                                .map(|c| c.as_str().to_string())
                                .unwrap_or_else(|| "other".into()),
                            is_installed,
                            is_enabled,
                            homepage: entry.homepage.clone(),
                            capabilities: entry.capabilities.clone(),
                            platforms,
                        });
                    }
                }
            }
        }

        self.refilter();
    }

    /// Recompute filtered indices based on search query
    pub fn refilter(&mut self) {
        let q = self.search_query.trim().to_lowercase();
        self.filtered_indices = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                if q.is_empty() {
                    return true;
                }
                item.id.to_lowercase().contains(&q)
                    || item.name.to_lowercase().contains(&q)
                    || item.description.to_lowercase().contains(&q)
                    || item.category.to_lowercase().contains(&q)
            })
            .map(|(idx, _)| idx)
            .collect();

        if self.filtered_indices.is_empty() {
            self.selected_index = 0;
            self.list_state.select(None);
        } else {
            self.selected_index = self.selected_index.min(self.filtered_indices.len() - 1);
            self.list_state.select(Some(self.selected_index));
        }
    }

    pub fn selected_item(&self) -> Option<&PluginDisplayItem> {
        let real_idx = *self.filtered_indices.get(self.selected_index)?;
        self.items.get(real_idx)
    }

    pub fn switch_tab(&mut self) {
        self.active_tab = match self.active_tab {
            PluginManagerTab::Installed => PluginManagerTab::Marketplace,
            PluginManagerTab::Marketplace => PluginManagerTab::Installed,
        };
        self.search_query.clear();
        self.search_active = false;
        self.selected_index = 0;
        self.rebuild_items();
    }

    /// Poll asynchronous operations
    pub fn poll_async(&mut self) -> bool {
        let mut changed = false;
        let mut op_result = None;
        if let Some(rx) = &self.async_op_rx
            && let Ok(receiver) = rx.lock()
            && let Ok(result) = receiver.try_recv()
        {
            op_result = Some(result);
        }
        if let Some(result) = op_result {
            self.is_operating = false;
            self.is_loading = false;
            match result {
                PluginOperationResult::Success(msg) => {
                    self.status_message = Some(format!("✓ {}", msg));
                    self.refresh_installed();
                }
                PluginOperationResult::Error(msg) => {
                    self.status_message = Some(format!("✗ {}", msg));
                }
            }
            self.async_op_rx = None;
            changed = true;
        }
        changed
    }

    /// Trigger asynchronous installation of the selected plugin
    pub fn trigger_install(&mut self) {
        let Some(item) = self.selected_item() else { return };
        let plugin_id = item.id.clone();
        self.is_operating = true;
        self.status_message = Some(format!("Installing plugin '{}' from registry...", plugin_id));

        let (tx, rx) = channel();
        self.async_op_rx = Some(Arc::new(Mutex::new(rx)));

        std::thread::spawn(move || {
            let cli_bin = resolve_voidb_cli_binary();
            let output = std::process::Command::new(&cli_bin)
                .args(["plugin", "install", &plugin_id, "--format", "json"])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    let _ = tx.send(PluginOperationResult::Success(format!(
                        "Plugin '{}' installed successfully",
                        plugin_id
                    )));
                }
                Ok(out) => {
                    let err = String::from_utf8_lossy(&out.stderr);
                    let err_msg = if err.trim().is_empty() {
                        String::from_utf8_lossy(&out.stdout).to_string()
                    } else {
                        err.to_string()
                    };
                    let _ = tx.send(PluginOperationResult::Error(format!(
                        "Install '{}' failed: {}",
                        plugin_id, err_msg.trim()
                    )));
                }
                Err(e) => {
                    let _ = tx.send(PluginOperationResult::Error(format!(
                        "Failed to spawn voidb-cli: {}",
                        e
                    )));
                }
            }
        });
    }

    /// Trigger asynchronous uninstallation of the selected plugin
    pub fn trigger_uninstall(&mut self) {
        let Some(item) = self.selected_item() else { return };
        let plugin_id = item.id.clone();
        self.is_operating = true;
        self.status_message = Some(format!("Uninstalling plugin '{}'...", plugin_id));

        let (tx, rx) = channel();
        self.async_op_rx = Some(Arc::new(Mutex::new(rx)));

        std::thread::spawn(move || {
            let cli_bin = resolve_voidb_cli_binary();
            let output = std::process::Command::new(&cli_bin)
                .args(["plugin", "uninstall", &plugin_id, "--format", "json"])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    let _ = tx.send(PluginOperationResult::Success(format!(
                        "Plugin '{}' uninstalled successfully",
                        plugin_id
                    )));
                }
                Ok(out) => {
                    let err = String::from_utf8_lossy(&out.stderr);
                    let _ = tx.send(PluginOperationResult::Error(format!(
                        "Uninstall '{}' failed: {}",
                        plugin_id, err.trim()
                    )));
                }
                Err(e) => {
                    let _ = tx.send(PluginOperationResult::Error(format!(
                        "Failed to spawn voidb-cli: {}",
                        e
                    )));
                }
            }
        });
    }

    /// Trigger asynchronous update/upgrade of the selected plugin
    pub fn trigger_update(&mut self) {
        let Some(item) = self.selected_item() else { return };
        let plugin_id = item.id.clone();
        self.is_operating = true;
        self.status_message = Some(format!("Updating plugin '{}' from registry...", plugin_id));

        let (tx, rx) = channel();
        self.async_op_rx = Some(Arc::new(Mutex::new(rx)));

        std::thread::spawn(move || {
            let cli_bin = resolve_voidb_cli_binary();
            let output = std::process::Command::new(&cli_bin)
                .args(["plugin", "update", &plugin_id, "--format", "json"])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    let _ = tx.send(PluginOperationResult::Success(format!(
                        "Plugin '{}' updated successfully",
                        plugin_id
                    )));
                }
                Ok(out) => {
                    let err = String::from_utf8_lossy(&out.stderr);
                    let err_msg = if err.trim().is_empty() {
                        String::from_utf8_lossy(&out.stdout).to_string()
                    } else {
                        err.to_string()
                    };
                    let _ = tx.send(PluginOperationResult::Error(format!(
                        "Update '{}' failed: {}",
                        plugin_id, err_msg.trim()
                    )));
                }
                Err(e) => {
                    let _ = tx.send(PluginOperationResult::Error(format!(
                        "Failed to spawn voidb-cli: {}",
                        e
                    )));
                }
            }
        });
    }

    /// Trigger toggle enable/disable
    pub fn trigger_toggle(&mut self) {
        let Some(item) = self.selected_item() else { return };
        let plugin_id = item.id.clone();
        let target_op = if item.is_enabled { "disable" } else { "enable" };
        self.is_operating = true;
        self.status_message = Some(format!("Updating plugin '{}' state to {}...", plugin_id, target_op));

        let (tx, rx) = channel();
        self.async_op_rx = Some(Arc::new(Mutex::new(rx)));

        std::thread::spawn(move || {
            let cli_bin = resolve_voidb_cli_binary();
            let output = std::process::Command::new(&cli_bin)
                .args(["plugin", target_op, &plugin_id, "--format", "json"])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    let _ = tx.send(PluginOperationResult::Success(format!(
                        "Plugin '{}' is now {}",
                        plugin_id,
                        if target_op == "enable" { "enabled" } else { "disabled" }
                    )));
                }
                Ok(out) => {
                    let err = String::from_utf8_lossy(&out.stderr);
                    let _ = tx.send(PluginOperationResult::Error(format!(
                        "Operation '{}' on '{}' failed: {}",
                        target_op, plugin_id, err.trim()
                    )));
                }
                Err(e) => {
                    let _ = tx.send(PluginOperationResult::Error(format!(
                        "Failed to spawn voidb-cli: {}",
                        e
                    )));
                }
            }
        });
    }

    /// Trigger background registry index fetch
    pub fn trigger_fetch_registry(&mut self) {
        if self.registry_index.is_some() || self.is_loading {
            return;
        }
        self.is_loading = true;
        self.status_message = Some("Fetching official plugin registry index...".into());

        let (tx, rx) = channel();
        self.async_op_rx = Some(Arc::new(Mutex::new(rx)));

        std::thread::spawn(move || {
            let cli_bin = resolve_voidb_cli_binary();
            let output = std::process::Command::new(&cli_bin)
                .args(["plugin", "registry", "list", "--format", "json"])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    let _ = tx.send(PluginOperationResult::Success(
                        "Official registry index synchronized".into()
                    ));
                }
                Ok(out) => {
                    let err = String::from_utf8_lossy(&out.stderr);
                    let _ = tx.send(PluginOperationResult::Error(format!(
                        "Registry fetch failed: {}",
                        err.trim()
                    )));
                }
                Err(e) => {
                    let _ = tx.send(PluginOperationResult::Error(format!(
                        "Failed to spawn voidb-cli: {}",
                        e
                    )));
                }
            }
        });
    }

    /// Handle key events in the Plugin Manager
    pub fn handle_key(&mut self, code: KeyCode) -> bool {
        if self.search_active {
            match code {
                KeyCode::Esc => {
                    self.search_active = false;
                    self.refilter();
                    return true;
                }
                KeyCode::Enter => {
                    self.search_active = false;
                    return true;
                }
                KeyCode::Backspace => {
                    self.search_query.pop();
                    self.refilter();
                    return true;
                }
                KeyCode::Char(c) => {
                    self.search_query.push(c);
                    self.refilter();
                    return true;
                }
                _ => return true,
            }
        }

        match code {
            KeyCode::Char('j') | KeyCode::Down => {
                if !self.filtered_indices.is_empty() {
                    self.selected_index = (self.selected_index + 1).min(self.filtered_indices.len() - 1);
                    self.list_state.select(Some(self.selected_index));
                }
                true
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.selected_index = self.selected_index.saturating_sub(1);
                self.list_state.select(Some(self.selected_index));
                true
            }
            KeyCode::Tab => {
                self.switch_tab();
                if self.active_tab == PluginManagerTab::Marketplace && self.registry_index.is_none() {
                    self.load_or_fetch_registry();
                }
                true
            }
            KeyCode::Char('/') => {
                self.search_active = true;
                true
            }
            KeyCode::Char('i') => {
                if !self.is_operating {
                    self.trigger_install();
                }
                true
            }
            KeyCode::Char('U') => {
                if !self.is_operating
                    && let Some(item) = self.selected_item()
                    && item.is_installed
                {
                    self.trigger_update();
                }
                true
            }
            KeyCode::Char('u') | KeyCode::Char('d') => {
                if !self.is_operating
                    && let Some(item) = self.selected_item()
                    && item.is_installed
                {
                    self.trigger_uninstall();
                }
                true
            }
            KeyCode::Char('x') | KeyCode::Char(' ') => {
                if !self.is_operating
                    && let Some(item) = self.selected_item()
                    && item.is_installed
                {
                    self.trigger_toggle();
                }
                true
            }
            KeyCode::Char('r') => {
                self.refresh_installed();
                self.load_or_fetch_registry();
                self.status_message = Some("Plugins and registry refreshed".into());
                true
            }
            _ => false,
        }
    }

    /// Load cached registry index or trigger async fetch
    pub fn load_or_fetch_registry(&mut self) {
        // Try local file load first (from repo or cached dir)
        let local_path = PathBuf::from("registry/index.json");
        if local_path.is_file()
            && let Ok(idx) = PluginRegistryIndex::load_from_file(&local_path)
        {
            self.set_registry_index(idx);
            return;
        }
        self.trigger_fetch_registry();
    }

    /// Render Plugin Manager modal dialog
    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        let width = area.width.clamp(64, 110);
        let height = area.height.clamp(18, 36);

        let x = (area.width.saturating_sub(width)) / 2;
        let y = (area.height.saturating_sub(height)) / 2;
        let dialog_area = Rect {
            x: area.x + x,
            y: area.y + y,
            width,
            height,
        };

        frame.render_widget(Clear, dialog_area);

        let title = match self.active_tab {
            PluginManagerTab::Installed => " 📦 Plugin Manager [Installed] ",
            PluginManagerTab::Marketplace => " 🌐 Plugin Manager [Online Marketplace] ",
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(title)
            .style(Style::default().bg(Color::Black));
        frame.render_widget(block, dialog_area);

        let inner = dialog_area.inner(ratatui::layout::Margin {
            horizontal: 2,
            vertical: 1,
        });

        // Layout: [Tabs & Search (2) | Content (Min 0) | Status & Help (3)]
        let vertical_chunks = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(6),
            Constraint::Length(3),
        ])
        .split(inner);

        // Top Header: Tab switches + Search query
        let tab_spans = vec![
            Span::styled("Tab: ", Style::default().fg(Color::DarkGray)),
            if self.active_tab == PluginManagerTab::Installed {
                Span::styled(
                    "[ Installed ]",
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("  Installed  ", Style::default().fg(Color::Gray))
            },
            Span::raw("   "),
            if self.active_tab == PluginManagerTab::Marketplace {
                Span::styled(
                    "[ Online Marketplace ]",
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("  Online Marketplace  ", Style::default().fg(Color::Gray))
            },
            Span::raw("   "),
            Span::styled(
                format!("(/ Search: {})", if self.search_query.is_empty() { "none" } else { &self.search_query }),
                if self.search_active {
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            ),
        ];
        frame.render_widget(Paragraph::new(Line::from(tab_spans)), vertical_chunks[0]);

        // Content split: [Left: Plugin List (40%) | Right: Details Panel (60%)]
        let content_chunks = Layout::horizontal([
            Constraint::Percentage(42),
            Constraint::Percentage(58),
        ])
        .split(vertical_chunks[1]);

        // Left List
        let items: Vec<ListItem> = self
            .filtered_indices
            .iter()
            .filter_map(|&idx| self.items.get(idx))
            .map(|item| {
                let status_icon = if item.is_installed {
                    if item.is_enabled {
                        "● [active]  "
                    } else {
                        "○ [disabled]"
                    }
                } else {
                    "+ [available]"
                };

                let style = if item.is_installed && item.is_enabled {
                    Style::default().fg(Color::Green)
                } else if item.is_installed {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Cyan)
                };

                let content = Line::from(vec![
                    Span::styled(status_icon, style),
                    Span::raw(" "),
                    Span::styled(&item.id, Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(format!(" v{}", item.version), Style::default().fg(Color::DarkGray)),
                ]);
                ListItem::new(content)
            })
            .collect();

        let list_title = format!("Plugins ({})", self.filtered_indices.len());
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(list_title))
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        frame.render_stateful_widget(list, content_chunks[0], &mut self.list_state);

        // Right Detail Panel
        let detail_text = if let Some(item) = self.selected_item() {
            let mut lines = Vec::new();
            lines.push(Line::from(vec![
                Span::styled("Name:        ", Style::default().fg(Color::Gray)),
                Span::styled(&item.name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("ID:          ", Style::default().fg(Color::Gray)),
                Span::styled(&item.id, Style::default().fg(Color::Cyan)),
                Span::raw("   "),
                Span::styled("Version: ", Style::default().fg(Color::Gray)),
                Span::styled(&item.version, Style::default().fg(Color::Yellow)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Category:    ", Style::default().fg(Color::Gray)),
                Span::styled(&item.category, Style::default().fg(Color::Magenta)),
                Span::raw("   "),
                Span::styled("Status: ", Style::default().fg(Color::Gray)),
                if item.is_installed {
                    if item.is_enabled {
                        Span::styled("Installed (Active)", Style::default().fg(Color::Green))
                    } else {
                        Span::styled("Installed (Disabled)", Style::default().fg(Color::Yellow))
                    }
                } else {
                    Span::styled("Not installed (Available in Registry)", Style::default().fg(Color::Cyan))
                },
            ]));

            if let Some(homepage) = &item.homepage {
                lines.push(Line::from(vec![
                    Span::styled("Homepage:    ", Style::default().fg(Color::Gray)),
                    Span::styled(homepage, Style::default().fg(Color::Blue)),
                ]));
            }

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Description:", Style::default().fg(Color::Gray))));
            lines.push(Line::from(Span::styled(
                if item.description.is_empty() { "No description provided." } else { &item.description },
                Style::default().fg(Color::White),
            )));

            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Capabilities: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    if item.capabilities.is_empty() {
                        "standard plugin contract".into()
                    } else {
                        item.capabilities.join(", ")
                    },
                    Style::default().fg(Color::DarkGray),
                ),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Platforms:    ", Style::default().fg(Color::Gray)),
                Span::styled(
                    if item.platforms.is_empty() {
                        "darwin, linux, windows".into()
                    } else {
                        item.platforms.join(", ")
                    },
                    Style::default().fg(Color::DarkGray),
                ),
            ]));

            lines
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled("No plugin selected.", Style::default().fg(Color::Gray))),
            ]
        };

        let detail_block = Block::default()
            .borders(Borders::ALL)
            .title(" Plugin Details ");
        frame.render_widget(Paragraph::new(detail_text).block(detail_block), content_chunks[1]);

        // Bottom Footer: Status and Help keybindings
        let status_span = if let Some(status) = &self.status_message {
            Span::styled(status, Style::default().fg(Color::Yellow))
        } else if self.is_operating {
            Span::styled("Processing operation...", Style::default().fg(Color::Yellow))
        } else if self.is_loading {
            Span::styled("Loading registry index...", Style::default().fg(Color::Yellow))
        } else {
            Span::styled("Ready", Style::default().fg(Color::DarkGray))
        };

        let help_spans = vec![
            Span::styled("Tab", Style::default().fg(Color::Yellow)),
            Span::raw(": Switch Mode | "),
            Span::styled("↑↓/jk", Style::default().fg(Color::Yellow)),
            Span::raw(": Move | "),
            Span::styled("/", Style::default().fg(Color::Yellow)),
            Span::raw(": Filter | "),
            Span::styled("i", Style::default().fg(Color::Green)),
            Span::raw(": Install | "),
            Span::styled("U", Style::default().fg(Color::Cyan)),
            Span::raw(": Update | "),
            Span::styled("u", Style::default().fg(Color::Red)),
            Span::raw(": Uninstall | "),
            Span::styled("Space", Style::default().fg(Color::Yellow)),
            Span::raw(": Toggle Enable | "),
            Span::styled("r", Style::default().fg(Color::Yellow)),
            Span::raw(": Refresh | "),
            Span::styled("Esc/q", Style::default().fg(Color::Yellow)),
            Span::raw(": Close"),
        ];

        let footer = Paragraph::new(vec![
            Line::from(vec![Span::styled("Status: ", Style::default().fg(Color::Gray)), status_span]),
            Line::from(help_spans),
        ])
        .block(Block::default().borders(Borders::TOP));

        frame.render_widget(footer, vertical_chunks[2]);
    }
}

fn resolve_voidb_cli_binary() -> PathBuf {
    if let Ok(path) = std::env::var("VOIDB_CLI_BIN") {
        return path.into();
    }
    if let Ok(current_exe) = std::env::current_exe()
        && let Some(dir) = current_exe.parent()
    {
        let sibling = dir.join("voidb-cli");
        if sibling.exists() {
            return sibling;
        }
    }
    "voidb-cli".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_manager_state_init() {
        let state = PluginManagerState::new();
        assert_eq!(state.active_tab, PluginManagerTab::Installed);
        assert!(!state.search_active);
    }

    #[test]
    fn test_plugin_manager_tab_switch() {
        let mut state = PluginManagerState::new();
        assert_eq!(state.active_tab, PluginManagerTab::Installed);
        state.switch_tab();
        assert_eq!(state.active_tab, PluginManagerTab::Marketplace);
        state.switch_tab();
        assert_eq!(state.active_tab, PluginManagerTab::Installed);
    }

    #[test]
    fn test_plugin_manager_filter() {
        let mut state = PluginManagerState::new();
        state.items = vec![
            PluginDisplayItem {
                id: "s3".into(),
                name: "S3 Object Storage".into(),
                description: "AWS S3 storage".into(),
                version: "0.3.0".into(),
                category: "storage".into(),
                is_installed: true,
                is_enabled: true,
                homepage: None,
                capabilities: vec!["buckets".into()],
                platforms: vec!["darwin".into()],
            },
            PluginDisplayItem {
                id: "docker".into(),
                name: "Docker Containers".into(),
                description: "Manage containers".into(),
                version: "0.3.0".into(),
                category: "infrastructure".into(),
                is_installed: true,
                is_enabled: false,
                homepage: None,
                capabilities: vec!["containers".into()],
                platforms: vec!["darwin".into()],
            },
        ];
        state.refilter();
        assert_eq!(state.filtered_indices.len(), 2);

        state.search_query = "s3".into();
        state.refilter();
        assert_eq!(state.filtered_indices.len(), 1);
        assert_eq!(state.selected_item().unwrap().id, "s3");

        state.search_query = "docker".into();
        state.refilter();
        assert_eq!(state.filtered_indices.len(), 1);
        assert_eq!(state.selected_item().unwrap().id, "docker");

        state.search_query = "nomatch".into();
        state.refilter();
        assert_eq!(state.filtered_indices.len(), 0);
        assert!(state.selected_item().is_none());
    }

    #[test]
    fn test_plugin_manager_key_navigation() {
        let mut state = PluginManagerState::new();
        state.items = vec![
            PluginDisplayItem {
                id: "a".into(),
                name: "A".into(),
                description: "".into(),
                version: "0.1".into(),
                category: "other".into(),
                is_installed: false,
                is_enabled: false,
                homepage: None,
                capabilities: vec![],
                platforms: vec![],
            },
            PluginDisplayItem {
                id: "b".into(),
                name: "B".into(),
                description: "".into(),
                version: "0.1".into(),
                category: "other".into(),
                is_installed: false,
                is_enabled: false,
                homepage: None,
                capabilities: vec![],
                platforms: vec![],
            },
        ];
        state.refilter();
        assert_eq!(state.selected_index, 0);

        state.handle_key(KeyCode::Char('j'));
        assert_eq!(state.selected_index, 1);

        state.handle_key(KeyCode::Char('k'));
        assert_eq!(state.selected_index, 0);
    }
}

