//! VoidB Application - Pure Router Architecture (v4.0)
//!
//! This module implements the VoidB shell as a pure router.
//! The shell ONLY manages tabs and routes events - all UI is plugin-controlled.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use crossterm::event::{self, KeyCode, KeyEvent, KeyModifiers};
use futures::StreamExt;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{ListItem, Paragraph};
use ratatui::{DefaultTerminal, Frame};
use serde_json::{Value, json};
use tokio::sync::{RwLock, mpsc};

use voidb_core::{
    ConnectionConfigRegistry, Event, Plugin, PluginRegistry, ShellCapabilities, TabManager,
    config::AppConfig,
};

use crate::plugins::ConnectionManagerPluginFactory;

/// Hard global actions — always intercepted, even when plugin wants raw input
#[derive(Debug, Clone, Copy)]
enum HardGlobalAction {
    Quit,        // Ctrl+Q: Quit VoidB
    ShellEscape, // Ctrl+\: Open shell escape menu (Tab Manager)
}

/// Soft global actions — only intercepted when plugin does NOT want raw input
#[derive(Debug, Clone, Copy)]
enum SoftGlobalAction {
    GoHome,          // q: Return to Connection Manager (tab 0)
    CloseCurrentTab, // Q (Shift+Q): Close the current tab
    ShowTabList,     // Ctrl+L: Show Tab Manager popup
}

/// A tab containing a plugin instance
struct Tab {
    /// Tab title
    title: String,
    /// Plugin instance
    plugin: Box<dyn Plugin>,
    /// Plugin-specific context used to create this tab
    context: Value,
}

/// Tab operation requests from plugins
#[derive(Debug)]
enum TabRequest {
    /// Open a new tab
    Open {
        title: String,
        plugin_id: String,
        context: Value,
    },
    /// Close the current tab
    CloseCurrent,
    /// Set current tab title
    SetTitle(String),
    /// List all tabs (response via oneshot channel)
    ListTabs(tokio::sync::oneshot::Sender<Vec<voidb_core::TabInfo>>),
    /// Close a specific tab by index
    CloseTab(usize),
    /// Switch to a specific tab by index
    SwitchTo(usize),
    /// Get active tab index
    GetActiveIndex(tokio::sync::oneshot::Sender<usize>),
    /// Quit the application
    Quit,
}

/// Tab Manager popup state
struct TabManagerPopup {
    /// Selected index in the filtered list
    selected: usize,
    /// Cached tab info
    tabs: Vec<voidb_core::TabInfo>,
    /// Search mode active
    search_active: bool,
    /// Search input buffer
    search_buffer: String,
    /// Filtered indices into self.tabs
    filtered_indices: Vec<usize>,
}

impl TabManagerPopup {
    fn refilter(&mut self) {
        if self.search_buffer.is_empty() {
            self.filtered_indices = (0..self.tabs.len()).collect();
        } else {
            let lower = self.search_buffer.to_lowercase();
            self.filtered_indices = self
                .tabs
                .iter()
                .enumerate()
                .filter(|(_, tab)| {
                    tab.title.to_lowercase().contains(&lower)
                        || tab.plugin_id.to_lowercase().contains(&lower)
                        || tab
                            .connection_id()
                            .unwrap_or_default()
                            .to_lowercase()
                            .contains(&lower)
                })
                .map(|(i, _)| i)
                .collect();
        }
        self.selected = 0;
    }

    fn insert_char(&mut self, c: char) {
        self.search_buffer.push(c);
        self.refilter();
    }

    fn delete_char(&mut self) {
        self.search_buffer.pop();
        self.refilter();
    }
}

/// Main VoidB application (pure router)
pub struct App {
    /// All tabs
    tabs: Vec<Tab>,
    /// Active tab index
    active_tab: usize,
    /// Plugin registry (for creating new plugins)
    plugin_registry: Arc<PluginRegistry>,
    /// Connection registry (shared data source)
    #[allow(dead_code)]
    connections: Arc<RwLock<ConnectionConfigRegistry>>,
    /// Shell capabilities (provided to plugins)
    capabilities: ShellCapabilities,
    /// Tab request receiver (from plugins)
    tab_rx: mpsc::UnboundedReceiver<TabRequest>,
    /// Render request receiver (from plugins)
    render_rx: mpsc::UnboundedReceiver<()>,
    /// Tab Manager popup (if active)
    tab_manager_popup: Option<TabManagerPopup>,
    /// Whether to quit
    should_quit: bool,
}

impl App {
    /// Create a new VoidB application
    pub fn new(config: AppConfig) -> Result<Self> {
        // Create connection registry from config
        let connections = Arc::new(RwLock::new(ConnectionConfigRegistry::from_connections(
            config.connections.clone(),
        )));

        // Create plugin registry
        let mut plugin_registry = PluginRegistry::new();

        // Register built-in plugins
        plugin_registry.register(Box::new(ConnectionManagerPluginFactory));

        // Wrap registry in Arc for sharing
        let plugin_registry = Arc::new(plugin_registry);

        // Create tab request channel
        let (tab_tx, tab_rx) = mpsc::unbounded_channel();

        // Create render request channel
        let (render_tx, render_rx) = mpsc::unbounded_channel();

        // Create tab manager with both senders
        let tab_manager = Arc::new(AppTabManager::new(tab_tx, render_tx));

        // Build shell capabilities (ARCH-04: inject shared runtime handle)
        let capabilities = ShellCapabilities::new(
            connections.clone(),
            tab_manager.clone() as Arc<dyn TabManager>,
            plugin_registry.clone(),
            tokio::runtime::Handle::current(),
        );

        // Create initial tab (Connection Manager)
        let connection_manager = plugin_registry.create("connection-manager", json!({}))?;
        let tabs = vec![Tab {
            title: "🔌 Connections".to_string(),
            plugin: connection_manager,
            context: json!({}),
        }];

        Ok(Self {
            tabs,
            active_tab: 0,
            plugin_registry,
            connections,
            capabilities,
            tab_rx,
            render_rx,
            tab_manager_popup: None,
            should_quit: false,
        })
    }

    /// Initialize all plugins
    fn init_plugins(&mut self) -> Result<()> {
        for tab in &mut self.tabs {
            tab.plugin.init(self.capabilities.clone())?;
        }
        Ok(())
    }

    /// Run the application event loop
    pub async fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        // Initialize plugins
        self.init_plugins()?;

        // If no tabs, show empty state message
        if self.tabs.is_empty() {
            eprintln!("No plugins registered. Please register plugins first.");
            return Ok(());
        }

        // Initial render (fix black screen on startup)
        terminal.draw(|frame| {
            if let Err(e) = self.render_frame(frame, None) {
                eprintln!("Render error: {}", e);
            }
        })?;

        let mut event_stream = event::EventStream::new();

        loop {
            // Wait for either a crossterm event or a plugin render request
            let event = tokio::select! {
                biased;
                // Plugin requested a render (e.g. SSH received data)
                _ = self.render_rx.recv() => {
                    // Drain any extra queued render requests
                    while self.render_rx.try_recv().is_ok() {}
                    Event::Tick
                }
                // Terminal event from crossterm
                ct_event = event_stream.next() => {
                    match ct_event {
                        Some(Ok(event::Event::Key(key)))
                            if key.kind == crossterm::event::KeyEventKind::Press
                                || key.kind == crossterm::event::KeyEventKind::Repeat =>
                        {
                            Event::Key(key)
                        }
                        Some(Ok(event::Event::Mouse(mouse))) => Event::Mouse(mouse),
                        Some(Ok(event::Event::Paste(text))) => Event::Paste(text),
                        Some(Ok(event::Event::Resize(w, h))) => Event::Resize {
                            width: w,
                            height: h,
                        },
                        Some(Ok(_)) => continue,
                        Some(Err(e)) => return Err(e.into()),
                        None => break, // Stream ended
                    }
                }
            };

            // Handle Tick: render with Tick event (lets plugins poll their channels)
            if matches!(event, Event::Tick) {
                terminal.draw(|frame| {
                    if let Err(e) = self.render_frame(frame, Some(Event::Tick)) {
                        eprintln!("Render error: {}", e);
                    }
                })?;
                continue;
            }

            // If Tab Manager popup is open, handle its events first
            if self.tab_manager_popup.is_some() {
                let handled = self.handle_tab_manager_event(&event);
                terminal.draw(|frame| {
                    if let Err(e) = self.render_frame(frame, None) {
                        eprintln!("Render error: {}", e);
                    }
                })?;
                if handled {
                    continue;
                }
            }

            // 1. Check hard global shortcuts (unconditional — plugins cannot override)
            if let Some(action) = self.check_hard_global(&event) {
                self.handle_hard_global(action);
                if self.should_quit {
                    break;
                }
                terminal.draw(|frame| {
                    if let Err(e) = self.render_frame(frame, None) {
                        eprintln!("Render error: {}", e);
                    }
                })?;
                continue;
            }

            // 2. If active plugin wants raw input, skip soft globals
            let raw_mode = self
                .tabs
                .get(self.active_tab)
                .map(|tab| tab.plugin.wants_raw_input())
                .unwrap_or(false);

            if !raw_mode {
                // 3. Check soft global shortcuts (only when plugin does NOT want raw input)
                if let Some(action) = self.check_soft_global(&event) {
                    self.handle_soft_global(action);
                    if self.should_quit {
                        break;
                    }
                    terminal.draw(|frame| {
                        if let Err(e) = self.render_frame(frame, None) {
                            eprintln!("Render error: {}", e);
                        }
                    })?;
                    continue;
                }
            }

            // 4. Route event to active plugin
            terminal.draw(|frame| {
                if let Err(e) = self.render_frame(frame, Some(event.clone())) {
                    eprintln!("Render error: {}", e);
                }
            })?;

            // 4. Process tab requests from plugins
            let mut had_tab_request = false;
            while let Ok(request) = self.tab_rx.try_recv() {
                if let Err(e) = self.handle_tab_request(request) {
                    eprintln!("Tab request error: {}", e);
                } else {
                    had_tab_request = true;
                }
            }

            // 5. If tab was opened/closed, re-render immediately
            if had_tab_request {
                terminal.draw(|frame| {
                    if let Err(e) = self.render_frame(frame, None) {
                        eprintln!("Render error: {}", e);
                    }
                })?;
            }

            // 6. Check quit condition
            if self.should_quit {
                break;
            }
        }

        Ok(())
    }

    /// Render a single frame
    fn render_frame(&mut self, frame: &mut Frame, event: Option<Event>) -> Result<()> {
        let area = frame.area();

        // Check minimum terminal size to prevent panic
        const MIN_WIDTH: u16 = 40;
        const MIN_HEIGHT: u16 = 10;

        if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
            // Terminal too small - show warning message
            let warning = ratatui::widgets::Paragraph::new(format!(
                "Terminal too small!\nMinimum: {}x{}\nCurrent: {}x{}",
                MIN_WIDTH, MIN_HEIGHT, area.width, area.height
            ))
            .style(ratatui::style::Style::default().fg(ratatui::style::Color::Red))
            .alignment(ratatui::layout::Alignment::Center);
            frame.render_widget(warning, area);
            return Ok(());
        }

        // Layout: [Tab Bar (1 line) | Plugin Area (rest)]
        let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(area);

        // Render tab bar
        self.render_tab_bar(frame, chunks[0]);

        // Render active plugin
        if let Some(tab) = self.tabs.get_mut(self.active_tab) {
            tab.plugin.update(frame, chunks[1], event)?;
        }

        // Render Tab Manager popup on top if active
        if let Some(popup) = &self.tab_manager_popup {
            self.render_tab_manager_popup(frame, area, popup);
        }

        Ok(())
    }

    /// Render tab bar at the top
    fn render_tab_bar(&self, frame: &mut Frame, area: Rect) {
        let mut spans: Vec<Span> = self
            .tabs
            .iter()
            .enumerate()
            .map(|(i, tab)| {
                let style = if i == self.active_tab {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                };
                Span::styled(format!(" {} ", tab.title), style)
            })
            .collect();

        // Right-aligned global shortcut hints (vary by raw mode)
        let is_raw = self
            .tabs
            .get(self.active_tab)
            .map(|tab| tab.plugin.wants_raw_input())
            .unwrap_or(false);
        let hint = if self.active_tab == 0 {
            " ^L:tabs  ^Q:quit "
        } else if is_raw {
            // ^4 is the same byte as ^\ in terminals without modifyOtherKeys
            // (e.g. VSCode/Cursor), where ^\ is reported as Ctrl+4.
            " ^\\/^4:menu  ^Q:quit "
        } else {
            " q:home  Q:close  ^L:tabs  ^Q:quit "
        };
        let tabs_width: usize = spans.iter().map(|s| s.width()).sum();
        let hint_width = hint.len();
        // Guard against narrow terminals: naive subtraction underflows usize and
        // either panics in debug or allocates a gigantic string via " ".repeat.
        let padding = (area.width as usize)
            .saturating_sub(tabs_width)
            .saturating_sub(hint_width);
        if padding > 0 {
            spans.push(Span::raw(" ".repeat(padding)));
        }
        spans.push(Span::styled(hint, Style::default().fg(Color::DarkGray)));

        let tabs_line = Line::from(spans);
        let tabs_widget = Paragraph::new(tabs_line);
        frame.render_widget(tabs_widget, area);
    }

    /// Check if event is a hard global shortcut (always intercepted, even in raw mode)
    fn check_hard_global(&self, event: &Event) -> Option<HardGlobalAction> {
        if let Event::Key(KeyEvent {
            code, modifiers, ..
        }) = event
        {
            // Ctrl+Q - quit VoidB
            if *code == KeyCode::Char('q') && modifiers.contains(KeyModifiers::CONTROL) {
                return Some(HardGlobalAction::Quit);
            }

            // Ctrl+\ - shell escape menu (always available, even in raw mode).
            //
            // Terminals that do not implement modifyOtherKeys / kitty keyboard
            // protocol (e.g. VSCode / Cursor integrated terminals) forward Ctrl+\
            // as the raw byte 0x1C. crossterm then decodes it as Ctrl+4 rather
            // than Ctrl+\. Accept both so the menu shortcut works everywhere.
            if modifiers.contains(KeyModifiers::CONTROL)
                && (*code == KeyCode::Char('\\') || *code == KeyCode::Char('4'))
            {
                return Some(HardGlobalAction::ShellEscape);
            }
        }

        None
    }

    /// Check if event is a soft global shortcut (only when plugin does NOT want raw input)
    fn check_soft_global(&self, event: &Event) -> Option<SoftGlobalAction> {
        if let Event::Key(KeyEvent {
            code, modifiers, ..
        }) = event
        {
            // q - return to home (Connection Manager)
            if *code == KeyCode::Char('q') && modifiers.is_empty() && self.active_tab != 0 {
                return Some(SoftGlobalAction::GoHome);
            }

            // Q (Shift+Q) - close current tab
            if *code == KeyCode::Char('Q') && self.active_tab != 0 {
                return Some(SoftGlobalAction::CloseCurrentTab);
            }

            // Ctrl+L - show Tab Manager popup
            if *code == KeyCode::Char('l') && modifiers.contains(KeyModifiers::CONTROL) {
                return Some(SoftGlobalAction::ShowTabList);
            }
        }

        None
    }

    /// Handle hard global action
    fn handle_hard_global(&mut self, action: HardGlobalAction) {
        match action {
            HardGlobalAction::Quit => {
                self.should_quit = true;
            }
            HardGlobalAction::ShellEscape => {
                self.show_tab_manager();
            }
        }
    }

    /// Handle soft global action
    fn handle_soft_global(&mut self, action: SoftGlobalAction) {
        match action {
            SoftGlobalAction::GoHome => {
                if !self.tabs.is_empty() {
                    self.active_tab = 0;
                }
            }
            SoftGlobalAction::CloseCurrentTab => {
                let _ = self.close_current_tab();
            }
            SoftGlobalAction::ShowTabList => {
                self.show_tab_manager();
            }
        }
    }

    /// Show Tab Manager popup
    fn show_tab_manager(&mut self) {
        let tabs = self.tab_infos();

        let filtered_indices = (0..tabs.len()).collect();
        self.tab_manager_popup = Some(TabManagerPopup {
            selected: self.active_tab,
            tabs,
            search_active: false,
            search_buffer: String::new(),
            filtered_indices,
        });
    }

    /// Open a new tab (called by plugins via TabManager)
    fn open_tab(&mut self, title: String, plugin_id: String, context: Value) -> Result<()> {
        let mut plugin = self.plugin_registry.create(&plugin_id, context.clone())?;
        plugin.init(self.capabilities.clone())?;

        self.tabs.push(Tab {
            title,
            plugin,
            context,
        });
        self.active_tab = self.tabs.len() - 1;

        Ok(())
    }

    fn tab_infos(&self) -> Vec<voidb_core::TabInfo> {
        self.tabs
            .iter()
            .enumerate()
            .map(|(index, tab)| voidb_core::TabInfo {
                index,
                title: tab.title.clone(),
                plugin_id: tab.plugin.id().to_string(),
                context: tab.context.clone(),
                is_active: index == self.active_tab,
            })
            .collect()
    }

    /// Close current tab (called by plugins via TabManager)
    fn close_current_tab(&mut self) -> Result<()> {
        if self.tabs.len() > 1 {
            self.tabs.remove(self.active_tab);
            if self.active_tab >= self.tabs.len() {
                self.active_tab = self.tabs.len() - 1;
            }
        } else {
            // Last tab - quit application
            self.should_quit = true;
        }
        Ok(())
    }

    /// Set current tab title (called by plugins via TabManager)
    fn set_tab_title(&mut self, title: String) -> Result<()> {
        if let Some(tab) = self.tabs.get_mut(self.active_tab) {
            tab.title = title;
        }
        Ok(())
    }

    /// Handle tab request from plugin
    fn handle_tab_request(&mut self, request: TabRequest) -> Result<()> {
        match request {
            TabRequest::Open {
                title,
                plugin_id,
                context,
            } => self.open_tab(title, plugin_id, context),
            TabRequest::CloseCurrent => self.close_current_tab(),
            TabRequest::SetTitle(title) => self.set_tab_title(title),
            TabRequest::ListTabs(tx) => {
                let _ = tx.send(self.tab_infos());
                Ok(())
            }
            TabRequest::CloseTab(index) => {
                if index < self.tabs.len() && self.tabs.len() > 1 {
                    self.tabs.remove(index);
                    if self.active_tab >= self.tabs.len() {
                        self.active_tab = self.tabs.len() - 1;
                    }
                }
                Ok(())
            }
            TabRequest::SwitchTo(index) => {
                if index < self.tabs.len() {
                    self.active_tab = index;
                }
                Ok(())
            }
            TabRequest::GetActiveIndex(tx) => {
                let _ = tx.send(self.active_tab);
                Ok(())
            }
            TabRequest::Quit => {
                self.should_quit = true;
                Ok(())
            }
        }
    }

    /// Handle Tab Manager popup event
    /// Returns true if event was handled
    fn handle_tab_manager_event(&mut self, event: &Event) -> bool {
        if let Event::Key(key) = event
            && let Some(popup) = &mut self.tab_manager_popup
        {
            if popup.search_active {
                // Search mode
                match key.code {
                    KeyCode::Esc => {
                        popup.search_active = false;
                        popup.search_buffer.clear();
                        popup.refilter();
                        return true;
                    }
                    KeyCode::Backspace => {
                        popup.delete_char();
                        return true;
                    }
                    KeyCode::Up => {
                        if popup.selected > 0 {
                            popup.selected -= 1;
                        }
                        return true;
                    }
                    KeyCode::Down => {
                        if popup.selected < popup.filtered_indices.len().saturating_sub(1) {
                            popup.selected += 1;
                        }
                        return true;
                    }
                    KeyCode::Enter => {
                        if let Some(&real_idx) = popup.filtered_indices.get(popup.selected) {
                            let tab_index = popup.tabs[real_idx].index;
                            self.tab_manager_popup = None;
                            if tab_index < self.tabs.len() {
                                self.active_tab = tab_index;
                            }
                        }
                        return true;
                    }
                    KeyCode::Char(c) => {
                        popup.insert_char(c);
                        return true;
                    }
                    _ => return true,
                }
            } else {
                // Normal mode
                match key.code {
                    KeyCode::Char('/') => {
                        popup.search_active = true;
                        popup.search_buffer.clear();
                        return true;
                    }
                    KeyCode::Esc | KeyCode::Char('q') => {
                        self.tab_manager_popup = None;
                        return true;
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        if popup.selected < popup.filtered_indices.len().saturating_sub(1) {
                            popup.selected += 1;
                        }
                        return true;
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        if popup.selected > 0 {
                            popup.selected -= 1;
                        }
                        return true;
                    }
                    KeyCode::Enter => {
                        if let Some(&real_idx) = popup.filtered_indices.get(popup.selected) {
                            let tab_index = popup.tabs[real_idx].index;
                            self.tab_manager_popup = None;
                            if tab_index < self.tabs.len() {
                                self.active_tab = tab_index;
                            }
                        }
                        return true;
                    }
                    KeyCode::Char('d') | KeyCode::Char('x') => {
                        if let Some(&real_idx) = popup.filtered_indices.get(popup.selected) {
                            let tab_index = popup.tabs[real_idx].index;
                            if self.tabs.len() > 1 && tab_index < self.tabs.len() {
                                self.tabs.remove(tab_index);
                                if self.active_tab >= self.tabs.len() {
                                    self.active_tab = self.tabs.len() - 1;
                                }
                                // Refresh tab list
                                self.show_tab_manager();
                            }
                        }
                        return true;
                    }
                    _ => {}
                }
            }
        }
        false
    }

    /// Render Tab Manager popup
    fn render_tab_manager_popup(&self, frame: &mut Frame, area: Rect, popup: &TabManagerPopup) {
        use ratatui::widgets::{Block, Borders, Clear, List, ListState};

        // Center popup (60% width, 70% height)
        let popup_area = Self::centered_rect(60, 70, area);

        // Clear the background area (make it opaque)
        frame.render_widget(Clear, popup_area);

        // Block title
        let title = if popup.search_active && !popup.search_buffer.is_empty() {
            format!(
                " Tab Manager ({}/{}) ",
                popup.filtered_indices.len(),
                popup.tabs.len()
            )
        } else {
            " Tab Manager ".to_string()
        };

        // Render block with background
        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .style(Style::default().bg(Color::Black));

        frame.render_widget(block, popup_area);

        // Inner area
        let inner = Rect {
            x: popup_area.x + 1,
            y: popup_area.y + 1,
            width: popup_area.width.saturating_sub(2),
            height: popup_area.height.saturating_sub(2),
        };

        if popup.search_active {
            // Layout: [SearchBar(1) | List(rest) | Help(1)]
            let chunks = Layout::vertical([
                Constraint::Length(1),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .split(inner);

            // Search bar
            let search_line = Line::from(vec![
                Span::styled(" /: ", Style::default().fg(Color::Yellow)),
                if popup.search_buffer.is_empty() {
                    Span::styled(
                        "(type to filter)",
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::ITALIC),
                    )
                } else {
                    Span::styled(&popup.search_buffer, Style::default().fg(Color::White))
                },
                Span::styled("▌", Style::default().fg(Color::Cyan)),
            ]);
            frame.render_widget(Paragraph::new(search_line), chunks[0]);

            // Tab list (filtered)
            let items = self.build_tab_list_items(popup);
            let list = List::new(items)
                .highlight_style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("> ");

            let mut state = ListState::default();
            if !popup.filtered_indices.is_empty() {
                state.select(Some(popup.selected));
            }
            frame.render_stateful_widget(list, chunks[1], &mut state);

            // Help
            let help = Paragraph::new(Line::from(vec![
                Span::styled("↑↓", Style::default().fg(Color::Yellow)),
                Span::raw(": Navigate  "),
                Span::styled("Enter", Style::default().fg(Color::Yellow)),
                Span::raw(": Switch  "),
                Span::styled("Esc", Style::default().fg(Color::Yellow)),
                Span::raw(": Exit search"),
            ]));
            frame.render_widget(help, chunks[2]);
        } else {
            // Layout: [List(rest) | Help(1)]
            let chunks = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);

            // Tab list (filtered — shows all when no search)
            let items = self.build_tab_list_items(popup);
            let list = List::new(items)
                .highlight_style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("> ");

            let mut state = ListState::default();
            if !popup.filtered_indices.is_empty() {
                state.select(Some(popup.selected));
            }
            frame.render_stateful_widget(list, chunks[0], &mut state);

            // Help
            let help = Paragraph::new(Line::from(vec![
                Span::styled("j/k", Style::default().fg(Color::Yellow)),
                Span::raw(": Navigate  "),
                Span::styled("Enter", Style::default().fg(Color::Yellow)),
                Span::raw(": Switch  "),
                Span::styled("d/x", Style::default().fg(Color::Yellow)),
                Span::raw(": Close  "),
                Span::styled("/", Style::default().fg(Color::Yellow)),
                Span::raw(": Search  "),
                Span::styled("Esc", Style::default().fg(Color::Yellow)),
                Span::raw(": Close"),
            ]));
            frame.render_widget(help, chunks[1]);
        }
    }

    /// Build tab list items from filtered indices
    fn build_tab_list_items<'a>(&self, popup: &'a TabManagerPopup) -> Vec<ListItem<'a>> {
        popup
            .filtered_indices
            .iter()
            .filter_map(|&idx| popup.tabs.get(idx))
            .map(|tab_info| {
                let active_marker = if tab_info.is_active { "● " } else { "  " };
                let conn_info = tab_info
                    .connection_id()
                    .map(|id| format!(" [{}]", id))
                    .unwrap_or_default();
                let text = format!(
                    "{}{:2}. {} ({}){}",
                    active_marker,
                    tab_info.index + 1,
                    tab_info.title,
                    tab_info.plugin_id,
                    conn_info
                );
                ListItem::new(text)
            })
            .collect()
    }

    /// Helper to create a centered rect
    fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
        let popup_layout = Layout::vertical([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

        Layout::horizontal([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
    }
}

/// Tab manager implementation (provides tab operations to plugins)
struct AppTabManager {
    /// Channel sender for tab requests
    tx: mpsc::UnboundedSender<TabRequest>,
    /// Channel sender for render requests
    render_tx: mpsc::UnboundedSender<()>,
}

impl AppTabManager {
    fn new(tx: mpsc::UnboundedSender<TabRequest>, render_tx: mpsc::UnboundedSender<()>) -> Self {
        Self { tx, render_tx }
    }
}

impl TabManager for AppTabManager {
    fn open(&self, title: String, plugin_id: String, context: Value) -> Result<()> {
        self.tx
            .send(TabRequest::Open {
                title,
                plugin_id,
                context,
            })
            .map_err(|e| anyhow!("Failed to send tab open request: {}", e))
    }

    fn close_current(&self) -> Result<()> {
        self.tx
            .send(TabRequest::CloseCurrent)
            .map_err(|e| anyhow!("Failed to send tab close request: {}", e))
    }

    fn set_title(&self, title: String) -> Result<()> {
        self.tx
            .send(TabRequest::SetTitle(title))
            .map_err(|e| anyhow!("Failed to send tab title request: {}", e))
    }

    fn request_render(&self) -> Result<()> {
        self.render_tx
            .send(())
            .map_err(|e| anyhow!("Failed to send render request: {}", e))
    }

    fn list_tabs(&self) -> Result<Vec<voidb_core::TabInfo>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx
            .send(TabRequest::ListTabs(tx))
            .map_err(|e| anyhow!("Failed to send list tabs request: {}", e))?;
        // Block on async receive
        rx.blocking_recv()
            .map_err(|e| anyhow!("Failed to receive tab list: {}", e))
    }

    fn close_tab(&self, index: usize) -> Result<()> {
        self.tx
            .send(TabRequest::CloseTab(index))
            .map_err(|e| anyhow!("Failed to send close tab request: {}", e))
    }

    fn switch_to(&self, index: usize) -> Result<()> {
        self.tx
            .send(TabRequest::SwitchTo(index))
            .map_err(|e| anyhow!("Failed to send switch tab request: {}", e))
    }

    fn active_tab_index(&self) -> Result<usize> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx
            .send(TabRequest::GetActiveIndex(tx))
            .map_err(|e| anyhow!("Failed to send get active index request: {}", e))?;
        rx.blocking_recv()
            .map_err(|e| anyhow!("Failed to receive active index: {}", e))
    }

    fn quit(&self) -> Result<()> {
        self.tx
            .send(TabRequest::Quit)
            .map_err(|e| anyhow!("Failed to send quit request: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use voidb_core::config::AppConfig;

    #[tokio::test]
    async fn tab_info_preserves_open_context() {
        let mut app = App::new(AppConfig::default()).expect("create app");
        let context = json!({
            "connection_id": "profile-1",
            "plugin_id": "sqlite",
            "profile_name": "Local SQLite"
        });

        app.open_tab(
            "SQLite - Local SQLite".to_string(),
            "connection-manager".to_string(),
            context.clone(),
        )
        .expect("open connection manager tab");

        let tabs = app.tab_infos();
        assert_eq!(tabs.len(), 2);
        assert_eq!(tabs[1].context, context);
        assert_eq!(tabs[1].connection_id().as_deref(), Some("profile-1"));
        assert!(tabs[1].is_active);

        app.show_tab_manager();
        let popup = app.tab_manager_popup.as_ref().expect("tab manager popup");
        assert_eq!(popup.tabs[1].context, context);
        assert_eq!(popup.tabs[1].connection_id().as_deref(), Some("profile-1"));
    }
}
