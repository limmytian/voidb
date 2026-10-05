//! Connection Dialog Component
//!
//! A modal dialog for creating/editing database connections.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use serde_json::{Value, json};

use voidb_core::{ConnectionConfig, DatabaseType};

/// A selectable connection type entry in the dialog.
/// Covers both built-in database types and plugin-provided types.
#[derive(Debug, Clone)]
pub struct ConnType {
    pub label: String,
    pub db_type: DatabaseType,
    pub plugin_id: Option<String>,
    pub default_port: u16,
    pub default_username: String,
    pub default_host: String,
}

impl ConnType {
    /// Built-in database type helper
    pub fn builtin(
        label: &str,
        db_type: DatabaseType,
        default_port: u16,
        default_username: &str,
    ) -> Self {
        Self {
            label: label.to_string(),
            db_type,
            plugin_id: None,
            default_port,
            default_username: default_username.to_string(),
            default_host: "localhost".to_string(),
        }
    }

    /// Plugin type helper
    pub fn plugin(
        label: &str,
        plugin_id: &str,
        default_port: u16,
        default_host: &str,
        default_username: &str,
    ) -> Self {
        Self {
            label: label.to_string(),
            db_type: DatabaseType::Plugin,
            plugin_id: Some(plugin_id.to_string()),
            default_port,
            default_username: default_username.to_string(),
            default_host: default_host.to_string(),
        }
    }
}

fn config_string(config: Option<&Value>, key: &str) -> Option<String> {
    config
        .and_then(|value| value.get(key))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn config_u16(config: Option<&Value>, key: &str) -> Option<u16> {
    config
        .and_then(|value| value.get(key))
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
}

fn optional_string(value: &str) -> Value {
    if value.trim().is_empty() {
        Value::Null
    } else {
        json!(value)
    }
}

fn required_or_default(value: &str, default: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        value.to_string()
    }
}

/// Default connection types (built-in only, used as fallback)
pub fn default_conn_types() -> Vec<ConnType> {
    vec![
        ConnType::builtin("MySQL", DatabaseType::MySQL, 3306, "root"),
        ConnType::builtin("PostgreSQL", DatabaseType::PostgreSQL, 5432, "postgres"),
        ConnType::builtin("SQLite", DatabaseType::SQLite, 0, ""),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    DbType,
    Name,
    Host,
    Port,
    Username,
    Password,
    Database,
}

impl Field {
    const ALL: &'static [Field] = &[
        Field::DbType,
        Field::Name,
        Field::Host,
        Field::Port,
        Field::Username,
        Field::Password,
        Field::Database,
    ];

    fn label(&self) -> &'static str {
        match self {
            Field::DbType => "Type",
            Field::Name => "Name",
            Field::Host => "Host",
            Field::Port => "Port",
            Field::Username => "Username",
            Field::Password => "Password",
            Field::Database => "Database",
        }
    }
}

pub struct ConnectionDialog {
    conn_types: Vec<ConnType>,
    type_idx: usize,
    focused_field: usize,
    name: String,
    host: String,
    port: String,
    username: String,
    password: String,
    database: String,
}

fn find_type_index(conn_types: &[ConnType], config: &ConnectionConfig) -> usize {
    if config.db_type == DatabaseType::Plugin {
        // Match by plugin_id
        conn_types
            .iter()
            .position(|ct| ct.db_type == DatabaseType::Plugin && ct.plugin_id == config.plugin_id)
            .unwrap_or(0)
    } else {
        conn_types
            .iter()
            .position(|ct| ct.db_type == config.db_type)
            .unwrap_or(0)
    }
}

impl ConnectionDialog {
    pub fn new(conn_types: Vec<ConnType>) -> Self {
        let types = if conn_types.is_empty() {
            default_conn_types()
        } else {
            conn_types
        };
        let first = &types[0];
        let host = first.default_host.clone();
        let port = first.default_port.to_string();
        let username = first.default_username.clone();
        Self {
            conn_types: types,
            type_idx: 0,
            focused_field: 0,
            name: String::new(),
            host,
            port,
            username,
            password: String::new(),
            database: String::new(),
        }
    }

    pub fn new_for_type(conn_types: Vec<ConnType>, selected: &ConnType) -> Self {
        let mut dialog = Self::new(conn_types);
        if let Some(idx) = dialog
            .conn_types
            .iter()
            .position(|ct| ct.db_type == selected.db_type && ct.plugin_id == selected.plugin_id)
        {
            dialog.type_idx = idx;
            dialog.apply_type_defaults();
        }
        dialog
    }

    pub fn from_config(config: &ConnectionConfig, conn_types: Vec<ConnType>) -> Self {
        let types = if conn_types.is_empty() {
            default_conn_types()
        } else {
            conn_types
        };
        let idx = find_type_index(&types, config);
        let plugin_config = config.plugin_config.as_ref();
        Self {
            conn_types: types,
            type_idx: idx,
            focused_field: 0,
            name: config.name.clone(),
            host: config_string(plugin_config, "host").unwrap_or_default(),
            port: config_u16(plugin_config, "port")
                .map(|port| port.to_string())
                .unwrap_or_default(),
            username: config_string(plugin_config, "username").unwrap_or_default(),
            password: config_string(plugin_config, "password").unwrap_or_default(),
            database: config_string(plugin_config, "database")
                .or_else(|| config_string(plugin_config, "path"))
                .or_else(|| config_u16(plugin_config, "db").map(|db| db.to_string()))
                .unwrap_or_default(),
        }
    }

    fn current_conn_type(&self) -> &ConnType {
        &self.conn_types[self.type_idx]
    }

    pub fn next_field(&mut self) {
        self.focused_field = (self.focused_field + 1) % Field::ALL.len();
    }

    pub fn prev_field(&mut self) {
        if self.focused_field == 0 {
            self.focused_field = Field::ALL.len() - 1;
        } else {
            self.focused_field -= 1;
        }
    }

    fn current_field(&self) -> Field {
        Field::ALL[self.focused_field]
    }

    /// Cycle connection type forward
    pub fn cycle_db_type_next(&mut self) {
        self.type_idx = (self.type_idx + 1) % self.conn_types.len();
        self.apply_type_defaults();
    }

    pub fn cycle_db_type_prev(&mut self) {
        if self.type_idx == 0 {
            self.type_idx = self.conn_types.len() - 1;
        } else {
            self.type_idx -= 1;
        }
        self.apply_type_defaults();
    }

    fn apply_type_defaults(&mut self) {
        let ct = &self.conn_types[self.type_idx];
        self.port = ct.default_port.to_string();
        self.host = ct.default_host.clone();
        if self.username.is_empty() || self.username == "root" || self.username == "postgres" {
            self.username = ct.default_username.clone();
        }
    }

    pub fn add_char(&mut self, c: char) {
        match self.current_field() {
            Field::DbType => {} // handled by cycle
            Field::Name => self.name.push(c),
            Field::Host => self.host.push(c),
            Field::Port => {
                if c.is_ascii_digit() {
                    self.port.push(c);
                }
            }
            Field::Username => self.username.push(c),
            Field::Password => self.password.push(c),
            Field::Database => self.database.push(c),
        }
    }

    pub fn delete_char(&mut self) {
        match self.current_field() {
            Field::DbType => {}
            Field::Name => {
                self.name.pop();
            }
            Field::Host => {
                self.host.pop();
            }
            Field::Port => {
                self.port.pop();
            }
            Field::Username => {
                self.username.pop();
            }
            Field::Password => {
                self.password.pop();
            }
            Field::Database => {
                self.database.pop();
            }
        }
    }

    /// Handle left/right arrow when on DbType field
    pub fn is_on_db_type_field(&self) -> bool {
        self.current_field() == Field::DbType
    }

    pub fn build_config(&self) -> Result<ConnectionConfig, String> {
        if self.name.trim().is_empty() {
            return Err("Name is required".to_string());
        }

        let ct = self.current_conn_type();

        let plugin_config = self.build_plugin_config(ct)?;

        Ok(ConnectionConfig {
            name: self.name.clone(),
            db_type: ct.db_type,
            plugin_id: ct.plugin_id.clone(),
            plugin_config,
        })
    }

    fn build_plugin_config(&self, ct: &ConnType) -> Result<Option<Value>, String> {
        let port = self.port.parse::<u16>().unwrap_or(ct.default_port);
        let optional_username = if self.username.trim().is_empty() {
            Value::Null
        } else {
            json!(self.username)
        };
        let optional_password = if self.password.is_empty() {
            Value::Null
        } else {
            json!(self.password)
        };

        let config = match (ct.db_type, ct.plugin_id.as_deref()) {
            (DatabaseType::MySQL, _) => json!({
                "host": required_or_default(&self.host, &ct.default_host),
                "port": port,
                "username": required_or_default(&self.username, &ct.default_username),
                "password": self.password,
                "database": optional_string(&self.database),
                "ssl_mode": null,
            }),
            (DatabaseType::PostgreSQL, _) => json!({
                "host": required_or_default(&self.host, &ct.default_host),
                "port": port,
                "username": required_or_default(&self.username, &ct.default_username),
                "password": self.password,
                "database": required_or_default(&self.database, "postgres"),
                "ssl_mode": null,
            }),
            (DatabaseType::SQLite, _) => {
                let path = self.database.trim();
                if path.is_empty() {
                    return Err("Database/path is required".to_string());
                }
                json!({ "path": path })
            }
            (DatabaseType::Plugin, Some("redis")) => json!({
                "host": required_or_default(&self.host, &ct.default_host),
                "port": port,
                "username": optional_username,
                "password": optional_password,
                "db": self.database.parse::<u8>().unwrap_or(0),
                "tls": false,
            }),
            (DatabaseType::Plugin, Some("duckdb")) => {
                let path = self.database.trim();
                if path.is_empty() {
                    return Err("Database/path is required".to_string());
                }
                json!({
                    "path": path,
                    "read_only": false,
                    "extensions": [],
                    "memory_limit": null,
                    "threads": null,
                })
            }
            (DatabaseType::Plugin, Some(_)) => json!({
                "host": self.host,
                "port": port,
                "username": optional_string(&self.username),
                "password": optional_string(&self.password),
                "database": optional_string(&self.database),
            }),
            (DatabaseType::Plugin, None) => return Ok(None),
        };

        Ok(Some(config))
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        if area.width < 60 || area.height < 20 {
            return;
        }

        let dialog_width = 60u16;
        let dialog_height = 20u16;
        let x = (area.width.saturating_sub(dialog_width)) / 2;
        let y = (area.height.saturating_sub(dialog_height)) / 2;

        let dialog_area = Rect {
            x: area.x + x,
            y: area.y + y,
            width: dialog_width,
            height: dialog_height,
        };

        frame.render_widget(Clear, dialog_area);

        let title = format!(" New {} Connection ", self.current_conn_type().label);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .style(Style::default().bg(Color::Black));

        frame.render_widget(block, dialog_area);

        let inner = dialog_area.inner(ratatui::layout::Margin {
            horizontal: 2,
            vertical: 1,
        });

        let chunks = Layout::vertical([Constraint::Length(14), Constraint::Length(3)]).split(inner);

        self.render_fields(frame, chunks[0]);
        self.render_buttons(frame, chunks[1]);
    }

    fn render_fields(&self, frame: &mut Frame, area: Rect) {
        let fields = Field::ALL;
        let chunks = Layout::vertical(
            fields
                .iter()
                .map(|_| Constraint::Length(2))
                .collect::<Vec<_>>(),
        )
        .split(area);

        for (i, field) in fields.iter().enumerate() {
            let is_focused = i == self.focused_field;

            let label_style = if is_focused {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };

            if *field == Field::DbType {
                let mut spans = vec![Span::styled(format!("{:12}", field.label()), label_style)];
                for (idx, ct) in self.conn_types.iter().enumerate() {
                    let selected = idx == self.type_idx;
                    let style = if selected && is_focused {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else if selected {
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };
                    spans.push(Span::styled(format!(" {} ", ct.label), style));
                    if idx < self.conn_types.len() - 1 {
                        spans.push(Span::raw(" "));
                    }
                }
                if is_focused {
                    spans.push(Span::styled("  ◀▶", Style::default().fg(Color::DarkGray)));
                }
                let paragraph = Paragraph::new(Line::from(spans));
                frame.render_widget(paragraph, chunks[i]);
            } else {
                let value = match field {
                    Field::Name => &self.name,
                    Field::Host => &self.host,
                    Field::Port => &self.port,
                    Field::Username => &self.username,
                    Field::Password => &self.password,
                    Field::Database => &self.database,
                    Field::DbType => unreachable!(),
                };

                let display_value = if matches!(field, Field::Password) {
                    "*".repeat(value.len())
                } else {
                    value.clone()
                };

                let value_style = Style::default().fg(Color::White);

                let cursor = if is_focused { "▏" } else { "" };

                let text = vec![Line::from(vec![
                    Span::styled(format!("{:12}", field.label()), label_style),
                    Span::styled(display_value, value_style),
                    Span::styled(cursor, Style::default().fg(Color::Yellow)),
                ])];

                let paragraph = Paragraph::new(text);
                frame.render_widget(paragraph, chunks[i]);
            }
        }
    }

    fn render_buttons(&self, frame: &mut Frame, area: Rect) {
        let help_text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("Tab", Style::default().fg(Color::Yellow)),
                Span::raw("/"),
                Span::styled("S-Tab", Style::default().fg(Color::Yellow)),
                Span::raw(": Navigate | "),
                Span::styled("Enter", Style::default().fg(Color::Yellow)),
                Span::raw(": Save | "),
                Span::styled("Esc", Style::default().fg(Color::Yellow)),
                Span::raw(": Cancel"),
            ]),
        ];

        let paragraph = Paragraph::new(help_text);
        frame.render_widget(paragraph, area);
    }
}
