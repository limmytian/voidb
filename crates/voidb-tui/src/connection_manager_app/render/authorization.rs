use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};

use super::centered_rect;
use crate::connection_manager_app::{
    AgentAuthorizationPresetKind, AuthorizationAction, AuthorizationStatusView,
    ConnectionManagerApp, JitApprovalDialog, JitDecision, format_use_limit,
};

impl ConnectionManagerApp {
    pub(super) fn render_authorization(&self, frame: &mut Frame, area: Rect) {
        let Some(dialog) = &self.authorization_dialog else {
            return;
        };
        let popup = centered_rect(88, 88, area);
        frame.render_widget(Clear, popup);
        let title = format!(
            " Agent authorization · {}/{} ",
            dialog.profile.plugin_id, dialog.profile.name
        );
        frame.render_widget(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
            popup,
        );
        let inner = popup.inner(ratatui::layout::Margin {
            horizontal: 2,
            vertical: 1,
        });
        let existing = self
            .authorization_statuses
            .get(&(dialog.profile.id.clone(), dialog.profile.plugin_id.clone()));
        if let Some(action) = dialog.review_action {
            let selected = dialog.selected_capabilities();
            let (heading, detail) = match action {
                AuthorizationAction::Authorize => (
                    if existing.is_some() {
                        "Review replacement"
                    } else {
                        "Review authorization"
                    },
                    format!(
                        "Preset: {}\nCapabilities: {}\nTTL: {} minutes\nUse limit: {}\nDestructive grant consent: {}\n\nThis does not acknowledge later destructive calls. Each call still requires --yes.",
                        dialog.preset_label(),
                        selected.join(", "),
                        dialog.ttl_minutes(),
                        format_use_limit(dialog.uses()),
                        if dialog.destructive_acknowledged {
                            "YES"
                        } else {
                            "no"
                        },
                    ),
                ),
                AuthorizationAction::Renew => (
                    "Review renewal",
                    format!(
                        "Keep immutable profile, plugin, capabilities, and destructive scope.\nNew TTL: {} minutes\nUse limit: {}",
                        dialog.ttl_minutes(),
                        format_use_limit(dialog.uses())
                    ),
                ),
                AuthorizationAction::RevokeProfile => (
                    "Review profile revoke",
                    "Close sessions and revoke only this immutable Profile ID and plugin grant."
                        .into(),
                ),
                AuthorizationAction::RevokeAll => (
                    "Review revoke all",
                    "Secondary global action: close sessions and revoke every local agent grant."
                        .into(),
                ),
            };
            frame.render_widget(
                Paragraph::new(Text::from(vec![
                    Line::styled(
                        heading,
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Line::raw(""),
                    Line::raw(detail),
                    Line::raw(""),
                    Line::styled(
                        "Enter confirm · Esc back",
                        Style::default().fg(Color::DarkGray),
                    ),
                    Line::styled(
                        dialog.message.as_deref().unwrap_or_default(),
                        Style::default().fg(Color::Yellow),
                    ),
                ]))
                .wrap(Wrap { trim: false }),
                inner,
            );
            return;
        }

        if !dialog.advanced {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(8),
                    Constraint::Length(4),
                ])
                .split(inner);
            let existing_text = existing
                .map(AuthorizationStatusView::detail)
                .unwrap_or_else(|| "OFF · no active grant".to_string());
            frame.render_widget(
                Paragraph::new(existing_text).block(
                    Block::default()
                        .title(" Current access ")
                        .borders(Borders::ALL),
                ),
                rows[0],
            );
            let read_only_count = dialog
                .capabilities
                .iter()
                .filter(|capability| capability.risk == "read_only")
                .count();
            let quick_access = if dialog.loading {
                "Loading the safe read-only capability set...".to_string()
            } else if read_only_count == 0 {
                "This plugin has no agent-ready read-only capabilities.".to_string()
            } else {
                format!(
                    "Allow read-only agent access\n\nProfile: {}/{}\nDuration: {} minutes\nBudget: {}\nSafe capabilities: {}\n\nCredentials stay inside the local broker. Write or destructive operations still require a specific approval.",
                    dialog.profile.plugin_id,
                    dialog.profile.name,
                    dialog.ttl_minutes(),
                    format_use_limit(dialog.uses()),
                    read_only_count,
                )
            };
            frame.render_widget(
                Paragraph::new(quick_access)
                    .wrap(Wrap { trim: true })
                    .block(
                        Block::default()
                            .title(" Quick read-only access · recommended ")
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Green)),
                    ),
                rows[1],
            );
            let controls = if existing.is_some() {
                "Enter review read-only access · r extend current · v revoke · a advanced · Esc close"
            } else {
                "Enter review and allow · a advanced · Esc close"
            };
            frame.render_widget(
                Paragraph::new(vec![
                    Line::styled(controls, Style::default().fg(Color::DarkGray)),
                    Line::styled(
                        dialog.message.as_deref().unwrap_or_default(),
                        Style::default().fg(Color::Yellow),
                    ),
                ])
                .wrap(Wrap { trim: true }),
                rows[2],
            );
            return;
        }

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(7),
                Constraint::Length(4),
            ])
            .split(inner);
        let existing_text = existing
            .map(AuthorizationStatusView::detail)
            .unwrap_or_else(|| "OFF · no active grant".to_string());
        frame.render_widget(
            Paragraph::new(existing_text).block(
                Block::default()
                    .title(" Current grant state ")
                    .borders(Borders::ALL),
            ),
            rows[0],
        );
        frame.render_widget(
            Paragraph::new(format!(
                "{}   ←/→ preset   t TTL={}m   u use-limit={}",
                dialog.preset_label(),
                dialog.ttl_minutes(),
                format_use_limit(dialog.uses())
            ))
            .block(Block::default().title(" Scope ").borders(Borders::ALL)),
            rows[1],
        );
        let acknowledgement = if dialog.requires_destructive_acknowledgement() {
            if dialog.destructive_acknowledged {
                "Destructive grant scope acknowledged: YES (d toggles)"
            } else {
                "Destructive grant scope requires acknowledgement (press d)"
            }
        } else {
            "No destructive grant acknowledgement required"
        };
        frame.render_widget(
            Paragraph::new(acknowledgement).style(Style::default().fg(
                if dialog.requires_destructive_acknowledgement() && !dialog.destructive_acknowledged
                {
                    Color::Yellow
                } else {
                    Color::Green
                },
            )),
            rows[2],
        );

        let selected = dialog.selected_capabilities();
        let items = if dialog.loading {
            vec![ListItem::new("Loading capability catalog...")]
        } else if dialog.capabilities.is_empty() {
            vec![ListItem::new("Unsupported: no agent-ready capabilities")]
        } else {
            dialog
                .capabilities
                .iter()
                .map(|capability| {
                    let checked = if selected.contains(&capability.id) {
                        "[x]"
                    } else {
                        "[ ]"
                    };
                    ListItem::new(format!("{checked} {} [{}]", capability.id, capability.risk))
                })
                .collect()
        };
        let mut state = ListState::default();
        if !dialog.capabilities.is_empty() {
            state.select(Some(dialog.capability_selected));
        }
        frame.render_stateful_widget(
            List::new(items)
                .highlight_symbol("▶ ")
                .highlight_style(Style::default().bg(Color::Rgb(30, 50, 65)))
                .block(
                    Block::default()
                        .title(if dialog.preset == AgentAuthorizationPresetKind::Custom {
                            " Capabilities · Space toggles Custom selection "
                        } else {
                            " Capabilities · preset-derived exact scope "
                        })
                        .borders(Borders::ALL),
                ),
            rows[3],
            &mut state,
        );
        let controls = if existing.is_some() {
            "Enter review authorize/replace · r renew · v revoke profile · x revoke all · a simple · Esc close"
        } else {
            "Enter review authorize · x revoke all · a simple · Esc close"
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(controls, Style::default().fg(Color::DarkGray)),
                Line::styled(
                    dialog.message.as_deref().unwrap_or_default(),
                    Style::default().fg(Color::Yellow),
                ),
            ])
            .wrap(Wrap { trim: true }),
            rows[4],
        );
    }

    pub(super) fn render_authorization_inbox(&self, frame: &mut Frame, area: Rect) {
        let popup = centered_rect(94, 92, area);
        frame.render_widget(Clear, popup);
        let pending_count = self
            .pending_authorization_requests
            .iter()
            .filter(|request| request.is_pending())
            .count();
        let title =
            format!(" JIT approval inbox · {pending_count} pending · canonical broker state ");
        frame.render_widget(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(
                    if self.authorization_snapshot_error.is_some() {
                        Color::Yellow
                    } else {
                        Color::Cyan
                    },
                )),
            popup,
        );
        let inner = popup.inner(ratatui::layout::Margin {
            horizontal: 2,
            vertical: 1,
        });
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Min(8),
                Constraint::Length(7),
                Constraint::Length(2),
            ])
            .split(inner);
        let freshness = match (
            &self.authorization_observed_at,
            &self.authorization_snapshot_error,
        ) {
            (Some(observed), None) => format!("Canonical refresh: {observed}"),
            (Some(observed), Some(error)) => {
                format!("STALE snapshot from {observed} · refresh failed: {error}")
            }
            (None, Some(error)) => format!("Canonical broker unavailable: {error}"),
            (None, None) => "Loading canonical approval inbox...".into(),
        };
        frame.render_widget(
            Paragraph::new(freshness).style(Style::default().fg(
                if self.authorization_snapshot_error.is_some() {
                    Color::Yellow
                } else {
                    Color::Green
                },
            )),
            rows[0],
        );
        let items = if self.pending_authorization_requests.is_empty() {
            vec![ListItem::new("No authorization requests")]
        } else {
            self.pending_authorization_requests
                .iter()
                .map(|request| {
                    let principal = request
                        .principal_fingerprint
                        .chars()
                        .take(24)
                        .collect::<String>();
                    let decision = if request.timed_out {
                        "\n    Auto-denied: review window expired".to_string()
                    } else {
                        request
                            .decision_reason
                            .as_ref()
                            .map_or_else(String::new, |reason| {
                                format!("\n    Decision: {}", sanitize_display_text(reason))
                            })
                    };
                    ListItem::new(format!(
                        "[{}] {} · {}/{} · {} · agent {}\n    {}{}",
                        request.status.to_uppercase(),
                        request.capability_id(),
                        request.plugin_id,
                        request.profile_id,
                        request.risk,
                        principal,
                        sanitize_display_text(&request.purpose),
                        decision,
                    ))
                })
                .collect()
        };
        let mut state = ListState::default();
        if !self.pending_authorization_requests.is_empty() {
            state.select(Some(self.authorization_inbox_selected));
        }
        frame.render_stateful_widget(
            List::new(items)
                .highlight_symbol("▶ ")
                .highlight_style(Style::default().bg(Color::Rgb(30, 50, 65)))
                .block(
                    Block::default()
                        .title(" Requests grouped by principal and immutable profile ")
                        .borders(Borders::ALL),
                ),
            rows[1],
            &mut state,
        );
        let detail = self
            .pending_authorization_requests
            .get(self.authorization_inbox_selected)
            .map(|request| {
                let revisions = self
                    .grant_revisions
                    .iter()
                    .filter(|revision| {
                        revision.principal_fingerprint == request.principal_fingerprint
                            && revision.profile_id == request.profile_id
                            && revision.plugin_id == request.plugin_id
                    })
                    .map(|revision| {
                        format!(
                            "{} r{} · {} · expires {}",
                            revision.grant_id,
                            revision.revision,
                            format_use_limit(revision.remaining_uses),
                            revision.expires_at
                        )
                    })
                    .collect::<Vec<_>>();
                format!(
                    "Created: {} · Expires: {}\nRequested scope: {}\nImmutable revisions: {}",
                    request.created_at,
                    request.expires_at,
                    serde_json::to_string(&request.scope).unwrap_or_else(|_| "invalid".into()),
                    if revisions.is_empty() {
                        "none".into()
                    } else {
                        revisions.join(" | ")
                    }
                )
            })
            .unwrap_or_else(|| "No selected request".into());
        frame.render_widget(
            Paragraph::new(detail).wrap(Wrap { trim: true }).block(
                Block::default()
                    .title(" Canonical details and revision history ")
                    .borders(Borders::ALL),
            ),
            rows[2],
        );
        frame.render_widget(
            Paragraph::new("j/k select · Enter review · d deny review · r refresh · Esc close")
                .style(Style::default().fg(Color::DarkGray)),
            rows[3],
        );
        if let Some(dialog) = &self.jit_approval_dialog {
            self.render_jit_approval_dialog(frame, area, dialog);
        }
    }

    pub(super) fn render_jit_approval_dialog(
        &self,
        frame: &mut Frame,
        area: Rect,
        dialog: &JitApprovalDialog,
    ) {
        let popup = centered_rect(82, 78, area);
        frame.render_widget(Clear, popup);
        let capability = self
            .authorization_capability_catalog
            .get(dialog.request.capability_id());
        let schema = capability
            .map(|item| {
                if item.approval_fields.is_empty() {
                    if item.capability_wide_allowed {
                        "Capability-wide approval is declared; no structured fields.".into()
                    } else {
                        "No compatible structured approval schema (fails closed).".into()
                    }
                } else {
                    format!(
                        "Declared review fields: {}",
                        item.approval_fields.join(" · ")
                    )
                }
            })
            .unwrap_or_else(|| {
                "Capability declaration unavailable (approval will fail closed).".into()
            });
        let decision_detail = match dialog.decision {
            JitDecision::Once => "One invocation/use, short bounded lifetime".into(),
            JitDecision::Bounded => format!(
                "{} minutes · {}",
                dialog.ttl_minutes(),
                format_use_limit(dialog.uses())
            ),
            JitDecision::AddToGrant => format!(
                "Amend {} · +{} minutes · {}",
                dialog.grant_id.as_deref().unwrap_or("no compatible grant"),
                dialog.ttl_minutes(),
                dialog.uses().map_or_else(
                    || "no use-count change".to_string(),
                    |uses| format!("+{uses} uses")
                )
            ),
            JitDecision::Deny => "Close request and start denial cooldown".into(),
        };
        let constraints = if dialog.editing_constraints {
            format!("{}█", dialog.constraints_json)
        } else if dialog.constraints_json.is_empty() {
            "<requested scope unchanged>".into()
        } else {
            dialog.constraints_json.clone()
        };
        let confirm = if dialog.confirm {
            "\nCONFIRM: Enter applies this single canonical decision · Esc back"
        } else {
            ""
        };
        let content = format!(
            "Agent: {}\nProfile/plugin: {}/{}\nCapability/risk: {} / {}\nPurpose: {}\nRequested scope: {}\n\n{}\n\nDecision: {} · {}\nNarrowing constraints: {}\n\n←/→ decision · t time · u uses · c edit constraints · Enter review · Esc back{}\n{}",
            dialog.request.principal_fingerprint,
            dialog.request.profile_id,
            dialog.request.plugin_id,
            dialog.request.capability_id(),
            dialog.request.risk,
            sanitize_display_text(&dialog.request.purpose),
            serde_json::to_string_pretty(&dialog.request.scope)
                .unwrap_or_else(|_| "invalid".into()),
            schema,
            dialog.decision.label(),
            decision_detail,
            constraints,
            confirm,
            dialog.message.as_deref().unwrap_or_default(),
        );
        frame.render_widget(
            Paragraph::new(content).wrap(Wrap { trim: false }).block(
                Block::default()
                    .title(" Core-owned JIT approval review ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(if dialog.confirm {
                        Color::Yellow
                    } else {
                        Color::Cyan
                    })),
            ),
            popup,
        );
    }
}

fn sanitize_display_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(240)
        .collect()
}
