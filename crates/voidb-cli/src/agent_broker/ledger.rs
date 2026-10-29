#![cfg_attr(not(unix), allow(unused_imports))]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use voidb_core::{
    AgentAuthorizationPresetKind, AgentAuthorizationScope, AgentBrokerHealth,
    CapabilityExecutionMode, ConnectionProfile, FrontendAgentGrant,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AgentGrantFile {
    pub(super) version: u32,
    pub(super) id: String,
    pub(super) token: String,
    pub(super) profile_id: String,
    pub(super) profile_name: String,
    pub(super) plugin_id: String,
    pub(super) capabilities: Vec<String>,
    /// Broker transport boundary. Legacy grant files default to stateless so
    /// they cannot silently authorize persistent-session operations.
    #[serde(default)]
    pub(super) execution_mode: CapabilityExecutionMode,
    #[serde(default)]
    pub(super) preset: Option<AgentAuthorizationPresetKind>,
    pub(super) allow_destructive: bool,
    pub(super) issued_at: DateTime<Utc>,
    pub(super) expires_at: DateTime<Utc>,
    /// `None` means the grant is bounded only by `expires_at`.
    #[serde(default)]
    pub(super) remaining_uses: Option<u32>,
    pub(super) socket_path: PathBuf,

    /// Empty for compatible proactive grants. JIT-issued grants persist exact
    /// Core-owned scopes and revalidate normalized operations before every
    /// stateless execution. Persistent sessions require an explicit proactive
    /// session grant.
    #[serde(default)]
    pub(super) authorization_scopes: Vec<AgentAuthorizationScope>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) principal_fingerprint: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) grant_revision: Option<u64>,
}

impl AgentGrantFile {
    pub(super) fn public(
        &self,
        broker_health: AgentBrokerHealth,
        active_session_count: usize,
    ) -> FrontendAgentGrant {
        FrontendAgentGrant {
            id: self.id.clone(),
            profile_id: self.profile_id.clone(),
            profile_name: self.profile_name.clone(),
            plugin_id: self.plugin_id.clone(),
            preset: self.preset.or(Some(if self.allow_destructive {
                AgentAuthorizationPresetKind::Custom
            } else {
                AgentAuthorizationPresetKind::ReadOnly
            })),
            capabilities: self.capabilities.clone(),
            execution_mode: self.execution_mode,
            destructive_acknowledged: self.allow_destructive,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            remaining_uses: self.remaining_uses,
            broker_health,
            active_session_count,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct GrantInspection {
    pub(super) broker_health: AgentBrokerHealth,
    pub(super) active_session_count: usize,
}

pub(super) const MAX_BATCH_AUTHORIZATION_GRANTS: usize = 64;
pub(super) const MAX_BATCH_AUTHORIZATION_SPEC_BYTES: u64 = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BatchAuthorizationSpec {
    pub(super) grants: Vec<BatchAuthorizationEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BatchAuthorizationEntry {
    pub(super) profile: String,
    pub(super) plugin: String,
    pub(super) purpose: String,

    #[serde(default)]
    pub(super) execution_mode: Option<String>,

    #[serde(default)]
    pub(super) preset: Option<String>,

    #[serde(default)]
    pub(super) capabilities: Vec<String>,
}

#[derive(Debug)]
pub(super) struct PreparedBatchGrant {
    pub(super) profile: ConnectionProfile,
    pub(super) plugin_id: String,
    pub(super) purpose: String,
    pub(super) execution_mode: CapabilityExecutionMode,
    pub(super) preset: AgentAuthorizationPresetKind,
    pub(super) capabilities: Vec<String>,
    pub(super) allow_destructive: bool,
    pub(super) existing: Vec<AgentGrantFile>,
}
