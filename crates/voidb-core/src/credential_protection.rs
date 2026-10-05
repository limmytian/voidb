//! Credential protection state model.
//!
//! This module describes how local credential-bearing stores are protected. It
//! intentionally does not hold master passwords or plaintext credential values.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::connection::ConnectionConfig;
use crate::profile_adapter::profile_plugin_id;
use crate::redaction::{RedactionTargetKind, collect_redaction_targets};

pub const DEFAULT_PASSPHRASE_WARNING_CODE: &str = "security.default_passphrase_credential_risk";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProtectionStore {
    Config,
    Profile,
    Credential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProtectionMode {
    DefaultPassphrase,
    UserPassphrase,
    Migrated,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MasterPasswordSessionState {
    NotConfigured,
    Locked,
    Unlocked,
    Forgotten,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMaterialState {
    Absent,
    Present,
    Referenced,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProtectionMigrationState {
    NotNeeded,
    Required,
    Complete,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CredentialMaterialSummary {
    pub credential_owner_count: usize,
    pub credential_item_count: usize,
    pub plugins: Vec<String>,
}

impl CredentialMaterialSummary {
    pub fn is_empty(&self) -> bool {
        self.credential_item_count == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialProtectionState {
    pub store: CredentialProtectionStore,
    pub mode: CredentialProtectionMode,
    pub material: CredentialMaterialState,
    pub master_password: MasterPasswordSessionState,
    pub migration: CredentialProtectionMigrationState,
    pub summary: CredentialMaterialSummary,
}

impl CredentialProtectionState {
    pub fn new(
        store: CredentialProtectionStore,
        mode: CredentialProtectionMode,
        material: CredentialMaterialState,
        master_password: MasterPasswordSessionState,
        summary: CredentialMaterialSummary,
    ) -> Self {
        let migration = migration_state(mode, material);

        Self {
            store,
            mode,
            material,
            master_password,
            migration,
            summary,
        }
    }

    pub fn requires_reencryption(&self) -> bool {
        self.mode == CredentialProtectionMode::DefaultPassphrase
            && self.material == CredentialMaterialState::Present
    }

    pub fn warning_code(&self) -> Option<&'static str> {
        self.requires_reencryption()
            .then_some(DEFAULT_PASSPHRASE_WARNING_CODE)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialProtectionReport {
    pub states: Vec<CredentialProtectionState>,
}

impl CredentialProtectionReport {
    pub fn new(states: Vec<CredentialProtectionState>) -> Self {
        Self { states }
    }

    pub fn requires_reencryption(&self) -> bool {
        self.states
            .iter()
            .any(CredentialProtectionState::requires_reencryption)
    }

    pub fn default_passphrase_states(&self) -> impl Iterator<Item = &CredentialProtectionState> {
        self.states
            .iter()
            .filter(|state| state.warning_code().is_some())
    }
}

pub fn legacy_config_default_passphrase_state(
    connections: &[ConnectionConfig],
) -> CredentialProtectionState {
    legacy_config_protection_state(
        connections,
        CredentialProtectionMode::DefaultPassphrase,
        MasterPasswordSessionState::NotConfigured,
    )
}

pub fn legacy_config_protection_state(
    connections: &[ConnectionConfig],
    mode: CredentialProtectionMode,
    master_password: MasterPasswordSessionState,
) -> CredentialProtectionState {
    let summary = credential_material_summary_for_connections(connections);
    let material = if summary.is_empty() {
        CredentialMaterialState::Absent
    } else {
        CredentialMaterialState::Present
    };

    CredentialProtectionState::new(
        CredentialProtectionStore::Config,
        mode,
        material,
        master_password,
        summary,
    )
}

pub fn migrated_profile_store_state(
    profile_count: usize,
    credential_ref_count: usize,
    plugins: Vec<String>,
) -> CredentialProtectionState {
    CredentialProtectionState::new(
        CredentialProtectionStore::Profile,
        CredentialProtectionMode::Migrated,
        if credential_ref_count == 0 {
            CredentialMaterialState::Absent
        } else {
            CredentialMaterialState::Referenced
        },
        MasterPasswordSessionState::NotConfigured,
        CredentialMaterialSummary {
            credential_owner_count: profile_count,
            credential_item_count: credential_ref_count,
            plugins: sorted_unique(plugins),
        },
    )
}

pub fn migrated_credential_store_state(
    credential_ref_count: usize,
    plugins: Vec<String>,
) -> CredentialProtectionState {
    CredentialProtectionState::new(
        CredentialProtectionStore::Credential,
        CredentialProtectionMode::Migrated,
        if credential_ref_count == 0 {
            CredentialMaterialState::Absent
        } else {
            CredentialMaterialState::Referenced
        },
        MasterPasswordSessionState::NotConfigured,
        CredentialMaterialSummary {
            credential_owner_count: credential_ref_count,
            credential_item_count: credential_ref_count,
            plugins: sorted_unique(plugins),
        },
    )
}

pub fn unknown_protection_state(store: CredentialProtectionStore) -> CredentialProtectionState {
    CredentialProtectionState::new(
        store,
        CredentialProtectionMode::Unknown,
        CredentialMaterialState::Unknown,
        MasterPasswordSessionState::Unknown,
        CredentialMaterialSummary::default(),
    )
}

pub fn credential_material_summary_for_connections(
    connections: &[ConnectionConfig],
) -> CredentialMaterialSummary {
    let mut credential_owner_count = 0;
    let mut credential_item_count = 0;
    let mut plugins = BTreeSet::new();

    for connection in connections {
        let Some(plugin_config) = &connection.plugin_config else {
            continue;
        };

        let item_count = collect_redaction_targets(plugin_config)
            .into_iter()
            .filter(|target| matches!(target.kind, RedactionTargetKind::Credential(_)))
            .count();

        if item_count == 0 {
            continue;
        }

        credential_owner_count += 1;
        credential_item_count += item_count;
        plugins.insert(profile_plugin_id(connection));
    }

    CredentialMaterialSummary {
        credential_owner_count,
        credential_item_count,
        plugins: plugins.into_iter().collect(),
    }
}

fn migration_state(
    mode: CredentialProtectionMode,
    material: CredentialMaterialState,
) -> CredentialProtectionMigrationState {
    match (mode, material) {
        (_, CredentialMaterialState::Absent) => CredentialProtectionMigrationState::NotNeeded,
        (CredentialProtectionMode::DefaultPassphrase, CredentialMaterialState::Present) => {
            CredentialProtectionMigrationState::Required
        }
        (
            CredentialProtectionMode::UserPassphrase | CredentialProtectionMode::Migrated,
            CredentialMaterialState::Present | CredentialMaterialState::Referenced,
        ) => CredentialProtectionMigrationState::Complete,
        _ => CredentialProtectionMigrationState::Unknown,
    }
}

fn sorted_unique(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::connection::DatabaseType;

    fn connection(
        name: &str,
        plugin_id: &str,
        plugin_config: serde_json::Value,
    ) -> ConnectionConfig {
        ConnectionConfig {
            name: name.into(),
            db_type: DatabaseType::Plugin,
            plugin_id: Some(plugin_id.into()),
            plugin_config: Some(plugin_config),
        }
    }

    #[test]
    fn default_passphrase_state_requires_reencryption_without_leaking_values() {
        let state = legacy_config_default_passphrase_state(&[connection(
            "assets",
            "s3",
            json!({
                "endpoint": "https://internal.example",
                "access_key": "AKIA_TEST_VALUE",
                "secret_key": "super-secret",
                "bucket": "private-bucket"
            }),
        )]);
        let encoded = serde_json::to_string(&state).expect("serialize state");

        assert!(state.requires_reencryption());
        assert_eq!(state.warning_code(), Some(DEFAULT_PASSPHRASE_WARNING_CODE));
        assert_eq!(
            state.migration,
            CredentialProtectionMigrationState::Required
        );
        assert_eq!(state.summary.credential_owner_count, 1);
        assert_eq!(state.summary.credential_item_count, 2);
        assert_eq!(state.summary.plugins, vec!["s3"]);
        assert!(!encoded.contains("internal.example"));
        assert!(!encoded.contains("AKIA_TEST_VALUE"));
        assert!(!encoded.contains("super-secret"));
        assert!(!encoded.contains("private-bucket"));
    }

    #[test]
    fn user_passphrase_state_clears_default_passphrase_warning() {
        let state = legacy_config_protection_state(
            &[connection("prod", "mysql", json!({ "password": "secret" }))],
            CredentialProtectionMode::UserPassphrase,
            MasterPasswordSessionState::Unlocked,
        );

        assert!(!state.requires_reencryption());
        assert_eq!(state.warning_code(), None);
        assert_eq!(
            state.migration,
            CredentialProtectionMigrationState::Complete
        );
    }

    #[test]
    fn migrated_store_states_reference_credentials_without_reencryption_warning() {
        let report = CredentialProtectionReport::new(vec![
            migrated_profile_store_state(2, 3, vec!["redis".into(), "mysql".into()]),
            migrated_credential_store_state(
                3,
                vec!["redis".into(), "mysql".into(), "redis".into()],
            ),
        ]);

        assert!(!report.requires_reencryption());
        assert_eq!(report.default_passphrase_states().count(), 0);
        assert_eq!(report.states[0].summary.credential_item_count, 3);
        assert_eq!(report.states[1].summary.plugins, vec!["mysql", "redis"]);
    }

    #[test]
    fn protection_state_serializes_stable_labels() {
        let encoded = serde_json::to_value(unknown_protection_state(
            CredentialProtectionStore::Credential,
        ))
        .expect("serialize state");

        assert_eq!(encoded["store"], "credential");
        assert_eq!(encoded["mode"], "unknown");
        assert_eq!(encoded["material"], "unknown");
        assert_eq!(encoded["master_password"], "unknown");
        assert_eq!(encoded["migration"], "unknown");
    }
}
