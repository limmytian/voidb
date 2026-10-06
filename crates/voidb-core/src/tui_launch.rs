//! Shared planning types for plugin-owned standalone TUI launches.
//!
//! Core builds a secret-free launch plan. The owning plugin CLI decides whether
//! to print the plan for preflight or enter its own terminal application.

use std::collections::BTreeMap;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::capability::{
    ConnectionInstanceId, ConnectionProfile, ConnectionProfileRef, CredentialGrant,
    CredentialGrantScope, PluginId, RedactionStatus,
};
use crate::error::VoidbError;

pub const TUI_LAUNCH_SCHEMA_VERSION: u32 = 1;
pub const TUI_LAUNCH_GRANT_TTL_SECONDS: i64 = 300;

pub const ENV_TUI_PLUGIN_ID: &str = "VOIDB_TUI_PLUGIN_ID";
pub const ENV_TUI_PROFILE_ID: &str = "VOIDB_TUI_PROFILE_ID";
pub const ENV_TUI_PROFILE_NAME: &str = "VOIDB_TUI_PROFILE_NAME";
pub const ENV_TUI_PURPOSE: &str = "VOIDB_TUI_PURPOSE";
pub const ENV_TUI_CREDENTIAL_GRANT_ID: &str = "VOIDB_TUI_CREDENTIAL_GRANT_ID";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TuiLaunchRequest {
    pub plugin_id: PluginId,
    pub profile: ConnectionProfileRef,
    pub purpose: String,
    pub readonly: bool,
    pub restore: bool,
    pub raw_input: bool,
}

impl TuiLaunchRequest {
    pub fn new(
        plugin_id: impl Into<PluginId>,
        profile: ConnectionProfileRef,
        purpose: impl Into<String>,
    ) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            profile,
            purpose: purpose.into(),
            readonly: false,
            restore: true,
            raw_input: false,
        }
    }

    pub fn readonly(mut self, readonly: bool) -> Self {
        self.readonly = readonly;
        self
    }

    pub fn restore(mut self, restore: bool) -> Self {
        self.restore = restore;
        self
    }

    pub fn raw_input(mut self, raw_input: bool) -> Self {
        self.raw_input = raw_input;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TuiLaunchPlan {
    pub schema_version: u32,
    pub plugin_id: PluginId,
    pub command: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub profile: TuiLaunchProfileSummary,
    pub purpose: String,
    pub readonly: bool,
    pub restore: bool,
    pub raw_input: bool,
    pub credential_grant: CredentialGrant,
    pub redaction: RedactionStatus,
}

impl TuiLaunchPlan {
    pub fn argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(1 + self.args.len());
        argv.push(self.command.clone());
        argv.extend(self.args.clone());
        argv
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TuiLaunchProfileSummary {
    pub id: String,
    #[serde(alias = "alias")]
    pub name: String,
    pub plugin_id: PluginId,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    #[serde(default)]
    pub credential_ref_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TuiLaunchExitCode {
    Ok = 0,
    Usage = 2,
    ProfileCredentialOrPolicy = 3,
    TargetUnavailable = 4,
    Terminal = 5,
    Plugin = 6,
    Unsupported = 7,
    Timeout = 124,
}

impl TuiLaunchExitCode {
    pub fn code(self) -> i32 {
        self as i32
    }
}

pub fn build_tui_launch_plan(
    profile: &ConnectionProfile,
    request: TuiLaunchRequest,
    command: impl Into<String>,
    issued_at: DateTime<Utc>,
) -> Result<TuiLaunchPlan, VoidbError> {
    if profile.plugin_id != request.plugin_id {
        return Err(VoidbError::Plugin(format!(
            "Profile '{}' belongs to plugin '{}', not '{}'",
            profile.name, profile.plugin_id, request.plugin_id
        )));
    }

    let profile_arg = profile_ref_arg(&request.profile);
    let instance_id = tui_instance_id(profile, &request.purpose);
    let grant = CredentialGrant {
        id: format!(
            "grant:tui:{}:{}",
            profile.id,
            sanitize_launch_token(&request.purpose)
        ),
        profile: ConnectionProfileRef::Id(profile.id.clone()),
        plugin_id: profile.plugin_id.clone(),
        scope: CredentialGrantScope::RuntimeInstance { instance_id },
        issued_at,
        expires_at: Some(issued_at + TimeDelta::seconds(TUI_LAUNCH_GRANT_TTL_SECONDS)),
        credential_refs: profile.credential_refs.clone(),
        redaction: RedactionStatus::NotRequired,
    };

    let args = launch_args(&request.plugin_id, &profile_arg, &request);
    let env = launch_env(profile, &request, &grant);

    Ok(TuiLaunchPlan {
        schema_version: TUI_LAUNCH_SCHEMA_VERSION,
        plugin_id: request.plugin_id,
        command: command.into(),
        args,
        env,
        profile: TuiLaunchProfileSummary {
            id: profile.id.clone(),
            name: profile.name.clone(),
            plugin_id: profile.plugin_id.clone(),
            display_name: profile.display_name.clone(),
            credential_ref_count: profile.credential_refs.len(),
        },
        purpose: request.purpose,
        readonly: request.readonly,
        restore: request.restore,
        raw_input: request.raw_input,
        credential_grant: grant,
        redaction: RedactionStatus::NotRequired,
    })
}

fn profile_ref_arg(profile_ref: &ConnectionProfileRef) -> String {
    match profile_ref {
        ConnectionProfileRef::Id(id) => format!("id:{}", id),
        ConnectionProfileRef::Name(name) => format!("name:{}", name),
    }
}

fn launch_args(plugin_id: &str, profile_arg: &str, request: &TuiLaunchRequest) -> Vec<String> {
    let mut args = vec![
        plugin_id.to_string(),
        "tui".to_string(),
        "--profile".to_string(),
        profile_arg.to_string(),
        "--purpose".to_string(),
        request.purpose.clone(),
    ];
    if request.readonly {
        args.push("--readonly".to_string());
    }
    if !request.restore {
        args.push("--no-restore".to_string());
    }
    args
}

fn launch_env(
    profile: &ConnectionProfile,
    request: &TuiLaunchRequest,
    grant: &CredentialGrant,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (ENV_TUI_PLUGIN_ID.to_string(), request.plugin_id.clone()),
        (ENV_TUI_PROFILE_ID.to_string(), profile.id.clone()),
        (ENV_TUI_PROFILE_NAME.to_string(), profile.name.clone()),
        (ENV_TUI_PURPOSE.to_string(), request.purpose.clone()),
        (ENV_TUI_CREDENTIAL_GRANT_ID.to_string(), grant.id.clone()),
    ])
}

fn tui_instance_id(profile: &ConnectionProfile, purpose: &str) -> ConnectionInstanceId {
    format!(
        "tui:{}:{}:{}",
        profile.plugin_id,
        sanitize_launch_token(&profile.id),
        sanitize_launch_token(purpose)
    )
}

fn sanitize_launch_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{ConnectionProfilePolicy, CredentialClass, CredentialRef};

    fn profile() -> ConnectionProfile {
        ConnectionProfile {
            id: "profile:ssh-prod".into(),
            name: "prod".into(),
            plugin_id: "ssh".into(),
            display_name: Some("prod ssh".into()),
            metadata: json!({
                "host_label": "prod.internal",
                "has_password": true
            }),
            default_options: serde_json::Value::Null,
            credential_refs: vec![CredentialRef {
                id: "credential:ssh-prod:password".into(),
                class: CredentialClass::Password,
                label: Some("legacy plugin_config /auth/password".into()),
            }],
            policy: ConnectionProfilePolicy::default(),
        }
    }

    #[test]
    fn launch_plan_uses_profile_ref_in_args_and_grant_ref_in_env() {
        let profile = profile();
        let request = TuiLaunchRequest::new(
            "ssh",
            ConnectionProfileRef::Name("prod".into()),
            "terminal",
        )
        .raw_input(true);

        let plan = build_tui_launch_plan(&profile, request, "voidb", DateTime::UNIX_EPOCH).unwrap();

        assert_eq!(plan.argv()[0], "voidb");
        assert!(plan.args.contains(&"--profile".to_string()));
        assert!(plan.args.contains(&"name:prod".to_string()));
        assert!(!plan.args.iter().any(|arg| arg.contains("grant:tui")));
        assert_eq!(
            plan.env.get(ENV_TUI_CREDENTIAL_GRANT_ID),
            Some(&"grant:tui:profile:ssh-prod:terminal".to_string())
        );
        assert_eq!(plan.credential_grant.credential_refs.len(), 1);
        assert!(plan.raw_input);
    }

    #[test]
    fn launch_plan_serialization_does_not_include_plaintext_secret() {
        let profile = profile();
        let request = TuiLaunchRequest::new("ssh", profile.profile_ref(), "terminal");
        let plan = build_tui_launch_plan(&profile, request, "voidb", DateTime::UNIX_EPOCH).unwrap();

        let serialized = serde_json::to_string(&plan).unwrap();

        assert!(!serialized.contains("ssh-secret"));
        assert!(!serialized.contains("private_key_material"));
        assert!(!serialized.contains("plaintext"));
    }

    #[test]
    fn launch_plan_rejects_wrong_plugin() {
        let profile = profile();
        let request = TuiLaunchRequest::new("email", profile.profile_ref(), "mailbox");

        let err =
            build_tui_launch_plan(&profile, request, "voidb", DateTime::UNIX_EPOCH).unwrap_err();

        assert!(err.to_string().contains("belongs to plugin 'ssh'"));
    }
}
