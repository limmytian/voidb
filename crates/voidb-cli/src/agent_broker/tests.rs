use crate::agent_session_host::AgentSessionHost;
use crate::builtin::invoke::resolved_authorization_capabilities;
use crate::jit_authorization::{CreateAuthorizationRequest, JitAuthorizationStore};
use chrono::Utc;
use clap::Command;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::io::IsTerminal;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::Notify;
#[cfg(unix)]
use tokio::task::JoinSet;
use uuid::Uuid;
#[cfg(feature = "full")]
use voidb_core::AgentAuthorizationSupportStatus;
use voidb_core::{
    AGENT_BROKER_LEGACY_PROTOCOL_VERSION, AGENT_BROKER_PROTOCOL_VERSION,
    AgentAuthorizationPresetKind, AgentAuthorizationScope, AgentBrokerHealth, AgentGrantAmendment,
    AgentPrincipal, AgentSessionCallRequest, AgentSessionCallResult, AgentSessionCallState,
    AgentSessionCallStatusRequest, AgentSessionCallView, AgentSessionCallWaitRequest,
    AgentSessionCallWaitResult, AgentSessionCancelRequest, AgentSessionCloseAgentRequest,
    AgentSessionConcurrency, AgentSessionControlKind, AgentSessionListRequest,
    AgentSessionOpenRequest, AgentSessionRef, AgentSessionStatusRequest, AuditOperation,
    CapabilityDefinition, CapabilityExecutionMode, ConnectionProfile, PluginSessionError,
    PluginSessionErrorCode, PluginSessionPurpose, RedactionStatus, normalize_agent_operation,
};

use super::audit::*;
use super::commands::*;
use super::jit::*;
use super::ledger::*;
use super::runtime::*;
use super::session::*;
use super::wire::*;

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;

use super::*;

#[derive(Default)]
struct BlockingSessionState {
    started: StdMutex<Vec<String>>,
    cancelled: StdMutex<HashSet<String>>,
    started_notify: Notify,
    control_notify: Notify,
    active_notify: Notify,
    active: AtomicUsize,
    max_active: AtomicUsize,
    closed: AtomicBool,
    cleanup_count: AtomicUsize,
}

struct BlockingSession {
    state: Arc<BlockingSessionState>,
}

struct ActiveCallGuard {
    state: Arc<BlockingSessionState>,
}

impl Drop for ActiveCallGuard {
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, Ordering::SeqCst);
        self.state.active_notify.notify_waiters();
    }
}

#[async_trait]
impl voidb_core::PluginAgentSession for BlockingSession {
    async fn call(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        let active = self.state.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.state.max_active.fetch_max(active, Ordering::SeqCst);
        let _active = ActiveCallGuard {
            state: Arc::clone(&self.state),
        };
        self.state
            .started
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(request.call_id.clone());
        self.state.started_notify.notify_waiters();
        loop {
            let controlled = self.state.control_notify.notified();
            if self.state.closed.load(Ordering::SeqCst) {
                return Err(PluginSessionError::new(
                    PluginSessionErrorCode::Aborted,
                    "fixture session closed",
                ));
            }
            if self
                .state
                .cancelled
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .contains(&request.call_id)
            {
                return Err(PluginSessionError::new(
                    PluginSessionErrorCode::Cancelled,
                    "fixture call cancelled",
                ));
            }
            controlled.await;
        }
    }

    async fn health(&self) -> Result<voidb_core::PluginSessionHealth, PluginSessionError> {
        Ok(voidb_core::PluginSessionHealth::Ready)
    }

    async fn cancel(&self, call_id: &str) -> Result<(), PluginSessionError> {
        self.state
            .cancelled
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(call_id.to_owned());
        self.state.control_notify.notify_waiters();
        Ok(())
    }

    async fn close(&self, _reason: String) -> Result<(), PluginSessionError> {
        if !self.state.closed.swap(true, Ordering::SeqCst) {
            self.state.cleanup_count.fetch_add(1, Ordering::SeqCst);
        }
        self.state.control_notify.notify_waiters();
        Ok(())
    }
}

struct BlockingSessionFactory {
    state: Arc<BlockingSessionState>,
}

#[async_trait]
impl voidb_core::PluginAgentSessionFactory for BlockingSessionFactory {
    fn plugin_id(&self) -> &str {
        "ssh"
    }

    async fn open(
        &self,
        _context: voidb_core::AgentSessionOpenContext,
    ) -> Result<Arc<dyn voidb_core::PluginAgentSession>, PluginSessionError> {
        Ok(Arc::new(BlockingSession {
            state: Arc::clone(&self.state),
        }))
    }
}

async fn wait_for_started_calls(state: &BlockingSessionState, expected: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut started = Box::pin(state.started_notify.notified());
            started.as_mut().enable();
            if state
                .started
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len()
                >= expected
            {
                return;
            }
            started.await;
        }
    })
    .await
    .expect("fixture calls start before timeout");
}

async fn wait_for_active_calls(state: &BlockingSessionState, expected: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut changed = Box::pin(state.active_notify.notified());
            changed.as_mut().enable();
            if state.active.load(Ordering::SeqCst) == expected {
                return;
            }
            changed.await;
        }
    })
    .await
    .expect("fixture active-call count changes before timeout");
}

struct RunningBlockingBroker {
    grant_path: PathBuf,
    grant: AgentGrantFile,
    session: AgentSessionRef,
    state: Arc<BlockingSessionState>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl RunningBlockingBroker {
    async fn start(
        directory: &Path,
        mut grant: AgentGrantFile,
        host_generation: u64,
        purpose: PluginSessionPurpose,
    ) -> Self {
        fs::create_dir_all(directory).expect("create blocking broker directory");
        let grant_path = directory.join("grant.json");
        grant.socket_path = directory.join("grant.sock");
        grant.execution_mode = CapabilityExecutionMode::SessionOnly;
        grant.capabilities = vec!["ssh.terminal_read".into()];
        write_grant(&grant_path, &grant).expect("write blocking broker grant");

        let state = Arc::new(BlockingSessionState::default());
        let mut host = AgentSessionHost::new(
            grant.id.clone(),
            grant.profile_id.clone(),
            grant.plugin_id.clone(),
            grant.capabilities.clone(),
            grant.expires_at,
            host_generation,
        );
        host.register_factory(Arc::new(BlockingSessionFactory {
            state: Arc::clone(&state),
        }));
        let session = host
            .open(
                AgentSessionOpenRequest {
                    purpose,
                    capabilities: grant.capabilities.clone(),
                    lease_seconds: 60,
                    concurrency: AgentSessionConcurrency::Serialized,
                    destructive_acknowledged: false,
                    input: Value::Null,
                },
                Utc::now(),
            )
            .await
            .expect("open blocking broker session")
            .session;

        let broker_path = grant_path.clone();
        let broker_grant = grant.clone();
        let task = tokio::spawn(async move {
            broker_loop_with_host(&broker_path, broker_grant, host, "test-password").await
        });
        wait_for_socket(&grant.socket_path)
            .await
            .expect("blocking broker socket ready");

        Self {
            grant_path,
            grant,
            session,
            state,
            task,
        }
    }

    fn call_request(&self, call_id: &str) -> AgentSessionCallRequest {
        AgentSessionCallRequest {
            session: self.session.clone(),
            call_id: call_id.into(),
            capability: "ssh.terminal_read".into(),
            input: json!({ "offset": 0 }),
            destructive_acknowledged: false,
            timeout_ms: Some(5_000),
            output_limit_bytes: 1024,
        }
    }

    async fn shutdown(self) {
        let response = send_request(
            &self.grant,
            BrokerRequest::Shutdown {
                token: self.grant.token.clone(),
            },
        )
        .await
        .expect("blocking broker shutdown response");
        assert!(response.ok);
        self.task
            .await
            .expect("blocking broker task")
            .expect("blocking broker exits");
    }
}

fn grant() -> AgentGrantFile {
    AgentGrantFile {
        version: GRANT_VERSION,
        id: "agent-grant:test".into(),
        token: "token".into(),
        profile_id: "profile:test".into(),
        profile_name: "prod".into(),
        plugin_id: "ssh".into(),
        capabilities: vec!["ssh.sftp_list".into(), "ssh.exec".into()],
        execution_mode: CapabilityExecutionMode::Stateless,
        preset: Some(AgentAuthorizationPresetKind::ReadOnly),
        allow_destructive: false,
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::minutes(15),
        remaining_uses: Some(10),
        socket_path: "/tmp/voidb-agent-test.sock".into(),
        authorization_scopes: Vec::new(),
        principal_fingerprint: None,
        grant_revision: None,
    }
}

#[test]
fn resolve_profile_accepts_bare_immutable_profile_id() {
    let profiles = vec![ConnectionProfile {
        id: "profile:test".into(),
        name: "ser7".into(),
        plugin_id: "ssh".into(),
        display_name: None,
        metadata: json!({}),
        default_options: serde_json::Value::Null,
        credential_refs: Vec::new(),
        policy: voidb_core::ConnectionProfilePolicy::default(),
    }];

    let resolved =
        resolve_profile(&profiles, "profile:test", "ssh").expect("bare profile id should resolve");
    assert_eq!(resolved.name, "ser7");
}

#[test]
fn agent_exec_builds_an_immutable_profile_invocation_without_grant_plumbing() {
    let matches = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "exec",
            "docker.list_containers",
            "--profile",
            "prod-docker",
            "--input-json",
            r#"{"all":true}"#,
            "--page-limit",
            "25",
        ])
        .expect("agent exec command parses");
    let (_, agent) = matches.subcommand().expect("agent command");
    let (_, exec) = agent.subcommand().expect("exec command");
    let input = parse_agent_exec_input(exec).expect("agent exec input");
    let argv = agent_exec_argv(exec, "docker.list_containers", "profile:docker", &input);

    assert_eq!(
        argv,
        vec![
            "invoke",
            "run",
            "docker.list_containers",
            "--profile",
            "id:profile:docker",
            "--input-json",
            r#"{"all":true}"#,
            "--format",
            "json",
            "--page-limit",
            "25",
        ]
    );
    assert!(!argv.iter().any(|argument| argument == "--grant"));
    assert!(!argv.iter().any(|argument| argument == "--plugin"));
}

#[cfg(feature = "full")]
#[test]
fn agent_exec_accepts_explicit_principal_binding_and_exact_jit_scope() {
    let matches = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "exec",
            "docker.list_containers",
            "--profile",
            "prod-docker",
            "--client-id",
            "agent",
            "--task-id",
            "task-123",
            "--instance-id",
            "desktop",
        ])
        .expect("agent exec principal parses");
    let (_, agent) = matches.subcommand().expect("agent command");
    let (_, exec) = agent.subcommand().expect("exec command");
    let principal = agent_exec_principal(exec)
        .expect("valid principal")
        .expect("explicit principal");
    assert_eq!(principal.client_id, "agent");
    assert_eq!(principal.task_id, "task-123");
    assert_eq!(principal.instance_id.as_deref(), Some("desktop"));

    let (scope, risk) =
        exact_agent_exec_scope("ssh", "ssh.diagnostics", json!({})).expect("exact SSH scope");
    assert_eq!(risk, voidb_core::CapabilityRiskLevel::ReadOnly);
    assert!(matches!(
        scope,
        AgentAuthorizationScope::ExactInvocation { capability_id, .. }
            if capability_id == "ssh.diagnostics"
    ));
}

#[test]
fn agent_exec_help_hides_principal_and_grant_plumbing() {
    let mut command = agent_command();
    let agent = command
        .find_subcommand_mut("agent")
        .expect("agent command exists");
    let exec = agent
        .find_subcommand_mut("exec")
        .expect("exec command exists");
    let help = exec.render_long_help().to_string();

    for hidden in [
        "--client-id",
        "--task-id",
        "--instance-id",
        "--grant",
        "--plugin",
    ] {
        assert!(!help.contains(hidden), "exec help exposed {hidden}");
    }
    for visible in [
        "docker.list_containers",
        "--profile",
        "--input-json",
        "--purpose",
        "--no-request",
    ] {
        assert!(help.contains(visible), "exec help omitted {visible}");
    }
}

#[test]
fn jit_request_create_requires_a_reviewable_purpose_and_keeps_reason_alias() {
    let base = [
        "voidb-cli",
        "agent",
        "request",
        "create",
        "--profile",
        "id:profile:test",
        "--plugin",
        "ssh",
        "--capability",
        "ssh.exec",
        "--scope",
        "capability",
        "--client-id",
        "agent",
        "--task-id",
        "task-purpose-test",
    ];
    assert!(agent_command().try_get_matches_from(base).is_err());

    for flag in ["--purpose", "--reason"] {
        let mut args = base.to_vec();
        args.extend([
            flag,
            "Inspect production uptime while triaging incident INC-42",
        ]);
        assert!(
            agent_command().try_get_matches_from(args).is_ok(),
            "{flag} should supply the review purpose"
        );
    }
}

#[test]
fn agent_exec_jit_prompt_exposes_the_interactive_cli_review_path() {
    let prompt = agent_exec_review_prompt(
        "docker",
        "prod\u{1b}[31m",
        "voidb-cli agent request review auth-request:00000000-0000-4000-8000-000000000000",
    );

    assert!(prompt.contains("Authorization required for docker/prod"));
    assert!(prompt.contains("password prompt hides input"));
    assert!(prompt.contains(
        "voidb-cli agent request review auth-request:00000000-0000-4000-8000-000000000000"
    ));
    assert!(prompt.contains("Connection Manager approval inbox (p)"));
    assert!(!prompt.contains('\u{1b}'));
}

#[test]
fn agent_exec_never_reuses_another_principals_jit_grant() {
    let approved = AgentPrincipal {
        client_id: "agent".into(),
        task_id: "task-a".into(),
        instance_id: None,
    };
    let other = AgentPrincipal {
        client_id: "agent".into(),
        task_id: "task-b".into(),
        instance_id: None,
    };
    let mut grant = grant();
    grant.principal_fingerprint = Some(approved.fingerprint().unwrap());

    assert!(grant_matches_agent_exec_principal(&grant, Some(&approved)).unwrap());
    assert!(!grant_matches_agent_exec_principal(&grant, Some(&other)).unwrap());
    assert!(!grant_matches_agent_exec_principal(&grant, None).unwrap());
}

#[test]
fn read_only_grant_accepts_scoped_invoke_and_profile_test() {
    let grant = grant();
    assert!(
        command_allowed(
            &grant,
            &[
                "invoke".into(),
                "run".into(),
                "ssh.sftp_list".into(),
                "--profile".into(),
                "id:profile:test".into(),
                "--input-json".into(),
                "{}".into(),
            ]
        )
        .is_ok()
    );
    assert_eq!(
        invoked_capability(&["invoke".into(), "run".into(), "ssh.sftp_list".into()]),
        Some("ssh.sftp_list")
    );
    assert!(
        command_allowed(
            &grant,
            &[
                "profile".into(),
                "test".into(),
                "id:profile:test".into(),
                "--plugin".into(),
                "ssh".into(),
            ]
        )
        .is_ok()
    );
}

#[test]
fn jit_grant_revalidates_exact_normalized_input_before_execution() {
    let mut grant = grant();
    grant.allow_destructive = true;
    let operation = normalize_agent_operation("ssh.exec", json!({ "command": "uptime" }))
        .expect("normalized operation");
    grant.authorization_scopes = vec![AgentAuthorizationScope::ExactInvocation {
        capability_id: operation.capability_id,
        normalized_input: operation.input,
        invocation_fingerprint: operation.fingerprint,
    }];

    let argv = |input: &str| {
        vec![
            "invoke".into(),
            "run".into(),
            "ssh.exec".into(),
            "--profile".into(),
            "id:profile:test".into(),
            "--input-json".into(),
            input.into(),
            "--yes".into(),
        ]
    };
    assert!(command_allowed(&grant, &argv(r#"{"command":"uptime"}"#)).is_ok());
    assert!(command_allowed(&grant, &argv(r#"{"command":"whoami"}"#)).is_err());
}

#[cfg(feature = "full")]
#[test]
fn local_filesystem_boundary_rejects_unscoped_proactive_grants() {
    for (plugin_id, capability_id) in [("ssh", "ssh.sftp_get"), ("ssh", "ssh.sftp_put")] {
        let mut scoped_only = grant();
        scoped_only.plugin_id = plugin_id.into();
        let error = ensure_capability_wide_authorization_allowed(&scoped_only, capability_id)
            .expect_err("local filesystem capability must reject capability-wide grants");
        assert!(
            error
                .to_string()
                .contains("permission.local_path_scope_required")
        );
    }

    let mut proactive = grant();
    proactive.capabilities.push("ssh.sftp_get".into());
    proactive.allow_destructive = true;
    let input = json!({
        "remote_path": "/remote/file.txt",
        "local_root": "/tmp",
        "local_path": "file.txt",
    });
    let argv = |input: &Value| {
        vec![
            "invoke".into(),
            "run".into(),
            "ssh.sftp_get".into(),
            "--profile".into(),
            "id:profile:test".into(),
            "--input-json".into(),
            input.to_string(),
        ]
    };

    let error = command_allowed(&proactive, &argv(&input)).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("permission.local_path_scope_required")
    );

    let operation = normalize_agent_operation("ssh.sftp_get", input.clone()).unwrap();
    proactive.authorization_scopes = vec![AgentAuthorizationScope::ExactInvocation {
        capability_id: operation.capability_id,
        normalized_input: operation.input,
        invocation_fingerprint: operation.fingerprint,
    }];
    assert!(command_allowed(&proactive, &argv(&input)).is_ok());

    let changed = json!({
        "remote_path": "/remote/file.txt",
        "local_root": "/tmp",
        "local_path": "other.txt",
    });
    assert!(command_allowed(&proactive, &argv(&changed)).is_err());
}

#[test]
fn jit_grant_execution_is_bound_to_the_approved_principal() {
    let mut grant = grant();
    let approved = AgentPrincipal {
        client_id: "agent".into(),
        task_id: "task-a".into(),
        instance_id: Some("desktop".into()),
    };
    grant.principal_fingerprint = Some(approved.fingerprint().unwrap());
    let command = |task_id: &str| {
        with_optional_principal_args(Command::new("run"))
            .try_get_matches_from([
                "run",
                "--client-id",
                "agent",
                "--task-id",
                task_id,
                "--instance-id",
                "desktop",
            ])
            .unwrap()
    };
    assert!(ensure_grant_principal(&grant, &command("task-a")).is_ok());
    assert!(ensure_grant_principal(&grant, &command("task-b")).is_err());
    let missing = with_optional_principal_args(Command::new("run"))
        .try_get_matches_from(["run"])
        .unwrap();
    assert!(ensure_grant_principal(&grant, &missing).is_err());
}

#[test]
fn ssh_reference_jit_flow_covers_scope_revision_session_and_preauthorization() {
    let root = std::env::temp_dir().join(format!("voidb-ssh-jit-{}", Uuid::new_v4()));
    let store = JitAuthorizationStore::with_policy(
        root.clone(),
        "broker-ssh-reference",
        crate::jit_authorization::JitAuthorizationPolicy::default(),
    )
    .expect("temporary JIT store");
    let now = Utc::now();
    let principal = AgentPrincipal {
        client_id: "agent".into(),
        task_id: "ssh-reference".into(),
        instance_id: Some("test".into()),
    };
    let constrained = AgentAuthorizationScope::Constrained {
        capability_id: "ssh.exec".into(),
        constraints: BTreeMap::from([("/command".into(), json!("uptime"))]),
    };
    let first = store
        .create(
            CreateAuthorizationRequest {
                principal: principal.clone(),
                profile_id: "profile:test".into(),
                plugin_id: "ssh".into(),
                scope: constrained.clone(),
                risk: voidb_core::CapabilityRiskLevel::Destructive,
                purpose: "Inspect uptime while triaging the production incident".into(),
                expires_at: now + chrono::Duration::minutes(5),
            },
            now,
        )
        .expect("request without preauthorization");
    let first_revision = store
        .approve(
            &first.request.id,
            constrained,
            AgentGrantAmendment::Bounded {
                ttl_seconds: 300,
                uses: Some(2),
            },
            now + chrono::Duration::seconds(1),
        )
        .expect("bounded approval");
    assert_eq!(first_revision.revision, 1);

    let exact = normalize_agent_operation("ssh.exec", json!({ "command": "whoami" }))
        .expect("exact SSH command");
    let exact_scope = AgentAuthorizationScope::ExactInvocation {
        capability_id: exact.capability_id,
        normalized_input: exact.input,
        invocation_fingerprint: exact.fingerprint,
    };
    let second = store
        .create(
            CreateAuthorizationRequest {
                principal: principal.clone(),
                profile_id: "profile:test".into(),
                plugin_id: "ssh".into(),
                scope: exact_scope.clone(),
                risk: voidb_core::CapabilityRiskLevel::Destructive,
                purpose: "Confirm the remote deployment identity before rollout".into(),
                expires_at: now + chrono::Duration::minutes(5),
            },
            now + chrono::Duration::seconds(2),
        )
        .expect("amendment request");
    let amended = store
        .approve(
            &second.request.id,
            exact_scope,
            AgentGrantAmendment::AddToGrant {
                grant_id: first_revision.grant_id.clone(),
                ttl_delta_seconds: 60,
                uses_delta: 2,
            },
            now + chrono::Duration::seconds(3),
        )
        .expect("immutable grant amendment");
    assert_eq!(amended.grant_id, first_revision.grant_id);
    assert_eq!(amended.revision, 2);

    let mut jit_grant = grant();
    jit_grant.id = amended.grant_id.clone();
    jit_grant.allow_destructive = true;
    jit_grant.authorization_scopes = store
        .effective_scopes(&amended.grant_id)
        .expect("effective scopes");
    jit_grant.principal_fingerprint = Some(principal.fingerprint().unwrap());
    jit_grant.grant_revision = Some(amended.revision);
    let argv = |command: &str| {
        vec![
            "invoke".into(),
            "run".into(),
            "ssh.exec".into(),
            "--profile".into(),
            "id:profile:test".into(),
            "--input-json".into(),
            json!({ "command": command }).to_string(),
            "--yes".into(),
        ]
    };
    assert!(command_allowed(&jit_grant, &argv("uptime")).is_ok());
    assert!(command_allowed(&jit_grant, &argv("whoami")).is_ok());
    assert!(command_allowed(&jit_grant, &argv("rm -rf /tmp/example")).is_err());

    let session_call = |command: &str| AgentSessionCallRequest {
        session: AgentSessionRef::new("agent-session:ssh", 1),
        call_id: format!("call-{command}"),
        capability: "ssh.exec".into(),
        input: json!({ "command": command }),
        destructive_acknowledged: true,
        timeout_ms: None,
        output_limit_bytes: 1024,
    };
    assert!(session_call_allowed(&jit_grant, &session_call("uptime")).is_err());
    assert!(session_call_allowed(&jit_grant, &session_call("pwd")).is_err());

    let mut proactive_session = grant();
    proactive_session.execution_mode = CapabilityExecutionMode::Both;
    proactive_session.allow_destructive = true;
    assert!(session_call_allowed(&proactive_session, &session_call("uptime")).is_ok());

    let mut capability_wide = grant();
    capability_wide.allow_destructive = true;
    capability_wide.authorization_scopes = vec![AgentAuthorizationScope::Capability {
        capability_id: "ssh.exec".into(),
    }];
    assert!(command_allowed(&capability_wide, &argv("date")).is_ok());

    let mut proactive = grant();
    proactive.allow_destructive = true;
    assert!(proactive.authorization_scopes.is_empty());
    assert!(command_allowed(&proactive, &argv("date")).is_ok());
    fs::remove_dir_all(root).expect("remove temporary JIT store");
}

#[test]
fn request_review_accepts_only_an_opaque_id_and_no_secret_parameters() {
    assert!(
        agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "request",
                "review",
                "auth-request:00000000-0000-4000-8000-000000000000",
            ])
            .is_ok()
    );
    for forbidden in ["--master-password", "--password", "--approve", "--command"] {
        assert!(
            agent_command()
                .try_get_matches_from([
                    "voidb-cli",
                    "agent",
                    "request",
                    "review",
                    "auth-request:00000000-0000-4000-8000-000000000000",
                    forbidden,
                    "secret-or-shell-text",
                ])
                .is_err(),
            "review unexpectedly accepted {forbidden}"
        );
    }
}

#[test]
fn tui_decision_accepts_only_non_secret_scope_and_password_stdin_marker() {
    let command = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "request",
            "decide",
            "auth-request:00000000-0000-4000-8000-000000000000",
            "--decision",
            "bounded",
            "--ttl-seconds",
            "300",
            "--uses",
            "2",
            "--constraints-json",
            r#"{"/cwd":"/srv/app"}"#,
            "--password-stdin",
        ])
        .expect("safe TUI decision arguments");
    let encoded = format!("{command:?}");
    for forbidden in ["master_password", "VOIDB_MASTER_PASSWORD", "secret-value"] {
        assert!(!encoded.contains(forbidden));
    }
    for forbidden in ["--master-password", "--password", "--shell"] {
        assert!(
            agent_command()
                .try_get_matches_from([
                    "voidb-cli",
                    "agent",
                    "request",
                    "decide",
                    "auth-request:00000000-0000-4000-8000-000000000000",
                    "--decision",
                    "once",
                    forbidden,
                    "secret-value",
                ])
                .is_err()
        );
    }
}

#[tokio::test]
async fn request_review_fails_closed_without_a_controlling_tty() {
    if !std::io::stdin().is_terminal() {
        assert_eq!(
            review_jit_request("auth-request:00000000-0000-4000-8000-000000000000")
                .await
                .unwrap(),
            JIT_EXIT_INVALID
        );
    }
}

#[test]
fn grant_rejects_other_profiles_plugins_files_and_destructive_ack() {
    let grant = grant();
    for argv in [
        vec!["invoke", "run", "mysql.query", "--profile", "prod"],
        vec!["invoke", "run", "ssh.sftp_list", "--profile", "other"],
        vec!["invoke", "run", "ssh.sftp_list", "--profile", "prod"],
        vec![
            "invoke",
            "run",
            "ssh.sftp_list",
            "--profile",
            "id:profile:test",
            "-pother",
        ],
        vec![
            "invoke",
            "run",
            "ssh.sftp_list",
            "--profile",
            "prod",
            "--input-file",
            "/tmp/input",
        ],
        vec![
            "invoke",
            "run",
            "ssh.sftp_list",
            "--profile=id:profile:test",
            "--input-file=/tmp/input",
        ],
        vec!["invoke", "run", "ssh.exec", "--profile", "prod", "--yes"],
    ] {
        assert!(
            command_allowed(
                &grant,
                &argv.into_iter().map(str::to_string).collect::<Vec<_>>()
            )
            .is_err()
        );
    }
}

#[test]
fn default_grant_fails_closed_on_non_read_only_capabilities() {
    assert!(ensure_read_only_capability("ssh.sftp_list").is_ok());
    assert!(ensure_read_only_capability("ssh.exec").is_err());
    assert!(ensure_read_only_capability("missing.capability").is_err());
}

#[test]
fn grant_scope_requires_exact_verified_capabilities() {
    let mode = CapabilityExecutionMode::Stateless;
    assert!(validate_grant_capabilities("ssh", &["*".into()], mode, false).is_err());
    assert!(validate_grant_capabilities("ssh", &["mysql.query".into()], mode, false).is_err());
    assert!(validate_grant_capabilities("ssh", &["ssh.exec".into()], mode, false).is_err());
    assert!(validate_grant_capabilities("ssh", &["ssh.exec".into()], mode, true).is_ok());
    let read_only = read_only_scope("ssh", mode).expect("SSH read-only catalog");
    assert!(read_only.contains(&"ssh.sftp_list".to_string()));
    assert!(!read_only.contains(&"ssh.sftp_get".to_string()));
    assert!(!read_only.contains(&"ssh.exec".to_string()));
    assert!(!read_only.contains(&"*".to_string()));
    let catalog = resolved_authorization_capabilities(Some("ssh"))
        .expect("password-free SSH authorization catalog");
    assert!(
        catalog
            .iter()
            .any(|capability| capability.qualified_id() == "ssh.exec")
    );
    let encoded = serde_json::to_string(&catalog).expect("serialize catalog");
    assert!(!encoded.contains("master_password"));
    assert!(!encoded.contains("socket_path"));
}

#[test]
fn jit_authorization_remains_stateless_only() {
    let definitions = resolved_authorization_capabilities(Some("ssh")).expect("SSH catalog");
    let terminal = definitions
        .iter()
        .find(|definition| definition.qualified_id() == "ssh.terminal_read")
        .expect("terminal capability");
    let error = validate_declared_jit_scope(
        terminal,
        &AgentAuthorizationScope::Capability {
            capability_id: "ssh.terminal_read".into(),
        },
    )
    .expect_err("session-only JIT scope must fail closed");
    assert!(error.to_string().contains("--execution-mode session_only"));

    let stateless = definitions
        .iter()
        .find(|definition| definition.qualified_id() == "ssh.sftp_list")
        .expect("stateless-capable capability");
    assert!(
        validate_declared_jit_scope(
            stateless,
            &AgentAuthorizationScope::Capability {
                capability_id: "ssh.sftp_list".into(),
            },
        )
        .is_ok()
    );
}

#[test]
fn execution_mode_boundaries_fail_closed_at_invoke_and_session_entrypoints() {
    let invoke = vec![
        "invoke".into(),
        "run".into(),
        "ssh.sftp_list".into(),
        "--profile".into(),
        "id:profile:test".into(),
        "--input-json".into(),
        "{}".into(),
    ];
    let session_call = AgentSessionCallRequest {
        session: AgentSessionRef::new("agent-session:test", 1),
        call_id: "call-mode-boundary".into(),
        capability: "ssh.sftp_list".into(),
        input: json!({}),
        destructive_acknowledged: false,
        timeout_ms: None,
        output_limit_bytes: 1024,
    };

    let stateless = grant();
    assert!(command_allowed(&stateless, &invoke).is_ok());
    assert!(session_call_allowed(&stateless, &session_call).is_err());

    let mut session = grant();
    session.execution_mode = CapabilityExecutionMode::SessionOnly;
    session.capabilities.push("ssh.terminal_read".into());
    assert!(command_allowed(&session, &invoke).is_err());
    assert!(session_call_allowed(&session, &session_call).is_ok());

    let mut open = AgentSessionOpenRequest {
        purpose: PluginSessionPurpose::InteractiveTerminal,
        capabilities: Vec::new(),
        lease_seconds: 300,
        concurrency: AgentSessionConcurrency::Serialized,
        destructive_acknowledged: false,
        input: json!({}),
    };
    assert!(session_open_allowed(&session, &open).is_err());
    open.capabilities = vec!["ssh.terminal_read".into()];
    let mut ungranted = grant();
    ungranted.execution_mode = CapabilityExecutionMode::SessionOnly;
    let error = session_open_allowed(&ungranted, &open)
        .expect_err("ungranted session capability must fail before host open");
    assert!(error.to_string().contains("outside the agent grant scope"));
    assert!(session_open_allowed(&session, &open).is_ok());
    open.capabilities.push("ssh.exec".into());
    assert!(session_open_allowed(&session, &open).is_err());
    open.capabilities = vec!["ssh.terminal_read".into()];
    open.purpose = PluginSessionPurpose::PortForward;
    assert!(session_open_allowed(&session, &open).is_err());

    let mut combined = grant();
    combined.execution_mode = CapabilityExecutionMode::Both;
    assert!(command_allowed(&combined, &invoke).is_ok());
    assert!(session_call_allowed(&combined, &session_call).is_ok());
}

#[test]
fn live_session_start_contract_validates_input_and_side_effect_acknowledgement() {
    let handoff = voidb_core::CapabilitySessionHandoff::new(
        PluginSessionPurpose::LogStream,
        ["docker.logs_follow"],
    )
    .with_live_session(voidb_core::AgentLiveSessionContract {
        protocol_version: voidb_core::AGENT_LIVE_SESSION_PROTOCOL_VERSION,
        kind: voidb_core::AgentLiveSessionKind::Log,
        resource: voidb_core::AgentLiveSessionResourceDescriptor {
            resource_type: "container".into(),
            identity_schema: json!({
                "type": "object",
                "required": ["container_id"],
                "properties": { "container_id": { "type": "string" } },
                "additionalProperties": false
            }),
            identity_fields: vec!["/container_id".into()],
            audit_identity: voidb_core::AgentLiveSessionAuditIdentity::Fingerprint,
        },
        start_parameters_schema: json!({
            "type": "object",
            "properties": { "follow": { "type": "boolean" } },
            "additionalProperties": false
        }),
        event_schema: json!({ "type": "object" }),
        operations: voidb_core::AgentLiveSessionOperations {
            events: "docker.logs_follow".into(),
            input: None,
            resize: None,
            signal: None,
        },
        buffer: voidb_core::AgentLiveSessionBufferPolicy::default(),
        reconnect: voidb_core::AgentLiveSessionReconnectPolicy::default(),
        delivery: voidb_core::AgentLiveSessionDeliveryPolicy::default(),
        control: voidb_core::AgentLiveSessionControlPolicy::default(),
        start_risk: voidb_core::CapabilityRiskLevel::ExternalSideEffect,
    });
    let mut grant = grant();
    grant.plugin_id = "docker".into();
    grant.capabilities = vec!["docker.logs_follow".into()];
    grant.execution_mode = CapabilityExecutionMode::SessionOnly;
    let mut request = AgentSessionOpenRequest {
        purpose: PluginSessionPurpose::LogStream,
        capabilities: grant.capabilities.clone(),
        lease_seconds: 60,
        concurrency: AgentSessionConcurrency::Serialized,
        destructive_acknowledged: false,
        input: json!({
            "resource": { "container_id": "fixture" },
            "parameters": { "follow": true }
        }),
    };

    let error = live_session_start_allowed(&grant, &request, &handoff)
        .expect_err("read-only grant must reject side-effecting start");
    assert!(error.to_string().contains("grant is read-only"));

    grant.allow_destructive = true;
    let error = live_session_start_allowed(&grant, &request, &handoff)
        .expect_err("start needs per-open acknowledgement");
    assert!(error.to_string().contains("requires --yes"));

    request.destructive_acknowledged = true;
    live_session_start_allowed(&grant, &request, &handoff)
        .expect("valid acknowledged live-session start");
    request.input["parameters"]["follow"] = json!("yes");
    let error = live_session_start_allowed(&grant, &request, &handoff)
        .expect_err("invalid start parameters");
    assert!(error.to_string().contains("does not match"));
    assert!(!error.to_string().contains("fixture"));
}

#[test]
fn legacy_grants_deserialize_as_stateless() {
    let mut encoded = serde_json::to_value(grant()).expect("serialize grant");
    encoded
        .as_object_mut()
        .expect("grant object")
        .remove("execution_mode");
    let legacy: AgentGrantFile = serde_json::from_value(encoded).expect("legacy grant");

    assert_eq!(legacy.execution_mode, CapabilityExecutionMode::Stateless);
    assert!(
        session_call_allowed(
            &legacy,
            &AgentSessionCallRequest {
                session: AgentSessionRef::new("agent-session:legacy", 1),
                call_id: "call-legacy".into(),
                capability: "ssh.sftp_list".into(),
                input: json!({}),
                destructive_acknowledged: false,
                timeout_ms: None,
                output_limit_bytes: 1024,
            },
        )
        .is_err()
    );
}

#[cfg(feature = "full")]
#[test]
fn shared_presets_resolve_and_validate_exact_cli_scopes() {
    let stateless = CapabilityExecutionMode::Stateless;
    let (preset, read_only) =
        resolve_authorization_scope("ssh", stateless, None, None).expect("default read-only scope");
    assert_eq!(preset, AgentAuthorizationPresetKind::ReadOnly);
    assert!(read_only.contains(&"ssh.sftp_list".into()));
    assert!(!read_only.contains(&"ssh.exec".into()));

    let (preset, interactive) =
        resolve_authorization_scope("ssh", stateless, Some("interactive_execute"), None)
            .expect("central interactive scope");
    assert_eq!(preset, AgentAuthorizationPresetKind::InteractiveExecute);
    assert_eq!(interactive, vec!["ssh.exec"]);

    let (preset, full_access) =
        resolve_authorization_scope("ssh", stateless, Some("full_access"), None)
            .expect("central full-access scope");
    assert_eq!(preset, AgentAuthorizationPresetKind::FullAccess);
    assert!(full_access.contains(&"ssh.exec".into()));
    assert!(full_access.contains(&"ssh.sftp_list".into()));
    assert!(!full_access.contains(&"*".into()));
    assert!(validate_grant_capabilities("ssh", &full_access, stateless, false).is_err());
    assert!(validate_grant_capabilities("ssh", &full_access, stateless, true).is_ok());

    let (preset, custom) =
        resolve_authorization_scope("ssh", stateless, None, Some(vec!["ssh.sftp_rm".into()]))
            .expect("explicit capabilities infer Custom");
    assert_eq!(preset, AgentAuthorizationPresetKind::Custom);
    assert_eq!(custom, vec!["ssh.sftp_rm"]);

    assert!(
        resolve_authorization_scope(
            "ssh",
            stateless,
            Some("read_only"),
            Some(vec!["ssh.exec".into()]),
        )
        .is_err()
    );
    assert!(
        resolve_authorization_scope(
            "ssh",
            stateless,
            Some("read_only"),
            Some(vec!["ssh.sftp_list".into()]),
        )
        .is_err()
    );
    assert!(
        resolve_authorization_scope(
            "ssh",
            stateless,
            Some("interactive_execute"),
            Some(vec!["ssh.sftp_rm".into()]),
        )
        .is_err()
    );
    assert!(
        resolve_authorization_scope(
            "ssh",
            stateless,
            Some("full_access"),
            Some(vec!["ssh.sftp_list".into()]),
        )
        .is_err()
    );
    assert!(resolve_authorization_scope("ssh", stateless, Some("custom"), None).is_err());

    let session = CapabilityExecutionMode::SessionOnly;
    let (_, session_read_only) =
        resolve_authorization_scope("ssh", session, None, None).expect("session read-only scope");
    assert!(session_read_only.contains(&"ssh.terminal_read".into()));
    assert!(session_read_only.contains(&"ssh.forward_status".into()));
    assert!(session_read_only.contains(&"ssh.sftp_list".into()));
    assert!(!session_read_only.contains(&"ssh.diagnostics".into()));
    assert!(
        validate_grant_capabilities("ssh", &["ssh.terminal_read".into()], session, false,).is_ok()
    );
    assert!(
        validate_grant_capabilities("ssh", &["ssh.terminal_read".into()], stateless, false,)
            .is_err()
    );
    assert!(
        validate_grant_capabilities("ssh", &["ssh.diagnostics".into()], session, false,).is_err()
    );

    let (_, combined) = resolve_authorization_scope(
        "ssh",
        CapabilityExecutionMode::Both,
        Some("full_access"),
        None,
    )
    .expect("combined full-access scope");
    assert_eq!(combined.len(), 15);
    assert!(combined.contains(&"ssh.diagnostics".into()));
    assert!(combined.contains(&"ssh.terminal_read".into()));
    assert!(
        validate_grant_capabilities("ssh", &combined, CapabilityExecutionMode::Both, true,).is_ok()
    );
}

#[test]
fn full_access_cli_preset_parses_with_explicit_destructive_acknowledgement() {
    let matches = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "authorize",
            "--profile",
            "docker",
            "--plugin",
            "docker",
            "--preset",
            "full_access",
            "--allow-destructive",
            "--yes",
        ])
        .expect("parse full-access authorization");
    let authorize = matches
        .subcommand_matches("agent")
        .and_then(|matches| matches.subcommand_matches("authorize"))
        .expect("authorize matches");
    assert_eq!(
        authorize.get_one::<String>("preset").map(String::as_str),
        Some("full_access")
    );
    assert_eq!(
        authorize
            .get_one::<String>("execution-mode")
            .map(String::as_str),
        Some("stateless")
    );
    assert!(authorize.get_flag("allow-destructive"));
    assert!(authorize.get_flag("yes"));
    assert_eq!(authorize.get_one::<u32>("uses"), None);

    let session = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "authorize",
            "--profile",
            "ssh-prod",
            "--plugin",
            "ssh",
            "--execution-mode",
            "session_only",
            "--capability",
            "ssh.terminal_read",
        ])
        .expect("parse session authorization");
    let authorize = session
        .subcommand_matches("agent")
        .and_then(|matches| matches.subcommand_matches("authorize"))
        .expect("session authorize matches");
    assert_eq!(
        authorize
            .get_one::<String>("execution-mode")
            .map(String::as_str),
        Some("session_only")
    );
}

#[test]
fn time_bounded_authorization_defaults_to_unlimited_uses_and_keeps_optional_limit() {
    let unlimited = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "authorize",
            "--profile",
            "prod",
            "--plugin",
            "ssh",
        ])
        .expect("parse time-only authorization");
    let unlimited = unlimited
        .subcommand_matches("agent")
        .and_then(|matches| matches.subcommand_matches("authorize"))
        .expect("authorize matches");
    assert_eq!(unlimited.get_one::<u32>("uses"), None);

    let limited = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "authorize",
            "--profile",
            "prod",
            "--plugin",
            "ssh",
            "--uses",
            "3",
        ])
        .expect("parse use-limited authorization");
    let limited = limited
        .subcommand_matches("agent")
        .and_then(|matches| matches.subcommand_matches("authorize"))
        .expect("authorize matches");
    assert_eq!(limited.get_one::<u32>("uses"), Some(&3));
}

#[test]
fn batch_authorization_spec_is_bounded_and_supports_mixed_scopes() {
    let directory = PathBuf::from("/tmp").join(format!("vb-agent-batch-spec-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("create batch spec directory");
    let path = directory.join("grants.json");
    fs::write(
        &path,
        br#"{
                "grants": [
                    {
                        "profile":"prod-db",
                        "plugin":"postgres",
                        "purpose":"Inspect replication health during incident INC-42",
                        "preset":"read_only"
                    },
                    {
                        "profile":"prod-ssh",
                        "plugin":"ssh",
                        "purpose":"Verify production uptime during incident INC-42",
                        "execution_mode":"stateless",
                        "capabilities":["ssh.exec"]
                    }
                ]
            }"#,
    )
    .expect("write batch spec");
    let spec = load_batch_authorization_spec(&path).expect("parse batch spec");
    assert_eq!(spec.grants.len(), 2);
    assert_eq!(spec.grants[0].preset.as_deref(), Some("read_only"));
    assert_eq!(
        spec.grants[0].purpose,
        "Inspect replication health during incident INC-42"
    );
    assert_eq!(spec.grants[1].capabilities, vec!["ssh.exec"]);
    assert!(grant_scope_requires_destructive(&spec.grants[1].capabilities).unwrap());
    assert!(validate_review_purpose(&spec.grants[0].purpose).is_ok());
    assert!(validate_review_purpose("   ").is_err());
    assert!(validate_review_purpose(&"x".repeat(1001)).is_err());

    let matches = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "authorize-batch",
            "--spec",
            path.to_str().expect("UTF-8 path"),
            "--ttl-minutes",
            "30",
        ])
        .expect("parse batch authorization");
    let batch = matches
        .subcommand_matches("agent")
        .and_then(|matches| matches.subcommand_matches("authorize-batch"))
        .expect("authorize-batch matches");
    assert_eq!(batch.get_one::<u32>("uses"), None);
    assert_eq!(batch.get_one::<u64>("ttl-minutes"), Some(&30));
    fs::remove_dir_all(directory).expect("remove batch spec directory");
}

#[cfg(feature = "full")]
#[test]
fn builtin_authorization_metadata_builds_shared_exact_presets() {
    for plugin_id in [
        "sqlite", "redis", "mysql", "postgres", "duckdb", "ssh", "sync",
    ] {
        let definitions = resolved_authorization_capabilities(Some(plugin_id))
            .unwrap_or_else(|error| panic!("{plugin_id} catalog failed: {error}"));
        assert!(
            definitions
                .iter()
                .all(|definition| definition.authorization.declared),
            "{plugin_id} has undeclared authorization metadata"
        );
    }

    let definitions = resolved_authorization_capabilities(Some("ssh")).expect("SSH catalog");
    let catalogs = build_authorization_plugin_catalogs(&definitions, Some("ssh"));
    let ssh = catalogs.first().expect("SSH plugin catalog");
    let read_only = ssh
        .presets
        .iter()
        .find(|preset| {
            preset.kind == AgentAuthorizationPresetKind::ReadOnly
                && preset.execution_mode == CapabilityExecutionMode::Stateless
        })
        .expect("read-only preset");
    assert!(read_only.recommended);
    assert!(read_only.capabilities.contains(&"ssh.sftp_list".into()));
    assert!(!read_only.capabilities.contains(&"ssh.exec".into()));
    let interactive = ssh
        .presets
        .iter()
        .find(|preset| {
            preset.kind == AgentAuthorizationPresetKind::InteractiveExecute
                && preset.execution_mode == CapabilityExecutionMode::Stateless
        })
        .expect("interactive preset");
    assert_eq!(interactive.capabilities, vec!["ssh.exec"]);
    assert!(interactive.requires_destructive_acknowledgement);
    assert!(interactive.session_purposes.is_empty());

    let session_interactive = ssh
        .presets
        .iter()
        .find(|preset| {
            preset.kind == AgentAuthorizationPresetKind::InteractiveExecute
                && preset.execution_mode == CapabilityExecutionMode::SessionOnly
        })
        .expect("session interactive preset");
    assert_eq!(session_interactive.capabilities, vec!["ssh.exec"]);
    assert_eq!(
        session_interactive.session_purposes,
        vec![PluginSessionPurpose::InteractiveTerminal]
    );
    let full_access = ssh
        .presets
        .iter()
        .find(|preset| {
            preset.kind == AgentAuthorizationPresetKind::FullAccess
                && preset.execution_mode == CapabilityExecutionMode::Stateless
        })
        .expect("full-access preset");
    let mut expected = definitions
        .iter()
        .filter(|definition| definition.supports_stateless_execution())
        .map(|definition| definition.qualified_id())
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(full_access.capabilities, expected);
    assert!(!full_access.recommended);
    assert!(full_access.requires_destructive_acknowledgement);

    let combined = ssh
        .presets
        .iter()
        .find(|preset| {
            preset.kind == AgentAuthorizationPresetKind::FullAccess
                && preset.execution_mode == CapabilityExecutionMode::Both
        })
        .expect("combined full-access preset");
    assert_eq!(combined.capabilities.len(), definitions.len());
    assert!(combined.capabilities.contains(&"ssh.terminal_read".into()));
    assert!(combined.capabilities.contains(&"ssh.diagnostics".into()));
}

#[test]
fn authorization_catalog_filters_supported_modes_and_remains_secret_free() {
    let definitions = resolved_authorization_capabilities(Some("ssh")).expect("SSH catalog");
    let filter = |mode| {
        definitions
            .iter()
            .filter(|definition| capability_matches_execution_modes(definition, &[mode]))
            .map(CapabilityDefinition::qualified_id)
            .collect::<Vec<_>>()
    };
    let stateless = filter(CapabilityExecutionMode::Stateless);
    assert!(stateless.contains(&"ssh.exec".into()));
    assert!(stateless.contains(&"ssh.sftp_list".into()));
    assert!(!stateless.contains(&"ssh.terminal_read".into()));
    let session = filter(CapabilityExecutionMode::SessionOnly);
    assert!(session.contains(&"ssh.exec".into()));
    assert!(session.contains(&"ssh.sftp_list".into()));
    assert!(session.contains(&"ssh.terminal_read".into()));
    assert!(!session.contains(&"ssh.diagnostics".into()));
    let combined = filter(CapabilityExecutionMode::Both);
    assert_eq!(combined.len(), definitions.len());
    assert!(combined.contains(&"ssh.diagnostics".into()));
    assert!(combined.contains(&"ssh.terminal_read".into()));

    let matches = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "catalog",
            "--plugin",
            "ssh",
            "--execution-mode",
            "stateless",
            "--execution-mode",
            "session_only",
            "--format",
            "table",
        ])
        .expect("catalog filters parse");
    let catalog = matches
        .subcommand_matches("agent")
        .and_then(|agent| agent.subcommand_matches("catalog"))
        .expect("catalog matches");
    assert_eq!(
        catalog
            .get_many::<String>("execution-mode")
            .expect("execution filters")
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["stateless", "session_only"]
    );
    assert_eq!(
        catalog.get_one::<String>("format").map(String::as_str),
        Some("table")
    );

    let table = authorization_catalog_table(
        &definitions
            .iter()
            .filter(|definition| definition.plugin_id == "ssh")
            .collect::<Vec<_>>(),
    );
    assert!(table.contains("ssh.terminal_read\tsession_only"));
    assert!(table.contains("interactive_terminal"));

    let encoded = serde_json::to_string(&build_authorization_plugin_catalogs(
        &definitions,
        Some("ssh"),
    ))
    .expect("serialize catalog");
    for forbidden in [
        "master_password",
        "token",
        "socket_path",
        "decrypted_config",
    ] {
        assert!(!encoded.contains(forbidden));
    }
}

#[cfg(feature = "full")]
#[test]
fn bundled_plugin_approval_fields_are_real_normalized_input_paths() {
    for plugin_id in ["sqlite", "redis", "mysql", "postgres", "duckdb", "ssh"] {
        let definitions = resolved_authorization_capabilities(Some(plugin_id))
            .unwrap_or_else(|error| panic!("{plugin_id} catalog failed: {error}"));
        let mut schema_count = 0;
        for definition in definitions {
            let Some(schema) = &definition.authorization.approval_schema else {
                continue;
            };
            schema_count += 1;
            schema.validate().unwrap_or_else(|error| {
                panic!("{} has invalid schema: {error}", definition.qualified_id())
            });
            for field in &schema.fields {
                if let Some(contract) = definition
                    .session_handoff
                    .as_ref()
                    .and_then(|handoff| handoff.live_session.as_ref())
                {
                    let (property, input_schema) = field
                        .path
                        .strip_prefix("/resource/")
                        .map(|property| (property, &contract.resource.identity_schema))
                        .or_else(|| {
                            field
                                .path
                                .strip_prefix("/parameters/")
                                .map(|property| (property, &contract.start_parameters_schema))
                        })
                        .unwrap_or_else(|| {
                            panic!(
                                "{} declares unsupported live-session approval path {}",
                                definition.qualified_id(),
                                field.path
                            )
                        });
                    assert!(
                        input_schema["properties"].get(property).is_some(),
                        "{} declares unenforced or nonexistent session-open field {}",
                        definition.qualified_id(),
                        field.path
                    );
                    continue;
                }
                let property = field
                    .path
                    .strip_prefix('/')
                    .expect("approval paths are JSON pointers");
                assert!(
                    definition.input_schema["properties"]
                        .get(property)
                        .is_some(),
                    "{} declares unenforced or nonexistent input field {}",
                    definition.qualified_id(),
                    field.path
                );
            }
        }
        assert!(
            schema_count > 0,
            "{plugin_id} has no enforceable structured JIT schema"
        );
    }
}

#[cfg(feature = "full")]
#[test]
fn incomplete_process_metadata_is_custom_only_and_sync_is_supported() {
    let mut definition = resolved_authorization_capabilities(Some("ssh"))
        .expect("SSH catalog")
        .into_iter()
        .next()
        .expect("SSH capability");
    definition.plugin_id = "example-process".into();
    definition.authorization = Default::default();
    let catalogs = build_authorization_plugin_catalogs(&[definition], None);
    let process = catalogs
        .iter()
        .find(|catalog| catalog.plugin_id == "example-process")
        .expect("process catalog");
    assert_eq!(process.presets.len(), 1);
    assert_eq!(
        process.presets[0].kind,
        AgentAuthorizationPresetKind::Custom
    );
    let sync_definitions = resolved_authorization_capabilities(Some("sync")).expect("Sync catalog");
    let sync_catalogs = build_authorization_plugin_catalogs(&sync_definitions, Some("sync"));
    let sync = sync_catalogs.first().expect("sync catalog");
    assert_eq!(
        sync.support.status,
        AgentAuthorizationSupportStatus::Supported
    );
    let read_only = sync
        .presets
        .iter()
        .find(|preset| preset.kind == AgentAuthorizationPresetKind::ReadOnly)
        .expect("Sync read-only preset");
    assert_eq!(
        read_only.capabilities,
        vec!["sync.diagnostics", "sync.diff", "sync.plan", "sync.status"]
    );
    let interactive = sync
        .presets
        .iter()
        .find(|preset| preset.kind == AgentAuthorizationPresetKind::InteractiveExecute)
        .expect("Sync mutation preset");
    assert_eq!(
        interactive.capabilities,
        vec!["sync.conflict_resolve", "sync.recovery"]
    );
    assert!(interactive.requires_destructive_acknowledgement);
}

#[test]
fn lifecycle_cli_requires_explicit_replace_renew_and_profile_revoke() {
    let replace = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "authorize",
            "--profile",
            "id:profile:test",
            "--plugin",
            "ssh",
            "--replace",
        ])
        .expect("parse replace");
    assert!(
        replace
            .subcommand_matches("agent")
            .and_then(|agent| agent.subcommand_matches("authorize"))
            .expect("authorize")
            .get_flag("replace")
    );

    agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "renew",
            "agent-grant:test",
            "--ttl-minutes",
            "5",
            "--uses",
            "3",
        ])
        .expect("parse renew");
    agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "revoke",
            "--profile",
            "id:profile:test",
            "--plugin",
            "ssh",
        ])
        .expect("parse profile revoke");
    assert!(
        agent_command()
            .try_get_matches_from([
                "voidb-cli",
                "agent",
                "revoke",
                "--profile",
                "id:profile:test",
            ])
            .is_err()
    );
}

#[test]
fn replacement_and_revoke_selection_are_bound_to_exact_profile_and_plugin() {
    let first = grant();
    let mut other_profile = first.clone();
    other_profile.id = "agent-grant:other-profile".into();
    other_profile.profile_id = "profile:other".into();
    other_profile.profile_name = "other".into();
    let mut other_plugin = first.clone();
    other_plugin.id = "agent-grant:other-plugin".into();
    other_plugin.plugin_id = "mysql".into();
    other_plugin.capabilities = vec!["mysql.query".into()];
    let grants = vec![first.clone(), other_profile, other_plugin];

    let replacements = grants_for_profile(&grants, &first.profile_id, &first.plugin_id);
    assert_eq!(replacements.len(), 1);
    assert_eq!(replacements[0].id, first.id);

    let profile = format!("id:{}", first.profile_id);
    let plugin = first.plugin_id.clone();
    let scoped = select_grants_for_revoke(&grants, false, None, Some(&profile), Some(&plugin));
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].id, first.id);
    assert_eq!(
        select_grants_for_revoke(&grants, true, None, None, None).len(),
        3
    );
}

#[tokio::test]
async fn forged_broker_token_is_denied_without_consuming_use_or_exposing_state() {
    let mut grant = grant();
    grant.token = "broker-secret-6ed71a".into();
    let remaining_uses = grant.remaining_uses;
    let mut host = AgentSessionHost::new(
        grant.id.clone(),
        grant.profile_id.clone(),
        grant.plugin_id.clone(),
        grant.capabilities.clone(),
        grant.expires_at,
        1,
    );
    let (response, terminate) = handle_broker_request(
        &mut grant,
        &mut host,
        "master-password-must-not-escape",
        BrokerRequest::Inspect {
            token: "forged-token".into(),
        },
    )
    .await;
    assert!(!response.ok);
    assert!(!terminate);
    assert_eq!(grant.remaining_uses, remaining_uses);
    assert_eq!(response.data, None);
    let encoded = serde_json::to_string(&response).expect("serialize denial");
    assert!(!encoded.contains(&grant.token));
    assert!(!encoded.contains("master-password-must-not-escape"));
}

#[tokio::test]
async fn grant_inspection_distinguishes_offline_and_stale_socket() {
    let directory = PathBuf::from("/tmp").join(format!("vb-agent-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("create temp directory");
    let mut grant = grant();
    grant.socket_path = directory.join("grant.sock");
    assert_eq!(
        inspect_grant(&grant).await.broker_health,
        AgentBrokerHealth::Offline
    );
    fs::write(&grant.socket_path, b"not-a-socket").expect("write stale socket marker");
    assert_eq!(
        inspect_grant(&grant).await.broker_health,
        AgentBrokerHealth::StaleSocket
    );
    let _ = fs::remove_dir_all(directory);
}

#[tokio::test]
async fn stale_recovery_removes_orphaned_socket_without_credentials() {
    let directory = PathBuf::from("/tmp").join(format!("vb-agent-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("create temp directory");
    let mut grant = grant();
    grant.id = format!("agent-grant:{}", Uuid::new_v4());
    grant.socket_path = directory.join("grant.sock");
    fs::write(&grant.socket_path, b"orphaned").expect("write stale socket marker");

    shutdown_grant(&grant, "stale_recovery")
        .await
        .expect("recover stale grant");

    assert!(!grant.socket_path.exists());
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn public_grant_projection_excludes_token_and_socket_path() {
    let grant = grant();
    let public = grant.public(AgentBrokerHealth::Online, 2);
    let value = frontend_grant_value(&public, Utc::now()).expect("serialize public grant");
    assert_eq!(value["active_session_count"], 2);
    assert_eq!(value["status"], "active");
    assert_eq!(value["active"], true);
    assert_eq!(value["allow_destructive"], false);
    assert_eq!(value["execution_mode"], "stateless");
    assert_eq!(value.get("grant"), None);
    assert_eq!(value.get("token"), None);
    assert_eq!(value.get("socket_path"), None);
}

#[test]
fn session_calls_recheck_capability_and_destructive_policy() {
    let mut grant = grant();
    grant.execution_mode = CapabilityExecutionMode::SessionOnly;
    grant
        .capabilities
        .extend(["ssh.terminal_read".into(), "ssh.terminal_write".into()]);
    let read_only = AgentSessionCallRequest {
        session: AgentSessionRef::new("session-1", 1),
        call_id: "call-1".into(),
        capability: "ssh.sftp_list".into(),
        input: Value::Null,
        destructive_acknowledged: false,
        timeout_ms: None,
        output_limit_bytes: 1024,
    };
    assert!(session_call_allowed(&grant, &read_only).is_ok());
    assert!(
        session_call_allowed(
            &grant,
            &AgentSessionCallRequest {
                capability: "ssh.terminal_read".into(),
                ..read_only.clone()
            }
        )
        .is_ok()
    );

    let destructive = AgentSessionCallRequest {
        capability: "ssh.exec".into(),
        ..read_only.clone()
    };
    assert!(session_call_allowed(&grant, &destructive).is_err());
    grant.allow_destructive = true;
    assert!(session_call_allowed(&grant, &destructive).is_err());
    assert!(
        session_call_allowed(
            &grant,
            &AgentSessionCallRequest {
                destructive_acknowledged: true,
                ..destructive
            }
        )
        .is_ok()
    );
    assert!(
        session_call_allowed(
            &grant,
            &AgentSessionCallRequest {
                capability: "ssh.terminal_write".into(),
                input: json!({ "keys": ["CTRL_C"] }),
                destructive_acknowledged: true,
                ..read_only
            }
        )
        .is_ok()
    );
}

#[test]
fn session_cli_parses_machine_readable_operation_envelopes() {
    let open = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "session",
            "open",
            "--grant",
            "agent-grant:test",
            "--purpose",
            "log_stream",
            "--capability",
            "docker.logs_follow",
            "--input-json",
            r#"{"resource":{"container_id":"fixture"}}"#,
            "--yes",
        ])
        .expect("parse session open");
    let open = open
        .subcommand_matches("agent")
        .and_then(|agent| agent.subcommand_matches("session"))
        .and_then(|session| session.subcommand_matches("open"))
        .expect("open matches");
    assert!(open.get_flag("yes"));

    let matches = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "session",
            "call",
            "--grant",
            "agent-grant:test",
            "agent-session:test",
            "--generation",
            "3",
            "--capability",
            "ssh.exec",
            "--call-id",
            "call:known-before-start",
            "--input-json",
            r#"{"command":"pwd"}"#,
            "--yes",
        ])
        .expect("parse session call");
    let operation = matches
        .subcommand_matches("agent")
        .and_then(|agent| agent.subcommand_matches("session"))
        .and_then(|session| session.subcommand_matches("call"))
        .expect("call matches");
    assert_eq!(session_ref(operation).generation, 3);
    assert_eq!(
        parse_session_json(operation, "input-json").expect("input"),
        json!({ "command": "pwd" })
    );
    assert!(operation.get_flag("yes"));
    assert_eq!(
        session_call_id(operation).expect("call ID"),
        "call:known-before-start"
    );
}

#[test]
fn session_cli_exposes_start_status_wait_and_control_lifecycle() {
    let start = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "session",
            "start",
            "--grant",
            "agent-grant:test",
            "agent-session:test",
            "--generation",
            "2",
            "--capability",
            "ssh.terminal_read",
            "--call-id",
            "call:async",
        ])
        .expect("parse start");
    let start = start
        .subcommand_matches("agent")
        .and_then(|agent| agent.subcommand_matches("session"))
        .and_then(|session| session.subcommand_matches("start"))
        .expect("start matches");
    let request = session_call_request(start).expect("start request");
    assert_eq!(request.call_id, "call:async");
    assert_eq!(request.session.generation, 2);

    let status = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "session",
            "status",
            "--grant",
            "agent-grant:test",
            "agent-session:test",
            "--call-id",
            "call:async",
        ])
        .expect("parse call status");
    let status = status
        .subcommand_matches("agent")
        .and_then(|agent| agent.subcommand_matches("session"))
        .and_then(|session| session.subcommand_matches("status"))
        .expect("status matches");
    assert_eq!(
        status.get_one::<String>("call-id").map(String::as_str),
        Some("call:async")
    );

    let wait = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "session",
            "wait",
            "--grant",
            "agent-grant:test",
            "agent-session:test",
            "--call-id",
            "call:async",
            "--wait-timeout-ms",
            "250",
        ])
        .expect("parse wait");
    let wait = wait
        .subcommand_matches("agent")
        .and_then(|agent| agent.subcommand_matches("session"))
        .and_then(|session| session.subcommand_matches("wait"))
        .expect("wait matches");
    assert_eq!(wait.get_one::<u64>("wait-timeout-ms"), Some(&250));
}

#[test]
fn broker_wire_protocol_negotiates_with_legacy_requests_and_responses() {
    let legacy_request: BrokerWireRequest = serde_json::from_value(json!({
        "action": "inspect",
        "token": "opaque"
    }))
    .expect("legacy request");
    assert_eq!(
        legacy_request.protocol_version,
        AGENT_BROKER_LEGACY_PROTOCOL_VERSION
    );

    let current_request = serde_json::to_value(BrokerWireRequest {
        protocol_version: AGENT_BROKER_PROTOCOL_VERSION,
        request: BrokerRequest::Inspect {
            token: "opaque".into(),
        },
    })
    .expect("current request");
    assert_eq!(
        current_request["protocol_version"],
        AGENT_BROKER_PROTOCOL_VERSION
    );
    assert_eq!(current_request["action"], "inspect");
    let legacy_broker_view: BrokerRequest =
        serde_json::from_value(current_request).expect("new request accepted by v1 broker");
    assert!(matches!(legacy_broker_view, BrokerRequest::Inspect { .. }));

    let grant = grant();
    let current_response = broker_data_response(&grant, json!({ "broker": "online" }));
    let mut legacy_response = serde_json::to_value(current_response).expect("response");
    legacy_response
        .as_object_mut()
        .expect("response object")
        .remove("protocol_version");
    let legacy_response: BrokerResponse =
        serde_json::from_value(legacy_response).expect("legacy response");
    assert_eq!(
        legacy_response.protocol_version,
        AGENT_BROKER_LEGACY_PROTOCOL_VERSION
    );
}

#[test]
fn session_cli_rejects_non_public_caller_owned_call_ids() {
    let matches = agent_command()
        .try_get_matches_from([
            "voidb-cli",
            "agent",
            "session",
            "call",
            "--grant",
            "agent-grant:test",
            "agent-session:test",
            "--capability",
            "ssh.exec",
            "--call-id",
            "contains a space",
        ])
        .expect("parse session call");
    let operation = matches
        .subcommand_matches("agent")
        .and_then(|agent| agent.subcommand_matches("session"))
        .and_then(|session| session.subcommand_matches("call"))
        .expect("call matches");
    let error = session_call_id(operation).expect_err("invalid call ID");
    assert!(error.to_string().contains("session.call_id_invalid"));
}

#[test]
fn session_audit_excludes_inputs_outputs_tokens_and_secret_values() {
    let grant = grant();
    let response = BrokerResponse {
        protocol_version: AGENT_BROKER_PROTOCOL_VERSION,
        ok: true,
        exit_code: 0,
        stdout: "secret-stdout".into(),
        stderr: "secret-stderr".into(),
        error: None,
        error_code: None,
        data: Some(json!({
            "session": { "session_id": "agent-session:test", "generation": 1 },
            "output": "top-secret-output"
        })),
        remaining_uses: Some(9),
        expires_at: grant.expires_at,
    };
    let event = build_agent_session_audit_event(
        &grant,
        AuditOperation::SessionCall,
        &response,
        AgentSessionAuditContext {
            session: Some(&AgentSessionRef::new("agent-session:test", 1)),
            call_id: Some("call:audit-safe"),
            capability: Some("ssh.exec"),
            purpose: Some(&PluginSessionPurpose::InteractiveTerminal),
        },
        Utc::now(),
    );
    let encoded = serde_json::to_string(&event).expect("serialize audit");
    assert!(encoded.contains("agent-session:test"));
    assert!(encoded.contains("call:audit-safe"));
    assert!(encoded.contains("ssh.exec"));
    for secret in [
        "secret-stdout",
        "secret-stderr",
        "top-secret-output",
        grant.token.as_str(),
    ] {
        assert!(!encoded.contains(secret));
    }
    assert_eq!(event.redaction, RedactionStatus::Applied);
}

#[test]
fn expired_or_exhausted_grants_are_rejected() {
    let mut grant = grant();
    grant.expires_at = Utc::now() - chrono::Duration::seconds(1);
    assert!(
        command_allowed(
            &grant,
            &[
                "profile".into(),
                "test".into(),
                "id:profile:test".into(),
                "--plugin".into(),
                "ssh".into()
            ]
        )
        .is_err()
    );
    grant.expires_at = Utc::now() + chrono::Duration::minutes(1);
    grant.remaining_uses = Some(0);
    assert!(
        command_allowed(
            &grant,
            &[
                "profile".into(),
                "test".into(),
                "id:profile:test".into(),
                "--plugin".into(),
                "ssh".into()
            ]
        )
        .is_err()
    );

    grant.remaining_uses = None;
    assert!(
        command_allowed(
            &grant,
            &[
                "profile".into(),
                "test".into(),
                "id:profile:test".into(),
                "--plugin".into(),
                "ssh".into()
            ]
        )
        .is_ok()
    );
    consume_agent_use(&mut grant, "profile", "test", None);
    assert_eq!(grant.remaining_uses, None);
}

#[tokio::test]
async fn password_pipe_is_closed_after_the_password_is_written() {
    let (writer, mut reader) = tokio::io::duplex(64);
    let receive = tokio::spawn(async move {
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .await
            .expect("read password pipe to EOF");
        bytes
    });

    write_password_and_close(writer, b"test-password")
        .await
        .expect("write and close password pipe");
    assert_eq!(
        receive.await.expect("password reader exits"),
        b"test-password"
    );
}

#[cfg(unix)]
#[test]
fn grant_rewrites_remain_parseable_during_concurrent_reads() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let directory = PathBuf::from("/tmp").join(format!("vb-agent-write-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("create temp grant directory");
    let grant_path = directory.join("grant.json");
    let mut grant = grant();
    write_grant(&grant_path, &grant).expect("write initial grant");

    let done = Arc::new(AtomicBool::new(false));
    let reader_done = Arc::clone(&done);
    let reader_path = grant_path.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        read_grant(&reader_path).expect("initial atomic grant read");
        ready_tx.send(()).expect("signal reader ready");
        let mut reads = 1;
        while !reader_done.load(Ordering::Acquire) {
            read_grant(&reader_path).expect("an atomic grant read");
            reads += 1;
        }
        reads
    });

    ready_rx.recv().expect("reader becomes ready");
    for remaining_uses in 1..=100 {
        grant.remaining_uses = Some(remaining_uses);
        write_grant(&grant_path, &grant).expect("rewrite grant");
    }
    done.store(true, Ordering::Release);
    assert!(reader.join().expect("reader exits") > 0);
    assert_eq!(
        fs::metadata(&grant_path)
            .expect("grant metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::read_dir(&directory)
            .expect("read temp directory")
            .count(),
        1
    );
    let _ = fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[tokio::test]
async fn broker_accepts_status_cancel_and_serialized_starts_during_a_blocked_call() {
    let directory = PathBuf::from("/tmp").join(format!("vb-agent-concurrent-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("create temp grant directory");
    let grant_path = directory.join("grant.json");
    let mut grant = grant();
    grant.socket_path = directory.join("grant.sock");
    grant.execution_mode = CapabilityExecutionMode::SessionOnly;
    grant.capabilities = vec!["ssh.terminal_read".into()];
    grant.remaining_uses = Some(2);
    write_grant(&grant_path, &grant).expect("write grant");

    let fixture = Arc::new(BlockingSessionState::default());
    let mut host = AgentSessionHost::new(
        grant.id.clone(),
        grant.profile_id.clone(),
        grant.plugin_id.clone(),
        grant.capabilities.clone(),
        grant.expires_at,
        1,
    );
    host.register_factory(Arc::new(BlockingSessionFactory {
        state: Arc::clone(&fixture),
    }));
    let session = host
        .open(
            AgentSessionOpenRequest {
                purpose: PluginSessionPurpose::InteractiveTerminal,
                capabilities: grant.capabilities.clone(),
                lease_seconds: 60,
                concurrency: AgentSessionConcurrency::Serialized,
                destructive_acknowledged: false,
                input: Value::Null,
            },
            Utc::now(),
        )
        .await
        .expect("open fixture session")
        .session;

    let broker_path = grant_path.clone();
    let broker_grant = grant.clone();
    let broker = tokio::spawn(async move {
        broker_loop_with_host(&broker_path, broker_grant, host, "test-password").await
    });
    wait_for_socket(&grant.socket_path)
        .await
        .expect("broker socket ready");

    let call_request = |call_id: &str| AgentSessionCallRequest {
        session: session.clone(),
        call_id: call_id.into(),
        capability: "ssh.terminal_read".into(),
        input: json!({ "offset": 0 }),
        destructive_acknowledged: false,
        timeout_ms: Some(5_000),
        output_limit_bytes: 1024,
    };
    let first = send_request(
        &grant,
        BrokerRequest::SessionCallStart {
            token: grant.token.clone(),
            request: call_request("call:first"),
        },
    )
    .await
    .expect("start first call");
    assert!(first.ok);
    wait_for_started_calls(&fixture, 1).await;

    let duplicate = send_request(
        &grant,
        BrokerRequest::SessionCallStart {
            token: grant.token.clone(),
            request: call_request("call:first"),
        },
    )
    .await
    .expect("duplicate start response");
    assert!(!duplicate.ok);
    assert_eq!(
        duplicate.error_code.as_deref(),
        Some("session.call_id_conflict")
    );
    assert_eq!(duplicate.remaining_uses, Some(1));

    let second = send_request(
        &grant,
        BrokerRequest::SessionCallStart {
            token: grant.token.clone(),
            request: call_request("call:second"),
        },
    )
    .await
    .expect("queue second call");
    assert!(second.ok);
    assert_eq!(second.remaining_uses, Some(0));
    let exhausted = send_request(
        &grant,
        BrokerRequest::SessionCallStart {
            token: grant.token.clone(),
            request: call_request("call:exhausted"),
        },
    )
    .await
    .expect("exhausted start response");
    assert!(!exhausted.ok);
    assert_eq!(exhausted.error_code.as_deref(), Some("session.expired"));
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(
        fixture
            .started
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_slice(),
        ["call:first"]
    );

    let status = tokio::time::timeout(
        Duration::from_millis(200),
        send_request(
            &grant,
            BrokerRequest::SessionCallStatus {
                token: grant.token.clone(),
                request: AgentSessionCallStatusRequest {
                    session: session.clone(),
                    call_id: "call:first".into(),
                },
            },
        ),
    )
    .await
    .expect("call status remains responsive")
    .expect("status response");
    let status: AgentSessionCallView =
        serde_json::from_value(status.data.expect("status data")).expect("call status");
    assert_eq!(status.lifecycle.state, AgentSessionCallState::Running);

    let timed_wait = send_request(
        &grant,
        BrokerRequest::SessionCallWait {
            token: grant.token.clone(),
            request: AgentSessionCallWaitRequest {
                session: session.clone(),
                call_id: "call:first".into(),
                timeout_ms: Some(10),
            },
        },
    )
    .await
    .expect("bounded non-terminal wait");
    let timed_wait: AgentSessionCallWaitResult =
        serde_json::from_value(timed_wait.data.expect("timed wait data"))
            .expect("timed wait result");
    assert!(timed_wait.wait_timed_out);
    assert_eq!(
        timed_wait.call.lifecycle.state,
        AgentSessionCallState::Running
    );

    let list = tokio::time::timeout(
        Duration::from_millis(200),
        send_request(
            &grant,
            BrokerRequest::SessionList {
                token: grant.token.clone(),
                request: AgentSessionListRequest::default(),
            },
        ),
    )
    .await
    .expect("session list remains responsive")
    .expect("list response");
    assert!(list.ok);
    assert_eq!(list.data.expect("list data")["count"], 1);

    let cancel_first = tokio::time::timeout(
        Duration::from_millis(200),
        send_request(
            &grant,
            BrokerRequest::SessionCancel {
                token: grant.token.clone(),
                request: AgentSessionCancelRequest {
                    session: session.clone(),
                    call_id: "call:first".into(),
                    timeout_ms: None,
                },
            },
        ),
    )
    .await
    .expect("cancel remains responsive")
    .expect("cancel response");
    assert!(cancel_first.ok);
    let first_wait = send_request(
        &grant,
        BrokerRequest::SessionCallWait {
            token: grant.token.clone(),
            request: AgentSessionCallWaitRequest {
                session: session.clone(),
                call_id: "call:first".into(),
                timeout_ms: Some(500),
            },
        },
    )
    .await
    .expect("wait first call");
    let first_wait: AgentSessionCallWaitResult =
        serde_json::from_value(first_wait.data.expect("wait data")).expect("wait result");
    assert!(!first_wait.wait_timed_out);
    assert_eq!(
        first_wait.call.lifecycle.state,
        AgentSessionCallState::Cancelled
    );

    wait_for_started_calls(&fixture, 2).await;
    assert_eq!(fixture.max_active.load(Ordering::SeqCst), 1);
    send_request(
        &grant,
        BrokerRequest::SessionCancel {
            token: grant.token.clone(),
            request: AgentSessionCancelRequest {
                session: session.clone(),
                call_id: "call:second".into(),
                timeout_ms: None,
            },
        },
    )
    .await
    .expect("cancel second call");
    let second_wait = send_request(
        &grant,
        BrokerRequest::SessionCallWait {
            token: grant.token.clone(),
            request: AgentSessionCallWaitRequest {
                session: session.clone(),
                call_id: "call:second".into(),
                timeout_ms: Some(500),
            },
        },
    )
    .await
    .expect("wait second call");
    let second_wait: AgentSessionCallWaitResult =
        serde_json::from_value(second_wait.data.expect("wait data")).expect("wait result");
    assert_eq!(
        second_wait.call.lifecycle.state,
        AgentSessionCallState::Cancelled
    );

    send_request(
        &grant,
        BrokerRequest::SessionClose {
            token: grant.token.clone(),
            request: AgentSessionCloseAgentRequest {
                session,
                reason: "test_complete".into(),
                timeout_ms: None,
            },
        },
    )
    .await
    .expect("close session");
    send_request(
        &grant,
        BrokerRequest::Shutdown {
            token: grant.token.clone(),
        },
    )
    .await
    .expect("shutdown response");
    broker.await.expect("broker task").expect("broker exits");
    let _ = fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broker_race_cancels_a_queued_call_before_driver_execution() {
    let directory =
        PathBuf::from("/tmp").join(format!("vb-agent-cancel-queued-{}", Uuid::new_v4()));
    let mut grant = grant();
    grant.remaining_uses = Some(2);
    let broker = RunningBlockingBroker::start(
        &directory,
        grant,
        1,
        PluginSessionPurpose::InteractiveTerminal,
    )
    .await;

    let first = send_request(
        &broker.grant,
        BrokerRequest::SessionCallStart {
            token: broker.grant.token.clone(),
            request: broker.call_request("call:running"),
        },
    )
    .await
    .expect("start running call");
    assert!(first.ok);
    wait_for_started_calls(&broker.state, 1).await;

    let queued = send_request(
        &broker.grant,
        BrokerRequest::SessionCallStart {
            token: broker.grant.token.clone(),
            request: broker.call_request("call:queued"),
        },
    )
    .await
    .expect("queue serialized call");
    assert!(queued.ok);

    let cancel = tokio::time::timeout(
        Duration::from_millis(200),
        send_request(
            &broker.grant,
            BrokerRequest::SessionCancel {
                token: broker.grant.token.clone(),
                request: AgentSessionCancelRequest {
                    session: broker.session.clone(),
                    call_id: "call:queued".into(),
                    timeout_ms: None,
                },
            },
        ),
    )
    .await
    .expect("queued cancel remains responsive")
    .expect("queued cancel response");
    assert!(cancel.ok);

    let queued_wait = tokio::time::timeout(
        Duration::from_millis(200),
        send_request(
            &broker.grant,
            BrokerRequest::SessionCallWait {
                token: broker.grant.token.clone(),
                request: AgentSessionCallWaitRequest {
                    session: broker.session.clone(),
                    call_id: "call:queued".into(),
                    timeout_ms: Some(150),
                },
            },
        ),
    )
    .await
    .expect("queued call reaches a terminal state without waiting for the gate")
    .expect("queued wait response");
    let queued_wait: AgentSessionCallWaitResult =
        serde_json::from_value(queued_wait.data.expect("queued wait data"))
            .expect("queued wait result");
    assert!(!queued_wait.wait_timed_out);
    assert_eq!(
        queued_wait.call.lifecycle.state,
        AgentSessionCallState::Cancelled
    );
    assert_eq!(queued_wait.call.lifecycle.started_at, None);
    assert_eq!(
        broker
            .state
            .started
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_slice(),
        ["call:running"]
    );
    assert_eq!(broker.state.active.load(Ordering::SeqCst), 1);

    send_request(
        &broker.grant,
        BrokerRequest::SessionCancel {
            token: broker.grant.token.clone(),
            request: AgentSessionCancelRequest {
                session: broker.session.clone(),
                call_id: "call:running".into(),
                timeout_ms: None,
            },
        },
    )
    .await
    .expect("cancel running call");
    wait_for_active_calls(&broker.state, 0).await;
    broker.shutdown().await;
    let _ = fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broker_race_close_aborts_an_inflight_transaction_and_cleans_runtime_artifacts() {
    let directory = PathBuf::from("/tmp").join(format!("vb-agent-close-race-{}", Uuid::new_v4()));
    let mut grant = grant();
    grant.remaining_uses = Some(1);
    let broker = RunningBlockingBroker::start(
        &directory,
        grant,
        7,
        PluginSessionPurpose::DatabaseTransaction,
    )
    .await;
    let grant_path = broker.grant_path.clone();
    let socket_path = broker.grant.socket_path.clone();

    let started = send_request(
        &broker.grant,
        BrokerRequest::SessionCallStart {
            token: broker.grant.token.clone(),
            request: broker.call_request("call:transaction"),
        },
    )
    .await
    .expect("start transaction call");
    assert!(started.ok);
    wait_for_started_calls(&broker.state, 1).await;

    let closed = tokio::time::timeout(
        // The fixture gate remains blocked, so completion proves independent control.
        // Allow shared CI scheduler latency without changing the 100 ms close deadline.
        Duration::from_secs(2),
        send_request(
            &broker.grant,
            BrokerRequest::SessionClose {
                token: broker.grant.token.clone(),
                request: AgentSessionCloseAgentRequest {
                    session: broker.session.clone(),
                    reason: "transaction_owner_closed".into(),
                    timeout_ms: Some(100),
                },
            },
        ),
    )
    .await
    .expect("close remains responsive during transaction I/O")
    .expect("close response");
    assert!(closed.ok);
    let calls: Vec<AgentSessionCallView> =
        serde_json::from_value(closed.data.expect("close data")["calls"].clone())
            .expect("closed call list");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].lifecycle.state, AgentSessionCallState::Aborted);
    assert_eq!(
        calls[0].lifecycle.control,
        Some(AgentSessionControlKind::Close)
    );
    wait_for_active_calls(&broker.state, 0).await;
    assert!(broker.state.closed.load(Ordering::SeqCst));
    assert_eq!(broker.state.cleanup_count.load(Ordering::SeqCst), 1);

    let repeated = send_request(
        &broker.grant,
        BrokerRequest::SessionClose {
            token: broker.grant.token.clone(),
            request: AgentSessionCloseAgentRequest {
                session: broker.session.clone(),
                reason: "repeat".into(),
                timeout_ms: None,
            },
        },
    )
    .await
    .expect("repeat close response");
    assert!(repeated.ok);
    assert_eq!(broker.state.cleanup_count.load(Ordering::SeqCst), 1);

    broker.shutdown().await;
    assert!(!socket_path.exists());
    assert!(!grant_path.exists());
    let _ = fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broker_race_restart_rejects_stale_ids_and_reuses_only_the_caller_call_id() {
    let directory = PathBuf::from("/tmp").join(format!("vb-agent-restart-{}", Uuid::new_v4()));
    let mut grant = grant();
    grant.remaining_uses = Some(2);

    let first = RunningBlockingBroker::start(
        &directory,
        grant.clone(),
        11,
        PluginSessionPurpose::InteractiveTerminal,
    )
    .await;
    let old_session = first.session.clone();
    let old_state = Arc::clone(&first.state);
    let grant_path = first.grant_path.clone();
    let socket_path = first.grant.socket_path.clone();
    let started = send_request(
        &first.grant,
        BrokerRequest::SessionCallStart {
            token: first.grant.token.clone(),
            request: first.call_request("call:reused-after-restart"),
        },
    )
    .await
    .expect("start pre-restart call");
    assert!(started.ok);
    wait_for_started_calls(&first.state, 1).await;
    first.shutdown().await;
    wait_for_active_calls(&old_state, 0).await;
    assert_eq!(old_state.cleanup_count.load(Ordering::SeqCst), 1);
    assert!(!socket_path.exists());
    assert!(!grant_path.exists());

    let restarted = RunningBlockingBroker::start(
        &directory,
        grant,
        12,
        PluginSessionPurpose::InteractiveTerminal,
    )
    .await;
    assert_ne!(restarted.session.session_id, old_session.session_id);

    let stale_call = send_request(
        &restarted.grant,
        BrokerRequest::SessionCallStatus {
            token: restarted.grant.token.clone(),
            request: AgentSessionCallStatusRequest {
                session: old_session.clone(),
                call_id: "call:reused-after-restart".into(),
            },
        },
    )
    .await
    .expect("stale call response");
    assert_eq!(
        stale_call.error_code.as_deref(),
        Some("session.call_not_found")
    );

    let stale_session = send_request(
        &restarted.grant,
        BrokerRequest::SessionStatus {
            token: restarted.grant.token.clone(),
            request: AgentSessionStatusRequest {
                session: old_session,
            },
        },
    )
    .await
    .expect("stale session response");
    assert_eq!(
        stale_session.error_code.as_deref(),
        Some("session.not_found")
    );

    let mut wrong_generation = restarted.session.clone();
    wrong_generation.generation += 1;
    let stale_generation = send_request(
        &restarted.grant,
        BrokerRequest::SessionStatus {
            token: restarted.grant.token.clone(),
            request: AgentSessionStatusRequest {
                session: wrong_generation,
            },
        },
    )
    .await
    .expect("stale generation response");
    assert_eq!(
        stale_generation.error_code.as_deref(),
        Some("session.stale")
    );

    let reused = send_request(
        &restarted.grant,
        BrokerRequest::SessionCallStart {
            token: restarted.grant.token.clone(),
            request: restarted.call_request("call:reused-after-restart"),
        },
    )
    .await
    .expect("reuse caller call ID in the new broker generation");
    assert!(reused.ok);
    wait_for_started_calls(&restarted.state, 1).await;
    send_request(
        &restarted.grant,
        BrokerRequest::SessionCancel {
            token: restarted.grant.token.clone(),
            request: AgentSessionCancelRequest {
                session: restarted.session.clone(),
                call_id: "call:reused-after-restart".into(),
                timeout_ms: None,
            },
        },
    )
    .await
    .expect("cancel post-restart call");
    wait_for_active_calls(&restarted.state, 0).await;
    restarted.shutdown().await;
    assert!(!socket_path.exists());
    assert!(!grant_path.exists());
    let _ = fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broker_race_concurrent_duplicate_callers_have_one_winner_across_repeated_rounds() {
    const ROUNDS: usize = 6;
    const CALLERS: usize = 8;

    let directory = PathBuf::from("/tmp").join(format!("vb-agent-caller-race-{}", Uuid::new_v4()));
    let mut grant = grant();
    grant.remaining_uses = Some(ROUNDS as u32 + 1);
    let broker = RunningBlockingBroker::start(
        &directory,
        grant,
        21,
        PluginSessionPurpose::InteractiveTerminal,
    )
    .await;

    for round in 0..ROUNDS {
        let call_id = format!("call:race:{round}");
        let barrier = Arc::new(tokio::sync::Barrier::new(CALLERS + 1));
        let mut callers = JoinSet::new();
        for _ in 0..CALLERS {
            let barrier = Arc::clone(&barrier);
            let grant = broker.grant.clone();
            let request = broker.call_request(&call_id);
            callers.spawn(async move {
                barrier.wait().await;
                send_request(
                    &grant,
                    BrokerRequest::SessionCallStart {
                        token: grant.token.clone(),
                        request,
                    },
                )
                .await
            });
        }
        barrier.wait().await;

        let mut accepted = 0;
        let mut conflicts = 0;
        let mut other_errors = Vec::new();
        while let Some(response) = callers.join_next().await {
            let response = response
                .expect("concurrent caller task")
                .expect("concurrent caller response");
            if response.ok {
                accepted += 1;
            } else if response.error_code.as_deref() == Some("session.call_id_conflict") {
                conflicts += 1;
            } else {
                other_errors.push((response.error_code, response.error));
            }
        }
        assert_eq!(accepted, 1);
        assert_eq!(conflicts, CALLERS - 1, "other errors: {other_errors:?}");
        assert_eq!(
            read_grant(&broker.grant_path)
                .expect("persisted use reservation")
                .remaining_uses,
            Some((ROUNDS - round) as u32)
        );
        wait_for_started_calls(&broker.state, round + 1).await;

        send_request(
            &broker.grant,
            BrokerRequest::SessionCancel {
                token: broker.grant.token.clone(),
                request: AgentSessionCancelRequest {
                    session: broker.session.clone(),
                    call_id,
                    timeout_ms: None,
                },
            },
        )
        .await
        .expect("cancel winning call");
        wait_for_active_calls(&broker.state, 0).await;
    }

    assert_eq!(
        broker
            .state
            .started
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len(),
        ROUNDS
    );
    assert_eq!(broker.state.max_active.load(Ordering::SeqCst), 1);
    broker.shutdown().await;
    let _ = fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[tokio::test]
async fn broker_shutdown_removes_private_runtime_artifacts() {
    let directory = PathBuf::from("/tmp").join(format!("vb-agent-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("create temp grant directory");
    let grant_path = directory.join("grant.json");
    let mut grant = grant();
    grant.socket_path = directory.join("grant.sock");
    write_grant(&grant_path, &grant).expect("write grant");

    let broker_path = grant_path.clone();
    let broker = tokio::spawn(async move { broker_loop(&broker_path, "test-password").await });
    wait_for_socket(&grant.socket_path)
        .await
        .expect("broker socket ready");
    assert_eq!(
        fs::metadata(&grant_path)
            .expect("grant metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&grant.socket_path)
            .expect("broker socket metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let mut legacy = UnixStream::connect(&grant.socket_path)
        .await
        .expect("connect legacy client");
    legacy
        .write_all(
            &serde_json::to_vec(&BrokerWireRequest {
                protocol_version: AGENT_BROKER_LEGACY_PROTOCOL_VERSION,
                request: BrokerRequest::SessionCallStatus {
                    token: grant.token.clone(),
                    request: AgentSessionCallStatusRequest {
                        session: AgentSessionRef::new("agent-session:test", 1),
                        call_id: "call:test".into(),
                    },
                },
            })
            .expect("serialize legacy async request"),
        )
        .await
        .expect("write legacy async request");
    legacy.shutdown().await.expect("finish legacy request");
    let mut legacy_response = Vec::new();
    legacy
        .read_to_end(&mut legacy_response)
        .await
        .expect("read legacy denial");
    let legacy_response: BrokerResponse =
        serde_json::from_slice(&legacy_response).expect("parse legacy denial");
    assert_eq!(
        legacy_response.error_code.as_deref(),
        Some("session.protocol_unsupported")
    );
    assert_eq!(
        legacy_response.protocol_version,
        AGENT_BROKER_LEGACY_PROTOCOL_VERSION
    );
    let response = send_request(
        &grant,
        BrokerRequest::Shutdown {
            token: grant.token.clone(),
        },
    )
    .await
    .expect("shutdown response");

    assert!(response.ok);
    broker.await.expect("broker task").expect("broker exits");
    assert!(!grant.socket_path.exists());
    assert!(!grant_path.exists());
    let _ = fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[tokio::test]
async fn broker_survives_bad_or_abandoned_client_connections() {
    let directory = PathBuf::from("/tmp").join(format!("vb-agent-bad-client-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("create temp grant directory");
    let grant_path = directory.join("grant.json");
    let mut grant = grant();
    grant.socket_path = directory.join("grant.sock");
    write_grant(&grant_path, &grant).expect("write grant");

    let broker_path = grant_path.clone();
    let broker = tokio::spawn(async move { broker_loop(&broker_path, "test-password").await });
    wait_for_socket(&grant.socket_path)
        .await
        .expect("broker socket ready");

    let mut malformed = UnixStream::connect(&grant.socket_path)
        .await
        .expect("connect malformed client");
    malformed
        .write_all(b"{")
        .await
        .expect("write malformed request");
    malformed.shutdown().await.expect("close malformed request");
    drop(malformed);

    let mut abandoned = UnixStream::connect(&grant.socket_path)
        .await
        .expect("connect abandoned client");
    abandoned
        .write_all(
            &serde_json::to_vec(&BrokerRequest::Inspect {
                token: grant.token.clone(),
            })
            .expect("serialize inspect request"),
        )
        .await
        .expect("write abandoned request");
    abandoned.shutdown().await.expect("close abandoned request");
    drop(abandoned);

    let response = send_request(
        &grant,
        BrokerRequest::Inspect {
            token: grant.token.clone(),
        },
    )
    .await
    .expect("broker stays available");
    assert!(response.ok);
    assert_eq!(response.remaining_uses, grant.remaining_uses);

    send_request(
        &grant,
        BrokerRequest::Shutdown {
            token: grant.token.clone(),
        },
    )
    .await
    .expect("shutdown response");
    broker.await.expect("broker task").expect("broker exits");
    let _ = fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[tokio::test]
async fn broker_remains_online_after_multiple_run_requests() {
    let directory = PathBuf::from("/tmp").join(format!("vb-agent-multi-run-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("create temp grant directory");
    let grant_path = directory.join("grant.json");
    let mut grant = grant();
    grant.socket_path = directory.join("grant.sock");
    write_grant(&grant_path, &grant).expect("write grant");

    let broker_path = grant_path.clone();
    let broker = tokio::spawn(async move { broker_loop(&broker_path, "test-password").await });
    wait_for_socket(&grant.socket_path)
        .await
        .expect("broker socket ready");

    for expected_remaining in [9, 8, 7] {
        let response = send_request(
            &grant,
            BrokerRequest::Run {
                token: grant.token.clone(),
                argv: vec![
                    "profile".into(),
                    "test".into(),
                    format!("id:{}", grant.profile_id),
                    "--plugin".into(),
                    grant.plugin_id.clone(),
                    "--format".into(),
                    "json".into(),
                ],
            },
        )
        .await
        .expect("run response");
        assert_eq!(response.remaining_uses, Some(expected_remaining));
    }

    let inspection = send_request(
        &grant,
        BrokerRequest::Inspect {
            token: grant.token.clone(),
        },
    )
    .await
    .expect("broker remains online");
    assert!(inspection.ok);
    assert_eq!(inspection.remaining_uses, Some(7));

    send_request(
        &grant,
        BrokerRequest::Shutdown {
            token: grant.token.clone(),
        },
    )
    .await
    .expect("shutdown response");
    broker.await.expect("broker task").expect("broker exits");
    let _ = fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[tokio::test]
async fn broker_lists_persistent_sessions_with_structured_data() {
    let directory = PathBuf::from("/tmp").join(format!("vb-agent-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("create temp grant directory");
    let grant_path = directory.join("grant.json");
    let mut grant = grant();
    grant.socket_path = directory.join("grant.sock");
    write_grant(&grant_path, &grant).expect("write grant");

    let broker_path = grant_path.clone();
    let broker = tokio::spawn(async move { broker_loop(&broker_path, "test-password").await });
    wait_for_socket(&grant.socket_path)
        .await
        .expect("broker socket ready");
    let response = send_request(
        &grant,
        BrokerRequest::Inspect {
            token: grant.token.clone(),
        },
    )
    .await
    .expect("inspect response");
    assert!(response.ok);
    assert_eq!(
        response.data,
        Some(json!({ "active_session_count": 0, "broker": "online" }))
    );
    assert_eq!(response.remaining_uses, grant.remaining_uses);

    let previous_profile = grant.profile_id.clone();
    let previous_plugin = grant.plugin_id.clone();
    let previous_capabilities = grant.capabilities.clone();
    let renewed_expiry = Utc::now() + chrono::Duration::minutes(5);
    let renewal = send_request(
        &grant,
        BrokerRequest::RenewGrant {
            token: grant.token.clone(),
            expires_at: renewed_expiry,
            remaining_uses: Some(3),
        },
    )
    .await
    .expect("renew response");
    assert!(renewal.ok);
    let renewed = read_grant(&grant_path).expect("renewed grant file");
    assert_eq!(renewed.profile_id, previous_profile);
    assert_eq!(renewed.plugin_id, previous_plugin);
    assert_eq!(renewed.capabilities, previous_capabilities);
    assert_eq!(renewed.remaining_uses, Some(3));
    assert_eq!(renewed.expires_at, renewed_expiry);

    send_request(
        &grant,
        BrokerRequest::Shutdown {
            token: grant.token.clone(),
        },
    )
    .await
    .expect("shutdown response");
    broker.await.expect("broker task").expect("broker exits");
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn review_decision_parsing_and_defaults() {
    assert_eq!(parse_review_decision(""), Some("b"));
    assert_eq!(parse_review_decision("  "), Some("b"));
    assert_eq!(parse_review_decision("b"), Some("b"));
    assert_eq!(parse_review_decision("B"), Some("b"));
    assert_eq!(parse_review_decision("bounded"), Some("b"));
    assert_eq!(parse_review_decision("time-bounded"), Some("b"));
    assert_eq!(parse_review_decision("o"), Some("o"));
    assert_eq!(parse_review_decision("once"), Some("o"));
    assert_eq!(parse_review_decision("a"), Some("a"));
    assert_eq!(parse_review_decision("add"), Some("a"));
    assert_eq!(parse_review_decision("add-to-grant"), Some("a"));
    assert_eq!(parse_review_decision("d"), Some("d"));
    assert_eq!(parse_review_decision("deny"), Some("d"));
    assert_eq!(parse_review_decision("reject"), Some("d"));
    assert_eq!(parse_review_decision("unknown"), None);
}

#[test]
fn review_principal_formatting() {
    let principal = AgentPrincipal {
        client_id: "antigravity".into(),
        task_id: "task-1".into(),
        instance_id: None,
    };
    let formatted = format_review_principal(&principal);
    assert!(formatted.contains("client=antigravity"));
    assert!(formatted.contains("task=task-1"));

    let principal_with_instance = AgentPrincipal {
        client_id: "antigravity".into(),
        task_id: "task-1".into(),
        instance_id: Some("inst-42".into()),
    };
    let formatted2 = format_review_principal(&principal_with_instance);
    assert!(formatted2.contains("instance=inst-42"));
}

#[test]
fn review_scope_and_risk_formatting() {
    assert_eq!(
        format_review_risk(voidb_core::CapabilityRiskLevel::ReadOnly),
        "read_only (safe)"
    );
    assert_eq!(
        format_review_risk(voidb_core::CapabilityRiskLevel::Destructive),
        "destructive (high risk)"
    );

    let scope = AgentAuthorizationScope::ExactInvocation {
        capability_id: "docker.list_containers".into(),
        normalized_input: json!({}),
        invocation_fingerprint: "fingerprint".into(),
    };
    let summary = format_review_scope_summary(&scope);
    assert!(summary.contains("Exact invocation: 'docker.list_containers'"));

    let scope_cap = AgentAuthorizationScope::Capability {
        capability_id: "mysql.query".into(),
    };
    let summary_cap = format_review_scope_summary(&scope_cap);
    assert!(summary_cap.contains("Capability 'mysql.query'"));
}
