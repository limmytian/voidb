//! SSH fixture-backed capability and service smoke driver.
//!
//! This example is script-facing. It exercises the SSH plugin capability
//! surface and the channel-mode service boundary against a disposable local
//! OpenSSH fixture using only generated fixture credentials and scratch paths.

#![allow(clippy::result_large_err)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::sleep;
use voidb_core::{
    ActorRef, ActorType, AgentSessionBinding, AgentSessionCallRequest, AgentSessionOpenContext,
    AgentSessionOpenRequest, AgentSessionRef, CapabilityError, CapabilityInvocation,
    CapabilityInvocationResult, InvocationConnectionTarget, InvocationControls, InvocationStatus,
    Pagination, PluginAgentSessionFactory, PluginSessionHealth, PluginSessionPurpose,
    RedactionStatus, TabInfo, TabManager,
};
use voidb_plugin_ssh::{
    SshAgentSessionFactory, SshAuthMethod, SshConfig, SshOptions, TerminalConfig,
    invoke_ssh_capability,
    service::{
        ForwardServiceCommand, ForwardStatus, ForwardType, SftpCommand, SftpEvent,
        SftpServiceCommand, SshCommand, SshEvent, SshService,
    },
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let env = FixtureEnv::from_env()?;
    ensure!(
        env.scratch.starts_with("/config/voidb-smoke-"),
        "refusing SSH smoke outside generated fixture scratch path: {}",
        env.scratch
    );

    let state_dir = env.state_dir();
    fs::create_dir_all(&state_dir).context("create SSH smoke state dir")?;

    let password_config = env.password_config()?;
    let public_key_config = env.public_key_config()?;

    run_direct_capability_smoke(&env, &state_dir, &password_config, &public_key_config).await?;
    run_channel_service_smoke(&env, &state_dir, &public_key_config).await?;
    run_persistent_agent_session_smoke(&env, &state_dir, &public_key_config).await?;

    println!("ssh fixture capability smoke passed");
    println!(
        "capabilities: diagnostics, test, exec, sftp_list, sftp_get, sftp_put, sftp_mkdir, sftp_rm"
    );
    println!("service: host-key prompt, PTY input, persistent shell/SFTP/forward, reconnect event");
    println!("scratch: {}", env.scratch);
    Ok(())
}

async fn run_persistent_agent_session_smoke(
    env: &FixtureEnv,
    state_dir: &Path,
    config: &SshConfig,
) -> Result<()> {
    let trusted_home = prepare_home(
        state_dir,
        "persistent-agent-session",
        Some(Path::new(&env.known_hosts_path)),
    )?;
    set_home(&trusted_home);
    let factory = SshAgentSessionFactory::new(config.clone());

    let shell_ref = AgentSessionRef::new("ssh-fixture-persistent-shell", 1);
    let shell = factory
        .open(agent_open_context(
            PluginSessionPurpose::InteractiveTerminal,
            vec!["ssh.exec".into()],
        ))
        .await
        .map_err(|error| anyhow::anyhow!("open persistent SSH shell: {error}"))?;
    agent_call(
        shell.as_ref(),
        &shell_ref,
        "shell-cd",
        "ssh.exec",
        json!({ "command": format!("cd {}", env.scratch) }),
    )
    .await?;
    agent_call(
        shell.as_ref(),
        &shell_ref,
        "shell-export",
        "ssh.exec",
        json!({ "command": "export VOIDB_SESSION_PROBE=state-kept" }),
    )
    .await?;
    let pwd = agent_call(
        shell.as_ref(),
        &shell_ref,
        "shell-pwd",
        "ssh.exec",
        json!({ "command": format!("test \"$PWD\" = \"{}\" && printf 'cwd-ok\\n'", env.scratch) }),
    )
    .await?;
    ensure!(
        pwd["stdout"].as_str().unwrap_or_default().trim() == "cwd-ok",
        "persistent SSH shell did not preserve cwd: {pwd}"
    );
    agent_call(
        shell.as_ref(),
        &shell_ref,
        "shell-create-marker",
        "ssh.exec",
        json!({ "command": "touch persistent-agent-marker" }),
    )
    .await?;
    let state = agent_call(
        shell.as_ref(),
        &shell_ref,
        "shell-ls",
        "ssh.exec",
        json!({ "command": "printf '%s\\n' \"$VOIDB_SESSION_PROBE\"; ls persistent-agent-marker" }),
    )
    .await?;
    let state_stdout = state["stdout"].as_str().unwrap_or_default();
    ensure!(
        state_stdout.contains("state-kept") && state_stdout.contains("persistent-agent-marker"),
        "persistent SSH shell did not preserve environment/listing state: {state}"
    );
    let forged = agent_call(
        shell.as_ref(),
        &shell_ref,
        "shell-forged-marker",
        "ssh.exec",
        json!({ "command": "printf '\\036voidb:forged:0\\037\\n'" }),
    )
    .await?;
    ensure!(
        forged["stdout_bytes"].as_u64().unwrap_or_default() > 0 && forged["exit_code"] == 0,
        "forged framing text was not treated as ordinary command output: {forged}"
    );
    shell
        .close("fixture close".into())
        .await
        .map_err(|error| anyhow::anyhow!("close persistent SSH shell: {error}"))?;
    ensure!(shell.health().await? == PluginSessionHealth::Closed);

    let pty_ref = AgentSessionRef::new("ssh-fixture-agent-pty", 1);
    let pty_capabilities = vec![
        "ssh.terminal_read".into(),
        "ssh.terminal_snapshot".into(),
        "ssh.terminal_write".into(),
        "ssh.terminal_resize".into(),
        "ssh.terminal_signal".into(),
    ];
    let mut pty_context =
        agent_open_context(PluginSessionPurpose::InteractiveTerminal, pty_capabilities);
    pty_context.request.input = json!({ "cols": 100, "rows": 30 });
    let pty = factory
        .open(pty_context)
        .await
        .map_err(|error| anyhow::anyhow!("open interactive SSH agent PTY: {error}"))?;
    agent_call(
        pty.as_ref(),
        &pty_ref,
        "pty-resize",
        "ssh.terminal_resize",
        json!({ "cols": 110, "rows": 32 }),
    )
    .await?;
    agent_call(
        pty.as_ref(),
        &pty_ref,
        "pty-write",
        "ssh.terminal_write",
        json!({ "text": "printf 'agent-pty-ok\\n'", "enter": true }),
    )
    .await?;
    let mut offset = 0;
    let mut transcript = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline && !transcript.contains("agent-pty-ok") {
        let read = agent_call(
            pty.as_ref(),
            &pty_ref,
            "pty-read",
            "ssh.terminal_read",
            json!({ "after_offset": offset, "max_bytes": 32768, "wait_ms": 250 }),
        )
        .await?;
        ensure!(
            read["gap"] == false,
            "interactive PTY output unexpectedly gapped: {read}"
        );
        offset = read["next_offset"].as_u64().unwrap_or(offset);
        transcript.push_str(read["text"].as_str().unwrap_or_default());
    }
    ensure!(
        transcript.contains("agent-pty-ok"),
        "interactive agent PTY did not return command output: {transcript:?}"
    );
    let snapshot = agent_call(
        pty.as_ref(),
        &pty_ref,
        "pty-snapshot",
        "ssh.terminal_snapshot",
        json!({}),
    )
    .await?;
    ensure!(
        snapshot["size"]["cols"] == 110 && snapshot["size"]["rows"] == 32,
        "interactive agent PTY did not retain resized dimensions: {snapshot}"
    );
    agent_call(
        pty.as_ref(),
        &pty_ref,
        "pty-recovery-key",
        "ssh.terminal_write",
        json!({ "keys": ["CTRL_C"] }),
    )
    .await?;
    pty.close("fixture close".into()).await?;
    ensure!(pty.health().await? == PluginSessionHealth::Closed);

    let sftp_ref = AgentSessionRef::new("ssh-fixture-persistent-sftp", 1);
    let sftp = factory
        .open(agent_open_context(
            PluginSessionPurpose::FileTransfer,
            vec!["ssh.sftp_list".into()],
        ))
        .await
        .map_err(|error| anyhow::anyhow!("open persistent SSH SFTP: {error}"))?;
    for call_id in ["sftp-list-one", "sftp-list-two"] {
        let listed = agent_call(
            sftp.as_ref(),
            &sftp_ref,
            call_id,
            "ssh.sftp_list",
            json!({ "path": env.scratch, "limit": 100 }),
        )
        .await?;
        ensure!(
            listed["entries"].as_array().is_some_and(|entries| entries
                .iter()
                .any(|entry| entry["name"] == "persistent-agent-marker")),
            "persistent SFTP list did not observe shell-created marker: {listed}"
        );
    }
    sftp.cancel("sftp-list-two").await?;
    ensure!(sftp.health().await? == PluginSessionHealth::Closed);

    let forward_ref = AgentSessionRef::new("ssh-fixture-persistent-forward", 1);
    let forward = factory
        .open(agent_open_context(
            PluginSessionPurpose::PortForward,
            vec!["ssh.forward_open".into(), "ssh.forward_status".into()],
        ))
        .await
        .map_err(|error| anyhow::anyhow!("open persistent SSH forward: {error}"))?;
    let opened = agent_call(
        forward.as_ref(),
        &forward_ref,
        "forward-open",
        "ssh.forward_open",
        json!({
            "bind_addr": "127.0.0.1",
            "bind_port": 0,
            "remote_host": "127.0.0.1",
            "remote_port": 2222,
        }),
    )
    .await?;
    let local_port = opened["bind_port"].as_u64().context("forward bind port")? as u16;
    let mut stream = TcpStream::connect(("127.0.0.1", local_port))
        .await
        .context("connect through persistent SSH forward")?;
    let mut banner = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut banner))
        .await
        .context("forward banner timeout")??;
    ensure!(
        String::from_utf8_lossy(&banner[..read]).starts_with("SSH-"),
        "persistent SSH forward did not bridge the remote SSH banner: {:?}",
        &banner[..read]
    );
    let status = agent_call(
        forward.as_ref(),
        &forward_ref,
        "forward-status",
        "ssh.forward_status",
        json!({}),
    )
    .await?;
    ensure!(status["active"] == true && status["status"]["connections"].as_u64().is_some());
    forward.cancel("forward-open").await?;
    ensure!(forward.health().await? == PluginSessionHealth::Closed);

    let denied = factory
        .open(agent_open_context(
            PluginSessionPurpose::InteractiveTerminal,
            vec!["ssh.sftp_list".into()],
        ))
        .await;
    ensure!(
        denied.is_err(),
        "wrong session capability scope should be denied"
    );
    Ok(())
}

fn agent_open_context(
    purpose: PluginSessionPurpose,
    capabilities: Vec<String>,
) -> AgentSessionOpenContext {
    let now = Utc::now();
    AgentSessionOpenContext {
        binding: AgentSessionBinding {
            grant_id: "ssh-fixture-grant".into(),
            profile_id: "ssh-fixture-profile".into(),
            plugin_id: "ssh".into(),
            purpose: purpose.clone(),
            allowed_capabilities: capabilities.clone(),
            host_generation: 1,
        },
        request: AgentSessionOpenRequest {
            purpose,
            capabilities,
            lease_seconds: 60,
            concurrency: Default::default(),
            destructive_acknowledged: false,
            input: Value::Null,
        },
        lease_expires_at: now + chrono::Duration::seconds(60),
    }
}

async fn agent_call(
    session: &dyn voidb_core::PluginAgentSession,
    session_ref: &AgentSessionRef,
    call_id: &str,
    capability: &str,
    input: Value,
) -> Result<Value> {
    session
        .call(AgentSessionCallRequest {
            session: session_ref.clone(),
            call_id: call_id.into(),
            capability: capability.into(),
            input,
            destructive_acknowledged: true,
            timeout_ms: Some(5_000),
            output_limit_bytes: 128 * 1024,
        })
        .await
        .map(|result| result.output)
        .map_err(|error| anyhow::anyhow!("persistent SSH agent call {call_id}: {error}"))
}

async fn run_direct_capability_smoke(
    env: &FixtureEnv,
    state_dir: &Path,
    password_config: &SshConfig,
    public_key_config: &SshConfig,
) -> Result<()> {
    let unknown_home = prepare_home(state_dir, "known-hosts-unknown", None)?;
    set_home(&unknown_home);
    let unknown_protected_samples = [
        env.password.as_str(),
        env.private_key_path.as_str(),
        env.known_hosts_path.as_str(),
    ];
    expect_error_code(
        password_config,
        "test",
        json!({}),
        false,
        None,
        ErrorExpectation {
            code: "ssh.host_key_unknown",
            protected_samples: &unknown_protected_samples,
            label: "ssh.test should reject unknown host keys in direct mode",
        },
    )
    .await?;

    let changed_home = prepare_home(
        state_dir,
        "known-hosts-changed",
        Some(Path::new(&env.changed_known_hosts_path)),
    )?;
    set_home(&changed_home);
    let changed_protected_samples = [
        env.password.as_str(),
        env.private_key_path.as_str(),
        env.known_hosts_path.as_str(),
    ];
    expect_error_code(
        password_config,
        "test",
        json!({}),
        false,
        None,
        ErrorExpectation {
            code: "ssh.host_key_changed",
            protected_samples: &changed_protected_samples,
            label: "ssh.test should reject changed host keys in direct mode",
        },
    )
    .await?;

    let trusted_home = prepare_home(
        state_dir,
        "known-hosts-trusted",
        Some(Path::new(&env.known_hosts_path)),
    )?;
    set_home(&trusted_home);

    let diagnostics = invoke_checked(
        password_config,
        "diagnostics",
        json!({}),
        false,
        None,
        "ssh.diagnostics should succeed",
    )
    .await?;
    ensure_succeeded(&diagnostics, "ssh.diagnostics")?;
    ensure!(
        diagnostics.output["auth_method"] == "password",
        "diagnostics should report password auth: {}",
        diagnostics.output
    );
    ensure_result_excludes(&diagnostics, env.password.as_str(), "ssh.diagnostics")?;
    ensure_result_excludes(
        &diagnostics,
        env.private_key_path.as_str(),
        "ssh.diagnostics",
    )?;

    let password_test = invoke_checked(
        password_config,
        "test",
        json!({}),
        false,
        None,
        "ssh.test password should succeed",
    )
    .await?;
    ensure_succeeded(&password_test, "ssh.test password")?;
    ensure!(
        password_test.output["reachable"] == true
            && password_test.output["auth_method"] == "password",
        "password test should report reachable password auth: {}",
        password_test.output
    );

    let key_test = invoke_checked(
        public_key_config,
        "test",
        json!({}),
        false,
        None,
        "ssh.test public key should succeed",
    )
    .await?;
    ensure_succeeded(&key_test, "ssh.test public key")?;
    ensure!(
        key_test.output["auth_method"] == "public_key",
        "public key test should report public_key auth: {}",
        key_test.output
    );

    let dry_run_secret = "voidb-ssh-fixture-dry-run-secret";
    let dry_exec = invoke_checked(
        &unavailable_config(env),
        "exec",
        json!({
            "command": format!("printf '{dry_run_secret}\\n'"),
            "max_stdout_bytes": 64,
            "max_stderr_bytes": 64
        }),
        true,
        None,
        "ssh.exec dry-run should not require a live target",
    )
    .await?;
    ensure_succeeded(&dry_exec, "ssh.exec dry-run")?;
    ensure_result_excludes(&dry_exec, dry_run_secret, "ssh.exec dry-run")?;

    let exec = invoke_checked(
        public_key_config,
        "exec",
        json!({
            "command": "printf 'stdout:'; whoami; printf 'stderr-line\\n' >&2; exit 7",
            "max_stdout_bytes": 128,
            "max_stderr_bytes": 128
        }),
        false,
        None,
        "ssh.exec should return bounded stdout, stderr, and exit code",
    )
    .await?;
    ensure_succeeded(&exec, "ssh.exec")?;
    ensure!(
        exec.output["exit_code"] == 7
            && exec.output["stdout"]
                .as_str()
                .unwrap_or_default()
                .contains("stdout:voidb")
            && exec.output["stderr"]
                .as_str()
                .unwrap_or_default()
                .contains("stderr-line")
            && exec.output["stdout_truncated"] == false
            && exec.output["stderr_truncated"] == false,
        "ssh.exec output mismatch: {}",
        exec.output
    );

    let local_upload = state_dir.join("put.txt");
    let local_download = state_dir.join("downloaded.txt");
    let upload_contents = format!("ssh fixture upload for {}\n", env.run_id);
    fs::write(&local_upload, &upload_contents).context("write local upload file")?;

    let upload_dir = format!("{}/uploaded", env.scratch);
    let remote_upload = format!("{upload_dir}/put.txt");

    let dry_mkdir = invoke_checked(
        &unavailable_config(env),
        "sftp_mkdir",
        json!({ "path": upload_dir }),
        true,
        None,
        "ssh.sftp_mkdir dry-run should not require a live target",
    )
    .await?;
    ensure_succeeded(&dry_mkdir, "ssh.sftp_mkdir dry-run")?;

    let dry_put = invoke_checked(
        &unavailable_config(env),
        "sftp_put",
        json!({
            "local_root": state_dir,
            "local_path": "put.txt",
            "remote_path": remote_upload
        }),
        true,
        None,
        "ssh.sftp_put dry-run should not require a live target",
    )
    .await?;
    ensure_succeeded(&dry_put, "ssh.sftp_put dry-run")?;

    invoke_checked(
        public_key_config,
        "sftp_mkdir",
        json!({ "path": upload_dir }),
        false,
        None,
        "ssh.sftp_mkdir should create scratch directory",
    )
    .await?;
    invoke_checked(
        public_key_config,
        "sftp_put",
        json!({
            "local_root": state_dir,
            "local_path": "put.txt",
            "remote_path": remote_upload
        }),
        false,
        None,
        "ssh.sftp_put should upload scratch file",
    )
    .await?;

    let paged = invoke_checked(
        public_key_config,
        "sftp_list",
        json!({ "path": env.scratch }),
        false,
        Some(Pagination {
            limit: 1,
            cursor: None,
        }),
        "ssh.sftp_list should page scratch directory",
    )
    .await?;
    ensure_succeeded(&paged, "ssh.sftp_list paged")?;
    ensure!(
        paged.output["entry_count"].as_u64().unwrap_or_default() <= 1
            && paged.output["source_entry_count"]
                .as_u64()
                .unwrap_or_default()
                >= 2
            && paged.output["next_cursor"].is_string(),
        "sftp_list should honor pagination over scratch entries: {}",
        paged.output
    );

    let list = invoke_checked(
        public_key_config,
        "sftp_list",
        json!({ "path": env.scratch }),
        false,
        Some(Pagination {
            limit: 20,
            cursor: None,
        }),
        "ssh.sftp_list should list scratch directory",
    )
    .await?;
    ensure_entry_present(&list.output, "fixture.txt")?;
    ensure_entry_present(&list.output, "uploaded")?;

    let get = invoke_checked(
        public_key_config,
        "sftp_get",
        json!({
            "remote_path": remote_upload,
            "local_root": state_dir,
            "local_path": "downloaded.txt"
        }),
        false,
        None,
        "ssh.sftp_get should download scratch file",
    )
    .await?;
    ensure_succeeded(&get, "ssh.sftp_get")?;
    let downloaded = fs::read_to_string(&local_download).context("read downloaded file")?;
    ensure!(
        downloaded == upload_contents,
        "downloaded file content mismatch"
    );

    let dry_rm = invoke_checked(
        &unavailable_config(env),
        "sftp_rm",
        json!({ "path": remote_upload }),
        true,
        None,
        "ssh.sftp_rm dry-run should not require a live target",
    )
    .await?;
    ensure_succeeded(&dry_rm, "ssh.sftp_rm dry-run")?;

    invoke_checked(
        public_key_config,
        "sftp_rm",
        json!({ "path": remote_upload }),
        false,
        None,
        "ssh.sftp_rm should remove scratch file",
    )
    .await?;

    expect_redacted_auth_failure(env, password_config).await?;

    Ok(())
}

async fn run_channel_service_smoke(
    env: &FixtureEnv,
    state_dir: &Path,
    public_key_config: &SshConfig,
) -> Result<()> {
    let channel_home = prepare_home(state_dir, "channel-first-use", None)?;
    set_home(&channel_home);

    let mut service = SshService::new(
        public_key_config.clone(),
        Arc::new(NoOpTabManager),
        tokio::runtime::Handle::current(),
    );
    service.send(SshCommand::Connect {
        config: public_key_config.clone(),
    });

    let mut prompted = false;
    loop {
        match next_service_event(&mut service, "connect channel service").await? {
            SshEvent::HostKeyVerify {
                host,
                port,
                key_changed,
                reply,
                ..
            } => {
                ensure!(
                    host == env.host,
                    "host-key prompt used unexpected host: {host}"
                );
                ensure!(
                    port == env.port,
                    "host-key prompt used unexpected port: {port}"
                );
                ensure!(
                    !key_changed,
                    "first-use channel smoke should not report changed key"
                );
                prompted = true;
                let _ = reply.send(true);
            }
            SshEvent::Connected => break,
            SshEvent::Error(message) => bail!("channel service connect failed: {message}"),
            other => bail!("unexpected channel event before connect: {other:?}"),
        }
    }
    ensure!(
        prompted,
        "channel service should expose first-use host-key prompt"
    );
    ensure!(
        channel_home.join(".ssh/known_hosts").is_file(),
        "accepted channel host key should be learned into isolated known_hosts"
    );

    let marker = format!("voidb-terminal-smoke-{}", env.run_id);
    service.send_pty_input(format!("printf '{marker}\\n'\n").into_bytes());
    wait_for_pty_marker(&mut service, &marker).await?;

    service.send(SshCommand::Sftp(SftpServiceCommand::Open));
    let mut sftp = loop {
        match next_service_event(&mut service, "open channel SFTP").await? {
            SshEvent::SftpReady(handle) => break handle,
            SshEvent::Error(message) | SshEvent::SftpError(message) => {
                bail!("channel SFTP open failed: {message}")
            }
            other => {
                if !matches!(other, SshEvent::Connected) {
                    continue;
                }
            }
        }
    };
    sftp.send(SftpCommand::ListDir(env.scratch.clone()));
    match next_sftp_event(&mut sftp, "list channel SFTP scratch").await? {
        SftpEvent::DirListed { path, entries } => {
            ensure!(
                path.ends_with(&env.scratch),
                "channel SFTP listed unexpected path: {path}"
            );
            ensure!(
                entries.iter().any(|entry| entry.name == "fixture.txt"),
                "channel SFTP list did not include fixture.txt"
            );
        }
        SftpEvent::Error(message) => bail!("channel SFTP list failed: {message}"),
        other => bail!("unexpected channel SFTP event: {}", sftp_event_name(&other)),
    }

    service.send(SshCommand::Forward(ForwardServiceCommand::Add(
        ForwardType::Local {
            bind_addr: "127.0.0.1".into(),
            bind_port: 0,
            remote_host: "127.0.0.1".into(),
            remote_port: env.port,
        },
    )));
    let forward_id = wait_for_forward_status(&mut service, ForwardStatus::Active).await?;
    service.send(SshCommand::Forward(ForwardServiceCommand::Remove(
        forward_id,
    )));
    let _ = wait_for_forward_status(&mut service, ForwardStatus::Stopped).await?;

    service.send(SshCommand::Reconnect);
    wait_for_reconnecting(&mut service).await?;

    service.send(SshCommand::Disconnect);
    wait_for_disconnected(&mut service).await?;

    Ok(())
}

#[derive(Debug)]
struct FixtureEnv {
    run_id: String,
    root: PathBuf,
    host: String,
    port: u16,
    user: String,
    password: String,
    private_key_path: String,
    known_hosts_path: String,
    changed_known_hosts_path: String,
    scratch: String,
}

impl FixtureEnv {
    fn from_env() -> Result<Self> {
        let run_id = required_env("VOIDB_FIXTURE_RUN_ID")?;
        let private_key_path = required_env("VOIDB_SSH_SMOKE_PRIVATE_KEY_PATH")?;
        let root = Path::new(&private_key_path)
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .context("private key path should live under the fixture run directory")?;

        Ok(Self {
            run_id,
            root,
            host: required_env("VOIDB_SSH_SMOKE_HOST")?,
            port: required_env("VOIDB_SSH_SMOKE_PORT")?
                .parse()
                .context("VOIDB_SSH_SMOKE_PORT must be a u16")?,
            user: required_env("VOIDB_SSH_SMOKE_USER")?,
            password: required_env("VOIDB_SSH_SMOKE_PASSWORD")?,
            private_key_path,
            known_hosts_path: required_env("VOIDB_SSH_SMOKE_KNOWN_HOSTS")?,
            changed_known_hosts_path: required_env("VOIDB_SSH_SMOKE_CHANGED_KNOWN_HOSTS")?,
            scratch: required_env("VOIDB_SSH_SMOKE_SCRATCH")?,
        })
    }

    fn state_dir(&self) -> PathBuf {
        self.root.join("ssh-capability-state")
    }

    fn password_config(&self) -> Result<SshConfig> {
        Ok(SshConfig {
            host: self.host.clone(),
            port: self.port,
            username: self.user.clone(),
            auth: SshAuthMethod::Password {
                password: self.password.clone(),
            },
            terminal: TerminalConfig::default(),
            options: fixture_options(),
        })
    }

    fn public_key_config(&self) -> Result<SshConfig> {
        Ok(SshConfig {
            host: self.host.clone(),
            port: self.port,
            username: self.user.clone(),
            auth: SshAuthMethod::PublicKey {
                private_key_path: self.private_key_path.clone(),
                passphrase: None,
            },
            terminal: TerminalConfig::default(),
            options: fixture_options(),
        })
    }
}

fn fixture_options() -> SshOptions {
    SshOptions {
        keep_alive_interval: 0,
        connect_timeout: 10,
        max_reconnect_attempts: 2,
        reconnect_base_delay: 1,
    }
}

fn unavailable_config(env: &FixtureEnv) -> SshConfig {
    SshConfig {
        host: "127.0.0.1".into(),
        port: 0,
        username: env.user.clone(),
        auth: SshAuthMethod::Password {
            password: "unused-dry-run-password".into(),
        },
        terminal: TerminalConfig::default(),
        options: fixture_options(),
    }
}

fn prepare_home(root: &Path, name: &str, known_hosts: Option<&Path>) -> Result<PathBuf> {
    let home = root.join(name);
    let ssh_dir = home.join(".ssh");
    fs::create_dir_all(&ssh_dir).with_context(|| format!("create isolated home {name}"))?;
    if let Some(source) = known_hosts {
        fs::copy(source, ssh_dir.join("known_hosts"))
            .with_context(|| format!("copy known_hosts from {}", source.display()))?;
    } else {
        fs::write(ssh_dir.join("known_hosts"), "").context("write empty known_hosts")?;
    }
    Ok(home)
}

fn set_home(home: &Path) {
    // This script-facing example runs on a current-thread runtime and changes
    // HOME only between isolated SSH calls, before each new connection starts.
    unsafe {
        std::env::set_var("HOME", home);
    }
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

async fn invoke(
    config: &SshConfig,
    capability_id: &str,
    input: Value,
    dry_run: bool,
    page: Option<Pagination>,
) -> std::result::Result<CapabilityInvocationResult, CapabilityError> {
    invoke_ssh_capability(
        config,
        CapabilityInvocation {
            id: format!("ssh-fixture-smoke-{capability_id}"),
            plugin_id: "ssh".into(),
            capability_id: capability_id.into(),
            connection: InvocationConnectionTarget::Stateless,
            input,
            controls: InvocationControls {
                dry_run,
                page,
                ..InvocationControls::default()
            },
            actor: Some(ActorRef {
                id: "agent:ssh-fixture-smoke".into(),
                actor_type: ActorType::Agent,
            }),
            requested_at: Utc::now(),
        },
    )
    .await
}

async fn invoke_checked(
    config: &SshConfig,
    capability_id: &str,
    input: Value,
    dry_run: bool,
    page: Option<Pagination>,
    label: &str,
) -> Result<CapabilityInvocationResult> {
    invoke(config, capability_id, input, dry_run, page)
        .await
        .map_err(|error| {
            let error_json = serde_json::to_string(&error).unwrap_or_else(|_| format!("{error:?}"));
            anyhow::anyhow!("{label}: {error_json}")
        })
}

struct ErrorExpectation<'a> {
    code: &'a str,
    protected_samples: &'a [&'a str],
    label: &'a str,
}

async fn expect_error_code(
    config: &SshConfig,
    capability_id: &str,
    input: Value,
    dry_run: bool,
    page: Option<Pagination>,
    expectation: ErrorExpectation<'_>,
) -> Result<()> {
    match invoke(config, capability_id, input, dry_run, page).await {
        Ok(result) => bail!(
            "{}: expected error, got output {}",
            expectation.label,
            result.output
        ),
        Err(error) => {
            ensure!(
                error.code == expectation.code
                    || error
                        .target
                        .as_ref()
                        .and_then(|target| target.code.as_deref())
                        == Some(expectation.code),
                "{}: expected error code {}, got {} / {:?}",
                expectation.label,
                expectation.code,
                error.code,
                error
                    .target
                    .as_ref()
                    .and_then(|target| target.code.as_deref())
            );
            ensure_error_excludes(&error, expectation.protected_samples, expectation.label)?;
        }
    }
    Ok(())
}

async fn expect_redacted_auth_failure(env: &FixtureEnv, config: &SshConfig) -> Result<()> {
    let mut bad = config.clone();
    bad.auth = SshAuthMethod::Password {
        password: format!("{}-wrong-secret", env.password),
    };
    set_home(&prepare_home(
        &env.state_dir(),
        "known-hosts-auth-failure",
        Some(Path::new(&env.known_hosts_path)),
    )?);

    match invoke(&bad, "test", json!({}), false, None).await {
        Ok(result) => bail!(
            "expected ssh.test auth failure, got output: {}",
            result.output
        ),
        Err(error) => {
            ensure_error_excludes(
                &error,
                &[
                    env.password.as_str(),
                    env.private_key_path.as_str(),
                    env.known_hosts_path.as_str(),
                ],
                "ssh.test auth failure",
            )?;
            ensure!(
                matches!(
                    error.redaction,
                    RedactionStatus::Applied | RedactionStatus::NotRequired
                ),
                "target error should report a non-failed redaction state: {:?}",
                error.redaction
            );
        }
    }
    Ok(())
}

fn ensure_succeeded(result: &CapabilityInvocationResult, label: &str) -> Result<()> {
    ensure!(
        result.status == InvocationStatus::Succeeded,
        "{label} returned non-success status: {:?}",
        result.status
    );
    Ok(())
}

fn ensure_result_excludes(
    result: &CapabilityInvocationResult,
    sample: &str,
    label: &str,
) -> Result<()> {
    let output = serde_json::to_string(&result.output)?;
    let summary = serde_json::to_string(&result.output_summary)?;
    ensure!(
        !output.contains(sample) && !summary.contains(sample),
        "{label} output exposed protected sample"
    );
    Ok(())
}

fn ensure_error_excludes(error: &CapabilityError, samples: &[&str], label: &str) -> Result<()> {
    let text = serde_json::to_string(error)?;
    for sample in samples.iter().copied().filter(|sample| !sample.is_empty()) {
        ensure!(
            !text.contains(sample),
            "{label} exposed protected sample in error: {text}"
        );
    }
    Ok(())
}

fn ensure_entry_present(output: &Value, name: &str) -> Result<()> {
    let entries = output["entries"]
        .as_array()
        .context("ssh.sftp_list output should include entries array")?;
    ensure!(
        entries.iter().any(|item| item["name"] == name),
        "ssh.sftp_list did not include expected entry {name}: {}",
        output
    );
    Ok(())
}

async fn next_service_event(service: &mut SshService, label: &str) -> Result<SshEvent> {
    for _ in 0..200 {
        if let Some(event) = service.poll_event() {
            return Ok(event);
        }
        sleep(Duration::from_millis(50)).await;
    }
    bail!("timed out waiting for SSH service event: {label}")
}

async fn next_sftp_event(
    handle: &mut voidb_plugin_ssh::service::SftpHandle,
    label: &str,
) -> Result<SftpEvent> {
    for _ in 0..200 {
        if let Some(event) = handle.poll_event() {
            return Ok(event);
        }
        sleep(Duration::from_millis(50)).await;
    }
    bail!("timed out waiting for SFTP event: {label}")
}

async fn wait_for_pty_marker(service: &mut SshService, marker: &str) -> Result<()> {
    let mut output = String::new();
    for _ in 0..200 {
        while let Some(chunk) = service.poll_pty_output() {
            output.push_str(&String::from_utf8_lossy(&chunk));
            if output.contains(marker) {
                return Ok(());
            }
        }
        if let Some(event) = service.poll_event() {
            match event {
                SshEvent::Error(message) => bail!("PTY smoke failed: {message}"),
                SshEvent::Disconnected => bail!("PTY smoke disconnected before marker"),
                _ => {}
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
    bail!("timed out waiting for PTY marker; output was: {output:?}")
}

async fn wait_for_forward_status(service: &mut SshService, expected: ForwardStatus) -> Result<u32> {
    for _ in 0..200 {
        match next_service_event(service, "forward status").await? {
            SshEvent::ForwardStatusChanged { id, status } if status == expected => return Ok(id),
            SshEvent::ForwardStatusChanged {
                status: ForwardStatus::Error(message),
                ..
            } => bail!("forwarding failed: {message}"),
            SshEvent::Error(message) => {
                bail!("SSH service error while waiting for forward: {message}")
            }
            _ => {}
        }
    }
    bail!("timed out waiting for forward status {expected:?}")
}

async fn wait_for_reconnecting(service: &mut SshService) -> Result<()> {
    for _ in 0..40 {
        match next_service_event(service, "reconnect event").await? {
            SshEvent::Reconnecting {
                attempt,
                max_attempts,
                ..
            } => {
                ensure!(
                    attempt == 1 && max_attempts >= 1,
                    "unexpected reconnect metadata: attempt={attempt} max={max_attempts}"
                );
                return Ok(());
            }
            SshEvent::Error(message) => {
                bail!("SSH service error while waiting for reconnect: {message}")
            }
            _ => {}
        }
    }
    bail!("timed out waiting for reconnect event")
}

async fn wait_for_disconnected(service: &mut SshService) -> Result<()> {
    for _ in 0..40 {
        match next_service_event(service, "disconnect channel service").await? {
            SshEvent::Disconnected => return Ok(()),
            SshEvent::Error(message) => {
                bail!("SSH service error while waiting for disconnect: {message}")
            }
            _ => {}
        }
    }
    bail!("timed out waiting for disconnect event")
}

fn sftp_event_name(event: &SftpEvent) -> &'static str {
    match event {
        SftpEvent::DirListed { .. } => "DirListed",
        SftpEvent::Error(_) => "Error",
        SftpEvent::DownloadComplete { .. } => "DownloadComplete",
        SftpEvent::DownloadProgress { .. } => "DownloadProgress",
        SftpEvent::UploadProgress { .. } => "UploadProgress",
        SftpEvent::UploadComplete { .. } => "UploadComplete",
        SftpEvent::OperationComplete(_) => "OperationComplete",
        SftpEvent::TransferCancelled => "TransferCancelled",
    }
}

struct NoOpTabManager;

impl TabManager for NoOpTabManager {
    fn open(&self, _title: String, _plugin_id: String, _context: Value) -> anyhow::Result<()> {
        Ok(())
    }

    fn close_current(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn set_title(&self, _title: String) -> anyhow::Result<()> {
        Ok(())
    }

    fn request_render(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn list_tabs(&self) -> anyhow::Result<Vec<TabInfo>> {
        Ok(Vec::new())
    }

    fn close_tab(&self, _index: usize) -> anyhow::Result<()> {
        Ok(())
    }

    fn switch_to(&self, _index: usize) -> anyhow::Result<()> {
        Ok(())
    }

    fn active_tab_index(&self) -> anyhow::Result<usize> {
        Ok(0)
    }

    fn quit(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
