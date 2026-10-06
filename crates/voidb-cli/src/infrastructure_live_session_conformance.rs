use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use serde_json::{Value, json};
use voidb_core::{
    AgentAuthorizationPresetKind, AgentLiveSessionAuditState, AgentLiveSessionAuditSummary,
    AgentLiveSessionBufferOverflow, AgentLiveSessionBufferPolicy, AgentLiveSessionCallCancellation,
    AgentLiveSessionCursor, AgentLiveSessionCursorKind, AgentLiveSessionEventBuffer,
    AgentLiveSessionEventKind, AgentLiveSessionReadRequest, AgentLiveSessionResumeOutcome,
    AgentSessionCallRequest, AgentSessionConcurrency, AgentSessionOpenRequest, AgentSessionRef,
    AuditOperation, CapabilityDefinition, CapabilityExecutionMode, CapabilityRiskLevel,
    PluginSessionError, PluginSessionErrorCode, RedactionStatus,
};

use super::{
    AgentGrantFile, AgentSessionAuditContext, GRANT_VERSION, broker_session_error,
    build_agent_session_audit_event, resolved_authorization_capabilities, session_call_allowed,
    session_open_allowed,
};

const SECRET: &str = "conformance-target-secret";

struct LiveFixture {
    event_capability: &'static str,
    start: Value,
    resume: Option<(AgentLiveSessionCursorKind, &'static str)>,
}

fn fixtures() -> Vec<LiveFixture> {
    vec![
        LiveFixture {
            event_capability: "docker.logs_follow",
            start: json!({
                "resource": { "container_id": SECRET },
                "parameters": { "tail": 10, "timestamps": true }
            }),
            resume: Some((AgentLiveSessionCursorKind::Timestamp, "1720000000")),
        },
        LiveFixture {
            event_capability: "docker.stats_follow",
            start: json!({
                "resource": { "container_id": SECRET },
                "parameters": {}
            }),
            resume: None,
        },
        LiveFixture {
            event_capability: "docker.events_follow",
            start: json!({
                "resource": { "scope": "daemon" },
                "parameters": { "filters": { "type": ["container"] } }
            }),
            resume: Some((
                AgentLiveSessionCursorKind::Timestamp,
                "1720000000.000000001",
            )),
        },
        LiveFixture {
            event_capability: "docker.exec_read",
            start: json!({
                "resource": { "container_id": SECRET },
                "parameters": { "command": ["/bin/sh"], "tty": true }
            }),
            resume: None,
        },
        LiveFixture {
            event_capability: "docker.attach_read",
            start: json!({
                "resource": { "container_id": SECRET },
                "parameters": { "tty": true, "logs": false }
            }),
            resume: None,
        },
        LiveFixture {
            event_capability: "kubernetes.watch_events",
            start: json!({
                "resource": {
                    "api_version": "v1",
                    "kind": "Pod",
                    "plural": "pods",
                    "namespace": SECRET
                },
                "parameters": { "label_selector": "app=fixture" }
            }),
            resume: Some((AgentLiveSessionCursorKind::ResourceVersion, "42")),
        },
        LiveFixture {
            event_capability: "kubernetes.logs_follow",
            start: json!({
                "resource": { "namespace": SECRET, "pod": "pod-a", "container": "main" },
                "parameters": { "tail": 10, "timestamps": true }
            }),
            resume: Some((
                AgentLiveSessionCursorKind::Timestamp,
                "2026-07-24T00:00:00Z",
            )),
        },
        LiveFixture {
            event_capability: "kubernetes.exec_read",
            start: json!({
                "resource": { "namespace": SECRET, "pod": "pod-a", "container": "main" },
                "parameters": { "command": ["/bin/sh"], "tty": true }
            }),
            resume: None,
        },
        LiveFixture {
            event_capability: "kubernetes.port_forward_events",
            start: json!({
                "resource": { "namespace": SECRET, "pod": "pod-a" },
                "parameters": { "remote_port": 8080, "local_port": 0 }
            }),
            resume: None,
        },
    ]
}

fn plugin_id(capability: &str) -> &str {
    capability
        .split_once('.')
        .expect("qualified fixture capability")
        .0
}

fn capability_definition(capability: &str) -> CapabilityDefinition {
    resolved_authorization_capabilities(Some(plugin_id(capability)))
        .expect("bundled authorization catalog")
        .into_iter()
        .find(|definition| definition.qualified_id() == capability)
        .unwrap_or_else(|| panic!("missing live capability {capability}"))
}

fn grant(plugin_id: &str, capabilities: Vec<String>, allow_destructive: bool) -> AgentGrantFile {
    AgentGrantFile {
        version: GRANT_VERSION,
        id: format!("agent-grant:conformance-{plugin_id}"),
        token: "opaque-test-token".into(),
        profile_id: format!("profile:{plugin_id}"),
        profile_name: "fixture".into(),
        plugin_id: plugin_id.into(),
        capabilities,
        execution_mode: CapabilityExecutionMode::SessionOnly,
        preset: Some(AgentAuthorizationPresetKind::Custom),
        allow_destructive,
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::minutes(5),
        remaining_uses: Some(100),
        socket_path: PathBuf::from(format!("/tmp/voidb-{plugin_id}-conformance.sock")),
        authorization_scopes: Vec::new(),
        principal_fingerprint: None,
        grant_revision: None,
    }
}

fn request(
    definition: &CapabilityDefinition,
    capabilities: Vec<String>,
    input: Value,
    acknowledged: bool,
) -> AgentSessionOpenRequest {
    AgentSessionOpenRequest {
        purpose: definition
            .session_handoff
            .as_ref()
            .expect("live handoff")
            .purpose
            .clone(),
        capabilities,
        lease_seconds: 60,
        concurrency: AgentSessionConcurrency::Serialized,
        destructive_acknowledged: acknowledged,
        input,
    }
}

fn cursor(kind: AgentLiveSessionCursorKind, value: &str) -> AgentLiveSessionCursor {
    AgentLiveSessionCursor {
        kind,
        value: value.to_string(),
        scope: None,
    }
}

async fn exercise_runtime(
    fixture: &LiveFixture,
    definition: &CapabilityDefinition,
) -> Result<(), PluginSessionError> {
    let handoff = definition.session_handoff.as_ref().expect("live handoff");
    let contract = handoff.live_session.as_ref().expect("live contract");
    let policy = AgentLiveSessionBufferPolicy {
        max_events: 1,
        max_bytes: contract.buffer.max_bytes.min(64 * 1024),
        overflow: contract.buffer.overflow,
    };
    let mut bounded_start = fixture.start.clone();
    bounded_start["buffer"] = serde_json::to_value(&policy).expect("buffer policy JSON");
    contract.validate_start(&bounded_start)?;

    let buffer = AgentLiveSessionEventBuffer::new(contract.clone(), policy.clone())?;
    for index in 0..3 {
        buffer
            .push(
                Utc::now(),
                AgentLiveSessionEventKind::Data,
                json!({ "fixture": fixture.event_capability, "index": index }),
                None,
                RedactionStatus::Applied,
                false,
            )
            .await?;
    }
    let snapshot = buffer.snapshot().await;
    assert_eq!(snapshot.retained_events, 1, "{}", fixture.event_capability);
    match policy.overflow {
        AgentLiveSessionBufferOverflow::Coalesce => {
            assert!(
                snapshot.coalesced_events >= 2,
                "{}",
                fixture.event_capability
            );
        }
        AgentLiveSessionBufferOverflow::DropOldest | AgentLiveSessionBufferOverflow::DropNewest => {
            assert!(snapshot.dropped_events >= 2, "{}", fixture.event_capability);
            assert!(snapshot.dropped_bytes > 0, "{}", fixture.event_capability);
        }
    }
    let batch = buffer
        .read_available(&AgentLiveSessionReadRequest::default())
        .await?;
    assert_eq!(batch.events.len(), 1, "{}", fixture.event_capability);

    let tiny_error = buffer
        .read_available(&AgentLiveSessionReadRequest {
            after_sequence: None,
            max_events: 1,
            max_bytes: 1,
            ..AgentLiveSessionReadRequest::default()
        })
        .await
        .expect_err("one-byte live batch must fail closed");
    assert_eq!(tiny_error.code, PluginSessionErrorCode::OutputLimit);

    if contract.reconnect.max_attempts == 0 {
        assert!(buffer.record_reconnect().await.is_err());
    } else {
        assert_eq!(buffer.record_reconnect().await?, 1);
        assert_eq!(buffer.snapshot().await.reconnect_attempts, 1);
    }

    match fixture.resume {
        Some((kind, value)) => {
            let mut resumed = fixture.start.clone();
            resumed["resume_from"] =
                serde_json::to_value(cursor(kind, value)).expect("resume cursor JSON");
            contract.validate_start(&resumed)?;
        }
        None => {
            let mut unsupported = fixture.start.clone();
            unsupported["resume_from"] = serde_json::to_value(cursor(
                AgentLiveSessionCursorKind::Opaque,
                "unsupported-resume",
            ))
            .expect("unsupported cursor JSON");
            assert!(contract.validate_start(&unsupported).is_err());
        }
    }

    let withheld = AgentLiveSessionEventBuffer::new(contract.clone(), policy.clone())?;
    withheld
        .push(
            Utc::now(),
            AgentLiveSessionEventKind::Data,
            json!({ "forbidden": SECRET }),
            None,
            RedactionStatus::FailedClosed,
            false,
        )
        .await?;
    let withheld_batch = withheld
        .read_available(&AgentLiveSessionReadRequest::default())
        .await?;
    assert!(withheld_batch.events[0].data.is_null());
    assert!(
        !serde_json::to_string(&withheld_batch)
            .unwrap()
            .contains(SECRET)
    );

    let waiting = AgentLiveSessionEventBuffer::new(contract.clone(), policy.clone())?;
    let cancellation = AgentLiveSessionCallCancellation::default();
    let waiting_reader = waiting.clone();
    let running_cancellation = cancellation.clone();
    let call_id = format!("cancel-{}", fixture.event_capability.replace('.', "-"));
    let running_call_id = call_id.clone();
    let task = tokio::spawn(async move {
        running_cancellation
            .run(
                &running_call_id,
                waiting_reader.read(&AgentLiveSessionReadRequest::default()),
            )
            .await
    });
    tokio::task::yield_now().await;
    cancellation.cancel(&call_id).await;
    let cancelled = task
        .await
        .expect("cancel task")
        .expect_err("cancelled read");
    assert_eq!(cancelled.code, PluginSessionErrorCode::Cancelled);

    let timeout_id = format!("timeout-{}", fixture.event_capability.replace('.', "-"));
    let timed_out = tokio::time::timeout(
        Duration::from_millis(1),
        cancellation.run(
            &timeout_id,
            waiting.read(&AgentLiveSessionReadRequest::default()),
        ),
    )
    .await;
    assert!(timed_out.is_err(), "{}", fixture.event_capability);
    waiting.close_source().await;
    let closed_batch = cancellation
        .run(
            &timeout_id,
            waiting.read(&AgentLiveSessionReadRequest::default()),
        )
        .await?;
    assert!(closed_batch.source_closed);

    let now = Utc::now();
    let audit = AgentLiveSessionAuditSummary {
        protocol_version: voidb_core::AGENT_LIVE_SESSION_PROTOCOL_VERSION,
        kind: contract.kind.clone(),
        resource_type: contract.resource.resource_type.clone(),
        resource_fingerprint: None,
        start_risk: contract.start_risk,
        state: AgentLiveSessionAuditState::Closed,
        started_at: now,
        finished_at: Some(now),
        delivered_events: batch.events.len() as u64,
        delivered_bytes: batch
            .events
            .iter()
            .map(|event| event.data_bytes as u64)
            .sum(),
        dropped_events: snapshot.dropped_events,
        dropped_bytes: snapshot.dropped_bytes,
        coalesced_events: snapshot.coalesced_events,
        reconnect_attempts: buffer.snapshot().await.reconnect_attempts,
        resume: if fixture.resume.is_some() {
            AgentLiveSessionResumeOutcome::Accepted
        } else {
            AgentLiveSessionResumeOutcome::Unsupported
        },
        redaction: RedactionStatus::Applied,
    };
    audit.validate()?;
    let encoded = serde_json::to_string(&audit).expect("audit JSON");
    assert!(!encoded.contains(SECRET));
    assert!(!encoded.contains("resume_from"));
    Ok(())
}

#[tokio::test]
async fn infrastructure_live_sessions_pass_shared_conformance() {
    let fixtures = fixtures();
    assert_eq!(fixtures.len(), 9);
    let mut family_counts = BTreeMap::<String, usize>::new();

    for fixture in &fixtures {
        let definition = capability_definition(fixture.event_capability);
        let handoff = definition
            .session_handoff
            .as_ref()
            .expect("session handoff");
        let contract = handoff.live_session.as_ref().expect("live contract");
        contract
            .validate(&handoff.capabilities)
            .unwrap_or_else(|error| panic!("{}: {error}", fixture.event_capability));
        contract
            .validate_start(&fixture.start)
            .unwrap_or_else(|error| panic!("{}: {error}", fixture.event_capability));
        assert_eq!(contract.operations.events, fixture.event_capability);
        assert_eq!(
            definition.execution_mode,
            CapabilityExecutionMode::SessionOnly
        );

        let declared = handoff.capabilities.iter().collect::<BTreeSet<_>>();
        let operations = contract.operations.capabilities().collect::<BTreeSet<_>>();
        assert_eq!(declared, operations, "{}", fixture.event_capability);
        for capability in &handoff.capabilities {
            let member = capability_definition(capability);
            assert_eq!(member.session_handoff.as_ref(), Some(handoff));
        }
        *family_counts
            .entry(definition.plugin_id.clone())
            .or_default() += 1;
        exercise_runtime(fixture, &definition)
            .await
            .unwrap_or_else(|error| panic!("{}: {error}", fixture.event_capability));
    }

    assert_eq!(
        family_counts,
        BTreeMap::from([
            ("docker".into(), 5),
            ("kubernetes".into(), 4),
        ])
    );
}

#[test]
fn infrastructure_live_session_authorization_fails_closed_for_every_family() {
    for fixture in fixtures() {
        let definition = capability_definition(fixture.event_capability);
        let handoff = definition
            .session_handoff
            .as_ref()
            .expect("session handoff");
        let contract = handoff.live_session.as_ref().expect("live contract");
        let capabilities = handoff.capabilities.clone();
        let plugin = definition.plugin_id.as_str();
        let mut open = request(
            &definition,
            capabilities.clone(),
            fixture.start.clone(),
            false,
        );
        let mut scoped_grant = grant(plugin, capabilities.clone(), false);

        if contract.start_risk == CapabilityRiskLevel::ReadOnly {
            session_open_allowed(&scoped_grant, &open)
                .unwrap_or_else(|error| panic!("{}: {error}", fixture.event_capability));
        } else {
            let error = session_open_allowed(&scoped_grant, &open)
                .expect_err("side-effecting start requires a mutating grant");
            assert!(error.to_string().contains("grant is read-only"));
            scoped_grant.allow_destructive = true;
            let error = session_open_allowed(&scoped_grant, &open)
                .expect_err("side-effecting start requires per-open acknowledgement");
            assert!(error.to_string().contains("requires --yes"));
            open.destructive_acknowledged = true;
            session_open_allowed(&scoped_grant, &open)
                .unwrap_or_else(|error| panic!("{}: {error}", fixture.event_capability));
        }

        let mut ungranted = grant(plugin, capabilities.clone(), true);
        ungranted.capabilities.pop();
        let error = session_open_allowed(&ungranted, &open)
            .expect_err("every requested family member must be granted");
        assert!(error.to_string().contains("outside the agent grant scope"));

        if capabilities.len() > 1 {
            let incomplete = request(
                &definition,
                vec![fixture.event_capability.into()],
                fixture.start.clone(),
                contract.start_risk != CapabilityRiskLevel::ReadOnly,
            );
            let complete_grant = grant(plugin, capabilities.clone(), true);
            let error = session_open_allowed(&complete_grant, &incomplete)
                .expect_err("live family must not open partially");
            assert!(
                error
                    .to_string()
                    .contains("complete declared capability family")
            );
        }

        for capability in capabilities {
            let member = capability_definition(&capability);
            let mut call_grant = grant(plugin, handoff.capabilities.clone(), false);
            let mut call = AgentSessionCallRequest {
                session: AgentSessionRef::new("agent-session:conformance", 1),
                call_id: format!("call-{}", capability.replace('.', "-")),
                capability: capability.clone(),
                input: json!({}),
                destructive_acknowledged: false,
                timeout_ms: Some(1_000),
                output_limit_bytes: 64 * 1024,
            };
            if member.effective_risk() == CapabilityRiskLevel::ReadOnly {
                session_call_allowed(&call_grant, &call)
                    .unwrap_or_else(|error| panic!("{capability}: {error}"));
            } else {
                assert!(session_call_allowed(&call_grant, &call).is_err());
                call_grant.allow_destructive = true;
                assert!(session_call_allowed(&call_grant, &call).is_err());
                call.destructive_acknowledged = true;
                session_call_allowed(&call_grant, &call)
                    .unwrap_or_else(|error| panic!("{capability}: {error}"));
            }
        }

        let response = broker_session_error(&scoped_grant, "session.policy_denied", "denied");
        let audit = build_agent_session_audit_event(
            &scoped_grant,
            AuditOperation::SessionOpen,
            &response,
            AgentSessionAuditContext {
                purpose: Some(&open.purpose),
                ..AgentSessionAuditContext::default()
            },
            Utc::now(),
        );
        assert!(!serde_json::to_string(&audit).unwrap().contains(SECRET));
    }
}

#[test]
fn infrastructure_snapshot_and_live_capabilities_remain_cli_parity_pairs() {
    for (snapshot, live) in [
        ("docker.logs", "docker.logs_follow"),
        ("docker.inspect_container", "docker.stats_follow"),
        ("kubernetes.list", "kubernetes.watch_events"),
        ("kubernetes.logs", "kubernetes.logs_follow"),
    ] {
        let snapshot = capability_definition(snapshot);
        let live = capability_definition(live);
        assert!(snapshot.supports_stateless_execution());
        assert!(!snapshot.supports_session_execution());
        assert!(!live.supports_stateless_execution());
        assert!(live.supports_session_execution());
        assert_eq!(snapshot.plugin_id, live.plugin_id);
    }
}
