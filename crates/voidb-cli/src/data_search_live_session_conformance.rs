use std::collections::{BTreeMap, BTreeSet};
use std::future::pending;
use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use serde_json::{Value, json};
use voidb_core::{
    AgentAuthorizationPresetKind, AgentLiveSessionAuditState, AgentLiveSessionAuditSummary,
    AgentLiveSessionBackpressureMode, AgentLiveSessionBufferPolicy,
    AgentLiveSessionCallCancellation, AgentLiveSessionCancelBehavior, AgentLiveSessionCloseEffect,
    AgentLiveSessionCursor, AgentLiveSessionCursorKind, AgentLiveSessionCursorScopePolicy,
    AgentLiveSessionEventBuffer, AgentLiveSessionEventInput, AgentLiveSessionEventKind,
    AgentLiveSessionKind, AgentLiveSessionReadRequest, AgentLiveSessionResumeMode,
    AgentLiveSessionResumeOutcome, AgentLiveSessionSourcePacedState, AgentSessionCallRequest,
    AgentSessionConcurrency, AgentSessionOpenRequest, AgentSessionRef, AuditOperation,
    CapabilityDefinition, CapabilityExecutionMode, CapabilityRiskLevel, PluginSessionError,
    PluginSessionErrorCode, RedactionStatus,
};

use super::{
    AgentGrantFile, AgentSessionAuditContext, GRANT_VERSION, broker_session_error,
    build_agent_session_audit_event, resolved_authorization_capabilities, session_call_allowed,
    session_open_allowed,
};

const SECRET: &str = "data-search-conformance-secret";
const CURSOR_SCOPE: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Clone, Copy)]
enum ResumeFixture {
    Unsupported,
    Cursor(AgentLiveSessionCursorKind, &'static str),
}

struct LiveFixture {
    capability: &'static str,
    start: Value,
    event: Value,
    resume: ResumeFixture,
}

fn fixtures() -> Vec<LiveFixture> {
    vec![
        LiveFixture {
            capability: "redis.pubsub_read",
            start: json!({
                "resource": { "scope": "subscriptions" },
                "parameters": { "channels": ["fixture.events"] }
            }),
            event: json!({
                "channel": "fixture.events",
                "pattern": null,
                "payload": "redacted",
                "payload_bytes": 8,
                "truncated": false
            }),
            resume: ResumeFixture::Unsupported,
        },
        LiveFixture {
            capability: "redis.monitor_read",
            start: json!({
                "resource": { "scope": "server" },
                "parameters": {}
            }),
            event: json!({
                "timestamp": 1721812000.5,
                "database": 0,
                "command_name": "GET",
                "argument_count": 1,
                "raw_omitted": true
            }),
            resume: ResumeFixture::Unsupported,
        },
        LiveFixture {
            capability: "redis.stream_read",
            start: json!({
                "resource": { "key": "fixture:events" },
                "parameters": { "start_id": "0-0", "count": 2, "block_ms": 250 }
            }),
            event: json!({
                "id": "1721812000000-0",
                "fields": { "kind": "fixture" },
                "fields_truncated": false
            }),
            resume: ResumeFixture::Cursor(AgentLiveSessionCursorKind::EventId, "1721812000000-0"),
        },
        LiveFixture {
            capability: "mongodb.cursor_read",
            start: json!({
                "resource": { "database": "fixture", "collection": "accounts" },
                "parameters": { "mode": "find", "batch_size": 2, "max_time_ms": 250 }
            }),
            event: json!({
                "document": { "_id": "fixture", "value": "redacted" },
                "document_omitted": false
            }),
            resume: ResumeFixture::Unsupported,
        },
        LiveFixture {
            capability: "mongodb.change_stream_read",
            start: json!({
                "resource": { "database": "fixture", "collection": "accounts" },
                "parameters": { "pipeline": [], "batch_size": 2, "max_await_ms": 250 }
            }),
            event: json!({
                "operation_type": "insert",
                "namespace": { "database": "fixture", "collection": "accounts" },
                "document_key": { "_id": "fixture" },
                "document_key_omitted": false,
                "full_document": null,
                "update_description": null,
                "update_description_omitted": false,
                "cluster_time": "1:1",
                "wall_time": null,
                "resume_token_omitted": true,
                "session_metadata_omitted": true
            }),
            resume: ResumeFixture::Cursor(AgentLiveSessionCursorKind::Opaque, "opaque-resume"),
        },
        LiveFixture {
            capability: "elasticsearch.search_stream_read",
            start: json!({
                "resource": { "index": "fixture-events" },
                "parameters": {
                    "mode": "pit",
                    "query": { "match_all": {} },
                    "sort": ["_shard_doc"],
                    "batch_size": 2,
                    "keep_alive_ms": 60000
                }
            }),
            event: json!({
                "event_type": "hit",
                "index": "fixture-events",
                "id": "fixture",
                "source": { "value": "redacted" },
                "source_omitted": false
            }),
            resume: ResumeFixture::Cursor(AgentLiveSessionCursorKind::Opaque, "opaque-resume"),
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
        id: format!("agent-grant:data-search-conformance-{plugin_id}"),
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
        socket_path: PathBuf::from(format!("/tmp/voidb-{plugin_id}-data-conformance.sock")),
        authorization_scopes: Vec::new(),
        principal_fingerprint: None,
        grant_revision: None,
    }
}

fn open_request(
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
        scope: Some(CURSOR_SCOPE.into()),
    }
}

fn event_input(
    fixture: &LiveFixture,
    contract: &voidb_core::AgentLiveSessionContract,
    redaction: RedactionStatus,
) -> AgentLiveSessionEventInput {
    let cursor = match fixture.resume {
        ResumeFixture::Unsupported => None,
        ResumeFixture::Cursor(kind, value) => Some(AgentLiveSessionCursor {
            kind,
            value: value.into(),
            scope: (contract.delivery.cursor_scope == AgentLiveSessionCursorScopePolicy::Required)
                .then(|| CURSOR_SCOPE.into()),
        }),
    };
    AgentLiveSessionEventInput {
        observed_at: Utc::now(),
        kind: AgentLiveSessionEventKind::Data,
        data: if matches!(redaction, RedactionStatus::FailedClosed) {
            json!({ "forbidden": SECRET })
        } else {
            fixture.event.clone()
        },
        cursor,
        redaction,
        terminal: false,
    }
}

async fn exercise_delivery(
    fixture: &LiveFixture,
    contract: &voidb_core::AgentLiveSessionContract,
) -> Result<(u64, u64, u64), PluginSessionError> {
    let policy = AgentLiveSessionBufferPolicy {
        max_events: 1,
        max_bytes: contract.buffer.max_bytes.min(64 * 1024),
        overflow: contract.buffer.overflow,
    };
    let mut bounded_start = fixture.start.clone();
    bounded_start["buffer"] = serde_json::to_value(&policy).expect("buffer policy JSON");
    contract.validate_start(&bounded_start)?;

    if contract.delivery.backpressure == AgentLiveSessionBackpressureMode::BoundedBuffer {
        let buffer = AgentLiveSessionEventBuffer::new(contract.clone(), policy)?;
        for _ in 0..3 {
            let event = event_input(fixture, contract, RedactionStatus::Applied);
            buffer
                .push(
                    event.observed_at,
                    event.kind,
                    event.data,
                    event.cursor,
                    event.redaction,
                    event.terminal,
                )
                .await?;
        }
        let snapshot = buffer.snapshot().await;
        assert_eq!(snapshot.retained_events, 1, "{}", fixture.capability);
        assert!(snapshot.dropped_events >= 2, "{}", fixture.capability);
        let batch = buffer
            .read_available(&AgentLiveSessionReadRequest::default())
            .await?;
        assert_eq!(batch.events.len(), 1, "{}", fixture.capability);
        Ok((
            snapshot.dropped_events,
            snapshot.dropped_bytes,
            snapshot.coalesced_events,
        ))
    } else {
        let mut state = AgentLiveSessionSourcePacedState::default();
        let candidates = (0..3)
            .map(|_| event_input(fixture, contract, RedactionStatus::Applied))
            .collect::<Vec<_>>();
        let request = AgentLiveSessionReadRequest {
            max_events: 1,
            max_bytes: 64 * 1024,
            wait_timeout_ms: 0,
            ..AgentLiveSessionReadRequest::default()
        };
        let (first, consumed) = state.build_batch(&request, contract, &candidates, false, false)?;
        assert_eq!(consumed, 1, "{}", fixture.capability);
        assert_eq!(first.events.len(), 1, "{}", fixture.capability);
        assert_eq!(first.dropped_events, 0, "{}", fixture.capability);
        assert_eq!(first.coalesced_events, 0, "{}", fixture.capability);

        let next = AgentLiveSessionReadRequest {
            after_sequence: Some(1),
            ..request
        };
        let (second, consumed) =
            state.build_batch(&next, contract, &candidates[1..], false, false)?;
        assert_eq!(consumed, 1, "{}", fixture.capability);
        assert_eq!(second.events[0].sequence, 2, "{}", fixture.capability);
        Ok((0, 0, 0))
    }
}

async fn exercise_failed_closed_redaction(
    fixture: &LiveFixture,
    contract: &voidb_core::AgentLiveSessionContract,
) -> Result<(), PluginSessionError> {
    let batch = if contract.delivery.backpressure == AgentLiveSessionBackpressureMode::BoundedBuffer
    {
        let buffer = AgentLiveSessionEventBuffer::new(contract.clone(), contract.buffer.clone())?;
        let event = event_input(fixture, contract, RedactionStatus::FailedClosed);
        buffer
            .push(
                event.observed_at,
                event.kind,
                event.data,
                event.cursor,
                event.redaction,
                event.terminal,
            )
            .await?;
        buffer
            .read_available(&AgentLiveSessionReadRequest::default())
            .await?
    } else {
        let mut state = AgentLiveSessionSourcePacedState::default();
        let candidate = event_input(fixture, contract, RedactionStatus::FailedClosed);
        state
            .build_batch(
                &AgentLiveSessionReadRequest {
                    wait_timeout_ms: 0,
                    ..AgentLiveSessionReadRequest::default()
                },
                contract,
                &[candidate],
                false,
                false,
            )?
            .0
    };
    assert!(batch.events[0].data.is_null(), "{}", fixture.capability);
    assert!(
        !serde_json::to_string(&batch).unwrap().contains(SECRET),
        "{}",
        fixture.capability
    );
    Ok(())
}

async fn exercise_cancellation(capability: &str) {
    let cancellation = AgentLiveSessionCallCancellation::default();
    let running = cancellation.clone();
    let call_id = format!("cancel-{}", capability.replace('.', "-"));
    let running_call_id = call_id.clone();
    let task = tokio::spawn(async move {
        running
            .run(
                &running_call_id,
                pending::<Result<(), PluginSessionError>>(),
            )
            .await
    });
    tokio::task::yield_now().await;
    cancellation.cancel(&call_id).await;
    let error = task
        .await
        .expect("cancellation task")
        .expect_err("pending call must be cancelled");
    assert_eq!(
        error.code,
        PluginSessionErrorCode::Cancelled,
        "{capability}"
    );
}

#[tokio::test]
async fn data_search_live_sessions_pass_shared_conformance() {
    let fixtures = fixtures();
    assert_eq!(fixtures.len(), 6);
    let mut family_counts = BTreeMap::<String, usize>::new();

    for fixture in &fixtures {
        let definition = capability_definition(fixture.capability);
        let handoff = definition
            .session_handoff
            .as_ref()
            .expect("session handoff");
        let contract = handoff.live_session.as_ref().expect("live contract");
        contract
            .validate(&handoff.capabilities)
            .unwrap_or_else(|error| panic!("{}: {error}", fixture.capability));
        contract
            .validate_start(&fixture.start)
            .unwrap_or_else(|error| panic!("{}: {error}", fixture.capability));
        assert_eq!(contract.operations.events, fixture.capability);
        assert_eq!(
            definition.execution_mode,
            CapabilityExecutionMode::SessionOnly
        );

        let declared = handoff.capabilities.iter().collect::<BTreeSet<_>>();
        let operations = contract.operations.capabilities().collect::<BTreeSet<_>>();
        assert_eq!(declared, operations, "{}", fixture.capability);
        for capability in &handoff.capabilities {
            let member = capability_definition(capability);
            assert_eq!(member.session_handoff.as_ref(), Some(handoff));
        }

        match fixture.resume {
            ResumeFixture::Unsupported => {
                let mut unsupported = fixture.start.clone();
                unsupported["resume_from"] =
                    serde_json::to_value(cursor(AgentLiveSessionCursorKind::Opaque, "invalid"))
                        .expect("resume cursor JSON");
                assert!(contract.validate_start(&unsupported).is_err());
            }
            ResumeFixture::Cursor(kind, value) => {
                let mut resumed = fixture.start.clone();
                resumed["resume_from"] =
                    serde_json::to_value(cursor(kind, value)).expect("resume cursor JSON");
                contract
                    .validate_start(&resumed)
                    .unwrap_or_else(|error| panic!("{}: {error}", fixture.capability));
            }
        }

        let (dropped_events, dropped_bytes, coalesced_events) =
            exercise_delivery(fixture, contract)
                .await
                .unwrap_or_else(|error| panic!("{}: {error}", fixture.capability));
        exercise_failed_closed_redaction(fixture, contract)
            .await
            .unwrap_or_else(|error| panic!("{}: {error}", fixture.capability));
        exercise_cancellation(fixture.capability).await;

        let reconnect_attempts = if contract.reconnect.max_attempts == 0 {
            let mut state = AgentLiveSessionSourcePacedState::default();
            assert!(state.record_reconnect(contract).is_err());
            0
        } else {
            let mut state = AgentLiveSessionSourcePacedState::default();
            state
                .record_reconnect(contract)
                .expect("declared reconnect")
        };
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
            delivered_events: 2,
            delivered_bytes: 128,
            dropped_events,
            dropped_bytes,
            coalesced_events,
            reconnect_attempts,
            resume: match fixture.resume {
                ResumeFixture::Unsupported => AgentLiveSessionResumeOutcome::Unsupported,
                ResumeFixture::Cursor(_, _) => AgentLiveSessionResumeOutcome::Accepted,
            },
            redaction: RedactionStatus::Applied,
        };
        audit.validate().expect("valid secret-free audit summary");
        let encoded = serde_json::to_string(&audit).expect("audit JSON");
        assert!(!encoded.contains(SECRET));
        assert!(!encoded.contains("resume_from"));

        *family_counts
            .entry(definition.plugin_id.clone())
            .or_default() += 1;
    }

    assert_eq!(
        family_counts,
        BTreeMap::from([
            ("elasticsearch".into(), 1),
            ("mongodb".into(), 2),
            ("redis".into(), 3),
        ])
    );
}

#[test]
fn data_search_contract_snapshot_is_stable() {
    let snapshots = fixtures()
        .into_iter()
        .map(|fixture| {
            let definition = capability_definition(fixture.capability);
            let contract = definition
                .session_handoff
                .as_ref()
                .and_then(|handoff| handoff.live_session.as_ref())
                .expect("live contract");
            (
                fixture.capability,
                contract.kind.clone(),
                contract.delivery.backpressure,
                contract.delivery.cursor_scope,
                contract.reconnect.resume,
                contract.reconnect.cursor_kind,
                contract.control.cancel,
                contract.control.close,
                contract.start_risk,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        snapshots,
        vec![
            (
                "redis.pubsub_read",
                AgentLiveSessionKind::Subscription,
                AgentLiveSessionBackpressureMode::BoundedBuffer,
                AgentLiveSessionCursorScopePolicy::Optional,
                AgentLiveSessionResumeMode::Restart,
                None,
                AgentLiveSessionCancelBehavior::CallOnly,
                AgentLiveSessionCloseEffect::StopObservation,
                CapabilityRiskLevel::ReadOnly,
            ),
            (
                "redis.monitor_read",
                AgentLiveSessionKind::Events,
                AgentLiveSessionBackpressureMode::BoundedBuffer,
                AgentLiveSessionCursorScopePolicy::Optional,
                AgentLiveSessionResumeMode::Restart,
                None,
                AgentLiveSessionCancelBehavior::CallOnly,
                AgentLiveSessionCloseEffect::StopObservation,
                CapabilityRiskLevel::ExternalSideEffect,
            ),
            (
                "redis.stream_read",
                AgentLiveSessionKind::Cursor,
                AgentLiveSessionBackpressureMode::SourcePaced,
                AgentLiveSessionCursorScopePolicy::Required,
                AgentLiveSessionResumeMode::BestEffortCursor,
                Some(AgentLiveSessionCursorKind::EventId),
                AgentLiveSessionCancelBehavior::CallAndSource,
                AgentLiveSessionCloseEffect::StopObservation,
                CapabilityRiskLevel::ReadOnly,
            ),
            (
                "mongodb.cursor_read",
                AgentLiveSessionKind::Cursor,
                AgentLiveSessionBackpressureMode::SourcePaced,
                AgentLiveSessionCursorScopePolicy::Optional,
                AgentLiveSessionResumeMode::Unsupported,
                None,
                AgentLiveSessionCancelBehavior::CallAndSource,
                AgentLiveSessionCloseEffect::StopObservation,
                CapabilityRiskLevel::ReadOnly,
            ),
            (
                "mongodb.change_stream_read",
                AgentLiveSessionKind::Cursor,
                AgentLiveSessionBackpressureMode::SourcePaced,
                AgentLiveSessionCursorScopePolicy::Required,
                AgentLiveSessionResumeMode::ExactCursor,
                Some(AgentLiveSessionCursorKind::Opaque),
                AgentLiveSessionCancelBehavior::CallAndSource,
                AgentLiveSessionCloseEffect::StopObservation,
                CapabilityRiskLevel::ReadOnly,
            ),
            (
                "elasticsearch.search_stream_read",
                AgentLiveSessionKind::Cursor,
                AgentLiveSessionBackpressureMode::SourcePaced,
                AgentLiveSessionCursorScopePolicy::Required,
                AgentLiveSessionResumeMode::BestEffortCursor,
                Some(AgentLiveSessionCursorKind::Opaque),
                AgentLiveSessionCancelBehavior::CallAndSource,
                AgentLiveSessionCloseEffect::StopObservation,
                CapabilityRiskLevel::ReadOnly,
            ),
        ]
    );
}

#[test]
fn data_search_live_session_authorization_fails_closed() {
    for fixture in fixtures() {
        let definition = capability_definition(fixture.capability);
        let handoff = definition
            .session_handoff
            .as_ref()
            .expect("session handoff");
        let contract = handoff.live_session.as_ref().expect("live contract");
        let capabilities = handoff.capabilities.clone();
        let plugin = definition.plugin_id.as_str();
        let mut open = open_request(
            &definition,
            capabilities.clone(),
            fixture.start.clone(),
            false,
        );
        let mut scoped_grant = grant(plugin, capabilities.clone(), false);

        if contract.start_risk == CapabilityRiskLevel::ReadOnly {
            session_open_allowed(&scoped_grant, &open)
                .unwrap_or_else(|error| panic!("{}: {error}", fixture.capability));
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
                .unwrap_or_else(|error| panic!("{}: {error}", fixture.capability));
        }

        let mut ungranted = grant(plugin, capabilities.clone(), true);
        ungranted.capabilities.clear();
        let error = session_open_allowed(&ungranted, &open)
            .expect_err("live family must stay inside the grant scope");
        assert!(error.to_string().contains("outside the agent grant scope"));

        let member = capability_definition(fixture.capability);
        let mut call_grant = grant(plugin, capabilities, false);
        let mut call = AgentSessionCallRequest {
            session: AgentSessionRef::new("agent-session:data-search-conformance", 1),
            call_id: format!("call-{}", fixture.capability.replace('.', "-")),
            capability: fixture.capability.into(),
            input: json!({}),
            destructive_acknowledged: false,
            timeout_ms: Some(1_000),
            output_limit_bytes: 64 * 1024,
        };
        if member.effective_risk() == CapabilityRiskLevel::ReadOnly {
            session_call_allowed(&call_grant, &call)
                .unwrap_or_else(|error| panic!("{}: {error}", fixture.capability));
        } else {
            assert!(session_call_allowed(&call_grant, &call).is_err());
            call_grant.allow_destructive = true;
            assert!(session_call_allowed(&call_grant, &call).is_err());
            call.destructive_acknowledged = true;
            session_call_allowed(&call_grant, &call)
                .unwrap_or_else(|error| panic!("{}: {error}", fixture.capability));
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

    let ttl = capability_definition("redis.ttl");
    let expire = capability_definition("redis.expire");
    assert_eq!(ttl.effective_risk(), CapabilityRiskLevel::ReadOnly);
    assert!(!ttl.destructive);
    assert_eq!(expire.effective_risk(), CapabilityRiskLevel::Destructive);
    assert!(expire.destructive);
    assert!(expire.supports_dry_run);
}

#[tokio::test]
async fn data_search_cancellation_and_timeout_are_bounded() {
    let cancellation = AgentLiveSessionCallCancellation::default();
    let timeout = tokio::time::timeout(
        Duration::from_millis(1),
        cancellation.run(
            "timeout-data-search",
            pending::<Result<(), PluginSessionError>>(),
        ),
    )
    .await;
    assert!(timeout.is_err());
    cancellation.close().await;
    let error = cancellation
        .run(
            "closed-data-search",
            pending::<Result<(), PluginSessionError>>(),
        )
        .await
        .expect_err("closed cancellation group must reject new calls");
    assert_eq!(error.code, PluginSessionErrorCode::Cancelled);
}
