//! Persistent, secret-free JIT authorization request and grant-revision store.
//!
//! This module deliberately owns state and policy rather than a plugin. The
//! local approval surface authenticates the human separately; agent-facing
//! calls are bound to a stable principal and never receive credential data.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use voidb_core::{
    AgentAuthorizationAuditAction, AgentAuthorizationAuditProjection, AgentAuthorizationDecision,
    AgentAuthorizationDecisionOutcome, AgentAuthorizationError, AgentAuthorizationRequest,
    AgentAuthorizationRequestStatus, AgentAuthorizationScope, AgentGrantAmendment,
    AgentGrantRevision, AgentLogicalGrant, AgentPrincipal, AppConfig, CapabilityRiskLevel,
    FrontendAuthorizationRequest, MAX_AGENT_GRANT_TTL_MINUTES, MAX_AGENT_GRANT_USES,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const STORE_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct JitAuthorizationPolicy {
    pub max_pending_global: usize,
    pub max_pending_per_principal: usize,
    pub rate_limit_requests: usize,
    pub rate_limit_window: Duration,
    pub denial_cooldown: Duration,
    pub max_wait: StdDuration,
}

impl Default for JitAuthorizationPolicy {
    fn default() -> Self {
        Self {
            max_pending_global: 128,
            max_pending_per_principal: 16,
            rate_limit_requests: 8,
            rate_limit_window: Duration::minutes(1),
            denial_cooldown: Duration::seconds(60),
            max_wait: StdDuration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone)]
pub struct JitAuthorizationStore {
    root: PathBuf,
    broker_instance_id: String,
    policy: JitAuthorizationPolicy,
}

#[derive(Debug, Clone)]
pub struct CreateAuthorizationRequest {
    pub principal: AgentPrincipal,
    pub profile_id: String,
    pub plugin_id: String,
    pub scope: AgentAuthorizationScope,
    pub risk: CapabilityRiskLevel,
    pub purpose: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateAuthorizationResult {
    pub request: FrontendAuthorizationRequest,
    pub review_command: String,
    pub deduplicated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WaitAuthorizationResult {
    pub request: FrontendAuthorizationRequest,
    pub timed_out: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequestRecord {
    version: u32,
    request: AgentAuthorizationRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GrantLedger {
    version: u32,
    logical: AgentLogicalGrant,
    revisions: Vec<AgentGrantRevision>,
}

#[derive(Debug, thiserror::Error)]
pub enum JitAuthorizationStoreError {
    #[error(transparent)]
    Contract(#[from] AgentAuthorizationError),
    #[error("authorization request was not found")]
    NotFound,
    #[error("authorization request ID is invalid")]
    InvalidRequestId,
    #[error("authorization request belongs to another principal or broker instance")]
    BindingMismatch,
    #[error("authorization request queue is full; retry after {retry_after_ms} ms")]
    QueueFull { retry_after_ms: u64 },
    #[error("authorization requests are rate limited; retry after {retry_after_ms} ms")]
    RateLimited { retry_after_ms: u64 },
    #[error("an equivalent denied request is cooling down; retry after {retry_after_ms} ms")]
    DenialCooldown { retry_after_ms: u64 },
    #[error("authorization grant amendment is invalid: {0}")]
    InvalidAmendment(String),
    #[error("authorization state is busy; retry shortly")]
    Busy,
    #[error("authorization persistence failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("authorization state is corrupt: {0}")]
    Corrupt(#[from] serde_json::Error),
}

impl JitAuthorizationStore {
    pub fn default_store() -> Result<Self, JitAuthorizationStoreError> {
        let root = AppConfig::config_dir()
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .join("agent-authorization");
        fs::create_dir_all(&root)?;
        set_private_directory(&root)?;
        let instance_path = root.join("broker-instance");
        let broker_instance_id = if instance_path.exists() {
            fs::read_to_string(&instance_path)?.trim().to_string()
        } else {
            let id = format!("broker-instance:{}", Uuid::new_v4());
            match write_private_bytes(&instance_path, id.as_bytes()) {
                Ok(()) => id,
                Err(JitAuthorizationStoreError::Io(error))
                    if error.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    fs::read_to_string(&instance_path)?.trim().to_string()
                }
                Err(error) => return Err(error),
            }
        };
        Self::new(root, broker_instance_id)
    }

    pub fn new(
        root: PathBuf,
        broker_instance_id: impl Into<String>,
    ) -> Result<Self, JitAuthorizationStoreError> {
        Self::with_policy(root, broker_instance_id, JitAuthorizationPolicy::default())
    }

    pub fn with_policy(
        root: PathBuf,
        broker_instance_id: impl Into<String>,
        policy: JitAuthorizationPolicy,
    ) -> Result<Self, JitAuthorizationStoreError> {
        let broker_instance_id = broker_instance_id.into();
        if broker_instance_id.trim().is_empty() {
            return Err(AgentAuthorizationError::InvalidRequest(
                "broker instance ID is required".into(),
            )
            .into());
        }
        for directory in [
            root.clone(),
            root.join("requests"),
            root.join("grants"),
            root.join("locks"),
        ] {
            fs::create_dir_all(&directory)?;
            set_private_directory(&directory)?;
        }
        let store = Self {
            root,
            broker_instance_id,
            policy,
        };
        store.recover_after_restart(Utc::now())?;
        Ok(store)
    }

    pub fn create(
        &self,
        input: CreateAuthorizationRequest,
        now: DateTime<Utc>,
    ) -> Result<CreateAuthorizationResult, JitAuthorizationStoreError> {
        self.expire_pending(now)?;
        let candidate = AgentAuthorizationRequest::new(
            format!("auth-request:{}", Uuid::new_v4()),
            self.broker_instance_id.clone(),
            input.principal,
            input.profile_id,
            input.plugin_id,
            input.scope,
            input.risk,
            input.purpose,
            now,
            input.expires_at,
        )?;
        let requests = self.load_requests()?;
        if let Some(existing) = requests.iter().find(|request| {
            request.request.status == AgentAuthorizationRequestStatus::Pending
                && request.request.request_fingerprint == candidate.request_fingerprint
        }) {
            return self.create_result(&existing.request, true);
        }

        let principal_fingerprint = candidate.principal.fingerprint()?;
        let pending_global = requests
            .iter()
            .filter(|record| record.request.status == AgentAuthorizationRequestStatus::Pending)
            .count();
        let pending_principal = requests
            .iter()
            .filter(|record| {
                record.request.status == AgentAuthorizationRequestStatus::Pending
                    && record.request.principal.fingerprint().as_deref()
                        == Ok(principal_fingerprint.as_str())
            })
            .count();
        if pending_global >= self.policy.max_pending_global
            || pending_principal >= self.policy.max_pending_per_principal
        {
            return Err(JitAuthorizationStoreError::QueueFull {
                retry_after_ms: 1_000,
            });
        }

        if let Some(denied_at) = requests
            .iter()
            .filter(|record| {
                record.request.status == AgentAuthorizationRequestStatus::Denied
                    && record.request.request_fingerprint == candidate.request_fingerprint
            })
            .filter_map(|record| record.request.decided_at)
            .max()
        {
            let available_at = denied_at + self.policy.denial_cooldown;
            if available_at > now {
                return Err(JitAuthorizationStoreError::DenialCooldown {
                    retry_after_ms: millis_until(now, available_at),
                });
            }
        }

        let recent = requests
            .iter()
            .filter(|record| {
                record.request.created_at > now - self.policy.rate_limit_window
                    && record.request.principal.fingerprint().as_deref()
                        == Ok(principal_fingerprint.as_str())
            })
            .count();
        if recent >= self.policy.rate_limit_requests {
            let oldest = requests
                .iter()
                .filter(|record| {
                    record.request.created_at > now - self.policy.rate_limit_window
                        && record.request.principal.fingerprint().as_deref()
                            == Ok(principal_fingerprint.as_str())
                })
                .map(|record| record.request.created_at)
                .min()
                .unwrap_or(now);
            return Err(JitAuthorizationStoreError::RateLimited {
                retry_after_ms: millis_until(now, oldest + self.policy.rate_limit_window),
            });
        }

        self.write_request(&candidate)?;
        self.append_audit(&candidate, AgentAuthorizationAuditAction::Request, now)?;
        self.create_result(&candidate, false)
    }

    pub fn get_for_principal(
        &self,
        request_id: &str,
        principal: &AgentPrincipal,
        now: DateTime<Utc>,
    ) -> Result<FrontendAuthorizationRequest, JitAuthorizationStoreError> {
        let mut request = self.read_request(request_id)?;
        self.ensure_agent_binding(&request, principal)?;
        if request.expire_at(now) {
            self.write_request(&request)?;
            self.append_audit(&request, AgentAuthorizationAuditAction::Expire, now)?;
        }
        Ok(FrontendAuthorizationRequest::try_from(&request)?)
    }

    pub fn get_for_review(
        &self,
        request_id: &str,
        now: DateTime<Utc>,
    ) -> Result<AgentAuthorizationRequest, JitAuthorizationStoreError> {
        let mut request = self.read_request(request_id)?;
        self.ensure_broker_binding(&request)?;
        if request.expire_at(now) {
            self.write_request(&request)?;
            self.append_audit(&request, AgentAuthorizationAuditAction::Expire, now)?;
        }
        self.append_audit(&request, AgentAuthorizationAuditAction::Review, now)?;
        Ok(request)
    }

    pub fn list_for_principal(
        &self,
        principal: &AgentPrincipal,
        now: DateTime<Utc>,
    ) -> Result<Vec<FrontendAuthorizationRequest>, JitAuthorizationStoreError> {
        self.expire_pending(now)?;
        let fingerprint = principal.fingerprint()?;
        self.load_requests()?
            .into_iter()
            .filter(|record| {
                record.request.broker_instance_id == self.broker_instance_id
                    && record.request.principal.fingerprint().as_deref() == Ok(fingerprint.as_str())
            })
            .map(|record| {
                FrontendAuthorizationRequest::try_from(&record.request).map_err(Into::into)
            })
            .collect()
    }

    /// Return the canonical, frontend-safe local review inbox.
    ///
    /// Unlike `list_for_principal`, this is intentionally broker-wide because
    /// it is consumed by local human approval surfaces. The projection omits
    /// credentials, broker tokens, socket paths, and the unhashed principal.
    pub fn list_for_review(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<FrontendAuthorizationRequest>, JitAuthorizationStoreError> {
        self.expire_pending(now)?;
        self.load_requests()?
            .into_iter()
            .filter(|record| record.request.broker_instance_id == self.broker_instance_id)
            .map(|record| {
                FrontendAuthorizationRequest::try_from(&record.request).map_err(Into::into)
            })
            .collect()
    }

    /// Return immutable grant revisions for local human review surfaces.
    pub fn list_revisions(&self) -> Result<Vec<AgentGrantRevision>, JitAuthorizationStoreError> {
        let mut revisions = Vec::new();
        for entry in fs::read_dir(self.root.join("grants"))? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let ledger: GrantLedger = serde_json::from_slice(&fs::read(path)?)?;
            if ledger.version == STORE_VERSION {
                revisions.extend(ledger.revisions);
            }
        }
        revisions.sort_by_key(|revision| revision.issued_at);
        Ok(revisions)
    }

    pub async fn wait_for_principal(
        &self,
        request_id: &str,
        principal: &AgentPrincipal,
        timeout: StdDuration,
    ) -> Result<WaitAuthorizationResult, JitAuthorizationStoreError> {
        let timeout = timeout.min(self.policy.max_wait);
        let started = tokio::time::Instant::now();
        loop {
            let request = self.get_for_principal(request_id, principal, Utc::now())?;
            if request.status.is_terminal() {
                return Ok(WaitAuthorizationResult {
                    request,
                    timed_out: false,
                });
            }
            if started.elapsed() >= timeout {
                return Ok(WaitAuthorizationResult {
                    request,
                    timed_out: true,
                });
            }
            tokio::time::sleep(StdDuration::from_millis(50)).await;
        }
    }

    pub fn cancel(
        &self,
        request_id: &str,
        principal: &AgentPrincipal,
        now: DateTime<Utc>,
    ) -> Result<FrontendAuthorizationRequest, JitAuthorizationStoreError> {
        let _lock = self.request_lock(request_id)?;
        let mut request = self.read_request(request_id)?;
        self.ensure_agent_binding(&request, principal)?;
        if self.persist_timeout_if_due(&mut request, now)? {
            return Err(AgentAuthorizationError::Expired.into());
        }
        if request.status != AgentAuthorizationRequestStatus::Pending {
            return Err(AgentAuthorizationError::AlreadyDecided.into());
        }
        request.status = AgentAuthorizationRequestStatus::Cancelled;
        request.decided_at = Some(now);
        self.write_request(&request)?;
        self.append_audit(&request, AgentAuthorizationAuditAction::Cancel, now)?;
        Ok(FrontendAuthorizationRequest::try_from(&request)?)
    }

    pub fn deny(
        &self,
        request_id: &str,
        reason: String,
        now: DateTime<Utc>,
    ) -> Result<FrontendAuthorizationRequest, JitAuthorizationStoreError> {
        let _lock = self.request_lock(request_id)?;
        let mut request = self.read_request(request_id)?;
        self.ensure_broker_binding(&request)?;
        if self.persist_timeout_if_due(&mut request, now)? {
            return Err(AgentAuthorizationError::Expired.into());
        }
        let decision = AgentAuthorizationDecision {
            request_id: request.id.clone(),
            decided_at: now,
            outcome: AgentAuthorizationDecisionOutcome::Deny { reason },
        };
        request.decide(&decision)?;
        self.write_request(&request)?;
        self.append_audit(&request, AgentAuthorizationAuditAction::Deny, now)?;
        Ok(FrontendAuthorizationRequest::try_from(&request)?)
    }

    pub fn approve(
        &self,
        request_id: &str,
        approved_scope: AgentAuthorizationScope,
        amendment: AgentGrantAmendment,
        now: DateTime<Utc>,
    ) -> Result<AgentGrantRevision, JitAuthorizationStoreError> {
        let _request_lock = self.request_lock(request_id)?;
        let mut request = self.read_request(request_id)?;
        self.ensure_broker_binding(&request)?;
        if self.persist_timeout_if_due(&mut request, now)? {
            return Err(AgentAuthorizationError::Expired.into());
        }
        let decision = AgentAuthorizationDecision {
            request_id: request.id.clone(),
            decided_at: now,
            outcome: AgentAuthorizationDecisionOutcome::Approve {
                scope: approved_scope.clone(),
                grant: amendment.clone(),
            },
        };
        request.decide(&decision)?;

        let ledger_key = self.ledger_key(&request)?;
        let _grant_lock = self.named_lock(&format!("grant-{ledger_key}"))?;
        let mut ledger = self.read_ledger(&ledger_key)?;
        let revision =
            self.build_revision(&request, approved_scope, amendment, now, ledger.as_ref())?;
        match &mut ledger {
            Some(ledger) => {
                ledger.logical.current_revision = revision.revision;
                ledger.revisions.push(revision.clone());
            }
            None => {
                ledger = Some(GrantLedger {
                    version: STORE_VERSION,
                    logical: AgentLogicalGrant {
                        id: revision.grant_id.clone(),
                        principal: request.principal.clone(),
                        profile_id: request.profile_id.clone(),
                        plugin_id: request.plugin_id.clone(),
                        current_revision: revision.revision,
                        created_at: now,
                        revoked_at: None,
                    },
                    revisions: vec![revision.clone()],
                });
            }
        }
        request.approved_grant_id = Some(revision.grant_id.clone());
        request.approved_revision = Some(revision.revision);
        self.write_ledger(&ledger_key, ledger.as_ref().expect("ledger is initialized"))?;
        self.write_request(&request)?;
        let action = if revision.revision == 1 {
            AgentAuthorizationAuditAction::Approve
        } else {
            AgentAuthorizationAuditAction::Amend
        };
        self.append_audit(&request, action, now)?;
        Ok(revision)
    }

    pub fn effective_scopes(
        &self,
        grant_id: &str,
    ) -> Result<Vec<AgentAuthorizationScope>, JitAuthorizationStoreError> {
        let mut scopes = Vec::new();
        for entry in fs::read_dir(self.root.join("grants"))? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let ledger: GrantLedger = serde_json::from_slice(&fs::read(path)?)?;
            if ledger.version == STORE_VERSION && ledger.logical.id == grant_id {
                if ledger.logical.revoked_at.is_some() {
                    return Ok(Vec::new());
                }
                for revision in ledger.revisions {
                    if !scopes.contains(&revision.scope) {
                        scopes.push(revision.scope);
                    }
                }
                return Ok(scopes);
            }
        }
        Ok(scopes)
    }

    /// Revoke a logical JIT grant after its live broker and sessions close.
    /// Immutable revisions remain available for audit, but no scope remains
    /// effective and future amendments fail closed.
    pub fn revoke_grant(
        &self,
        grant_id: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, JitAuthorizationStoreError> {
        for entry in fs::read_dir(self.root.join("grants"))? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let candidate: GrantLedger = serde_json::from_slice(&fs::read(&path)?)?;
            if candidate.version != STORE_VERSION || candidate.logical.id != grant_id {
                continue;
            }
            let key = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    JitAuthorizationStoreError::InvalidAmendment(
                        "logical grant ledger name is invalid".into(),
                    )
                })?;
            let _lock = self.named_lock(&format!("grant-{key}"))?;
            let mut ledger = self.read_ledger(key)?.ok_or_else(|| {
                JitAuthorizationStoreError::InvalidAmendment(
                    "logical grant ledger disappeared during revoke".into(),
                )
            })?;
            if ledger.logical.revoked_at.is_some() {
                return Ok(false);
            }
            ledger.logical.revoked_at = Some(now);
            self.write_ledger(key, &ledger)?;
            if let Some(revision) = ledger.revisions.last() {
                self.append_audit_projection(&AgentAuthorizationAuditProjection {
                    action: AgentAuthorizationAuditAction::Revoke,
                    request_id: revision.source_request_id.clone(),
                    principal_fingerprint: revision.principal_fingerprint.clone(),
                    profile_id: revision.profile_id.clone(),
                    plugin_id: revision.plugin_id.clone(),
                    scope_fingerprint: revision.scope.canonical_fingerprint(),
                    occurred_at: now,
                })?;
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn build_revision(
        &self,
        request: &AgentAuthorizationRequest,
        scope: AgentAuthorizationScope,
        amendment: AgentGrantAmendment,
        now: DateTime<Utc>,
        ledger: Option<&GrantLedger>,
    ) -> Result<AgentGrantRevision, JitAuthorizationStoreError> {
        let (grant_id, revision, expires_at, total_uses, remaining_uses) = match amendment {
            AgentGrantAmendment::Once => (
                ledger
                    .map(|ledger| ledger.logical.id.clone())
                    .unwrap_or_else(|| format!("agent-grant:{}", Uuid::new_v4())),
                ledger.map_or(1, |ledger| ledger.logical.current_revision + 1),
                request.expires_at.min(now + Duration::minutes(5)),
                Some(1),
                Some(1),
            ),
            AgentGrantAmendment::Bounded { ttl_seconds, uses } => {
                validate_bounds(ttl_seconds, uses)?;
                (
                    ledger
                        .map(|ledger| ledger.logical.id.clone())
                        .unwrap_or_else(|| format!("agent-grant:{}", Uuid::new_v4())),
                    ledger.map_or(1, |ledger| ledger.logical.current_revision + 1),
                    now + Duration::seconds(ttl_seconds as i64),
                    uses,
                    uses,
                )
            }
            AgentGrantAmendment::AddToGrant {
                grant_id,
                ttl_delta_seconds,
                uses_delta,
            } => {
                let ledger = ledger.ok_or_else(|| {
                    JitAuthorizationStoreError::InvalidAmendment(
                        "add_to_grant requires an existing logical grant".into(),
                    )
                })?;
                if ledger.logical.id != grant_id || ledger.logical.revoked_at.is_some() {
                    return Err(JitAuthorizationStoreError::InvalidAmendment(
                        "logical grant binding is stale or revoked".into(),
                    ));
                }
                let previous = ledger.revisions.last().ok_or_else(|| {
                    JitAuthorizationStoreError::InvalidAmendment(
                        "logical grant has no revision history".into(),
                    )
                })?;
                let expires_at = previous.expires_at + Duration::seconds(ttl_delta_seconds as i64);
                let maximum = now + Duration::minutes(MAX_AGENT_GRANT_TTL_MINUTES as i64);
                let remaining_uses = previous
                    .remaining_uses
                    .map(|remaining| remaining.saturating_add(uses_delta));
                if ttl_delta_seconds == 0 && uses_delta == 0 {
                    return Err(JitAuthorizationStoreError::InvalidAmendment(
                        "grant amendment must change time, uses, or scope".into(),
                    ));
                }
                if previous.remaining_uses.is_none() && uses_delta > 0 {
                    return Err(JitAuthorizationStoreError::InvalidAmendment(
                        "an unlimited grant cannot be extended by a use count".into(),
                    ));
                }
                if expires_at > maximum
                    || remaining_uses.is_some_and(|uses| uses > MAX_AGENT_GRANT_USES)
                {
                    return Err(JitAuthorizationStoreError::InvalidAmendment(
                        "grant amendment exceeds time or use bounds".into(),
                    ));
                }
                (
                    grant_id,
                    ledger.logical.current_revision + 1,
                    expires_at,
                    previous
                        .total_uses
                        .map(|total| total.saturating_add(uses_delta)),
                    remaining_uses,
                )
            }
        };
        Ok(AgentGrantRevision {
            id: format!("agent-grant-revision:{}", Uuid::new_v4()),
            grant_id,
            revision,
            source_request_id: request.id.clone(),
            principal_fingerprint: request.principal.fingerprint()?,
            profile_id: request.profile_id.clone(),
            plugin_id: request.plugin_id.clone(),
            scope,
            issued_at: now,
            expires_at,
            total_uses,
            remaining_uses,
        })
    }

    fn create_result(
        &self,
        request: &AgentAuthorizationRequest,
        deduplicated: bool,
    ) -> Result<CreateAuthorizationResult, JitAuthorizationStoreError> {
        Ok(CreateAuthorizationResult {
            request: FrontendAuthorizationRequest::try_from(request)?,
            review_command: format!("voidb-cli agent request review {}", request.id),
            deduplicated,
        })
    }

    fn ensure_agent_binding(
        &self,
        request: &AgentAuthorizationRequest,
        principal: &AgentPrincipal,
    ) -> Result<(), JitAuthorizationStoreError> {
        self.ensure_broker_binding(request)?;
        if &request.principal != principal {
            return Err(JitAuthorizationStoreError::BindingMismatch);
        }
        Ok(())
    }

    fn ensure_broker_binding(
        &self,
        request: &AgentAuthorizationRequest,
    ) -> Result<(), JitAuthorizationStoreError> {
        if request.broker_instance_id != self.broker_instance_id {
            return Err(JitAuthorizationStoreError::BindingMismatch);
        }
        Ok(())
    }

    fn recover_after_restart(&self, now: DateTime<Utc>) -> Result<(), JitAuthorizationStoreError> {
        for record in self.load_requests()? {
            let mut request = record.request;
            if request.status == AgentAuthorizationRequestStatus::Pending
                && request.broker_instance_id != self.broker_instance_id
            {
                request.status = AgentAuthorizationRequestStatus::Superseded;
                request.decided_at = Some(now);
                self.write_request(&request)?;
            }
        }
        Ok(())
    }

    fn expire_pending(&self, now: DateTime<Utc>) -> Result<(), JitAuthorizationStoreError> {
        for record in self.load_requests()? {
            let mut request = record.request;
            self.persist_timeout_if_due(&mut request, now)?;
        }
        Ok(())
    }

    fn persist_timeout_if_due(
        &self,
        request: &mut AgentAuthorizationRequest,
        now: DateTime<Utc>,
    ) -> Result<bool, JitAuthorizationStoreError> {
        if !request.expire_at(now) {
            return Ok(false);
        }
        self.write_request(request)?;
        self.append_audit(request, AgentAuthorizationAuditAction::Expire, now)?;
        Ok(true)
    }

    fn load_requests(&self) -> Result<Vec<RequestRecord>, JitAuthorizationStoreError> {
        let mut requests = Vec::new();
        for entry in fs::read_dir(self.root.join("requests"))? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let record: RequestRecord = serde_json::from_slice(&fs::read(path)?)?;
            if record.version == STORE_VERSION {
                requests.push(record);
            }
        }
        requests.sort_by_key(|record| record.request.created_at);
        Ok(requests)
    }

    fn read_request(
        &self,
        request_id: &str,
    ) -> Result<AgentAuthorizationRequest, JitAuthorizationStoreError> {
        validate_request_id(request_id)?;
        let path = self.request_path(request_id);
        if !path.exists() {
            return Err(JitAuthorizationStoreError::NotFound);
        }
        let record: RequestRecord = serde_json::from_slice(&fs::read(path)?)?;
        if record.version != STORE_VERSION {
            return Err(JitAuthorizationStoreError::NotFound);
        }
        Ok(record.request)
    }

    fn write_request(
        &self,
        request: &AgentAuthorizationRequest,
    ) -> Result<(), JitAuthorizationStoreError> {
        write_private_json(
            &self.request_path(&request.id),
            &RequestRecord {
                version: STORE_VERSION,
                request: request.clone(),
            },
        )
    }

    fn request_path(&self, request_id: &str) -> PathBuf {
        self.root.join("requests").join(format!(
            "{}.json",
            request_id.trim_start_matches("auth-request:")
        ))
    }

    fn ledger_key(
        &self,
        request: &AgentAuthorizationRequest,
    ) -> Result<String, JitAuthorizationStoreError> {
        let principal = request.principal.fingerprint()?;
        Ok(format!(
            "{}-{}-{}",
            principal.trim_start_matches("agent-principal:"),
            safe_component(&request.profile_id),
            safe_component(&request.plugin_id)
        ))
    }

    fn read_ledger(&self, key: &str) -> Result<Option<GrantLedger>, JitAuthorizationStoreError> {
        let path = self.root.join("grants").join(format!("{key}.json"));
        if !path.exists() {
            return Ok(None);
        }
        let ledger: GrantLedger = serde_json::from_slice(&fs::read(path)?)?;
        Ok((ledger.version == STORE_VERSION).then_some(ledger))
    }

    fn write_ledger(
        &self,
        key: &str,
        ledger: &GrantLedger,
    ) -> Result<(), JitAuthorizationStoreError> {
        write_private_json(
            &self.root.join("grants").join(format!("{key}.json")),
            ledger,
        )
    }

    fn request_lock(&self, request_id: &str) -> Result<FileLock, JitAuthorizationStoreError> {
        validate_request_id(request_id)?;
        self.named_lock(&format!(
            "request-{}",
            request_id.trim_start_matches("auth-request:")
        ))
    }

    fn named_lock(&self, name: &str) -> Result<FileLock, JitAuthorizationStoreError> {
        FileLock::acquire(self.root.join("locks").join(format!("{name}.lock")))
    }

    fn append_audit(
        &self,
        request: &AgentAuthorizationRequest,
        action: AgentAuthorizationAuditAction,
        now: DateTime<Utc>,
    ) -> Result<(), JitAuthorizationStoreError> {
        let projection = AgentAuthorizationAuditProjection {
            action,
            request_id: request.id.clone(),
            principal_fingerprint: request.principal.fingerprint()?,
            profile_id: request.profile_id.clone(),
            plugin_id: request.plugin_id.clone(),
            scope_fingerprint: request.scope.canonical_fingerprint(),
            occurred_at: now,
        };
        self.append_audit_projection(&projection)
    }

    fn append_audit_projection(
        &self,
        projection: &AgentAuthorizationAuditProjection,
    ) -> Result<(), JitAuthorizationStoreError> {
        let path = self.root.join("audit.jsonl");
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(path)?;
        serde_json::to_writer(&mut file, projection)?;
        file.write_all(b"\n")?;
        Ok(())
    }
}

fn validate_bounds(ttl_seconds: u64, uses: Option<u32>) -> Result<(), JitAuthorizationStoreError> {
    if ttl_seconds == 0
        || ttl_seconds > MAX_AGENT_GRANT_TTL_MINUTES * 60
        || uses.is_some_and(|uses| !(1..=MAX_AGENT_GRANT_USES).contains(&uses))
    {
        return Err(JitAuthorizationStoreError::InvalidAmendment(
            "bounded approval exceeds time or use limits".into(),
        ));
    }
    Ok(())
}

fn validate_request_id(request_id: &str) -> Result<(), JitAuthorizationStoreError> {
    let Some(value) = request_id.strip_prefix("auth-request:") else {
        return Err(JitAuthorizationStoreError::InvalidRequestId);
    };
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| JitAuthorizationStoreError::InvalidRequestId)
}

fn safe_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .take(100)
        .collect()
}

fn millis_until(now: DateTime<Utc>, later: DateTime<Utc>) -> u64 {
    later.signed_duration_since(now).num_milliseconds().max(1) as u64
}

fn set_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn write_private_json<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), JitAuthorizationStoreError> {
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let content = serde_json::to_vec_pretty(value)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    file.write_all(&content)?;
    file.sync_all()?;
    #[cfg(unix)]
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    fs::rename(&temporary, path)?;
    Ok(())
}

fn write_private_bytes(path: &Path, content: &[u8]) -> Result<(), JitAuthorizationStoreError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

struct FileLock {
    path: PathBuf,
}

impl FileLock {
    fn acquire(path: PathBuf) -> Result<Self, JitAuthorizationStoreError> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&path) {
            Ok(mut file) => {
                writeln!(file, "{}", std::process::id())?;
                Ok(Self { path })
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(JitAuthorizationStoreError::Busy)
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::sync::{Arc, Barrier};

    fn temp_store(instance: &str) -> (PathBuf, JitAuthorizationStore) {
        let path = std::env::temp_dir().join(format!("voidb-jit-test-{}", Uuid::new_v4()));
        let store = JitAuthorizationStore::new(path.clone(), instance).unwrap();
        (path, store)
    }

    fn principal(task: &str) -> AgentPrincipal {
        AgentPrincipal {
            client_id: "agent".into(),
            task_id: task.into(),
            instance_id: Some("desktop".into()),
        }
    }

    fn input(now: DateTime<Utc>, principal: AgentPrincipal) -> CreateAuthorizationRequest {
        CreateAuthorizationRequest {
            principal,
            profile_id: "profile:ssh-prod".into(),
            plugin_id: "ssh".into(),
            scope: AgentAuthorizationScope::ExactInvocation {
                capability_id: "ssh.exec".into(),
                normalized_input: json!({"argv": ["uptime"]}),
                invocation_fingerprint: "agent-invocation:test".into(),
            },
            risk: CapabilityRiskLevel::Destructive,
            purpose: "Check production uptime for incident triage".into(),
            expires_at: now + Duration::minutes(5),
        }
    }

    #[test]
    fn create_deduplicates_and_isolates_principals() {
        let (path, store) = temp_store("broker-a");
        let now = Utc::now();
        let first = store.create(input(now, principal("one")), now).unwrap();
        let duplicate = store.create(input(now, principal("one")), now).unwrap();
        assert_eq!(first.request.id, duplicate.request.id);
        assert!(duplicate.deduplicated);
        assert!(matches!(
            store.get_for_principal(&first.request.id, &principal("two"), now),
            Err(JitAuthorizationStoreError::BindingMismatch)
        ));
        assert_eq!(
            store
                .list_for_principal(&principal("one"), now)
                .unwrap()
                .len(),
            1
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn request_ids_have_uuid_v4_entropy_expire_and_form_inert_review_commands() {
        let (path, store) = temp_store("broker-a");
        let now = Utc::now();
        let mut ids = BTreeSet::new();
        for index in 0..64 {
            let result = store
                .create(input(now, principal(&format!("entropy-{index}"))), now)
                .unwrap();
            let raw = result.request.id.strip_prefix("auth-request:").unwrap();
            let uuid = Uuid::parse_str(raw).unwrap();
            assert_eq!(uuid.get_version_num(), 4);
            assert!(ids.insert(result.request.id.clone()));
            let parts = result.review_command.split_whitespace().collect::<Vec<_>>();
            assert_eq!(parts[..4], ["voidb-cli", "agent", "request", "review"]);
            assert_eq!(parts[4], result.request.id);
            for shell_metacharacter in [';', '\n', '\r', '`', '$', '|', '&'] {
                assert!(!result.review_command.contains(shell_metacharacter));
            }
        }
        assert_eq!(ids.len(), 64);
        let first = ids.first().unwrap();
        let expired = store
            .get_for_review(first, now + Duration::minutes(6))
            .unwrap();
        assert_eq!(expired.status, AgentAuthorizationRequestStatus::Denied);
        assert!(expired.timed_out);
        assert_eq!(
            expired.decision_reason.as_deref(),
            Some("Authorization request timed out before approval.")
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn late_approval_atomically_persists_timeout_denial() {
        let (path, store) = temp_store("broker-a");
        let now = Utc::now();
        let mut request = input(now, principal("late-review"));
        request.expires_at = now + Duration::seconds(1);
        let created = store.create(request, now).unwrap();

        assert!(matches!(
            store.approve(
                &created.request.id,
                created.request.scope.clone(),
                AgentGrantAmendment::Once,
                now + Duration::seconds(2),
            ),
            Err(JitAuthorizationStoreError::Contract(
                AgentAuthorizationError::Expired
            ))
        ));
        let persisted = store.read_request(&created.request.id).unwrap();
        assert_eq!(persisted.status, AgentAuthorizationRequestStatus::Denied);
        assert!(persisted.timed_out);
        assert!(persisted.approved_grant_id.is_none());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn denial_cooldown_and_audit_projection_are_deterministic_and_redacted() {
        let (path, store) = temp_store("broker-a");
        let now = Utc::now();
        let created = store.create(input(now, principal("one")), now).unwrap();
        store
            .deny(
                &created.request.id,
                "operator policy".into(),
                now + Duration::seconds(1),
            )
            .unwrap();
        assert!(matches!(
            store.create(
                input(now + Duration::seconds(2), principal("one")),
                now + Duration::seconds(2)
            ),
            Err(JitAuthorizationStoreError::DenialCooldown { .. })
        ));
        assert!(
            store
                .create(
                    input(now + Duration::seconds(62), principal("one")),
                    now + Duration::seconds(62),
                )
                .is_ok()
        );
        let audit = fs::read_to_string(path.join("audit.jsonl")).unwrap();
        for forbidden in [
            "operator policy",
            "Check production uptime",
            "desktop",
            "broker-a",
            "argv",
        ] {
            assert!(!audit.contains(forbidden), "audit leaked {forbidden}");
        }
        assert!(audit.contains("scope_fingerprint"));
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn concurrent_duplicate_decision_has_exactly_one_winner() {
        let (path, store) = temp_store("broker-a");
        let now = Utc::now();
        let created = store.create(input(now, principal("one")), now).unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            let request_id = created.request.id.clone();
            let scope = created.request.scope.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store.approve(
                    &request_id,
                    scope,
                    AgentGrantAmendment::Once,
                    now + Duration::seconds(1),
                )
            }));
        }
        barrier.wait();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .filter(|result| result.is_err())
                .all(|result| {
                    matches!(
                        result,
                        Err(JitAuthorizationStoreError::Busy)
                            | Err(JitAuthorizationStoreError::Contract(
                                AgentAuthorizationError::AlreadyDecided
                            ))
                    )
                })
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn concurrent_grant_amendments_serialize_into_distinct_immutable_revisions() {
        let (path, store) = temp_store("broker-a");
        let now = Utc::now();
        let first = store.create(input(now, principal("one")), now).unwrap();
        let base = store
            .approve(
                &first.request.id,
                first.request.scope,
                AgentGrantAmendment::Bounded {
                    ttl_seconds: 300,
                    uses: Some(2),
                },
                now + Duration::seconds(1),
            )
            .unwrap();
        let create_amendment = |command: &str, offset: i64| {
            let mut request = input(now + Duration::seconds(offset), principal("one"));
            request.scope = AgentAuthorizationScope::ExactInvocation {
                capability_id: "ssh.exec".into(),
                normalized_input: json!({"argv": [command]}),
                invocation_fingerprint: format!("agent-invocation:{command}"),
            };
            store
                .create(request, now + Duration::seconds(offset))
                .unwrap()
        };
        let second = create_amendment("whoami", 2);
        let third = create_amendment("date", 3);
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for request in [second.request, third.request] {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            let grant_id = base.grant_id.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..100 {
                    match store.approve(
                        &request.id,
                        request.scope.clone(),
                        AgentGrantAmendment::AddToGrant {
                            grant_id: grant_id.clone(),
                            ttl_delta_seconds: 30,
                            uses_delta: 1,
                        },
                        now + Duration::seconds(4),
                    ) {
                        Err(JitAuthorizationStoreError::Busy) => {
                            std::thread::yield_now();
                        }
                        result => return result,
                    }
                }
                Err(JitAuthorizationStoreError::Busy)
            }));
        }
        barrier.wait();
        let mut revisions = threads
            .into_iter()
            .map(|thread| thread.join().unwrap().unwrap().revision)
            .collect::<Vec<_>>();
        revisions.sort_unstable();
        assert_eq!(revisions, vec![2, 3]);
        let history = store.list_revisions().unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history.last().unwrap().revision, 3);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn two_agents_on_one_profile_get_isolated_scopes_grants_and_amendments() {
        let (path, store) = temp_store("broker-a");
        let now = Utc::now();
        let agent_a = principal("conversation-a");
        let agent_b = principal("conversation-b");
        let mut request_a = input(now, agent_a.clone());
        request_a.scope = AgentAuthorizationScope::Capability {
            capability_id: "ssh.exec".into(),
        };
        let request_a = store.create(request_a, now).unwrap();
        let narrowed_a = AgentAuthorizationScope::Constrained {
            capability_id: "ssh.exec".into(),
            constraints: std::collections::BTreeMap::from([("/command".into(), json!("uptime"))]),
        };
        let revision_a = store
            .approve(
                &request_a.request.id,
                narrowed_a.clone(),
                AgentGrantAmendment::Bounded {
                    ttl_seconds: 300,
                    uses: Some(2),
                },
                now + Duration::seconds(1),
            )
            .unwrap();

        let mut request_b = input(now, agent_b.clone());
        request_b.scope = AgentAuthorizationScope::ExactInvocation {
            capability_id: "ssh.exec".into(),
            normalized_input: json!({"command": "whoami"}),
            invocation_fingerprint: "agent-invocation:whoami".into(),
        };
        let request_b = store.create(request_b, now).unwrap();
        let revision_b = store
            .approve(
                &request_b.request.id,
                request_b.request.scope.clone(),
                AgentGrantAmendment::Once,
                now + Duration::seconds(1),
            )
            .unwrap();
        assert_ne!(revision_a.grant_id, revision_b.grant_id);
        assert_ne!(
            revision_a.principal_fingerprint,
            revision_b.principal_fingerprint
        );
        assert!(matches!(
            store.get_for_principal(&request_a.request.id, &agent_b, now),
            Err(JitAuthorizationStoreError::BindingMismatch)
        ));
        assert!(matches!(
            store.get_for_principal(&request_b.request.id, &agent_a, now),
            Err(JitAuthorizationStoreError::BindingMismatch)
        ));

        let mut amendment_b = input(now + Duration::seconds(2), agent_b);
        amendment_b.scope = AgentAuthorizationScope::Constrained {
            capability_id: "ssh.exec".into(),
            constraints: std::collections::BTreeMap::from([("/command".into(), json!("date"))]),
        };
        let amendment_b = store
            .create(amendment_b, now + Duration::seconds(2))
            .unwrap();
        assert!(matches!(
            store.approve(
                &amendment_b.request.id,
                amendment_b.request.scope,
                AgentGrantAmendment::AddToGrant {
                    grant_id: revision_a.grant_id,
                    ttl_delta_seconds: 30,
                    uses_delta: 1,
                },
                now + Duration::seconds(3),
            ),
            Err(JitAuthorizationStoreError::InvalidAmendment(_))
        ));
        assert_eq!(store.list_for_principal(&agent_a, now).unwrap().len(), 1);
        fs::remove_dir_all(path).unwrap();
    }

    #[tokio::test]
    async fn wait_observes_cancel_and_bounds_pending_timeout() {
        let (path, store) = temp_store("broker-a");
        let now = Utc::now();
        let created = store.create(input(now, principal("one")), now).unwrap();
        let pending = store
            .wait_for_principal(
                &created.request.id,
                &principal("one"),
                StdDuration::from_millis(5),
            )
            .await
            .unwrap();
        assert!(pending.timed_out);
        store
            .cancel(&created.request.id, &principal("one"), Utc::now())
            .unwrap();
        let cancelled = store
            .wait_for_principal(
                &created.request.id,
                &principal("one"),
                StdDuration::from_millis(5),
            )
            .await
            .unwrap();
        assert!(!cancelled.timed_out);
        assert_eq!(
            cancelled.request.status,
            AgentAuthorizationRequestStatus::Cancelled
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn restart_supersedes_abandoned_pending_requests() {
        let (path, first_store) = temp_store("broker-a");
        let now = Utc::now();
        let created = first_store
            .create(input(now, principal("one")), now)
            .unwrap();
        drop(first_store);
        let restarted = JitAuthorizationStore::new(path.clone(), "broker-b").unwrap();
        let record = restarted.read_request(&created.request.id).unwrap();
        assert_eq!(record.status, AgentAuthorizationRequestStatus::Superseded);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn approval_creates_immutable_revisions_and_rejects_duplicate_decisions() {
        let (path, store) = temp_store("broker-a");
        let now = Utc::now();
        let first = store.create(input(now, principal("one")), now).unwrap();
        let revision = store
            .approve(
                &first.request.id,
                first.request.scope.clone(),
                AgentGrantAmendment::Bounded {
                    ttl_seconds: 300,
                    uses: Some(2),
                },
                now + Duration::seconds(1),
            )
            .unwrap();
        assert_eq!(revision.revision, 1);
        assert!(matches!(
            store.approve(
                &first.request.id,
                first.request.scope,
                AgentGrantAmendment::Once,
                now + Duration::seconds(2),
            ),
            Err(JitAuthorizationStoreError::Contract(
                AgentAuthorizationError::AlreadyDecided
            ))
        ));

        let second = store
            .create(
                input(now + Duration::seconds(2), principal("one")),
                now + Duration::seconds(2),
            )
            .unwrap();
        let amended = store
            .approve(
                &second.request.id,
                second.request.scope,
                AgentGrantAmendment::AddToGrant {
                    grant_id: revision.grant_id.clone(),
                    ttl_delta_seconds: 30,
                    uses_delta: 1,
                },
                now + Duration::seconds(3),
            )
            .unwrap();
        assert_eq!(amended.revision, 2);
        assert_eq!(amended.grant_id, revision.grant_id);
        assert_ne!(amended.id, revision.id);
        let status = store
            .get_for_principal(&second.request.id, &principal("one"), Utc::now())
            .unwrap();
        assert_eq!(status.grant_id.as_deref(), Some(revision.grant_id.as_str()));
        assert_eq!(status.grant_revision, Some(2));
        assert_eq!(store.effective_scopes(&revision.grant_id).unwrap().len(), 1);
        let review_inbox = store.list_for_review(Utc::now()).unwrap();
        assert_eq!(review_inbox.len(), 2);
        assert!(review_inbox.iter().all(|request| {
            request
                .principal_fingerprint
                .starts_with("agent-principal:")
                && !request.principal_fingerprint.contains("one")
        }));
        let revisions = store.list_revisions().unwrap();
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].revision, 1);
        assert_eq!(revisions[1].revision, 2);
        assert!(
            store
                .revoke_grant(&revision.grant_id, now + Duration::seconds(4))
                .unwrap()
        );
        assert!(
            !store
                .revoke_grant(&revision.grant_id, now + Duration::seconds(5))
                .unwrap()
        );
        assert!(
            store
                .effective_scopes(&revision.grant_id)
                .unwrap()
                .is_empty()
        );
        let mut after_revoke_input = input(now + Duration::seconds(6), principal("one"));
        after_revoke_input.scope = AgentAuthorizationScope::ExactInvocation {
            capability_id: "ssh.exec".into(),
            normalized_input: json!({"argv": ["date"]}),
            invocation_fingerprint: "agent-invocation:date".into(),
        };
        let after_revoke = store
            .create(after_revoke_input, now + Duration::seconds(6))
            .unwrap();
        assert!(matches!(
            store.approve(
                &after_revoke.request.id,
                after_revoke.request.scope,
                AgentGrantAmendment::AddToGrant {
                    grant_id: revision.grant_id.clone(),
                    ttl_delta_seconds: 30,
                    uses_delta: 1,
                },
                now + Duration::seconds(7),
            ),
            Err(JitAuthorizationStoreError::InvalidAmendment(_))
        ));
        assert!(
            fs::read_to_string(path.join("audit.jsonl"))
                .unwrap()
                .contains("\"action\":\"revoke\"")
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn time_bounded_approval_defaults_to_unlimited_uses() {
        let (path, store) = temp_store("broker-a");
        let now = Utc::now();
        let created = store.create(input(now, principal("one")), now).unwrap();
        let revision = store
            .approve(
                &created.request.id,
                created.request.scope,
                AgentGrantAmendment::Bounded {
                    ttl_seconds: 300,
                    uses: None,
                },
                now + Duration::seconds(1),
            )
            .unwrap();
        assert_eq!(revision.total_uses, None);
        assert_eq!(revision.remaining_uses, None);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn malicious_request_ids_never_escape_store_directory() {
        let (path, store) = temp_store("broker-a");
        for request_id in ["../secret", "auth-request:../../secret", "request;rm -rf"] {
            assert!(matches!(
                store.get_for_review(request_id, Utc::now()),
                Err(JitAuthorizationStoreError::InvalidRequestId)
            ));
        }
        fs::remove_dir_all(path).unwrap();
    }
}
