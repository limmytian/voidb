//! `/v1/objects` - object-level encrypted sync storage.
//!
//! Object routes persist opaque ciphertext plus redacted manifest metadata. The
//! server never receives or returns decrypted payloads or target-system labels.
//!
//! Author: Limmy

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, put},
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{
    error::{ApiError, ApiResult, ObjectRevisionConflictBody, RedactedObjectActor},
    state::AppState,
};

use super::AuthSession;

const REDACTED_ACTOR_ID: &str = "<redacted:actor>";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/objects", get(list_objects))
        .route("/v1/objects/{object_id}", put(put_object))
        .route("/v1/objects/{object_id}/latest", get(get_latest_object))
        .route("/v1/objects/{object_id}/history", get(get_object_history))
        .route(
            "/v1/objects/{object_id}/revisions/{server_revision}",
            get(get_object_revision),
        )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Profile,
    CredentialRef,
    ProfilePolicy,
    PluginCompatibility,
    CredentialRecord,
    AppPreference,
}

impl ObjectKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::CredentialRef => "credential_ref",
            Self::ProfilePolicy => "profile_policy",
            Self::PluginCompatibility => "plugin_compatibility",
            Self::CredentialRecord => "credential_record",
            Self::AppPreference => "app_preference",
        }
    }

    fn object_id_prefix(self) -> &'static str {
        match self {
            Self::Profile => "sync_profile_",
            Self::CredentialRef => "sync_credref_",
            Self::ProfilePolicy => "sync_policy_",
            Self::PluginCompatibility => "sync_plugin_",
            Self::CredentialRecord => "sync_credrec_",
            Self::AppPreference => "sync_pref_",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    Human,
    Agent,
    System,
}

impl ActorType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::System => "system",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStatus {
    NotRequired,
    Applied,
    Withheld,
    FailedClosed,
}

impl RedactionStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Applied => "applied",
            Self::Withheld => "withheld",
            Self::FailedClosed => "failed_closed",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutObjectRequest {
    pub schema_version: i64,
    pub object_kind: ObjectKind,
    pub object_version: i64,
    #[serde(default)]
    pub base_server_revision: Option<i64>,
    pub payload_hash: String,
    pub payload_size: i64,
    pub updated_at: DateTime<Utc>,
    pub updated_by: ObjectActor,
    #[serde(default)]
    pub deleted: bool,
    pub redaction: RedactionStatus,
    pub ciphertext: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectActor {
    pub actor_type: ActorType,
    pub actor_id: String,
    pub device_id: String,
}

#[derive(Debug, Serialize)]
pub struct PutObjectResponse {
    pub object_id: String,
    pub object_kind: ObjectKind,
    pub object_version: i64,
    pub server_revision: i64,
    pub received_at: DateTime<Utc>,
    pub manifest: ObjectManifestEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectManifestEntry {
    pub object_id: String,
    pub object_kind: ObjectKind,
    pub schema_version: i64,
    pub object_version: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_server_revision: Option<i64>,
    pub deleted: bool,
    pub payload_hash: String,
    pub payload_size: i64,
    pub redaction: RedactionStatus,
}

#[derive(Debug, Serialize)]
pub struct ObjectResponse {
    pub object_id: String,
    pub object_kind: String,
    pub schema_version: i64,
    pub object_version: i64,
    pub server_revision: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_server_revision: Option<i64>,
    pub payload_hash: String,
    pub payload_size: i64,
    pub updated_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub updated_by: RedactedActorResponse,
    pub deleted: bool,
    pub redaction: String,
    pub manifest: serde_json::Value,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct ObjectSummary {
    pub object_id: String,
    pub object_kind: String,
    pub schema_version: i64,
    pub object_version: i64,
    pub server_revision: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_server_revision: Option<i64>,
    pub payload_hash: String,
    pub payload_size: i64,
    pub updated_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub updated_by: RedactedActorResponse,
    pub deleted: bool,
    pub redaction: String,
    pub manifest: serde_json::Value,
    pub ciphertext_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct RedactedActorResponse {
    pub actor_type: String,
    pub actor_id: &'static str,
    pub device_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ListObjectsQuery {
    #[serde(default)]
    pub kind: Option<ObjectKind>,
    #[serde(default)]
    pub include_deleted: bool,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    100
}

async fn put_object(
    State(state): State<AppState>,
    session: AuthSession,
    Path(object_id): Path<String>,
    Json(req): Json<PutObjectRequest>,
) -> ApiResult<impl IntoResponse> {
    validate_put_request(&object_id, &req)?;

    let ciphertext = B64
        .decode(&req.ciphertext)
        .map_err(|_| ApiError::BadRequest("invalid base64 ciphertext".into()))?;
    if ciphertext.is_empty() {
        return Err(ApiError::BadRequest("ciphertext empty".into()));
    }
    if ciphertext.len() > state.config.max_blob_bytes {
        return Err(ApiError::PayloadTooLarge);
    }

    let manifest = ObjectManifestEntry {
        object_id: object_id.clone(),
        object_kind: req.object_kind,
        schema_version: req.schema_version,
        object_version: req.object_version,
        base_server_revision: req.base_server_revision,
        deleted: req.deleted,
        payload_hash: req.payload_hash.clone(),
        payload_size: req.payload_size,
        redaction: req.redaction,
    };
    let manifest_str = serde_json::to_string(&manifest)
        .map_err(|e| ApiError::BadRequest(format!("manifest not serializable: {e}")))?;

    let user_id = session.user_id;
    let auth_device_id = session.device_id;
    let expected_server_revision = req.base_server_revision.unwrap_or(0);
    let object_kind = req.object_kind.as_str().to_string();
    let actor_type = req.updated_by.actor_type.as_str().to_string();
    let request_device_id = req.updated_by.device_id.clone();
    let device_id = if request_device_id == auth_device_id {
        request_device_id
    } else {
        auth_device_id
    };
    let redaction = req.redaction.as_str().to_string();
    let storage_kind = format!("object-{object_id}");
    let blobs = state.blobs.clone();
    let db = state.db.clone();

    let response = tokio::task::spawn_blocking(move || -> ApiResult<PutObjectResponse> {
        let mut conn = db.get()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let current = fetch_current_revision(&tx, &user_id, &object_id)?;
        let current_revision = current
            .as_ref()
            .map(|current| current.server_revision)
            .unwrap_or(0);
        if current_revision != expected_server_revision {
            let current = current.expect("current row exists when revision is non-zero");
            return Err(ApiError::ObjectRevisionConflict(Box::new(
                ObjectRevisionConflictBody {
                    code: "sync.conflict.object_revision_mismatch",
                    object_id,
                    object_kind,
                    attempted_base_server_revision: expected_server_revision,
                    current_server_revision: current.server_revision,
                    attempted_object_version: req.object_version,
                    current_object_version: current.object_version,
                    server_updated_at: current.received_at,
                    server_updated_by: RedactedObjectActor {
                        actor_type: current.actor_type,
                        actor_id: REDACTED_ACTOR_ID,
                        device_id: current.device_id,
                    },
                    redaction: current.redaction,
                },
            )));
        }

        let new_revision = current_revision + 1;
        let rel_path = blobs.relative_path(&user_id, &storage_kind, new_revision);
        let (ciphertext_size, ciphertext_sha256) = blobs.write(&rel_path, &ciphertext)?;
        let received_at = Utc::now();
        let received_at_str = received_at.to_rfc3339();

        tx.execute(
            "INSERT INTO object_revisions (
                user_id, object_id, object_kind, server_revision,
                schema_version, object_version, base_server_revision,
                device_id, updated_at, received_at,
                updated_by_actor_type, updated_by_actor_id_redacted,
                deleted, redaction, payload_hash, payload_size, manifest,
                ciphertext_path, ciphertext_size, ciphertext_sha256
            ) VALUES (
                ?1, ?2, ?3, ?4,
                ?5, ?6, ?7,
                ?8, ?9, ?10,
                ?11, ?12,
                ?13, ?14, ?15, ?16, ?17,
                ?18, ?19, ?20
            )",
            params![
                &user_id,
                &object_id,
                &object_kind,
                new_revision,
                req.schema_version,
                req.object_version,
                req.base_server_revision,
                &device_id,
                req.updated_at,
                &received_at_str,
                &actor_type,
                REDACTED_ACTOR_ID,
                if req.deleted { 1 } else { 0 },
                &redaction,
                &req.payload_hash,
                req.payload_size,
                &manifest_str,
                &rel_path,
                ciphertext_size as i64,
                &ciphertext_sha256[..],
            ],
        )?;

        tx.execute(
            "INSERT INTO object_latest (user_id, object_id, server_revision, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(user_id, object_id) DO UPDATE SET
                server_revision = excluded.server_revision,
                updated_at = excluded.updated_at",
            params![&user_id, &object_id, new_revision, &received_at_str],
        )?;

        tx.commit()?;

        Ok(PutObjectResponse {
            object_id,
            object_kind: req.object_kind,
            object_version: req.object_version,
            server_revision: new_revision,
            received_at,
            manifest,
        })
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))??;

    Ok((StatusCode::OK, Json(response)))
}

async fn list_objects(
    State(state): State<AppState>,
    session: AuthSession,
    Query(q): Query<ListObjectsQuery>,
) -> ApiResult<Json<Vec<ObjectSummary>>> {
    let user_id = session.user_id;
    let kind = q.kind.map(|kind| kind.as_str().to_string());
    let include_deleted = if q.include_deleted { 1 } else { 0 };
    let limit = q.limit.clamp(1, 500) as i64;

    let rows = tokio::task::spawn_blocking(move || -> ApiResult<Vec<ObjectSummary>> {
        let conn = state.db.get()?;
        let mut stmt = conn.prepare(
            "SELECT r.object_id, r.object_kind, r.schema_version, r.object_version,
                    r.server_revision, r.base_server_revision, r.payload_hash, r.payload_size,
                    r.updated_at, r.received_at, r.updated_by_actor_type, r.device_id,
                    r.deleted, r.redaction, r.manifest, r.ciphertext_sha256
             FROM object_latest l
             JOIN object_revisions r
               ON r.user_id = l.user_id
              AND r.object_id = l.object_id
              AND r.server_revision = l.server_revision
             WHERE l.user_id = ?1
               AND (?2 IS NULL OR r.object_kind = ?2)
               AND (?3 = 1 OR r.deleted = 0)
             ORDER BY r.received_at DESC
             LIMIT ?4",
        )?;
        let rows = stmt
            .query_map(params![&user_id, kind, include_deleted, limit], row_to_summary)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))??;

    Ok(Json(rows))
}

async fn get_latest_object(
    State(state): State<AppState>,
    session: AuthSession,
    Path(object_id): Path<String>,
) -> ApiResult<Json<ObjectResponse>> {
    fetch_object(state, session.user_id, object_id, None)
        .await
        .map(Json)
}

async fn get_object_revision(
    State(state): State<AppState>,
    session: AuthSession,
    Path((object_id, server_revision)): Path<(String, i64)>,
) -> ApiResult<Json<ObjectResponse>> {
    if server_revision <= 0 {
        return Err(ApiError::BadRequest("invalid server_revision".into()));
    }
    fetch_object(state, session.user_id, object_id, Some(server_revision))
        .await
        .map(Json)
}

async fn get_object_history(
    State(state): State<AppState>,
    session: AuthSession,
    Path(object_id): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> ApiResult<Json<Vec<ObjectSummary>>> {
    let user_id = session.user_id;
    let limit = q.limit.clamp(1, 500) as i64;

    let rows = tokio::task::spawn_blocking(move || -> ApiResult<Vec<ObjectSummary>> {
        let conn = state.db.get()?;
        let mut stmt = conn.prepare(
            "SELECT object_id, object_kind, schema_version, object_version,
                    server_revision, base_server_revision, payload_hash, payload_size,
                    updated_at, received_at, updated_by_actor_type, device_id,
                    deleted, redaction, manifest, ciphertext_sha256
             FROM object_revisions
             WHERE user_id = ?1 AND object_id = ?2
             ORDER BY server_revision DESC
             LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![&user_id, &object_id, limit], row_to_summary)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))??;

    if rows.is_empty() {
        return Err(ApiError::NotFound);
    }
    Ok(Json(rows))
}

async fn fetch_object(
    state: AppState,
    user_id: String,
    object_id: String,
    server_revision: Option<i64>,
) -> ApiResult<ObjectResponse> {
    tokio::task::spawn_blocking(move || -> ApiResult<ObjectResponse> {
        let conn = state.db.get()?;
        let target_revision = match server_revision {
            Some(revision) => revision,
            None => conn
                .query_row(
                    "SELECT server_revision FROM object_latest
                     WHERE user_id = ?1 AND object_id = ?2",
                    params![&user_id, &object_id],
                    |r| r.get::<_, i64>(0),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?,
        };

        let row = conn
            .query_row(
                "SELECT object_id, object_kind, schema_version, object_version,
                        server_revision, base_server_revision, payload_hash, payload_size,
                        updated_at, received_at, updated_by_actor_type, device_id,
                        deleted, redaction, manifest, ciphertext_path, ciphertext_sha256
                 FROM object_revisions
                 WHERE user_id = ?1 AND object_id = ?2 AND server_revision = ?3",
                params![&user_id, &object_id, target_revision],
                |r| {
                    Ok(StoredObject {
                        object_id: r.get(0)?,
                        object_kind: r.get(1)?,
                        schema_version: r.get(2)?,
                        object_version: r.get(3)?,
                        server_revision: r.get(4)?,
                        base_server_revision: r.get(5)?,
                        payload_hash: r.get(6)?,
                        payload_size: r.get(7)?,
                        updated_at: r.get(8)?,
                        received_at: r.get(9)?,
                        actor_type: r.get(10)?,
                        device_id: r.get(11)?,
                        deleted: r.get::<_, i64>(12)? != 0,
                        redaction: r.get(13)?,
                        manifest: r.get(14)?,
                        ciphertext_path: r.get(15)?,
                        ciphertext_sha256: r.get(16)?,
                    })
                },
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;

        let ciphertext = state.blobs.read(&row.ciphertext_path)?;
        Ok(row.into_response(B64.encode(ciphertext)))
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))?
}

#[derive(Debug)]
struct CurrentObject {
    server_revision: i64,
    object_version: i64,
    received_at: DateTime<Utc>,
    actor_type: String,
    device_id: String,
    redaction: String,
}

fn fetch_current_revision(
    conn: &rusqlite::Connection,
    user_id: &str,
    object_id: &str,
) -> Result<Option<CurrentObject>, rusqlite::Error> {
    conn.query_row(
        "SELECT r.server_revision, r.object_version, r.received_at,
                r.updated_by_actor_type, r.device_id, r.redaction
         FROM object_latest l
         JOIN object_revisions r
           ON r.user_id = l.user_id
          AND r.object_id = l.object_id
          AND r.server_revision = l.server_revision
         WHERE l.user_id = ?1 AND l.object_id = ?2",
        params![user_id, object_id],
        |r| {
            Ok(CurrentObject {
                server_revision: r.get(0)?,
                object_version: r.get(1)?,
                received_at: r.get(2)?,
                actor_type: r.get(3)?,
                device_id: r.get(4)?,
                redaction: r.get(5)?,
            })
        },
    )
    .optional()
}

#[derive(Debug)]
struct StoredObject {
    object_id: String,
    object_kind: String,
    schema_version: i64,
    object_version: i64,
    server_revision: i64,
    base_server_revision: Option<i64>,
    payload_hash: String,
    payload_size: i64,
    updated_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    actor_type: String,
    device_id: String,
    deleted: bool,
    redaction: String,
    manifest: String,
    ciphertext_path: String,
    ciphertext_sha256: Vec<u8>,
}

impl StoredObject {
    fn into_summary(self) -> ObjectSummary {
        ObjectSummary {
            object_id: self.object_id,
            object_kind: self.object_kind,
            schema_version: self.schema_version,
            object_version: self.object_version,
            server_revision: self.server_revision,
            base_server_revision: self.base_server_revision,
            payload_hash: self.payload_hash,
            payload_size: self.payload_size,
            updated_at: self.updated_at,
            received_at: self.received_at,
            updated_by: RedactedActorResponse {
                actor_type: self.actor_type,
                actor_id: REDACTED_ACTOR_ID,
                device_id: self.device_id,
            },
            deleted: self.deleted,
            redaction: self.redaction,
            manifest: parse_manifest(&self.manifest),
            ciphertext_sha256: hex::encode(self.ciphertext_sha256),
        }
    }

    fn into_response(self, ciphertext: String) -> ObjectResponse {
        ObjectResponse {
            object_id: self.object_id,
            object_kind: self.object_kind,
            schema_version: self.schema_version,
            object_version: self.object_version,
            server_revision: self.server_revision,
            base_server_revision: self.base_server_revision,
            payload_hash: self.payload_hash,
            payload_size: self.payload_size,
            updated_at: self.updated_at,
            received_at: self.received_at,
            updated_by: RedactedActorResponse {
                actor_type: self.actor_type,
                actor_id: REDACTED_ACTOR_ID,
                device_id: self.device_id,
            },
            deleted: self.deleted,
            redaction: self.redaction,
            manifest: parse_manifest(&self.manifest),
            ciphertext,
            ciphertext_sha256: hex::encode(self.ciphertext_sha256),
        }
    }
}

fn row_to_summary(r: &rusqlite::Row<'_>) -> Result<ObjectSummary, rusqlite::Error> {
    Ok(StoredObject {
        object_id: r.get(0)?,
        object_kind: r.get(1)?,
        schema_version: r.get(2)?,
        object_version: r.get(3)?,
        server_revision: r.get(4)?,
        base_server_revision: r.get(5)?,
        payload_hash: r.get(6)?,
        payload_size: r.get(7)?,
        updated_at: r.get(8)?,
        received_at: r.get(9)?,
        actor_type: r.get(10)?,
        device_id: r.get(11)?,
        deleted: r.get::<_, i64>(12)? != 0,
        redaction: r.get(13)?,
        manifest: r.get(14)?,
        ciphertext_path: String::new(),
        ciphertext_sha256: r.get(15)?,
    }
    .into_summary())
}

fn parse_manifest(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).unwrap_or_else(|_| serde_json::json!({}))
}

fn validate_put_request(object_id: &str, req: &PutObjectRequest) -> Result<(), ApiError> {
    validate_object_id(req.object_kind, object_id)?;
    if req.schema_version <= 0 {
        return Err(ApiError::BadRequest("invalid schema_version".into()));
    }
    if req.object_version <= 0 {
        return Err(ApiError::BadRequest("invalid object_version".into()));
    }
    if req
        .base_server_revision
        .is_some_and(|revision| revision < 0)
    {
        return Err(ApiError::BadRequest("invalid base_server_revision".into()));
    }
    validate_payload_hash(&req.payload_hash)?;
    if req.payload_size <= 0 {
        return Err(ApiError::BadRequest("invalid payload_size".into()));
    }
    if req.updated_by.actor_id.trim().is_empty() {
        return Err(ApiError::BadRequest("updated_by.actor_id required".into()));
    }
    if req.updated_by.device_id.trim().is_empty() {
        return Err(ApiError::BadRequest("updated_by.device_id required".into()));
    }
    Ok(())
}

fn validate_object_id(kind: ObjectKind, object_id: &str) -> Result<(), ApiError> {
    let prefix = kind.object_id_prefix();
    let Some(body) = object_id.strip_prefix(prefix) else {
        return Err(ApiError::BadRequest(
            "object_id prefix does not match object_kind".into(),
        ));
    };
    if body.is_empty() {
        return Err(ApiError::BadRequest(
            "object_id missing opaque suffix".into(),
        ));
    }
    for ch in body.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-' {
            return Err(ApiError::BadRequest(
                "object_id contains invalid characters".into(),
            ));
        }
    }
    Ok(())
}

fn validate_payload_hash(payload_hash: &str) -> Result<(), ApiError> {
    let Some(hex_digest) = payload_hash.strip_prefix("sha256:") else {
        return Err(ApiError::BadRequest(
            "payload_hash must start with sha256:".into(),
        ));
    };
    if hex_digest.len() != 64 || !hex_digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(
            "payload_hash must contain a sha256 hex digest".into(),
        ));
    }
    Ok(())
}
