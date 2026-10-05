//! `/v1/blobs/{kind}/...` — encrypted payload storage with optimistic locking.
//!
//! Semantics:
//!   - `PUT /v1/blobs/{kind}` — atomic append-or-replace; the client asserts
//!     `expected_revision`. On mismatch the server returns 409 with the current
//!     revision.
//!   - `GET /v1/blobs/{kind}/latest` — full ciphertext of the latest revision.
//!   - `GET /v1/blobs/{kind}/history` — lightweight revision list.
//!   - `GET /v1/blobs/{kind}/revisions/{r}` — specific historical revision.
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
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::{
    error::{ApiError, ApiResult},
    state::AppState,
};

use super::AuthSession;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/blobs/{kind}", put(put_blob))
        .route("/v1/blobs/{kind}/latest", get(get_latest))
        .route("/v1/blobs/{kind}/history", get(get_history))
        .route("/v1/blobs/{kind}/revisions/{rev}", get(get_revision))
}

// -----------------------------------------------------------------------------
// PUT
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PutBlobRequest {
    /// 0 means "no blob exists yet"; any other value must match the current
    /// server revision, otherwise 409.
    pub expected_revision: i64,
    pub manifest: serde_json::Value,
    pub ciphertext: String,
}

#[derive(Debug, Serialize)]
pub struct PutBlobResponse {
    pub revision: i64,
    pub created_at: DateTime<Utc>,
}

async fn put_blob(
    State(state): State<AppState>,
    session: AuthSession,
    Path(kind): Path<String>,
    Json(req): Json<PutBlobRequest>,
) -> ApiResult<impl IntoResponse> {
    validate_kind(&kind)?;

    let ciphertext = B64
        .decode(&req.ciphertext)
        .map_err(|_| ApiError::BadRequest("invalid base64 ciphertext".into()))?;
    if ciphertext.is_empty() {
        return Err(ApiError::BadRequest("ciphertext empty".into()));
    }
    if ciphertext.len() > state.config.max_blob_bytes {
        return Err(ApiError::PayloadTooLarge);
    }

    let manifest_str = serde_json::to_string(&req.manifest)
        .map_err(|e| ApiError::BadRequest(format!("manifest not serializable: {e}")))?;

    let user_id = session.user_id.clone();
    let device_id = session.device_id.clone();
    let expected = req.expected_revision;
    let history_keep = state.config.history_keep;
    let blobs = state.blobs.clone();
    let db = state.db.clone();

    let resp = tokio::task::spawn_blocking(move || -> ApiResult<PutBlobResponse> {
        let mut conn = db.get()?;
        // IMMEDIATE so the revision check + insert happen under a single writer
        // lock — avoids races when two devices push concurrently.
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let current: i64 = tx.query_row(
            "SELECT COALESCE(MAX(revision), 0) FROM blobs WHERE user_id = ?1 AND kind = ?2",
            params![user_id, kind],
            |r| r.get(0),
        )?;
        if expected != current {
            return Err(ApiError::RevisionConflict { current });
        }

        let new_rev = current + 1;
        let rel_path = blobs.relative_path(&user_id, &kind, new_rev);
        let (size, sha256) = blobs.write(&rel_path, &ciphertext)?;
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        tx.execute(
            "INSERT INTO blobs (
                user_id, kind, revision, device_id, manifest,
                ciphertext_path, ciphertext_size, ciphertext_sha256, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                user_id,
                kind,
                new_rev,
                device_id,
                manifest_str,
                rel_path,
                size as i64,
                &sha256[..],
                now_str,
            ],
        )?;

        tx.execute(
            "INSERT INTO blob_latest (user_id, kind, revision, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(user_id, kind) DO UPDATE SET
                revision = excluded.revision,
                updated_at = excluded.updated_at",
            params![user_id, kind, new_rev, now_str],
        )?;

        // Prune old revisions.
        let pruned_paths: Vec<String> = if history_keep > 0 {
            let mut stmt = tx.prepare(
                "SELECT revision, ciphertext_path FROM blobs
                 WHERE user_id = ?1 AND kind = ?2 AND revision <= ?3
                 ORDER BY revision",
            )?;
            let rows = stmt
                .query_map(
                    params![user_id, kind, new_rev - history_keep as i64],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                )?
                .collect::<Result<Vec<_>, _>>()?;
            let to_prune: Vec<(i64, String)> = rows;
            for (rev, _) in &to_prune {
                tx.execute(
                    "DELETE FROM blobs WHERE user_id = ?1 AND kind = ?2 AND revision = ?3",
                    params![user_id, kind, rev],
                )?;
            }
            to_prune.into_iter().map(|(_, p)| p).collect()
        } else {
            Vec::new()
        };

        tx.commit()?;

        for p in pruned_paths {
            blobs.delete(&p);
        }

        Ok(PutBlobResponse {
            revision: new_rev,
            created_at: now,
        })
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))??;

    Ok((StatusCode::OK, Json(resp)))
}

// -----------------------------------------------------------------------------
// GET latest
// -----------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct BlobResponse {
    pub revision: i64,
    pub device_id: String,
    pub created_at: DateTime<Utc>,
    pub manifest: serde_json::Value,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
}

async fn get_latest(
    State(state): State<AppState>,
    session: AuthSession,
    Path(kind): Path<String>,
) -> ApiResult<Json<BlobResponse>> {
    validate_kind(&kind)?;
    fetch_blob(state, session.user_id, kind, None).await.map(Json)
}

async fn get_revision(
    State(state): State<AppState>,
    session: AuthSession,
    Path((kind, rev)): Path<(String, i64)>,
) -> ApiResult<Json<BlobResponse>> {
    validate_kind(&kind)?;
    fetch_blob(state, session.user_id, kind, Some(rev)).await.map(Json)
}

async fn fetch_blob(
    state: AppState,
    user_id: String,
    kind: String,
    revision: Option<i64>,
) -> ApiResult<BlobResponse> {
    tokio::task::spawn_blocking(move || -> ApiResult<BlobResponse> {
        let conn = state.db.get()?;
        let target_rev: i64 = match revision {
            Some(r) => r,
            None => {
                let row: Option<i64> = conn
                    .query_row(
                        "SELECT revision FROM blob_latest WHERE user_id = ?1 AND kind = ?2",
                        params![user_id, kind],
                        |r| r.get(0),
                    )
                    .ok();
                row.ok_or(ApiError::NotFound)?
            }
        };

        let row = conn.query_row(
            "SELECT revision, device_id, manifest, ciphertext_path, ciphertext_sha256, created_at
             FROM blobs WHERE user_id = ?1 AND kind = ?2 AND revision = ?3",
            params![user_id, kind, target_rev],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, DateTime<Utc>>(5)?,
                ))
            },
        );

        let (rev, device_id, manifest_str, path, sha, created_at) = match row {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Err(ApiError::NotFound),
            Err(e) => return Err(ApiError::from(e)),
        };

        let ciphertext = state.blobs.read(&path)?;
        let manifest: serde_json::Value =
            serde_json::from_str(&manifest_str).unwrap_or(serde_json::json!({}));

        Ok(BlobResponse {
            revision: rev,
            device_id,
            created_at,
            manifest,
            ciphertext: B64.encode(&ciphertext),
            ciphertext_sha256: hex::encode(sha),
        })
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))?
}

// -----------------------------------------------------------------------------
// GET history
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    #[serde(default = "default_history_limit")]
    pub limit: u32,
}

fn default_history_limit() -> u32 {
    20
}

#[derive(Debug, Serialize)]
pub struct HistoryRow {
    pub revision: i64,
    pub device_id: String,
    pub created_at: DateTime<Utc>,
    pub ciphertext_size: i64,
    pub ciphertext_sha256: String,
}

async fn get_history(
    State(state): State<AppState>,
    session: AuthSession,
    Path(kind): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> ApiResult<Json<Vec<HistoryRow>>> {
    validate_kind(&kind)?;
    let user_id = session.user_id;
    let limit = q.limit.clamp(1, 500);

    let rows = tokio::task::spawn_blocking(move || -> ApiResult<Vec<HistoryRow>> {
        let conn = state.db.get()?;
        let mut stmt = conn.prepare(
            "SELECT revision, device_id, ciphertext_size, ciphertext_sha256, created_at
             FROM blobs WHERE user_id = ?1 AND kind = ?2
             ORDER BY revision DESC LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![user_id, kind, limit as i64], |r| {
                Ok(HistoryRow {
                    revision: r.get(0)?,
                    device_id: r.get(1)?,
                    ciphertext_size: r.get(2)?,
                    ciphertext_sha256: hex::encode(r.get::<_, Vec<u8>>(3)?),
                    created_at: r.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))??;

    Ok(Json(rows))
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn validate_kind(kind: &str) -> Result<(), ApiError> {
    if kind.is_empty() || kind.len() > 64 {
        return Err(ApiError::BadRequest("invalid kind".into()));
    }
    // Allow ASCII alnum, '-', '_', ':', '.'
    for c in kind.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.')) {
            return Err(ApiError::BadRequest("invalid kind".into()));
        }
    }
    Ok(())
}
