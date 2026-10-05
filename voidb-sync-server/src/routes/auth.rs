//! `/v1/auth/*` — registration, challenge, login, logout.
//!
//! Author: Limmy

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::Utc;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::{hash_auth, new_token, random_bytes, verify_auth},
    config::RegistrationPolicy,
    error::{ApiError, ApiResult},
    state::AppState,
};

use super::AuthSession;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/register", post(register))
        .route("/v1/auth/challenge", post(challenge))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/recovery/challenge", post(recovery_challenge))
        .route("/v1/auth/recovery/reset", post(recovery_reset))
        .route("/v1/auth/logout", post(logout))
}

// -----------------------------------------------------------------------------
// Common types
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub out_len: u32,
}

impl KdfParams {
    fn to_json(&self) -> String {
        serde_json::to_string(&serde_json::json!({
            "m_cost": self.m_cost,
            "t_cost": self.t_cost,
            "p_cost": self.p_cost,
            "out_len": self.out_len,
        }))
        .unwrap_or_else(|_| "{}".to_string())
    }
}

fn decode_b64(label: &str, s: &str) -> Result<Vec<u8>, ApiError> {
    B64.decode(s)
        .map_err(|_| ApiError::BadRequest(format!("invalid base64 in {label}")))
}

// -----------------------------------------------------------------------------
// Register
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub auth_hash_client: String,
    pub kdf_salt_auth: String,
    pub kdf_params_auth: KdfParams,
    pub kdf_salt_kek: String,
    pub kdf_params_kek: KdfParams,
    pub wrapped_dek: String,
    #[serde(default)]
    pub recovery_hash_client: Option<String>,
    #[serde(default)]
    pub kdf_salt_recovery_auth: Option<String>,
    #[serde(default)]
    pub kdf_params_recovery_auth: Option<KdfParams>,
    #[serde(default)]
    pub kdf_salt_recovery_kek: Option<String>,
    #[serde(default)]
    pub kdf_params_recovery_kek: Option<KdfParams>,
    #[serde(default)]
    pub recovery_wrapped_dek: Option<String>,
    pub device_name: String,
    #[serde(default)]
    pub invite_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub device_id: String,
    pub token: String,
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<impl IntoResponse> {
    if state.config.registration == RegistrationPolicy::Closed {
        return Err(ApiError::RegistrationDisabled);
    }

    let email = req.email.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(ApiError::BadRequest("invalid email".into()));
    }
    if req.device_name.trim().is_empty() {
        return Err(ApiError::BadRequest("device_name required".into()));
    }

    let auth_hash_client = decode_b64("auth_hash_client", &req.auth_hash_client)?;
    let kdf_salt_auth = decode_b64("kdf_salt_auth", &req.kdf_salt_auth)?;
    let kdf_salt_kek = decode_b64("kdf_salt_kek", &req.kdf_salt_kek)?;
    let wrapped_dek = decode_b64("wrapped_dek", &req.wrapped_dek)?;
    let recovery = decode_recovery_registration(&req)?;

    let srv_salt: [u8; 16] = random_bytes();
    let auth_hash_stored = hash_auth(&auth_hash_client, &srv_salt)?;
    let recovery = recovery
        .map(|recovery| {
            let recovery_srv_salt: [u8; 16] = random_bytes();
            let recovery_hash_stored =
                hash_auth(&recovery.recovery_hash_client, &recovery_srv_salt)?;
            Ok::<_, ApiError>(RecoveryStorage {
                recovery_srv_salt,
                recovery_hash_stored,
                kdf_salt_recovery_auth: recovery.kdf_salt_recovery_auth,
                kdf_params_recovery_auth: recovery.kdf_params_recovery_auth,
                kdf_salt_recovery_kek: recovery.kdf_salt_recovery_kek,
                kdf_params_recovery_kek: recovery.kdf_params_recovery_kek,
                recovery_wrapped_dek: recovery.recovery_wrapped_dek,
            })
        })
        .transpose()?;

    let user_id = Uuid::new_v4().to_string();
    let device_id = Uuid::new_v4().to_string();
    let (token_plain, token_hash) = new_token();
    let now = Utc::now().to_rfc3339();

    let kdf_auth_json = req.kdf_params_auth.to_json();
    let kdf_kek_json = req.kdf_params_kek.to_json();
    let registration = state.config.registration;
    let device_name = req.device_name.clone();
    let invite_token = req.invite_token.clone();
    let user_id_for_db = user_id.clone();
    let device_id_for_db = device_id.clone();

    tokio::task::spawn_blocking(move || -> ApiResult<()> {
        let mut conn = state.db.get()?;
        let tx = conn.transaction()?;

        if registration == RegistrationPolicy::InviteOnly {
            let Some(raw) = invite_token.as_ref().map(|s| s.trim()) else {
                return Err(ApiError::Forbidden("invite token required".into()));
            };
            if raw.is_empty() {
                return Err(ApiError::Forbidden("invite token required".into()));
            }
            let hash = {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(raw.as_bytes());
                let out: [u8; 32] = h.finalize().into();
                out
            };
            let available: i64 = tx.query_row(
                "SELECT COUNT(1) FROM invite_tokens WHERE token_hash = ?1 AND used_at IS NULL",
                [&hash[..]],
                |r| r.get(0),
            )?;
            if available == 0 {
                return Err(ApiError::Forbidden("invalid or used invite token".into()));
            }
            tx.execute(
                "UPDATE invite_tokens SET used_at = ?1, used_by = ?2 WHERE token_hash = ?3",
                params![now, user_id_for_db, &hash[..]],
            )?;
        }

        let email_exists: i64 = tx.query_row(
            "SELECT COUNT(1) FROM users WHERE email = ?1",
            [&email],
            |r| r.get(0),
        )?;
        if email_exists > 0 {
            return Err(ApiError::BadRequest("email already registered".into()));
        }

        tx.execute(
            "INSERT INTO users (
                id, email, srv_salt, auth_hash_stored,
                kdf_salt_auth, kdf_params_auth,
                kdf_salt_kek, kdf_params_kek,
                wrapped_dek,
                recovery_srv_salt, recovery_hash_stored,
                kdf_salt_recovery_auth, kdf_params_recovery_auth,
                kdf_salt_recovery_kek, kdf_params_recovery_kek,
                recovery_wrapped_dek, recovery_updated_at,
                created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?18)",
            params![
                user_id_for_db,
                email,
                &srv_salt[..],
                &auth_hash_stored[..],
                &kdf_salt_auth[..],
                kdf_auth_json,
                &kdf_salt_kek[..],
                kdf_kek_json,
                &wrapped_dek[..],
                recovery.as_ref().map(|r| &r.recovery_srv_salt[..]),
                recovery.as_ref().map(|r| &r.recovery_hash_stored[..]),
                recovery.as_ref().map(|r| &r.kdf_salt_recovery_auth[..]),
                recovery.as_ref().map(|r| r.kdf_params_recovery_auth.as_str()),
                recovery.as_ref().map(|r| &r.kdf_salt_recovery_kek[..]),
                recovery.as_ref().map(|r| r.kdf_params_recovery_kek.as_str()),
                recovery.as_ref().map(|r| &r.recovery_wrapped_dek[..]),
                recovery.as_ref().map(|_| now.as_str()),
                now
            ],
        )?;

        tx.execute(
            "INSERT INTO devices (id, user_id, name, token_hash, created_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![device_id_for_db, user_id_for_db, device_name, &token_hash[..], now],
        )?;

        tx.commit()?;
        Ok(())
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))??;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            user_id,
            device_id,
            token: token_plain,
        }),
    ))
}

struct RecoveryRegistration {
    recovery_hash_client: Vec<u8>,
    kdf_salt_recovery_auth: Vec<u8>,
    kdf_params_recovery_auth: String,
    kdf_salt_recovery_kek: Vec<u8>,
    kdf_params_recovery_kek: String,
    recovery_wrapped_dek: Vec<u8>,
}

struct RecoveryStorage {
    recovery_srv_salt: [u8; 16],
    recovery_hash_stored: [u8; 32],
    kdf_salt_recovery_auth: Vec<u8>,
    kdf_params_recovery_auth: String,
    kdf_salt_recovery_kek: Vec<u8>,
    kdf_params_recovery_kek: String,
    recovery_wrapped_dek: Vec<u8>,
}

type RecoveryChallengeRow = (Vec<u8>, String, Vec<u8>, String, Vec<u8>);

fn decode_recovery_registration(
    req: &RegisterRequest,
) -> Result<Option<RecoveryRegistration>, ApiError> {
    let present = [
        req.recovery_hash_client.is_some(),
        req.kdf_salt_recovery_auth.is_some(),
        req.kdf_params_recovery_auth.is_some(),
        req.kdf_salt_recovery_kek.is_some(),
        req.kdf_params_recovery_kek.is_some(),
        req.recovery_wrapped_dek.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();

    if present == 0 {
        return Ok(None);
    }
    if present != 6 {
        return Err(ApiError::BadRequest(
            "incomplete recovery registration fields".into(),
        ));
    }

    Ok(Some(RecoveryRegistration {
        recovery_hash_client: decode_b64(
            "recovery_hash_client",
            req.recovery_hash_client.as_deref().unwrap_or_default(),
        )?,
        kdf_salt_recovery_auth: decode_b64(
            "kdf_salt_recovery_auth",
            req.kdf_salt_recovery_auth.as_deref().unwrap_or_default(),
        )?,
        kdf_params_recovery_auth: req
            .kdf_params_recovery_auth
            .as_ref()
            .expect("presence checked")
            .to_json(),
        kdf_salt_recovery_kek: decode_b64(
            "kdf_salt_recovery_kek",
            req.kdf_salt_recovery_kek.as_deref().unwrap_or_default(),
        )?,
        kdf_params_recovery_kek: req
            .kdf_params_recovery_kek
            .as_ref()
            .expect("presence checked")
            .to_json(),
        recovery_wrapped_dek: decode_b64(
            "recovery_wrapped_dek",
            req.recovery_wrapped_dek.as_deref().unwrap_or_default(),
        )?,
    }))
}

// -----------------------------------------------------------------------------
// Challenge — exposes the client-side KDF parameters needed for login.
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub kdf_salt_auth: String,
    pub kdf_params_auth: serde_json::Value,
}

async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> ApiResult<Json<ChallengeResponse>> {
    let email = req.email.trim().to_ascii_lowercase();

    let row = tokio::task::spawn_blocking(move || -> ApiResult<Option<(Vec<u8>, String)>> {
        let conn = state.db.get()?;
        let row = conn.query_row(
            "SELECT kdf_salt_auth, kdf_params_auth FROM users WHERE email = ?1",
            [&email],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?)),
        );
        match row {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(ApiError::from(e)),
        }
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))??;

    // MVP: surface 404 for unknown emails. Known trade-off: allows user
    // enumeration. Fix later by returning deterministic fake salts.
    let (salt_auth, params_auth) = row.ok_or(ApiError::NotFound)?;
    let params_auth_val: serde_json::Value =
        serde_json::from_str(&params_auth).unwrap_or(serde_json::json!({}));

    Ok(Json(ChallengeResponse {
        kdf_salt_auth: B64.encode(&salt_auth),
        kdf_params_auth: params_auth_val,
    }))
}

// -----------------------------------------------------------------------------
// Login
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub auth_hash_client: String,
    pub device_name: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user_id: String,
    pub device_id: String,
    pub token: String,
    pub wrapped_dek: String,
    pub kdf_salt_kek: String,
    pub kdf_params_kek: serde_json::Value,
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let email = req.email.trim().to_ascii_lowercase();
    let auth_hash_client = decode_b64("auth_hash_client", &req.auth_hash_client)?;
    if req.device_name.trim().is_empty() {
        return Err(ApiError::BadRequest("device_name required".into()));
    }
    let device_name = req.device_name.clone();

    let (token_plain, token_hash) = new_token();
    let device_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let resp = tokio::task::spawn_blocking(move || -> ApiResult<LoginResponse> {
        let mut conn = state.db.get()?;
        let tx = conn.transaction()?;

        let row = tx.query_row(
            "SELECT id, srv_salt, auth_hash_stored, wrapped_dek, kdf_salt_kek, kdf_params_kek
             FROM users WHERE email = ?1",
            [&email],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, String>(5)?,
                ))
            },
        );

        let (user_id, srv_salt, stored, wrapped_dek, salt_kek, params_kek) = match row {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Err(ApiError::Unauthorized),
            Err(e) => return Err(ApiError::from(e)),
        };

        let recomputed = hash_auth(&auth_hash_client, &srv_salt)?;
        if !verify_auth(&stored, &recomputed) {
            return Err(ApiError::Unauthorized);
        }

        tx.execute(
            "INSERT INTO devices (id, user_id, name, token_hash, created_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![device_id, user_id, device_name, &token_hash[..], now],
        )?;

        tx.commit()?;

        let params_kek_val: serde_json::Value =
            serde_json::from_str(&params_kek).unwrap_or(serde_json::json!({}));

        Ok(LoginResponse {
            user_id,
            device_id: device_id.clone(),
            token: token_plain.clone(),
            wrapped_dek: B64.encode(&wrapped_dek),
            kdf_salt_kek: B64.encode(&salt_kek),
            kdf_params_kek: params_kek_val,
        })
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))??;

    Ok(Json(resp))
}

// -----------------------------------------------------------------------------
// Recovery — recover the DEK with a high-entropy recovery code, then reset auth.
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RecoveryChallengeRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct RecoveryChallengeResponse {
    pub kdf_salt_recovery_auth: String,
    pub kdf_params_recovery_auth: serde_json::Value,
    pub kdf_salt_recovery_kek: String,
    pub kdf_params_recovery_kek: serde_json::Value,
    pub recovery_wrapped_dek: String,
}

async fn recovery_challenge(
    State(state): State<AppState>,
    Json(req): Json<RecoveryChallengeRequest>,
) -> ApiResult<Json<RecoveryChallengeResponse>> {
    let email = req.email.trim().to_ascii_lowercase();

    let row = tokio::task::spawn_blocking(move || -> ApiResult<Option<RecoveryChallengeRow>> {
        let conn = state.db.get()?;
        let row = conn.query_row(
            "SELECT
                    kdf_salt_recovery_auth,
                    kdf_params_recovery_auth,
                    kdf_salt_recovery_kek,
                    kdf_params_recovery_kek,
                    recovery_wrapped_dek
                 FROM users
                 WHERE email = ?1 AND recovery_hash_stored IS NOT NULL",
            [&email],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                ))
            },
        );
        match row {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(ApiError::from(e)),
        }
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))??;

    let (
        salt_recovery_auth,
        params_recovery_auth,
        salt_recovery_kek,
        params_recovery_kek,
        recovery_wrapped_dek,
    ) = row.ok_or(ApiError::NotFound)?;

    Ok(Json(RecoveryChallengeResponse {
        kdf_salt_recovery_auth: B64.encode(&salt_recovery_auth),
        kdf_params_recovery_auth: serde_json::from_str(&params_recovery_auth)
            .unwrap_or(serde_json::json!({})),
        kdf_salt_recovery_kek: B64.encode(&salt_recovery_kek),
        kdf_params_recovery_kek: serde_json::from_str(&params_recovery_kek)
            .unwrap_or(serde_json::json!({})),
        recovery_wrapped_dek: B64.encode(&recovery_wrapped_dek),
    }))
}

#[derive(Debug, Deserialize)]
pub struct RecoveryResetRequest {
    pub email: String,
    pub recovery_hash_client: String,
    pub auth_hash_client: String,
    pub kdf_salt_auth: String,
    pub kdf_params_auth: KdfParams,
    pub kdf_salt_kek: String,
    pub kdf_params_kek: KdfParams,
    pub wrapped_dek: String,
    pub device_name: String,
}

async fn recovery_reset(
    State(state): State<AppState>,
    Json(req): Json<RecoveryResetRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let email = req.email.trim().to_ascii_lowercase();
    if req.device_name.trim().is_empty() {
        return Err(ApiError::BadRequest("device_name required".into()));
    }

    let recovery_hash_client = decode_b64("recovery_hash_client", &req.recovery_hash_client)?;
    let auth_hash_client = decode_b64("auth_hash_client", &req.auth_hash_client)?;
    let kdf_salt_auth = decode_b64("kdf_salt_auth", &req.kdf_salt_auth)?;
    let kdf_salt_kek = decode_b64("kdf_salt_kek", &req.kdf_salt_kek)?;
    let wrapped_dek = decode_b64("wrapped_dek", &req.wrapped_dek)?;
    let new_srv_salt: [u8; 16] = random_bytes();
    let new_auth_hash_stored = hash_auth(&auth_hash_client, &new_srv_salt)?;
    let kdf_auth_json = req.kdf_params_auth.to_json();
    let kdf_kek_json = req.kdf_params_kek.to_json();
    let kdf_params_kek_value: serde_json::Value =
        serde_json::from_str(&kdf_kek_json).unwrap_or(serde_json::json!({}));
    let device_name = req.device_name;
    let (token_plain, token_hash) = new_token();
    let device_id = Uuid::new_v4().to_string();
    let device_id_for_db = device_id.clone();
    let now = Utc::now().to_rfc3339();

    let resp = tokio::task::spawn_blocking(move || -> ApiResult<LoginResponse> {
        let mut conn = state.db.get()?;
        let tx = conn.transaction()?;

        let row = tx.query_row(
            "SELECT id, recovery_srv_salt, recovery_hash_stored
             FROM users
             WHERE email = ?1 AND recovery_hash_stored IS NOT NULL",
            [&email],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            },
        );

        let (user_id, recovery_srv_salt, recovery_stored) = match row {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Err(ApiError::Unauthorized),
            Err(e) => return Err(ApiError::from(e)),
        };

        let recomputed = hash_auth(&recovery_hash_client, &recovery_srv_salt)?;
        if !verify_auth(&recovery_stored, &recomputed) {
            return Err(ApiError::Unauthorized);
        }

        tx.execute(
            "UPDATE users
             SET srv_salt = ?1,
                 auth_hash_stored = ?2,
                 kdf_salt_auth = ?3,
                 kdf_params_auth = ?4,
                 kdf_salt_kek = ?5,
                 kdf_params_kek = ?6,
                 wrapped_dek = ?7,
                 updated_at = ?8
             WHERE id = ?9",
            params![
                &new_srv_salt[..],
                &new_auth_hash_stored[..],
                &kdf_salt_auth[..],
                kdf_auth_json.as_str(),
                &kdf_salt_kek[..],
                kdf_kek_json.as_str(),
                &wrapped_dek[..],
                now.as_str(),
                user_id.as_str(),
            ],
        )?;

        tx.execute(
            "INSERT INTO devices (id, user_id, name, token_hash, created_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![device_id_for_db, user_id, device_name, &token_hash[..], now],
        )?;

        tx.commit()?;

        Ok(LoginResponse {
            user_id,
            device_id,
            token: token_plain,
            wrapped_dek: B64.encode(&wrapped_dek),
            kdf_salt_kek: B64.encode(&kdf_salt_kek),
            kdf_params_kek: kdf_params_kek_value,
        })
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))??;

    Ok(Json(resp))
}

// -----------------------------------------------------------------------------
// Logout — revokes the current device token.
// -----------------------------------------------------------------------------

async fn logout(State(state): State<AppState>, session: AuthSession) -> ApiResult<StatusCode> {
    let device_id = session.device_id;
    tokio::task::spawn_blocking(move || -> ApiResult<()> {
        let conn = state.db.get()?;
        conn.execute("DELETE FROM devices WHERE id = ?1", [&device_id])?;
        Ok(())
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))??;

    Ok(StatusCode::NO_CONTENT)
}
