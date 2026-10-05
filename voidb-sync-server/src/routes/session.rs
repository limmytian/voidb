//! Bearer-token extractor.
//!
//! Resolves `Authorization: Bearer <token>` into (user_id, device_id) by
//! looking up `sha256(token)` in the `devices` table.
//!
//! Author: Limmy

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header::AUTHORIZATION, request::Parts},
};
use chrono::Utc;

use crate::{auth::hash_token, error::ApiError, state::AppState};

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub user_id: String,
    pub device_id: String,
}

impl<S> FromRequestParts<S> for AuthSession
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;

        let token = header
            .strip_prefix("Bearer ")
            .ok_or(ApiError::Unauthorized)?
            .trim();

        if token.is_empty() {
            return Err(ApiError::Unauthorized);
        }

        let token_hash = hash_token(token);
        let db = app_state.db.clone();
        let now = Utc::now().to_rfc3339();

        tokio::task::spawn_blocking(move || -> Result<AuthSession, ApiError> {
            let conn = db.get()?;
            let mut stmt = conn.prepare_cached(
                "SELECT id, user_id FROM devices WHERE token_hash = ?1",
            )?;
            let row: Result<(String, String), rusqlite::Error> =
                stmt.query_row([&token_hash[..]], |r: &rusqlite::Row<'_>| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                });

            match row {
                Ok((device_id, user_id)) => {
                    let _ = conn.execute(
                        "UPDATE devices SET last_seen_at = ?1 WHERE id = ?2",
                        rusqlite::params![now, device_id],
                    );
                    Ok(AuthSession {
                        user_id,
                        device_id,
                    })
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Err(ApiError::Unauthorized),
                Err(e) => Err(ApiError::from(e)),
            }
        })
        .await
        .map_err(|e| ApiError::internal(format!("join error: {e}")))?
    }
}
