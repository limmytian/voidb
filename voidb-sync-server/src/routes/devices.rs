//! `/v1/devices` — list + revoke.
//!
//! Author: Limmy

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{
    error::{ApiError, ApiResult},
    state::AppState,
};

use super::AuthSession;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/devices", get(list))
        .route("/v1/devices/{id}", axum::routing::delete(revoke))
}

#[derive(Serialize)]
pub struct DeviceRow {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub is_current: bool,
}

async fn list(
    State(state): State<AppState>,
    session: AuthSession,
) -> ApiResult<Json<Vec<DeviceRow>>> {
    let user_id = session.user_id;
    let current = session.device_id;

    let rows = tokio::task::spawn_blocking(move || -> ApiResult<Vec<DeviceRow>> {
        let conn = state.db.get()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, created_at, last_seen_at
             FROM devices WHERE user_id = ?1 ORDER BY created_at",
        )?;
        let rows = stmt
            .query_map([&user_id], |r| {
                let id: String = r.get(0)?;
                Ok(DeviceRow {
                    is_current: id == current,
                    id,
                    name: r.get(1)?,
                    created_at: r.get(2)?,
                    last_seen_at: r.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))??;

    Ok(Json(rows))
}

async fn revoke(
    State(state): State<AppState>,
    session: AuthSession,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let user_id = session.user_id;

    let deleted = tokio::task::spawn_blocking(move || -> ApiResult<usize> {
        let conn = state.db.get()?;
        let affected = conn.execute(
            "DELETE FROM devices WHERE id = ?1 AND user_id = ?2",
            rusqlite::params![id, user_id],
        )?;
        Ok(affected)
    })
    .await
    .map_err(|e| ApiError::internal(format!("join: {e}")))??;

    if deleted == 0 {
        Err(ApiError::NotFound)
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}
