//! Miscellaneous endpoints: health check + `/v1/me`.
//!
//! Author: Limmy

use axum::{Json, Router, extract::State, routing::get};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{error::ApiResult, state::AppState};

use super::AuthSession;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/healthz", get(healthz))
        .route("/v1/me", get(me))
}

async fn healthz() -> &'static str {
    "ok"
}

#[derive(Serialize)]
struct DeviceSummary {
    id: String,
    name: String,
    created_at: DateTime<Utc>,
    last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct MeResponse {
    user_id: String,
    email: String,
    device_id: String,
    devices: Vec<DeviceSummary>,
}

async fn me(
    State(state): State<AppState>,
    session: AuthSession,
) -> ApiResult<Json<MeResponse>> {
    let user_id = session.user_id.clone();
    let device_id = session.device_id.clone();

    let resp = tokio::task::spawn_blocking(move || -> ApiResult<MeResponse> {
        let conn = state.db.get()?;
        let email: String = conn.query_row(
            "SELECT email FROM users WHERE id = ?1",
            [&user_id],
            |r| r.get(0),
        )?;

        let mut stmt = conn.prepare(
            "SELECT id, name, created_at, last_seen_at FROM devices WHERE user_id = ?1 ORDER BY created_at",
        )?;
        let rows = stmt
            .query_map([&user_id], |r| {
                Ok(DeviceSummary {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    created_at: r.get(2)?,
                    last_seen_at: r.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(MeResponse {
            user_id,
            email,
            device_id,
            devices: rows,
        })
    })
    .await
    .map_err(|e| crate::error::ApiError::internal(format!("join: {e}")))??;

    Ok(Json(resp))
}
