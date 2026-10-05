//! Unified error type + Axum `IntoResponse` mapping.
//!
//! Author: Limmy

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("not found")]
    NotFound,

    #[error("conflict: revision {current}")]
    RevisionConflict { current: i64 },

    #[error("object revision conflict")]
    ObjectRevisionConflict(Box<ObjectRevisionConflictBody>),

    #[error("payload too large")]
    PayloadTooLarge,

    #[error("registration disabled")]
    RegistrationDisabled,

    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    pub fn internal<E: std::fmt::Display>(msg: E) -> Self {
        Self::Internal(msg.to_string())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error = %e, "unhandled error");
        ApiError::Internal(e.to_string())
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!(error = %e, "sqlite error");
        ApiError::Internal(format!("db error: {e}"))
    }
}

impl From<r2d2::Error> for ApiError {
    fn from(e: r2d2::Error) -> Self {
        ApiError::Internal(format!("db pool error: {e}"))
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        ApiError::Internal(format!("io error: {e}"))
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_revision: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjectRevisionConflictBody {
    pub code: &'static str,
    pub object_id: String,
    pub object_kind: String,
    pub attempted_base_server_revision: i64,
    pub current_server_revision: i64,
    pub attempted_object_version: i64,
    pub current_object_version: i64,
    pub server_updated_at: chrono::DateTime<chrono::Utc>,
    pub server_updated_by: RedactedObjectActor,
    pub redaction: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedactedObjectActor {
    pub actor_type: String,
    pub actor_id: &'static str,
    pub device_id: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::ObjectRevisionConflict(body) = self {
            return (StatusCode::CONFLICT, Json(*body)).into_response();
        }

        let (status, code) = match &self {
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            ApiError::RevisionConflict { .. } => (StatusCode::CONFLICT, "revision_conflict"),
            ApiError::ObjectRevisionConflict(_) => unreachable!("handled above"),
            ApiError::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            ApiError::RegistrationDisabled => (StatusCode::FORBIDDEN, "registration_disabled"),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };

        let current_revision = match &self {
            ApiError::RevisionConflict { current } => Some(*current),
            _ => None,
        };

        let body = ErrorBody {
            error: code,
            message: self.to_string(),
            current_revision,
        };
        (status, Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
