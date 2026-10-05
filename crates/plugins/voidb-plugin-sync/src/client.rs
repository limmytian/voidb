//! HTTP client for talking to voidb-sync-server.
//!
//! Author: Limmy

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::crypto::KdfParams;
use crate::error::{ObjectConflictDetails, SyncError};

#[derive(Clone)]
pub struct SyncClient {
    base: String,
    http: reqwest::Client,
    token: Option<String>,
}

impl SyncClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("voidb-plugin-sync/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            http,
            token: None,
        }
    }

    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }

    pub fn set_token(&mut self, token: Option<String>) {
        self.token = token;
    }

    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn handle<T: for<'de> Deserialize<'de>>(resp: reqwest::Response) -> Result<T, SyncError> {
        let status = resp.status();
        if status.is_success() {
            return resp.json::<T>().await.map_err(SyncError::from);
        }
        let body: Value = resp.json().await.unwrap_or_else(|_| json!({}));
        let code = body
            .get("error")
            .or_else(|| body.get("code"))
            .and_then(|v| v.as_str())
            .unwrap_or("http_error")
            .to_string();
        let message = body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let current_revision = body.get("current_revision").and_then(|v| v.as_i64());

        if status == StatusCode::UNAUTHORIZED {
            return Err(SyncError::Unauthorized);
        }
        if status == StatusCode::CONFLICT
            && let Some(current) = current_revision
        {
            return Err(SyncError::Conflict { current });
        }
        if status == StatusCode::CONFLICT && code == "sync.conflict.object_revision_mismatch" {
            let object_id = body
                .get("object_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let object_kind = body
                .get("object_kind")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let current_server_revision = body
                .get("current_server_revision")
                .and_then(|v| v.as_u64())
                .unwrap_or_default();
            let attempted_base_server_revision = body
                .get("attempted_base_server_revision")
                .and_then(|v| v.as_u64())
                .unwrap_or_default();
            let attempted_object_version = body
                .get("attempted_object_version")
                .and_then(|v| v.as_u64())
                .unwrap_or_default();
            let current_object_version = body
                .get("current_object_version")
                .and_then(|v| v.as_u64())
                .unwrap_or_default();
            let server_updated_at = body
                .get("server_updated_at")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let redaction = body
                .get("redaction")
                .and_then(|v| v.as_str())
                .unwrap_or("withheld")
                .to_string();
            return Err(SyncError::ObjectConflict {
                object_id,
                object_kind,
                details: Box::new(ObjectConflictDetails {
                    attempted_base_server_revision,
                    current_server_revision,
                    attempted_object_version,
                    current_object_version,
                    server_updated_at,
                    redaction,
                }),
            });
        }
        Err(SyncError::Server {
            status: status.as_u16(),
            code,
            message,
            current_revision,
        })
    }

    // -------------------------------------------------------------------------
    // Health
    // -------------------------------------------------------------------------

    pub async fn healthz(&self) -> Result<bool, SyncError> {
        let resp = self.http.get(self.url("/v1/healthz")).send().await?;
        Ok(resp.status().is_success())
    }

    // -------------------------------------------------------------------------
    // Auth
    // -------------------------------------------------------------------------

    pub async fn register(&self, req: RegisterRequest) -> Result<AuthResponse, SyncError> {
        let resp = self
            .http
            .post(self.url("/v1/auth/register"))
            .json(&req)
            .send()
            .await?;
        Self::handle(resp).await
    }

    pub async fn challenge(&self, email: &str) -> Result<ChallengeResponse, SyncError> {
        let resp = self
            .http
            .post(self.url("/v1/auth/challenge"))
            .json(&json!({ "email": email }))
            .send()
            .await?;
        Self::handle(resp).await
    }

    pub async fn login(
        &self,
        email: &str,
        auth_hash_client: &[u8],
        device_name: &str,
    ) -> Result<LoginResponse, SyncError> {
        let body = json!({
            "email": email,
            "auth_hash_client": B64.encode(auth_hash_client),
            "device_name": device_name,
        });
        let resp = self
            .http
            .post(self.url("/v1/auth/login"))
            .json(&body)
            .send()
            .await?;
        Self::handle(resp).await
    }

    pub async fn recovery_challenge(
        &self,
        email: &str,
    ) -> Result<RecoveryChallengeResponse, SyncError> {
        let resp = self
            .http
            .post(self.url("/v1/auth/recovery/challenge"))
            .json(&json!({ "email": email }))
            .send()
            .await?;
        Self::handle(resp).await
    }

    pub async fn recover(&self, req: RecoveryResetRequest) -> Result<LoginResponse, SyncError> {
        let resp = self
            .http
            .post(self.url("/v1/auth/recovery/reset"))
            .json(&req)
            .send()
            .await?;
        Self::handle(resp).await
    }

    pub async fn logout(&self) -> Result<(), SyncError> {
        let token = self.token.as_ref().ok_or(SyncError::NotLoggedIn)?;
        let resp = self
            .http
            .post(self.url("/v1/auth/logout"))
            .bearer_auth(token)
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else if resp.status() == StatusCode::UNAUTHORIZED {
            Err(SyncError::Unauthorized)
        } else {
            Err(SyncError::Server {
                status: resp.status().as_u16(),
                code: "logout_failed".into(),
                message: resp.text().await.unwrap_or_default(),
                current_revision: None,
            })
        }
    }

    // -------------------------------------------------------------------------
    // Blobs
    // -------------------------------------------------------------------------

    pub async fn put_blob(
        &self,
        kind: &str,
        expected_revision: i64,
        manifest: &Value,
        ciphertext: &[u8],
    ) -> Result<PutBlobResponse, SyncError> {
        let token = self.token.as_ref().ok_or(SyncError::NotLoggedIn)?;
        let body = json!({
            "expected_revision": expected_revision,
            "manifest": manifest,
            "ciphertext": B64.encode(ciphertext),
        });
        let resp = self
            .http
            .put(self.url(&format!("/v1/blobs/{kind}")))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?;
        Self::handle(resp).await
    }

    pub async fn get_latest(&self, kind: &str) -> Result<Option<BlobResponse>, SyncError> {
        let token = self.token.as_ref().ok_or(SyncError::NotLoggedIn)?;
        let resp = self
            .http
            .get(self.url(&format!("/v1/blobs/{kind}/latest")))
            .bearer_auth(token)
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let v: BlobResponse = Self::handle(resp).await?;
        Ok(Some(v))
    }

    // -------------------------------------------------------------------------
    // Objects
    // -------------------------------------------------------------------------

    pub async fn put_object(
        &self,
        object_id: &str,
        req: &PutObjectRequest,
    ) -> Result<PutObjectResponse, SyncError> {
        let token = self.token.as_ref().ok_or(SyncError::NotLoggedIn)?;
        let resp = self
            .http
            .put(self.url(&format!("/v1/objects/{object_id}")))
            .bearer_auth(token)
            .json(req)
            .send()
            .await?;
        Self::handle(resp).await
    }

    pub async fn list_objects(
        &self,
        include_deleted: bool,
    ) -> Result<Vec<ObjectSummary>, SyncError> {
        let token = self.token.as_ref().ok_or(SyncError::NotLoggedIn)?;
        let resp = self
            .http
            .get(self.url(&format!("/v1/objects?include_deleted={include_deleted}")))
            .bearer_auth(token)
            .send()
            .await?;
        Self::handle(resp).await
    }

    pub async fn get_object_latest(
        &self,
        object_id: &str,
    ) -> Result<Option<ObjectResponse>, SyncError> {
        let token = self.token.as_ref().ok_or(SyncError::NotLoggedIn)?;
        let resp = self
            .http
            .get(self.url(&format!("/v1/objects/{object_id}/latest")))
            .bearer_auth(token)
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let v: ObjectResponse = Self::handle(resp).await?;
        Ok(Some(v))
    }
}

// -----------------------------------------------------------------------------
// DTOs
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct RegisterRequest {
    pub email: String,
    pub auth_hash_client: String,
    pub kdf_salt_auth: String,
    pub kdf_params_auth: KdfParams,
    pub kdf_salt_kek: String,
    pub kdf_params_kek: KdfParams,
    pub wrapped_dek: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_hash_client: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_salt_recovery_auth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_params_recovery_auth: Option<KdfParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_salt_recovery_kek: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_params_recovery_kek: Option<KdfParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_wrapped_dek: Option<String>,
    pub device_name: String,
    pub invite_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthResponse {
    pub user_id: String,
    pub device_id: String,
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChallengeResponse {
    pub kdf_salt_auth: String,
    pub kdf_params_auth: KdfParams,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponse {
    pub user_id: String,
    pub device_id: String,
    pub token: String,
    pub wrapped_dek: String,
    pub kdf_salt_kek: String,
    pub kdf_params_kek: KdfParams,
}

#[derive(Debug, Deserialize)]
pub struct RecoveryChallengeResponse {
    pub kdf_salt_recovery_auth: String,
    pub kdf_params_recovery_auth: KdfParams,
    pub kdf_salt_recovery_kek: String,
    pub kdf_params_recovery_kek: KdfParams,
    pub recovery_wrapped_dek: String,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct PutBlobResponse {
    pub revision: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlobResponse {
    pub revision: i64,
    pub device_id: String,
    pub created_at: String,
    pub manifest: Value,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PutObjectRequest {
    pub schema_version: u32,
    pub object_kind: String,
    pub object_version: u64,
    pub base_server_revision: Option<u64>,
    pub payload_hash: String,
    pub payload_size: u64,
    pub updated_at: String,
    pub updated_by: ObjectActor,
    pub deleted: bool,
    pub redaction: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjectActor {
    pub actor_type: String,
    pub actor_id: String,
    pub device_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PutObjectResponse {
    pub object_id: String,
    pub object_kind: String,
    pub object_version: u64,
    pub server_revision: u64,
    pub received_at: String,
    pub manifest: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ObjectSummary {
    pub object_id: String,
    pub object_kind: String,
    pub schema_version: u32,
    pub object_version: u64,
    pub server_revision: u64,
    pub deleted: bool,
    pub manifest: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ObjectResponse {
    pub object_id: String,
    pub object_kind: String,
    pub object_version: u64,
    pub server_revision: u64,
    pub deleted: bool,
    pub manifest: Value,
    pub ciphertext: String,
}
