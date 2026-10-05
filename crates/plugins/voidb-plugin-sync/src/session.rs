//! In-memory session secrets.
//!
//! After a successful login the plugin holds:
//!   - the DEK (required to encrypt/decrypt bundles)
//!   - the bearer token (required for every authenticated API call)
//!
//! These never touch disk. Losing the plugin process means you need to log
//! in again. That's the intended trade-off for "password is the only secret
//! the user has to protect".
//!
//! Author: Limmy

#[derive(Clone)]
pub struct Session {
    pub user_id: String,
    pub device_id: String,
    pub token: String,
    pub dek: Vec<u8>,
    pub email: String,
    pub server_url: String,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .field("token", &"<redacted>")
            .field("dek", &format!("<{} bytes>", self.dek.len()))
            .field("email", &self.email)
            .field("server_url", &self.server_url)
            .finish()
    }
}
