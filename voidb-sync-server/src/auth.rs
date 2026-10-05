//! Authentication primitives: Argon2id verifier + bearer tokens.
//!
//! Threat model reminder:
//!   - Clients never send the plaintext password. They send
//!     `auth_hash_client = Argon2id(password, kdf_salt_auth)`, using parameters
//!     that the server returned on `/v1/auth/challenge`.
//!   - The server re-hashes `auth_hash_client` with a per-user `srv_salt` and
//!     compares constant-time against the stored value.
//!   - Bearer tokens are 32 random bytes. Only `sha256(token)` is persisted.
//!
//! Author: Limmy

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::ApiError;

/// Hash length for `auth_hash_stored`.
const AUTH_HASH_LEN: usize = 32;

/// Server-side Argon2 parameters (reasonably cheap — the input is already
/// a 32-byte client-derived hash, not a low-entropy password).
fn server_params() -> Params {
    Params::new(4 * 1024, 3, 1, Some(AUTH_HASH_LEN))
        .expect("static argon2 params are valid")
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

/// Compute the stored verifier from the client-supplied auth hash.
pub fn hash_auth(auth_hash_client: &[u8], srv_salt: &[u8]) -> Result<[u8; AUTH_HASH_LEN], ApiError> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, server_params());
    let mut out = [0u8; AUTH_HASH_LEN];
    argon
        .hash_password_into(auth_hash_client, srv_salt, &mut out)
        .map_err(|e| ApiError::internal(format!("argon2: {e}")))?;
    Ok(out)
}

/// Constant-time comparison of stored vs recomputed verifier.
pub fn verify_auth(stored: &[u8], recomputed: &[u8]) -> bool {
    stored.ct_eq(recomputed).into()
}

/// Issue a new bearer token. Returns (plaintext_token_b64, sha256_hash).
pub fn new_token() -> (String, [u8; 32]) {
    let raw: [u8; 32] = random_bytes();
    let token_b64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, raw);
    let mut hasher = Sha256::new();
    hasher.update(token_b64.as_bytes());
    let digest = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    (token_b64, hash)
}

/// Hash a presented bearer token for DB lookup.
pub fn hash_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}
