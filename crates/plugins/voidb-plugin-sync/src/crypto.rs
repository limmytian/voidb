//! Client-side key derivation + envelope encryption.
//!
//! Layered scheme (matches [`voidb-sync-server`'s security model]):
//!
//! ```text
//! password + kdf_salt_auth --Argon2id--> auth_hash_client  (sent to server)
//! password + kdf_salt_kek  --Argon2id--> KEK
//! KEK + random nonce       --AES-GCM--->  wrapped_dek = nonce || ct(dek)
//! DEK + random nonce       --AES-GCM---> ciphertext of the user bundle
//! ```
//!
//! The server stores `wrapped_dek` opaquely and returns it on login; the
//! client needs the password to unwrap it.
//!
//! Author: Limmy

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::SyncError;

const RECOVERY_CODE_BYTES: usize = 32;

/// Argon2 parameter set (kept in sync with the server-issued value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub out_len: u32,
}

impl KdfParams {
    /// Reasonable defaults for both auth and KEK derivation (4 MiB, t=3, p=1).
    pub fn default_client() -> Self {
        Self {
            m_cost: 4096,
            t_cost: 3,
            p_cost: 1,
            out_len: 32,
        }
    }

    fn argon(&self) -> Result<Argon2<'static>, SyncError> {
        let params = Params::new(
            self.m_cost,
            self.t_cost,
            self.p_cost,
            Some(self.out_len as usize),
        )
        .map_err(|e| SyncError::Crypto(format!("invalid argon2 params: {e}")))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

/// Generate a high-entropy recovery code that can re-wrap the DEK if the user
/// forgets their password. The server never stores this value.
pub fn generate_recovery_code() -> String {
    format!(
        "vbrec-{}",
        B64_URL.encode(random_bytes(RECOVERY_CODE_BYTES))
    )
}

fn normalize_recovery_code(code: &str) -> String {
    code.trim().to_string()
}

/// Derive a fixed-size key from a password using Argon2id.
pub fn derive(password: &str, salt: &[u8], params: &KdfParams) -> Result<Vec<u8>, SyncError> {
    let mut out = vec![0u8; params.out_len as usize];
    params
        .argon()?
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| SyncError::Crypto(format!("argon2: {e}")))?;
    Ok(out)
}

/// Derive recovery-code material with the same hardened KDF as passwords.
pub fn derive_recovery_code(
    recovery_code: &str,
    salt: &[u8],
    params: &KdfParams,
) -> Result<Vec<u8>, SyncError> {
    derive(&normalize_recovery_code(recovery_code), salt, params)
}

/// Wrap a DEK under a KEK. Output layout: `nonce (12) || ciphertext`.
pub fn wrap_dek(kek: &[u8], dek: &[u8]) -> Result<Vec<u8>, SyncError> {
    if kek.len() != 32 {
        return Err(SyncError::Crypto("kek must be 32 bytes".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(kek)
        .map_err(|e| SyncError::Crypto(format!("cipher init: {e}")))?;
    let nonce_bytes = random_bytes(12);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, dek)
        .map_err(|e| SyncError::Crypto(format!("encrypt: {e}")))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap a DEK that was produced by [`wrap_dek`].
pub fn unwrap_dek(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, SyncError> {
    if kek.len() != 32 {
        return Err(SyncError::Crypto("kek must be 32 bytes".into()));
    }
    if wrapped.len() < 12 + 16 {
        return Err(SyncError::Crypto("wrapped_dek too short".into()));
    }
    let (nonce_bytes, ct) = wrapped.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(kek)
        .map_err(|e| SyncError::Crypto(format!("cipher init: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| SyncError::Crypto(format!("decrypt (wrong password?): {e}")))
}

pub fn wrap_dek_with_recovery_code(
    recovery_code: &str,
    salt: &[u8],
    params: &KdfParams,
    dek: &[u8],
) -> Result<Vec<u8>, SyncError> {
    let recovery_kek = derive_recovery_code(recovery_code, salt, params)?;
    wrap_dek(&recovery_kek, dek)
}

pub fn unwrap_dek_with_recovery_code(
    recovery_code: &str,
    salt: &[u8],
    params: &KdfParams,
    wrapped: &[u8],
) -> Result<Vec<u8>, SyncError> {
    let recovery_kek = derive_recovery_code(recovery_code, salt, params)?;
    unwrap_dek(&recovery_kek, wrapped)
}

/// Encrypt a bundle payload with the DEK. Output layout: `nonce || ct`.
pub fn encrypt_bundle(dek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SyncError> {
    if dek.len() != 32 {
        return Err(SyncError::Crypto("dek must be 32 bytes".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(dek)
        .map_err(|e| SyncError::Crypto(format!("cipher init: {e}")))?;
    let nonce_bytes = random_bytes(12);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SyncError::Crypto(format!("encrypt: {e}")))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`encrypt_bundle`].
pub fn decrypt_bundle(dek: &[u8], envelope: &[u8]) -> Result<Vec<u8>, SyncError> {
    if dek.len() != 32 {
        return Err(SyncError::Crypto("dek must be 32 bytes".into()));
    }
    if envelope.len() < 12 + 16 {
        return Err(SyncError::Crypto("bundle too short".into()));
    }
    let (nonce_bytes, ct) = envelope.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(dek)
        .map_err(|e| SyncError::Crypto(format!("cipher init: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| SyncError::Crypto(format!("decrypt: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_roundtrip() {
        let kek = random_bytes(32);
        let dek = random_bytes(32);
        let wrapped = wrap_dek(&kek, &dek).unwrap();
        let unwrapped = unwrap_dek(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn bundle_roundtrip() {
        let dek = random_bytes(32);
        let msg = b"hello world, this is a secret payload";
        let envelope = encrypt_bundle(&dek, msg).unwrap();
        let back = decrypt_bundle(&dek, &envelope).unwrap();
        assert_eq!(&back[..], &msg[..]);
    }

    #[test]
    fn tampered_bundle_fails_closed() {
        let dek = random_bytes(32);
        let mut envelope = encrypt_bundle(&dek, b"authenticated secret payload").unwrap();
        let final_byte = envelope.last_mut().expect("encrypted payload");
        *final_byte ^= 0x01;
        assert!(decrypt_bundle(&dek, &envelope).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let kek = random_bytes(32);
        let wrong = random_bytes(32);
        let dek = random_bytes(32);
        let wrapped = wrap_dek(&kek, &dek).unwrap();
        assert!(unwrap_dek(&wrong, &wrapped).is_err());
    }

    #[test]
    fn recovery_code_wraps_dek_without_plaintext_leak() {
        let code = generate_recovery_code();
        let wrong_code = generate_recovery_code();
        let params = KdfParams::default_client();
        let salt = random_bytes(16);
        let dek = random_bytes(32);

        assert!(code.starts_with("vbrec-"));
        assert!(!code.contains(char::is_whitespace));

        let wrapped = wrap_dek_with_recovery_code(&code, &salt, &params, &dek).unwrap();
        assert_ne!(wrapped, dek);

        let recovered = unwrap_dek_with_recovery_code(&code, &salt, &params, &wrapped).unwrap();
        assert_eq!(recovered, dek);
        assert!(unwrap_dek_with_recovery_code(&wrong_code, &salt, &params, &wrapped).is_err());
    }
}
