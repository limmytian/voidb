//! Ed25519 Plugin Package Signing and Verification
//!
//! Provides detached signature generation and verification for VoidB plugin
//! distribution archives and package manifests using Ed25519 public-key cryptography.

use crate::error::VoidbError;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const SIGNATURE_SCHEME_ED25519: &str = "ed25519";
pub const SIGNATURE_FILE_EXTENSION: &str = "sig";

/// Result of cryptographic signature verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerificationResult {
    pub valid: bool,
    pub scheme: String,
    pub key_id: Option<String>,
    pub public_key: String,
    pub message: String,
}

/// Sign bytes using an Ed25519 secret key. Returns hex-encoded signature.
pub fn sign_bytes(data: &[u8], signing_key: &SigningKey) -> String {
    let signature = signing_key.sign(data);
    hex::encode(signature.to_bytes())
}

/// Sign a file using an Ed25519 secret key. Returns hex-encoded signature.
pub fn sign_file<P: AsRef<Path>>(path: P, signing_key: &SigningKey) -> Result<String, VoidbError> {
    let bytes = fs::read(path.as_ref())?;
    Ok(sign_bytes(&bytes, signing_key))
}

/// Compute the default detached signature file path: `<path>.sig`.
pub fn default_signature_path<P: AsRef<Path>>(path: P) -> std::path::PathBuf {
    let p = path.as_ref();
    std::path::PathBuf::from(format!("{}.{}", p.display(), SIGNATURE_FILE_EXTENSION))
}

/// Sign a file and write detached signature to `<file>.sig`.
pub fn sign_file_detached<P: AsRef<Path>>(
    path: P,
    signing_key: &SigningKey,
) -> Result<String, VoidbError> {
    let path = path.as_ref();
    let sig_hex = sign_file(path, signing_key)?;
    let sig_path = default_signature_path(path);
    fs::write(&sig_path, &sig_hex)?;
    Ok(sig_hex)
}

/// Verify signature for bytes given an Ed25519 public key (hex-encoded 32 bytes).
pub fn verify_bytes_signature(
    data: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<SignatureVerificationResult, VoidbError> {
    let public_key_bytes = hex::decode(public_key_hex.trim())
        .map_err(|e| VoidbError::Crypto(format!("Invalid public key hex: {e}")))?;
    if public_key_bytes.len() != 32 {
        return Err(VoidbError::Crypto("Public key must be 32 bytes".into()));
    }

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&public_key_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| VoidbError::Crypto(format!("Invalid Ed25519 verifying key: {e}")))?;

    let sig_bytes = hex::decode(signature_hex.trim())
        .map_err(|e| VoidbError::Crypto(format!("Invalid signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(VoidbError::Crypto("Signature must be 64 bytes".into()));
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    match verifying_key.verify_strict(data, &signature) {
        Ok(()) => Ok(SignatureVerificationResult {
            valid: true,
            scheme: SIGNATURE_SCHEME_ED25519.into(),
            key_id: None,
            public_key: public_key_hex.trim().into(),
            message: "Signature verification succeeded".into(),
        }),
        Err(e) => Ok(SignatureVerificationResult {
            valid: false,
            scheme: SIGNATURE_SCHEME_ED25519.into(),
            key_id: None,
            public_key: public_key_hex.trim().into(),
            message: format!("Signature verification failed: {e}"),
        }),
    }
}

/// Verify file signature using an Ed25519 public key.
pub fn verify_file_signature<P: AsRef<Path>>(
    path: P,
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<SignatureVerificationResult, VoidbError> {
    let bytes = fs::read(path.as_ref())?;
    verify_bytes_signature(&bytes, signature_hex, public_key_hex)
}

/// Generate a new random Ed25519 keypair for signing.
pub fn generate_signing_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let (signing_key, verifying_key) = generate_signing_keypair();
        let pub_hex = hex::encode(verifying_key.to_bytes());

        let message = b"voidb plugin payload content for s3 plugin";
        let sig_hex = sign_bytes(message, &signing_key);

        let result = verify_bytes_signature(message, &sig_hex, &pub_hex).expect("verify");
        assert!(result.valid);
        assert_eq!(result.scheme, "ed25519");

        // Verify tampering is rejected
        let mut tampered = message.to_vec();
        tampered.push(b'!');
        let bad_result = verify_bytes_signature(&tampered, &sig_hex, &pub_hex).expect("verify bad");
        assert!(!bad_result.valid);
    }

    #[test]
    fn test_wrong_key_does_not_verify() {
        let (signing_key, _) = generate_signing_keypair();
        let (other_key, other_verifying) = generate_signing_keypair();
        assert_ne!(signing_key.to_bytes(), other_key.to_bytes());

        let message = b"signed by the real publisher";
        let sig_hex = sign_bytes(message, &signing_key);
        let result = verify_bytes_signature(message, &sig_hex, &hex::encode(other_verifying.to_bytes()))
            .expect("verification itself must not error");
        assert!(!result.valid);
    }

    #[test]
    fn test_invalid_public_key_inputs_are_errors() {
        let (signing_key, verifying_key) = generate_signing_keypair();
        let sig_hex = sign_bytes(b"m", &signing_key);
        let pub_hex = hex::encode(verifying_key.to_bytes());

        assert!(verify_bytes_signature(b"m", &sig_hex, "not-hex!").is_err());
        // 31 bytes of valid hex must be rejected by length.
        let short = &pub_hex[..62];
        assert!(verify_bytes_signature(b"m", &sig_hex, short).is_err());
    }

    #[test]
    fn test_invalid_signature_inputs_are_errors() {
        let (_, verifying_key) = generate_signing_keypair();
        let pub_hex = hex::encode(verifying_key.to_bytes());

        assert!(verify_bytes_signature(b"m", "zz-not-hex", &pub_hex).is_err());
        assert!(verify_bytes_signature(b"m", &"a".repeat(63), &pub_hex).is_err());
    }

    #[test]
    fn test_file_signature_roundtrip_and_tamper_detection() {
        let (signing_key, verifying_key) = generate_signing_keypair();
        let pub_hex = hex::encode(verifying_key.to_bytes());
        let dir = std::env::temp_dir().join(format!(
            "voidb-signing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("plugin.tar.zst");
        std::fs::write(&path, b"package payload").expect("write package");

        let sig_hex = sign_file_detached(&path, &signing_key).expect("sign detached");
        assert_eq!(
            default_signature_path(&path),
            dir.join("plugin.tar.zst.sig")
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("plugin.tar.zst.sig")).expect("sig file"),
            sig_hex
        );
        assert!(verify_file_signature(&path, &sig_hex, &pub_hex)
            .expect("verify file")
            .valid);

        std::fs::write(&path, b"package payload TAMPERED").expect("tamper package");
        assert!(
            !verify_file_signature(&path, &sig_hex, &pub_hex)
                .expect("verify tampered file")
                .valid
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn test_generated_keypairs_are_independent() {
        let (key_a, verify_a) = generate_signing_keypair();
        let (key_b, verify_b) = generate_signing_keypair();
        assert_ne!(key_a.to_bytes(), key_b.to_bytes());
        assert_ne!(verify_a.to_bytes(), verify_b.to_bytes());
        // Each key verifies its own message.
        let sig = sign_bytes(b"payload", &key_a);
        assert!(
            verify_bytes_signature(b"payload", &sig, &hex::encode(verify_a.to_bytes()))
                .expect("verify")
                .valid
        );
    }
}
