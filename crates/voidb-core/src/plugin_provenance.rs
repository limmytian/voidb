//! Authenticated plugin payloads anchored in compiled release trust roots.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::VoidbError;
use crate::plugin_signing::verify_bytes_signature;
use crate::process_plugin::{ProcessPluginCandidate, ProcessPluginManifest, digest_file};

pub const PROVENANCE_FILE: &str = "provenance.json";
pub const PROVENANCE_DOMAIN: &[u8] = b"voidb-plugin-provenance-v1\n";
pub const HOST_TARGET: &str = env!("VOIDB_BUILD_TARGET");
pub const OFFICIAL_KEY_ID: &str = "official-2026-10";
pub const OFFICIAL_PUBLIC_KEY: &str =
    "2d00e2e461719c94b77cf0e9d1d49a9cf1c8dbe8f802696b801b432bfcc95ea2";
const MAX_PROOF_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginProvenance {
    pub key_id: String,
    pub payload: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginProvenancePayload {
    pub schema_version: u32,
    pub plugin_id: String,
    pub version: String,
    pub protocol_version: String,
    pub target: String,
    pub binary_path: String,
    pub files: BTreeMap<String, String>,
}

fn denied(message: impl Into<String>) -> VoidbError {
    VoidbError::Security(message.into())
}

/// Authenticate identity and the complete current package before child launch.
pub fn verify_plugin_provenance(candidate: &ProcessPluginCandidate) -> Result<(), VoidbError> {
    verify_plugin_provenance_for_target(candidate, HOST_TARGET)
}

/// Verify distribution assets for a declared target without launching them.
/// Runtime callers must use `verify_plugin_provenance`, which fixes the host target.
pub fn verify_plugin_provenance_for_target(
    candidate: &ProcessPluginCandidate,
    target: &str,
) -> Result<(), VoidbError> {
    verify_with_keys(candidate, target, |key_id| match key_id {
        OFFICIAL_KEY_ID => Some(OFFICIAL_PUBLIC_KEY),
        #[cfg(test)]
        "test-only" => Some(TEST_PUBLIC_KEY),
        _ => None,
    })
}

/// Verify a package with an explicitly supplied publisher policy.
/// Launch gates always use compiled roots through `verify_plugin_provenance`.
pub fn verify_plugin_provenance_with_roots(
    candidate: &ProcessPluginCandidate,
    roots: &[(&str, &str)],
) -> Result<(), VoidbError> {
    verify_plugin_provenance_with_roots_for_target(candidate, roots, HOST_TARGET)
}

/// Verify publisher-policy fixtures or distribution metadata for a declared target.
pub fn verify_plugin_provenance_with_roots_for_target(
    candidate: &ProcessPluginCandidate,
    roots: &[(&str, &str)],
    target: &str,
) -> Result<(), VoidbError> {
    verify_with_keys(candidate, target, |id| {
        roots
            .iter()
            .find(|(key_id, _)| *key_id == id)
            .map(|(_, key)| *key)
    })
}

/// Build a payload for a trusted publisher; this does not authorize execution.
pub fn build_provenance_payload(
    candidate: &ProcessPluginCandidate,
    target: &str,
) -> Result<PluginProvenancePayload, VoidbError> {
    let root = &candidate.source.plugin_dir;
    let mut files = BTreeMap::new();
    collect_files(root, root, &mut files)?;
    let binary = candidate
        .resolved_runtime_command
        .as_ref()
        .ok_or_else(|| denied("Missing publisher executable"))?;
    let binary_path = binary
        .strip_prefix(root)
        .map_err(|_| denied("Publisher executable escapes package"))?
        .to_str()
        .ok_or_else(|| denied("Publisher executable must be UTF-8"))?
        .replace(std::path::MAIN_SEPARATOR, "/");
    Ok(PluginProvenancePayload {
        schema_version: 1,
        plugin_id: candidate.id.clone(),
        version: candidate
            .version
            .clone()
            .ok_or_else(|| denied("Missing publisher version"))?,
        protocol_version: candidate
            .protocol_version
            .clone()
            .ok_or_else(|| denied("Missing publisher protocol"))?,
        target: target.into(),
        binary_path,
        files,
    })
}

fn verify_with_keys<'a>(
    candidate: &ProcessPluginCandidate,
    target: &str,
    key: impl Fn(&str) -> Option<&'a str>,
) -> Result<(), VoidbError> {
    let root = &candidate.source.plugin_dir;
    reject_symlink_ancestors(root)?;
    let proof_path = root.join(PROVENANCE_FILE);
    let metadata = fs::symlink_metadata(&proof_path)
        .map_err(|_| denied("Missing authenticated plugin provenance; install a signed release"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_PROOF_BYTES
    {
        return Err(denied("Invalid plugin provenance file"));
    }
    let envelope: PluginProvenance = serde_json::from_slice(&fs::read(&proof_path)?)
        .map_err(|_| denied("Malformed plugin provenance"))?;
    let public_key = key(&envelope.key_id).ok_or_else(|| denied("Untrusted plugin signer"))?;
    let mut message = PROVENANCE_DOMAIN.to_vec();
    message.extend_from_slice(envelope.payload.as_bytes());
    let verified = verify_bytes_signature(&message, &envelope.signature, public_key)
        .map_err(|_| denied("Invalid plugin provenance signature"))?;
    if !verified.valid {
        return Err(denied("Invalid plugin provenance signature"));
    }
    let payload: PluginProvenancePayload = serde_json::from_str(&envelope.payload)
        .map_err(|_| denied("Malformed authenticated payload"))?;
    let manifest: ProcessPluginManifest =
        toml::from_str(&fs::read_to_string(&candidate.manifest_path)?)
            .map_err(|_| denied("Invalid current plugin manifest"))?;
    if payload.schema_version != 1
        || payload.plugin_id != candidate.id
        || Some(&payload.version) != candidate.version.as_ref()
        || Some(&payload.protocol_version) != candidate.protocol_version.as_ref()
        || payload.target != target
        || candidate.manifest.as_ref() != Some(&manifest)
        || candidate.manifest_path != root.join("plugin.toml")
    {
        return Err(denied(
            "Authenticated plugin identity does not match discovery or host target",
        ));
    }
    if !safe_relative(&payload.binary_path)
        || candidate.resolved_runtime_command.as_ref() != Some(&root.join(&payload.binary_path))
        || !payload.files.contains_key("plugin.toml")
        || !payload.files.contains_key(&payload.binary_path)
    {
        return Err(denied(
            "Authenticated executable path does not match discovery",
        ));
    }
    let mut actual = BTreeMap::new();
    collect_files(root, root, &mut actual)?;
    if payload.files != actual {
        return Err(denied(
            "Plugin payload differs from authenticated file digests",
        ));
    }
    Ok(())
}

fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\\')
        && !value.contains(':')
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

/// Reject existing symlink ancestors before mutating plugin metadata paths.
pub fn reject_plugin_path_symlinks(path: &Path) -> Result<(), VoidbError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(denied("Symlinked plugin metadata path is not trusted"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn reject_symlink_ancestors(path: &Path) -> Result<(), VoidbError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    for ancestor in absolute.ancestors() {
        if fs::symlink_metadata(ancestor)?.file_type().is_symlink() {
            return Err(denied("Symlinked plugin root ancestry is not trusted"));
        }
    }
    Ok(())
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, String>,
) -> Result<(), VoidbError> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(denied("Symlinked plugin payload is not trusted"));
        }
        if metadata.is_dir() {
            collect_files(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| denied("Plugin payload escapes root"))?
                .to_str()
                .ok_or_else(|| denied("Plugin payload path must be UTF-8"))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if relative == PROVENANCE_FILE {
                continue;
            }
            if !safe_relative(&relative) {
                return Err(denied("Invalid payload path"));
            }
            files.insert(
                relative,
                digest_file(&path).map_err(|error| denied(error.to_string()))?,
            );
        } else {
            return Err(denied("Plugin payload contains nonregular files"));
        }
    }
    Ok(())
}

#[cfg(test)]
const TEST_PUBLIC_KEY: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

#[cfg(test)]
pub(crate) fn sign_test_candidate(candidate: &ProcessPluginCandidate) {
    use crate::plugin_signing::sign_bytes;
    let root = &candidate.source.plugin_dir;
    let mut files = BTreeMap::new();
    collect_files(root, root, &mut files).expect("fixture payload");
    let payload = PluginProvenancePayload {
        schema_version: 1,
        plugin_id: candidate.id.clone(),
        version: candidate.version.clone().unwrap(),
        protocol_version: candidate.protocol_version.clone().unwrap(),
        target: HOST_TARGET.into(),
        binary_path: candidate
            .resolved_runtime_command
            .as_ref()
            .unwrap()
            .strip_prefix(root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace(std::path::MAIN_SEPARATOR, "/"),
        files,
    };
    let payload = serde_json::to_string(&payload).unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    assert_eq!(hex::encode(key.verifying_key().to_bytes()), TEST_PUBLIC_KEY);
    let mut message = PROVENANCE_DOMAIN.to_vec();
    message.extend_from_slice(payload.as_bytes());
    let proof = PluginProvenance {
        key_id: "test-only".into(),
        payload,
        signature: sign_bytes(&message, &key),
    };
    fs::write(
        root.join(PROVENANCE_FILE),
        serde_json::to_vec(&proof).unwrap(),
    )
    .unwrap();
}
