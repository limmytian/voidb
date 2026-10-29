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
pub(crate) fn sign_test_candidate(candidate: &ProcessPluginCandidate) {    use crate::plugin_signing::sign_bytes;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_plugin::{
        current_platform, discover_process_plugins_from_roots, ProcessPluginRoot,
        ProcessPluginRootKind,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Temporary directory removed on drop.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "voidb-provenance-{label}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system time")
                    .as_nanos()
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            // Canonicalize so macOS /var and /tmp symlink ancestors do not
            // trip the trusted-ancestry check under test.
            let canonical = fs::canonicalize(&path).expect("canonical temp dir");
            Self(canonical)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Write a minimal but structurally valid plugin package into `root`.
    fn write_fixture_plugin(root: &Path, id: &str) {
        let plugin_dir = root.join(id);
        let schemas = plugin_dir.join("schemas");
        let bin = plugin_dir.join("bin");
        fs::create_dir_all(&schemas).expect("create schemas dir");
        fs::create_dir_all(&bin).expect("create bin dir");

        for schema_name in [
            "profile.schema.json",
            "get-input.schema.json",
            "get-output.schema.json",
            "set-input.schema.json",
            "set-output.schema.json",
        ] {
            fs::write(schemas.join(schema_name), r#"{"type":"object"}"#).expect("write schema");
        }

        let command = bin.join("voidb-plugin-test");
        fs::write(&command, "#!/bin/sh\nexit 0\n").expect("write command");
        make_executable(&command);

        let manifest = format!(
            r#"
id = "{id}"
name = "{id}"
version = "0.1.0"
protocol_version = "1"
description = "Test plugin."

[runtime]
command = "voidb-plugin-test"
args = []
transport = "stdio-jsonrpc"

[connections]
profile_schema = "schemas/profile.schema.json"
secret_classes = ["password"]

[[capabilities]]
id = "get"
description = "Read one key."
input_schema = "schemas/get-input.schema.json"
output_schema = "schemas/get-output.schema.json"
permissions = ["connection.read"]
destructive = false
streaming = false
connection_required = true
required_secret_classes = []
supports_dry_run = false
default_timeout_ms = 10000

[[capabilities]]
id = "set"
description = "Write one key."
input_schema = "schemas/set-input.schema.json"
output_schema = "schemas/set-output.schema.json"
permissions = ["connection.read"]
destructive = true
streaming = false
connection_required = true
required_secret_classes = []
supports_dry_run = true
default_timeout_ms = 10000

[ui]
tui = false

[requirements]
voidb_core = ">=0.1.0"
platforms = ["{}"]
"#,
            current_platform()
        );
        fs::write(plugin_dir.join("plugin.toml"), manifest).expect("write manifest");
    }

    fn make_executable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    fn discovered_candidate(root: &Path, id: &str) -> ProcessPluginCandidate {
        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            root,
            ProcessPluginRootKind::User,
            0,
        )]);
        discovery
            .effective_candidate(id)
            .cloned()
            .expect("effective candidate")
    }

    /// Sign an attacker-controlled payload with the compiled test key.
    fn write_provenance(candidate: &ProcessPluginCandidate, payload: &PluginProvenancePayload) {
        let payload = serde_json::to_string(payload).expect("serialize payload");
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let mut message = PROVENANCE_DOMAIN.to_vec();
        message.extend_from_slice(payload.as_bytes());
        let proof = PluginProvenance {
            key_id: "test-only".into(),
            payload,
            signature: crate::plugin_signing::sign_bytes(&message, &key),
        };
        fs::write(
            candidate.source.plugin_dir.join(PROVENANCE_FILE),
            serde_json::to_vec(&proof).expect("serialize proof"),
        )
        .expect("write provenance");
    }

    #[test]
    fn signed_package_verifies_for_host_target() {
        let temp = TempDir::new("signed-ok");
        write_fixture_plugin(&temp.0, "redis");
        let candidate = discovered_candidate(&temp.0, "redis");
        sign_test_candidate(&candidate);
        assert!(verify_plugin_provenance_for_target(&candidate, HOST_TARGET).is_ok());
    }

    #[test]
    fn missing_provenance_is_rejected() {
        let temp = TempDir::new("missing");
        write_fixture_plugin(&temp.0, "redis");
        let candidate = discovered_candidate(&temp.0, "redis");
        let error = verify_plugin_provenance_for_target(&candidate, HOST_TARGET)
            .expect_err("unsigned package must fail closed");
        assert!(error.to_string().contains("Missing authenticated plugin provenance"));
    }

    #[test]
    fn tampered_payload_file_is_rejected() {
        let temp = TempDir::new("tampered-file");
        write_fixture_plugin(&temp.0, "redis");
        let candidate = discovered_candidate(&temp.0, "redis");
        sign_test_candidate(&candidate);

        let schema = candidate
            .source
            .plugin_dir
            .join("schemas")
            .join("get-input.schema.json");
        fs::write(&schema, r#"{"type":"object","hacked":true}"#).expect("tamper");

        let error = verify_plugin_provenance_for_target(&candidate, HOST_TARGET)
            .expect_err("tampered payload must fail closed");
        assert!(error.to_string().contains("differs from authenticated file digests"));
    }

    #[test]
    fn tampered_binary_is_rejected() {
        let temp = TempDir::new("tampered-binary");
        write_fixture_plugin(&temp.0, "redis");
        let candidate = discovered_candidate(&temp.0, "redis");
        sign_test_candidate(&candidate);

        let binary = candidate.source.plugin_dir.join("bin").join("voidb-plugin-test");
        fs::write(&binary, "#!/bin/sh\nrm -rf /tmp/pwned\n").expect("tamper binary");
        make_executable(&binary);

        assert!(verify_plugin_provenance_for_target(&candidate, HOST_TARGET).is_err());
    }

    #[test]
    fn untrusted_signer_key_id_is_rejected() {
        let temp = TempDir::new("untrusted-key");
        write_fixture_plugin(&temp.0, "redis");
        let candidate = discovered_candidate(&temp.0, "redis");
        sign_test_candidate(&candidate);

        // Keep a valid signature but claim an unknown signer identity.
        let mut envelope: PluginProvenance = serde_json::from_slice(&fs::read(
            candidate.source.plugin_dir.join(PROVENANCE_FILE),
        )
        .expect("read provenance"))
        .expect("parse provenance");
        envelope.key_id = "attacker-2026-01".into();
        fs::write(
            candidate.source.plugin_dir.join(PROVENANCE_FILE),
            serde_json::to_vec(&envelope).expect("serialize"),
        )
        .expect("write provenance");

        let error = verify_plugin_provenance_for_target(&candidate, HOST_TARGET)
            .expect_err("unknown key id must fail closed");
        assert!(error.to_string().contains("Untrusted plugin signer"));
    }

    #[test]
    fn wrong_target_is_rejected() {
        let temp = TempDir::new("wrong-target");
        write_fixture_plugin(&temp.0, "redis");
        let candidate = discovered_candidate(&temp.0, "redis");
        sign_test_candidate(&candidate);

        let error = verify_plugin_provenance_for_target(&candidate, "x86_64-unknown-other")
            .expect_err("foreign target must fail closed");
        assert!(error
            .to_string()
            .contains("does not match discovery or host target"));
    }

    #[test]
    fn malformed_provenance_is_rejected() {
        let temp = TempDir::new("malformed");
        write_fixture_plugin(&temp.0, "redis");
        let candidate = discovered_candidate(&temp.0, "redis");
        fs::write(
            candidate.source.plugin_dir.join(PROVENANCE_FILE),
            b"this is not json",
        )
        .expect("write malformed provenance");

        let error = verify_plugin_provenance_for_target(&candidate, HOST_TARGET)
            .expect_err("malformed proof must fail closed");
        assert!(error.to_string().contains("Malformed plugin provenance"));
    }

    #[test]
    fn oversized_provenance_is_rejected() {
        let temp = TempDir::new("oversized");
        write_fixture_plugin(&temp.0, "redis");
        let candidate = discovered_candidate(&temp.0, "redis");
        fs::write(
            candidate.source.plugin_dir.join(PROVENANCE_FILE),
            vec![b'a'; (MAX_PROOF_BYTES + 1) as usize],
        )
        .expect("write oversized provenance");

        let error = verify_plugin_provenance_for_target(&candidate, HOST_TARGET)
            .expect_err("oversized proof must fail closed");
        assert!(error.to_string().contains("Invalid plugin provenance file"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_provenance_file_is_rejected() {
        let temp = TempDir::new("symlink-proof");
        write_fixture_plugin(&temp.0, "redis");
        let candidate = discovered_candidate(&temp.0, "redis");
        sign_test_candidate(&candidate);

        let real = temp.0.join("real-provenance.json");
        fs::rename(candidate.source.plugin_dir.join(PROVENANCE_FILE), &real)
            .expect("move provenance");
        std::os::unix::fs::symlink(
            &real,
            candidate.source.plugin_dir.join(PROVENANCE_FILE),
        )
        .expect("symlink provenance");

        let error = verify_plugin_provenance_for_target(&candidate, HOST_TARGET)
            .expect_err("symlinked proof must fail closed");
        assert!(error.to_string().contains("Invalid plugin provenance file"));
    }

    #[test]
    fn binary_path_escape_is_rejected() {
        let temp = TempDir::new("path-escape");
        write_fixture_plugin(&temp.0, "redis");
        let candidate = discovered_candidate(&temp.0, "redis");

        let mut files = BTreeMap::new();
        collect_files(
            &candidate.source.plugin_dir,
            &candidate.source.plugin_dir,
            &mut files,
        )
        .expect("collect payload digests");
        let payload = PluginProvenancePayload {
            schema_version: 1,
            plugin_id: candidate.id.clone(),
            version: candidate.version.clone().unwrap(),
            protocol_version: candidate.protocol_version.clone().unwrap(),
            target: HOST_TARGET.into(),
            binary_path: "../outside/voidb-plugin-test".into(),
            files,
        };
        write_provenance(&candidate, &payload);

        let error = verify_plugin_provenance_for_target(&candidate, HOST_TARGET)
            .expect_err("escaping binary path must fail closed");
        assert!(error
            .to_string()
            .contains("Authenticated executable path does not match discovery"));
    }

    #[test]
    fn reject_plugin_path_symlinks_flags_symlinked_ancestors() {
        let temp = TempDir::new("symlink-ancestor");
        let target = temp.0.join("real");
        fs::create_dir_all(&target).expect("create target dir");
        let link = temp.0.join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).expect("symlink dir");

        #[cfg(unix)]
        {
            let error = reject_plugin_path_symlinks(&link.join("child"))
                .expect_err("symlinked ancestor must be rejected");
            assert!(error.to_string().contains("Symlinked plugin metadata path"));
            assert!(reject_plugin_path_symlinks(&target).is_ok());
        }
    }
}
