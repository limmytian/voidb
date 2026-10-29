//! End-to-end integration tests that drive the real `voidb-cli` binary.
//!
//! These complement the in-crate unit tests by exercising actual process
//! boundaries: argument parsing, plugin discovery through the
//! `VOIDB_PLUGIN_PATH` development root, and fail-closed behavior for unknown
//! or invalid plugins.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

/// Run the built `voidb-cli` binary with the given arguments.
fn run_cli(args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_voidb-cli"));
    command.args(args);
    for (key, value) in extra_env {
        command.env(key, value);
    }
    command.output().expect("spawn voidb-cli")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Temporary directory removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "voidb-cli-integration-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&command, fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    let manifest = format!(
        r#"
id = "{id}"
name = "{id}"
version = "0.1.0"
protocol_version = "1"
description = "Integration fixture plugin."

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
        voidb_core::process_plugin::current_platform()
    );
    fs::write(plugin_dir.join("plugin.toml"), manifest).expect("write manifest");
}

#[test]
fn version_flag_reports_the_binary_version() {
    let output = run_cli(&["--version"], &[]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(!out.trim().is_empty(), "version output must not be empty");
    assert!(
        out.contains(env!("CARGO_PKG_VERSION")),
        "version output should contain the workspace version, got: {out}"
    );
}

#[test]
fn plugin_list_discovers_fixture_from_development_root() {
    let root = TempDir::new("dev-root");
    write_fixture_plugin(&root.0, "integration-fixture");

    let output = run_cli(
        &["plugin", "list"],
        &[("VOIDB_PLUGIN_PATH", root.0.to_str().expect("utf8 path"))],
    );

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains("integration-fixture"),
        "plugin list should surface the development-root fixture, got: {out}"
    );
}

#[test]
fn plugin_list_hides_invalid_manifests_unless_requested() {
    let root = TempDir::new("invalid-root");
    write_fixture_plugin(&root.0, "valid-fixture");
    // A second directory whose manifest is malformed must be isolated, not fatal.
    let broken = root.0.join("broken-fixture");
    fs::create_dir_all(&broken).expect("create broken plugin dir");
    fs::write(broken.join("plugin.toml"), "not = valid [toml").expect("write broken manifest");

    let env = [("VOIDB_PLUGIN_PATH", root.0.to_str().expect("utf8 path"))];

    let default_run = run_cli(&["plugin", "list"], &env);
    assert!(default_run.status.success(), "stderr: {}", stderr(&default_run));
    let default_out = stdout(&default_run);
    assert!(default_out.contains("valid-fixture"), "got: {default_out}");
    assert!(
        !default_out.contains("broken-fixture"),
        "invalid candidates must be hidden by default, got: {default_out}"
    );

    let include_invalid = run_cli(&["plugin", "list", "--include-invalid"], &env);
    assert!(
        include_invalid.status.success(),
        "stderr: {}",
        stderr(&include_invalid)
    );
    assert!(
        stdout(&include_invalid).contains("broken-fixture"),
        "got: {}",
        stdout(&include_invalid)
    );
}

#[test]
fn describing_an_unknown_plugin_fails_closed() {
    let output = run_cli(&["plugin", "describe", "definitely-not-a-plugin"], &[]);

    // The CLI's contract is a machine-readable error envelope rather than a
    // non-zero exit or a panic: agents parse {"ok": false, "error": {...}}.
    let out = stdout(&output);
    assert!(
        !out.contains("panic"),
        "failure path must be a clean envelope, not a panic; got: {out}"
    );
    assert!(
        out.contains("\"ok\": false"),
        "unknown plugin must produce an error envelope, got: {out}"
    );
    assert!(
        out.contains("validation.plugin_not_found"),
        "expected validation.plugin_not_found, got: {out}"
    );
}
