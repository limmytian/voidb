//! Optional first-launch plugin installation before entering the terminal UI.

use std::io::{IsTerminal, Write};
use std::path::Path;

pub fn offer_plugin_installation() {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return;
    }
    let Some(data_dir) = dirs::data_local_dir() else {
        return;
    };
    let marker = data_dir.join("voidb/plugin-onboarding-v1");
    let discovery = voidb_core::process_plugin::discover_process_plugins();
    let has_plugins = ["mysql", "postgres", "sqlite", "redis", "ssh", "duckdb"]
        .iter()
        .all(|id| {
            discovery.effective_candidate(id).is_some_and(|candidate| {
                voidb_core::process_plugin::verify_plugin_binary_integrity(candidate).is_ok()
            })
        });
    if marker.exists() || has_plugins {
        return;
    }

    println!("VoidB plugins are optional and installed in your user plugin directory.");
    println!("Recommended: MySQL, PostgreSQL, SQLite, Redis, SSH and DuckDB.");
    print!("Download and install these plugins now? [y/N] ");
    if std::io::stdout().flush().is_err() {
        return;
    }
    let mut answer = String::new();
    match std::io::stdin().read_line(&mut answer) {
        Ok(0) | Err(_) => return,
        Ok(_) => {}
    }
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        println!("Installing plugins; this may take a moment...");
        if let Err(error) = install_recommended_plugins() {
            println!("Plugin installation did not complete: {error}");
            println!("Retry later with: voidb-cli plugin install-default");
            return;
        }
        println!("Recommended plugins installed.");
    } else {
        println!("Skipped. Install later with: voidb-cli plugin install-default");
    }
    // A failed install or interrupted prompt must remain retryable next launch.
    if let Err(error) = remember_choice(&marker) {
        tracing::warn!("Could not persist plugin onboarding choice: {error}");
    }
}

fn remember_choice(marker: &Path) -> std::io::Result<()> {
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(marker, "acknowledged\n")
}

fn install_recommended_plugins() -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let name = if cfg!(windows) {
        "voidb-cli.exe"
    } else {
        "voidb-cli"
    };
    let cli = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Missing executable directory"))?
        .join(name);
    let output = std::process::Command::new(cli)
        .args(["plugin", "install-default", "--format", "json"])
        .env_remove(voidb_core::VOIDB_MASTER_PASSWORD_ENV)
        .stdin(std::process::Stdio::null())
        .output()?;
    if !output.status.success() {
        anyhow::bail!("Plugin installer exited with {}", output.status);
    }
    let response: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    validate_install_response(&response)
}

fn validate_install_response(response: &serde_json::Value) -> anyhow::Result<()> {
    if response.get("ok").and_then(|value| value.as_bool()) != Some(true) {
        anyhow::bail!("Plugin installer reported an error");
    }
    let results = response
        .pointer("/data/results")
        .and_then(|value| value.as_array())
        .ok_or_else(|| anyhow::anyhow!("Missing plugin installation results"))?;
    if results.len() != 6
        || results.iter().any(|item| {
            !matches!(
                item.get("status").and_then(|value| value.as_str()),
                Some("installed" | "already_installed")
            )
        })
    {
        anyhow::bail!(
            "Some recommended plugins could not be installed; use voidb-cli plugin install-default for details"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn zero_exit_status_with_partial_install_failure_is_not_success() {
        let response = json!({"ok": true, "data": {"results": [
            {"status": "installed"}, {"status": "installed"},
            {"status": "already_installed"}, {"status": "installed"},
            {"status": "installed"}, {"status": "failed"}
        ]}});
        assert!(validate_install_response(&response).is_err());
    }

    #[test]
    fn complete_install_accepts_existing_plugins_but_not_empty_results() {
        let response = json!({"ok": true, "data": {"results":
            vec![json!({"status": "already_installed"}); 6]}});
        assert!(validate_install_response(&response).is_ok());
        assert!(validate_install_response(&json!({"ok": true, "data": {"results": []}})).is_err());
    }
}
