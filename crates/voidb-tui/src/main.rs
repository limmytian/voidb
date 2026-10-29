mod connection_manager_app;
mod plugin_onboarding;
mod profile_forms;

use anyhow::Result;

use connection_manager_app::ConnectionManagerApp;

/// The legacy embedded-shell launch mode was removed in v0.3.6; the native
/// Connection Manager is the only terminal application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchMode {
    ConnectionManager,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging to file (avoids polluting terminal)
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("voidb")
        .join("logs");
    std::fs::create_dir_all(&log_dir)?;

    let log_file = std::fs::File::create(log_dir.join("voidb.log"))?;
    tracing_subscriber::fmt()
        .with_writer(log_file)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let launch_mode = parse_launch_mode()?;

    tracing::info!("VoidB starting up");

    // The native Connection Manager renders locked profile metadata without
    // decrypting credentials, so the raw (still-encrypted) config suffices.
    let config_path = voidb_core::config::AppConfig::config_path()?;
    let config = voidb_core::config::AppConfig::load_raw_from_path(&config_path)?;

    tracing::info!(
        "Loaded configuration from {:?}",
        voidb_core::config::AppConfig::config_path()
    );

    tracing::info!("Loaded {} connection(s)", config.connections.len());

    plugin_onboarding::offer_plugin_installation();

    // Initialize terminal
    let mut terminal = ratatui::init();

    // Enable mouse capture, bracketed paste, and keyboard enhancement protocol
    crossterm::execute!(
        std::io::stdout(),
        crossterm::event::EnableMouseCapture,
        crossterm::event::EnableBracketedPaste,
    )?;

    // Enable Kitty keyboard protocol if supported by the terminal.
    // DISAMBIGUATE_ESCAPE_CODES: encodes modifier+special keys (Shift+Enter etc.)
    //   as CSI-u sequences without affecting normal text input or IME composition.
    // REPORT_EVENT_TYPES: enables Press/Release/Repeat distinction.
    // NOTE: REPORT_ALL_KEYS_AS_ESCAPE_CODES is intentionally NOT used because it
    //   converts ALL input (including IME-composed CJK characters) into escape
    //   sequences, which breaks Chinese/Japanese/Korean input on macOS.
    let keyboard_enhancement_enabled =
        if crossterm::terminal::supports_keyboard_enhancement().unwrap_or(false) {
            crossterm::execute!(
                std::io::stdout(),
                crossterm::event::PushKeyboardEnhancementFlags(
                    crossterm::event::KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
                        | crossterm::event::KeyboardEnhancementFlags::REPORT_EVENT_TYPES,
                )
            )?;
            true
        } else {
            false
        };

    // Run the native terminal app.
    let result = match launch_mode {
        LaunchMode::ConnectionManager => {
            let mut app = ConnectionManagerApp::new(config)?;
            app.run(&mut terminal).await
        }
    };

    // Restore terminal
    if keyboard_enhancement_enabled {
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::event::PopKeyboardEnhancementFlags,
        );
    }
    crossterm::execute!(
        std::io::stdout(),
        crossterm::event::DisableBracketedPaste,
        crossterm::event::DisableMouseCapture,
    )?;
    ratatui::restore();

    tracing::info!("VoidB shut down");

    result
}

fn parse_launch_mode() -> Result<LaunchMode> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        println!(
            "Usage: voidb [--connection-manager]\n\nDefault: native Connection Manager\n(deprecated: --shell is accepted and launches the native Connection Manager)"
        );
        std::process::exit(0);
    }
    Ok(launch_mode_from_args(args))
}

/// Resolve the launch mode from argv. `--shell` is retained as a deprecated
/// alias so existing scripts keep working; it launches the native manager.
fn launch_mode_from_args(args: impl IntoIterator<Item = String>) -> LaunchMode {
    let args = args.into_iter().collect::<Vec<_>>();
    match args.as_slice() {
        [arg] if matches!(arg.as_str(), "--shell" | "shell") => {
            eprintln!(
                "warning: the embedded shell mode was removed in v0.3.6; \
                 launching the native Connection Manager instead"
            );
            LaunchMode::ConnectionManager
        }
        _ => LaunchMode::ConnectionManager,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_launches_native_connection_manager() {
        assert_eq!(
            launch_mode_from_args(Vec::<String>::new()),
            LaunchMode::ConnectionManager
        );
    }

    #[test]
    fn explicit_connection_manager_flag_launches_the_manager() {
        assert_eq!(
            launch_mode_from_args(vec!["--connection-manager".into()]),
            LaunchMode::ConnectionManager
        );
    }

    #[test]
    fn deprecated_shell_flag_still_launches_the_manager() {
        assert_eq!(
            launch_mode_from_args(vec!["--shell".into()]),
            LaunchMode::ConnectionManager
        );
        assert_eq!(
            launch_mode_from_args(vec!["shell".into()]),
            LaunchMode::ConnectionManager
        );
    }
}
