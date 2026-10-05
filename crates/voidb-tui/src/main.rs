// mod app; // Old message-based architecture (backed up as app_old.rs.bak)
mod app_v4; // New v4.0 pure router architecture
mod components;
mod connection_manager_app;
mod plugins; // Built-in plugins
mod profile_forms;
mod theme;

use anyhow::Result;

// Use v4 App for now (can switch back with `use app::App;`)
use app_v4::App;
use connection_manager_app::ConnectionManagerApp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchMode {
    Shell,
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

    // The native Connection Manager can render locked profile metadata without
    // decrypting credentials. The legacy shell still requires its connection
    // list to be decrypted before startup.
    let config_path = voidb_core::config::AppConfig::config_path()?;
    let config = match launch_mode {
        LaunchMode::ConnectionManager => {
            voidb_core::config::AppConfig::load_raw_from_path(&config_path)?
        }
        LaunchMode::Shell => voidb_core::config::AppConfig::load()?,
    };

    tracing::info!(
        "Loaded configuration from {:?}",
        voidb_core::config::AppConfig::config_path()
    );

    tracing::info!("Loaded {} connection(s)", config.connections.len());

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

    // Run the selected terminal app.
    let result = match launch_mode {
        LaunchMode::Shell => {
            let mut app = App::new(config)?;
            app.run(&mut terminal).await
        }
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
            "Usage: voidb [--connection-manager | --shell]\n\nDefault: native Connection Manager"
        );
        std::process::exit(0);
    }
    launch_mode_from_args(args)
}

fn launch_mode_from_args(args: impl IntoIterator<Item = String>) -> Result<LaunchMode> {
    let args = args.into_iter().collect::<Vec<_>>();
    match args.as_slice() {
        [] => Ok(LaunchMode::ConnectionManager),
        [arg] if matches!(arg.as_str(), "--connection-manager" | "connection-manager") => {
            Ok(LaunchMode::ConnectionManager)
        }
        [arg] if matches!(arg.as_str(), "--shell" | "shell") => Ok(LaunchMode::Shell),
        [other] => anyhow::bail!(
            "Unknown argument '{other}'. Usage: voidb [--connection-manager | --shell]"
        ),
        _ => anyhow::bail!("Usage: voidb [--connection-manager | --shell]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_launches_native_connection_manager() {
        assert_eq!(
            launch_mode_from_args(Vec::<String>::new()).expect("default mode"),
            LaunchMode::ConnectionManager
        );
    }

    #[test]
    fn explicit_connection_manager_and_shell_modes_are_supported() {
        assert_eq!(
            launch_mode_from_args(vec!["--connection-manager".into()]).expect("manager mode"),
            LaunchMode::ConnectionManager
        );
        assert_eq!(
            launch_mode_from_args(vec!["--shell".into()]).expect("shell mode"),
            LaunchMode::Shell
        );
    }
}
