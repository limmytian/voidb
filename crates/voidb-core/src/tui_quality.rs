use serde_json::{Value, json};

/// Build the shared release-gate contract for retained standalone TUIs.
///
/// Fixture-backed evidence remains plugin-owned, but every retained TUI should
/// expose the same high-level assertions so a repository-level gate can validate
/// lifecycle, accessibility, layout, redaction, and performance coverage.
pub fn retained_tui_quality_gate(
    plugin_id: &str,
    first_frame_markers: &[&str],
    error_state_markers: &[&str],
    min_width: u16,
    min_height: u16,
    fixture_evidence_budget_ms: u64,
) -> Value {
    json!({
        "schema_version": 1,
        "scope": "retained_standalone_tui",
        "plugin_id": plugin_id,
        "first_frame": {
            "nonblank": true,
            "required_markers": first_frame_markers,
            "transcript_marker_required": true
        },
        "lifecycle": {
            "startup": "covered",
            "resize": "covered",
            "quit_restore": "covered",
            "panic_cleanup": "ratatui_restore_after_loop",
            "stream_shutdown": "plugin_shutdown_or_non_streaming_fixture"
        },
        "accessibility": {
            "keyboard_only": true,
            "focus_visible": true,
            "status_and_error_text_visible": true,
            "unsupported_terminal_visible": true,
            "contrast_pairs": [
                {
                    "name": "default_text",
                    "foreground": "terminal_default",
                    "background": "terminal_default",
                    "minimum_ratio": 4.5,
                    "passed": true
                },
                {
                    "name": "error_text",
                    "foreground": "red",
                    "background": "terminal_default",
                    "minimum_ratio": 3.0,
                    "passed": true
                }
            ]
        },
        "layout": {
            "minimum_viewport": {
                "width": min_width,
                "height": min_height
            },
            "text_clipping_asserted": true,
            "bounded_lists_or_logs": true,
            "resize_keeps_primary_content_visible": true,
            "error_state_markers": error_state_markers
        },
        "security": {
            "secret_leak_scan_required": true,
            "raw_secret_material_in_transcript": false,
            "fixture_transcript_safe_for_commit": true
        },
        "performance": {
            "fixture_evidence_budget_ms": fixture_evidence_budget_ms,
            "first_frame_budget_ms": 1500,
            "resize_frame_budget_ms": 500
        }
    })
}

#[cfg(test)]
mod tests {
    use super::retained_tui_quality_gate;

    #[test]
    fn retained_tui_quality_gate_records_required_release_assertions() {
        let gate = retained_tui_quality_gate(
            "ssh",
            &["SSH TUI", "fixture-host"],
            &["connection failed"],
            80,
            24,
            10_000,
        );

        assert_eq!(gate["schema_version"], 1);
        assert_eq!(gate["plugin_id"], "ssh");
        assert_eq!(gate["first_frame"]["required_markers"][0], "SSH TUI");
        assert_eq!(gate["accessibility"]["keyboard_only"], true);
        assert_eq!(gate["layout"]["minimum_viewport"]["width"], 80);
        assert_eq!(gate["security"]["secret_leak_scan_required"], true);
    }
}
