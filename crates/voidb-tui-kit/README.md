# voidb-tui-kit

Shared TUI building blocks for VoidB standalone process plugins.

The plugin-owned TUI guide's template helpers (`safe_error_summary`,
`window_start`, `centered_rect`), the bounded-line log buffer, and the
startup auto-load rule were duplicated verbatim across the official plugin
repositories and drifted occasionally. This crate is the single home for the
proven-duplicated, plugin-agnostic pieces so a fix or improvement lands once
and every adopting plugin inherits it on its next git-revision bump.

Ownership boundary:

- **Kit-owned**: pure functions and small generic primitives that carry no
  plugin semantics (layout math, error summarization, bounded buffers) and
  the canonical statements of shared flows (startup auto-load).
- **Plugin-owned**: every view, keybinding, resource model, and any local
  divergence from a kit helper that a plugin deliberately needs. A plugin may
  keep a local override; drift from the kit then becomes a reviewable
  decision instead of an accident.

Versioning: the kit follows the core workspace version but is consumed by
plugins through a git revision pin (`voidb-tui-kit = { git = "...", rev =
"..." }`), exactly like `voidb-process-plugin-sdk` and `voidb-core`, so
adopting a kit change is an explicit, reviewable dependency bump per plugin.
See `docs/adr-tui-shared-kit.md` for the full decision record.
