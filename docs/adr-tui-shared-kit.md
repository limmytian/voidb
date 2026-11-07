# ADR: Shared TUI Kit for Process Plugins

- Status: Accepted (0.4.2, pilot stage)
- Supersedes: none
- Related: [Roadmap 0.4.2 Workstream 4](roadmap-0.4.2.md),
  [Plugin-Owned TUI Development Guide](plugin-owned-tui-development-guide.md),
  [Process Plugin Development Guide](process-plugin-development-guide.md)

## Context

Every official plugin repository ships a standalone TUI built from one
shared template. The template duplicated a set of helpers verbatim —
`safe_error_summary`, `window_start`, `centered_rect`, the bounded-line
buffer, the overlay/plan confirmation flow, and the startup auto-load rule —
so a fix had to be re-applied in 14 repositories, and the copies drifted:
`centered_rect` diverged in one plugin, `safe_error_summary` in three, each
without a recorded reason.

A shared home must be chosen before the 0.4.2 pilot (docker + jenkins) can
migrate. The candidates:

- **A sibling crate next to the SDK in the core repository**
  (`crates/voidb-tui-kit`), consumed by plugins through a git revision pin.
- **Modules inside `voidb-process-plugin-sdk`**, riding the SDK's existing
  dependency edge.
- **A standalone repository**, published like a plugin.

## Decision

1. **A sibling crate in the core repository: `crates/voidb-tui-kit`.**
   Plugins already depend on `voidb-core` and `voidb-process-plugin-sdk`
   through git revision pins of this repository, so a third pinned dependency
   from the same repository adds no new distribution infrastructure, gets the
   same provenance and review path, and keeps the 0.4.2 pilot as small as a
   `Cargo.toml` edit plus import changes.
   Rejected alternatives:
   - *Inside the SDK crate* — would force a `ratatui` dependency onto every
     SDK consumer (including future headless tooling) and couples unrelated
     release cadences: a TUI layout fix would require an SDK version bump.
   - *A standalone repository* — maximizes independence but adds release,
     provenance, and review plumbing for a crate whose only consumers are the
     plugins, and slows the 0.5 full migration for no current benefit.

2. **Ownership boundary: pure primitives in the kit, semantics in plugins.**
   Kit-owned: plugin-agnostic functions and small generic primitives —
   layout math (`window_start`, `centered_rect`), error summarization
   (`safe_error_summary`), bounded streaming buffers (`BoundedLines`). A
   shared flow is admitted only when its contract, not its implementation, is
   the shared asset: the startup auto-load rule is documented in the kit and
   locked by a fixture-mode regression test per plugin rather than wrapped in
   callback plumbing. Plugin-owned: every view, keybinding, resource model,
   and any deliberate local divergence from a kit helper (today: the
   `safe_error_summary` variants in email, postgres, and ssh stay local until
   their owners reconcile them).

3. **Versioning: workspace version, git-revision adoption.** The kit carries
   the core workspace version but is never consumed by a floating branch;
   each plugin pins an exact revision, so adopting a kit change is an
   explicit, reviewable dependency bump per plugin — the same discipline the
   SDK already uses.

4. **Migration order: primitives first, flows later.** 0.4.2 hoists the four
   proven-duplicated primitives and migrates the two pilot plugins (docker,
   jenkins) with their full test suites green. The overlay/plan confirmation
   flow stays plugin-owned for now: generalizing it needs a shared
   state/interaction model that the pilot's regression surface should not
   absorb in one step. The remaining twelve plugins migrate onto the kit in
   0.5, one plugin per change set, tests green per repo.

## Consequences

- A primitive fix lands once; every adopting plugin inherits it on its next
  revision bump, and unadopted plugins keep working unchanged.
- Deliberate divergence is visible: a plugin either uses the kit or carries a
  reviewed local override, instead of silently drifting.
- The core repository gains one small crate with a `ratatui` dependency; the
  SDK remains ratatui-free.
- The per-plugin regression tests for the shared startup auto-load rule
  (fixture mode asserts the initial refresh command is queued before the
  first draw) become the mechanism that locks the 0.4.1 acceptance criterion
  in every adopting plugin, independent of kit code.
