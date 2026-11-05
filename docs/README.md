# VoidB Documentation

VoidB is a terminal-based database management tool with vim-style keybindings and a native plugin architecture.

## Documentation

- [Architecture](architecture.md) - Router architecture, plugin equality, CLI dispatch, and human/machine operational boundaries
- [Connection Manager TUI](connection-manager-tui.md) - Native configuration surface for saved profiles, credential state, diagnostics, plugin metadata, and CLI guidance
- [Conventions](conventions.md) - Development conventions, code style, error handling, and guidelines
- [Service Layer Design](service-layer-design.md) - Service-layer decisions, invariants, and known pitfalls from the plugin decoupling milestone
- [Technology Stack](tech-stack.md) - Languages, runtime, dependencies, and build tooling inventory
- [0.4.1 Iteration Roadmap](roadmap-0.4.1.md) - Scope, workstreams, sequencing, and definition of done for the 0.4.1 iteration
- [Process Plugin Quickstart](quickstart-process-plugin.md) - Five-minute quickstart for writing stdio-jsonrpc process plugins in multiple languages
- [Process Plugin Development and Certification Guide](process-plugin-development-guide.md) - Specification, cargo-generate template, packaging tooling, and certification checklist
- [Process Plugin Package Management](process-plugin-package-management.md) - Local package inputs, installation layout, and lifecycle boundaries for process plugins
- [Plugin Conformance And Certification](plugin-conformance.md) - Deterministic conformance checks and certification maturity levels for process plugins
- [Security Notes](security.md) - Credential encryption key sources, per-installation secret, legacy-config warnings, and recommended UX surface
- [Master Password UX and Credential Protection State](master-password-ux.md) - CLI/TUI setup, unlock, forget, recovery, and protection-state rules
- [Agent Authorization Broker](agent-authorization-broker.md) - short-lived profile-scoped grants, automatic expiry, and revocation
- [Agent Operator, Migration, and Troubleshooting Guide](agent-operator-guide.md) - copyable adoption, compatibility, authorization, session cleanup, staging-root, TUI threshold, error, upgrade, and rollback workflows
- [Security Release Checklist](security-release-checklist.md) - Release-gate checks for TLS defaults, file permissions, credential warnings, and destructive-operation controls
- [CI Check Tiers](ci-checks.md) - Fast and full validation commands for local development and CI
- [Release Candidate Checklist](release-candidate-checklist.md) - Unified release-candidate gate matrix, manual smoke matrix, and residual-risk notes
- [Agent and TUI Aggregate Release Gate](agent-tui-release-gate.md) - Layered focused, deterministic, full, and live-fixture evidence command
- [Release Packaging](release-packaging.md) - Build matrix, artifact names, feature variants, platform prerequisites, and package-readiness results
- [Capability Core Model](capability-core-model.md) - Profile, runtime instance, and invocation type boundaries for the capability-first migration
- [Plugin Session Capability](plugin-session-capability.md) - Shared session lifecycle contract for reusable plugin-owned runtime state
- [Infrastructure Agent Live-Session Contract](infrastructure-agent-live-session-contract.md) - Bounded discovery, event, resume, control, risk, and audit protocol for infrastructure streams
- [Data and Search Agent Live-Session Contract](data-search-agent-live-session-contract.md) - Scoped cursors, checkpoints, heartbeats, pull timeouts, truncation, backpressure, and planned Redis/MongoDB/Elasticsearch mappings
- [Storage Agent Transfer Contract](storage-agent-transfer-contract.md) - Shared S3/WebDAV transfer IDs, progress, chunking, resume, conflict, cancellation, cleanup, and local-path binding
- [Persistent Agent Session Adoption](persistent-agent-session-adoption.md) - Requirement 85 process-boundary gap, per-plugin semantic session matrix, and delivery slices
- [Unified Agent Authorization Contract](agent-authorization-contract.md) - Requirement 86 frontend-safe grant state, preset semantics, and bundled plugin capability audit
- [Just-in-Time Agent Authorization](jit-agent-authorization.md) - Requirement 87 request, local review, principal isolation, structured scope, immutable revision, and proactive compatibility contract
- [External-Agent Interaction Contract](assist-handoff.md) - Normative external-first matrix for SSH session sharing, infrastructure context sharing, capability-only plugins, and local operation gates
- [Connection Profile CLI Contract](connection-profile-cli.md) - Agent-safe CLI commands for listing, creating, updating, inspecting, validating, and testing saved profiles
- [Capability Discovery and Invocation CLI Contract](capability-cli.md) - Agent-facing plugin discovery, capability discovery, and generic invoke command contract
- [Agent-Friendly Execution Controls](agent-friendly-execution-controls.md) - Timeout, cancellation, pagination, streaming, dry-run, destructive-operation, and exit-code behavior
- [Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md) - Agent/plugin data exposure, credential grant, redaction, and local trust-boundary policy
- [Local Path Authorization Policy](local-path-authorization-policy.md) - Allowed-root grants, canonical path resolution, staging, no-overwrite, bounded scans, redaction, and audit rules for agent-triggered local filesystem access
- [Audit and Structured Error Schema](audit-and-error-schema.md) - Invocation audit fields, stable error categories, timing metadata, and target-system failure reporting
- [Sync Boundary Under The Capability Model](sync-boundary.md) - Rules for syncing profile metadata, credential references, encrypted credential state, and device-local sync data
- [VoidB Sync Architecture](sync-plugin.md) - End-to-end encrypted, opt-in sync plugin and server architecture
- [Object-Level Sync Model](object-level-sync-model.md) - Object IDs, versions, redacted manifests, and device enrollment/recovery boundaries for stable sync
- [Governed Team Profile Sharing](team-profile-sharing.md) - Team-scoped profile collections, import restrictions, local credential re-enrollment, and opaque share metadata
- [Plugin Manifest Schema](plugin-manifest-schema.md) - Process-plugin manifest fields for identity, runtime transport, connection schemas, capabilities, and optional TUI declaration
- [Plugin Package Signing and Verification](plugin-package-signing.md) - Ed25519 signing and verification architecture for distribution plugin packages
- [Plugin Registry Index and Metadata Specification](plugin-registry-index-specification.md) - Schema, generation, and validation for the official plugin registry index
- [Plugin Invocation Transport](plugin-invocation-transport.md) - First stdio JSON-RPC message contract for invocation, streaming, cancellation, timeout, health checks, and structured errors
- [Runtime Plugin Discovery](runtime-plugin-discovery.md) - Installed plugin search paths, manifest validation, on-demand process startup, crash handling, and version compatibility
- [Process Plugin SDK](process-plugin-sdk.md) - Rust SDK primitives, local example packages, and non-Rust SDK feasibility for external process plugins
- [External Process Plugin Workflow](external-plugin-workflow.md) - End-to-end author flow for building, installing, testing, certifying, and invoking external process plugins
- [Plugin Installation Model](plugin-installation-model.md) - Local package installation, manifest ownership, version compatibility, update, disable, and uninstall boundaries
- [Profile Migration](profile-migration.md) - Explicit, non-destructive migration from legacy `ConnectionConfig` entries to capability-first profile records
- [Shared SQL Capability Contract](sql-capability-contract.md) - Canonical SQL query, exec, result, pagination, target-error, and metadata shapes for SQL plugins
- [SQL Agent Parity Matrix](sql-agent-parity.md) - Canonical Agent parity comparison for the PostgreSQL, MySQL, SQLite, and DuckDB surfaces
- [SSH Plugin](ssh-plugin.md) - SSH terminal, SFTP, forwarding, agent capability surface, fixture smoke, and release gate
- [Agent Capability Examples](agent-capability-examples.md) - Concrete schema discovery, invocation, structured error, and repeated runtime instance examples for agents
- [TUI Adapter Boundary](tui-adapter-boundary.md) - Ownership rules for TUI surfaces that consume profiles, capabilities, and plugin services without becoming the core contract
- [Plugin-Owned TUI Development Guide](plugin-owned-tui-development-guide.md) - Cookbook for building standalone plugin TUIs with CLI commands, service-layer usage, terminal lifecycle, tests, and release gates
- [Plugin-Owned TUI Launch Contract](plugin-owned-tui-launch-contract.md) - Command shape, profile/credential handoff, terminal lifecycle, exit-code, and dependency rules for standalone plugin TUIs
- [Standalone TUI UX Acceptance Criteria](standalone-tui-ux-acceptance.md) - Measurable startup, input, accessibility, safety, error recovery, and evidence gates for retained plugin TUIs
- [TUI Interaction Performance Contract](tui-interaction-performance.md) - Real-PTY interaction performance targets for the Connection Manager and retained plugin TUIs
- [TUI CI And Real-Terminal Coverage](tui-terminal-coverage.md) - Automated real-PTY CI gate plus manual real-terminal coverage matrix
- [Live Operations TUI Safety](live-operations-tui-safety.md) - Docker, Kubernetes, and Jenkins stream bounds, cancellation, exec/attach escapes, watch throttling, confirmations, and audit summaries
- [Storage TUI Launch And Rollback](storage-tui-launch-and-rollback.md) - S3 and WebDAV standalone TUI commands, fixture evidence, unsupported terminals, rollback behavior, and CLI/capability equivalents
- [Readiness Documentation Map](readiness.md) - Canonical current documentation and historical evidence boundaries
- [Agent Capability and Experience Matrix](agent-capability-matrix.md) - Generated built-in Agent and plugin experience inventory
- [Changelog](../CHANGELOG.md) - Version history

## Language Policy

All documentation must be written in **English**.
