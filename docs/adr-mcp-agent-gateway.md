# ADR: MCP Agent Gateway

- Status: Accepted (0.4.1)
- Supersedes: none
- Related: [MCP Server](mcp-server.md),
  [Roadmap 0.4.1 Workstream 3](roadmap-0.4.1.md),
  [JIT Agent Authorization](jit-agent-authorization.md),
  [Capability CLI](capability-cli.md)

## Context

VoidB's agent surface is already broker-mediated: `vb agent exec` finds a
scoped grant and forwards calls as broker `Run` requests that execute in
scoped child processes; `vb mcp serve` did not exist, so MCP hosts (Claude
Desktop, ZCode, Cursor, and other MCP clients) had no standard way to reach
the capability catalog. The 0.4.1 roadmap includes an MCP MVP as
Workstream 3 with one open decision: pin the protocol revision and choose the
authorization architecture before implementing.

## Decision

1. **Pin MCP revision `2025-06-18`.** It is the last revision with the
   `initialize` lifecycle handshake as the primary lifecycle, it is widely
   deployed, and it matches the roadmap's handshake requirement. The
   `2026-07-28` "Modern" revision replaces the handshake with per-request
   `_meta` versioning and `server/discover`; adopting it later is an additive
   server change behind capability negotiation.
2. **The MCP server is a broker grant client, not a credential holder.**
   `tools/call` reuses the `vb agent exec` path: `find_agent_exec_grant`
   matches a grant by command/principal/broker health, and the call is sent
   as `BrokerRequest::Run`, executed by the broker in a scoped child process.
   Rejected alternatives:
   - *Direct `invoke run` in the server process* — would require decrypting
     profiles (the master password) inside the long-lived server process and
     would bypass grant enforcement, destructive gates, and the scoped-child
     boundary. Rejected.
   - *Bridging plugin `serve` sessions directly* — session bridging is an
     explicit MVP non-goal; plugin sessions land through the adoption
     workstreams first.
3. **The server runs on raw configuration.** `vb mcp serve` is exempt from
   master-password unlock (`command_can_use_raw_config`) because everything
   it serves — capability metadata, profile references, matrix resources —
   is secret-free, and execution is delegated to the broker. A compromised
   server process yields capability metadata, not credentials.
4. **Risk maps to MCP annotations, policy stays in the broker.**
   `read_only` → `readOnlyHint: true`; `destructive` and
   `external_side_effect` → `destructiveHint: true`; `mutating` → no hint.
   Annotations are advisory hints per the MCP spec; authorization, dry-run,
   and acknowledgement rules remain broker-enforced.
5. **Tool failures use MCP's two error channels.** Unknown tools and invalid
   arguments are JSON-RPC protocol errors (-32601/-32602). Everything the
   broker denied — missing grant, read-only rejection, TTL expiry, child
   failure — is an execution error (`isError: true`) with the structured
   VoidB envelope in `structuredContent` and `vb agent authorize` guidance,
   so clients and models can react without protocol breakage.
6. **Reserved tool arguments** (`voidb_profile`,
   `voidb_acknowledge_destructive`) are stripped from the capability input
   before execution. Profile resolution reuses the standard profile-ref
   forms; connectionless capabilities default to `system:<plugin>`.

## Consequences

- MCP clients inherit the broker's security model unchanged; no new
  credential surface exists.
- The server exposes only stateless tools in the MVP; session-only
  capabilities are filtered from `tools/list` until live-session bridging is
  designed.
- The catalog is read at request time from installed plugins, so tool lists
  reflect `vb plugin install/update` without restarting the server.
- Upgrading to a newer MCP revision only touches `wire.rs` negotiation and
  capability advertisement.
