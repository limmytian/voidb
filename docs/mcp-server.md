# MCP Server (`vb mcp serve`)

VoidB ships a Model Context Protocol (MCP) stdio server that exposes the
installed capability catalog as MCP tools. Every tool call is routed through
the agent authorization broker, so MCP clients get the same safety properties
as `vb agent exec`: scoped grants, destructive gates, redaction, bounded
output, and audit.

Protocol revision: **`2025-06-18`** (pinned; see
[ADR: MCP Agent Gateway](adr-mcp-agent-gateway.md)).

## Running

```bash
vb mcp serve [--client-id <id> --task-id <id>] [--instance-id <id>] [--quiet]
```

The server reads newline-delimited JSON-RPC on stdin and writes frames to
stdout; logs go to stderr. It runs on raw configuration — the server process
never receives the master password and never decrypts profiles.

Point any MCP client at the binary:

```json
{
  "mcpServers": {
    "voidb": {
      "command": "vb",
      "args": ["mcp", "serve"]
    }
  }
}
```

## Tools

`tools/list` returns one tool per stateless capability in the installed
catalog (the same source as `vb invoke list`):

- `name` is the qualified capability id (`<plugin>.<capability>`).
- `inputSchema` is the capability's declared JSON Schema.
- `annotations` map the VoidB risk level: `read_only` → `readOnlyHint: true`;
  `destructive` and `external_side_effect` → `destructiveHint: true`.
  Annotations are hints; enforcement always happens in the broker.
- Session-only capabilities are excluded from the MVP: they fail closed
  outside a broker session and would be dead tools.

`tools/call` arguments are the capability input plus two reserved fields that
are stripped before execution:

| Reserved argument | Meaning |
|---|---|
| `voidb_profile` | Optional profile id or name. Defaults to the plugin's system profile (`system:<plugin>`). |
| `voidb_acknowledge_destructive` | `true` adds the explicit `--yes` acknowledgement. Requires an allow-destructive grant. |

### Authorization

A tool call without a matching active grant returns an MCP execution error
(`isError: true`) whose `structuredContent` carries a stable
`authorization.grant_required` error plus `guidance.cli_args` for
`vb agent authorize`. The call never bypasses the broker:

1. The server finds a grant exactly like `vb agent exec` (principal match,
   broker online, command allowed).
2. It sends the broker a `Run` request; the broker spawns `vb invoke run` in
   a scoped child process with the master password piped in memory-only.
3. The child's JSON envelope becomes the tool result: `data` maps to
   `structuredContent`; policy denials map to `isError: true` results the
   client can display and the model can self-correct from.

## Resources

| URI | Content |
|---|---|
| `voidb://profiles` | Redacted profile references: `id`, `name`, `plugin_id`, `display_name`. Never credentials or host details. |
| `voidb://capability-matrix` | The generated built-in Agent capability matrix (full builds only). |

## Security properties

- The server process runs on raw configuration and holds no master password.
- Credentials cross only as broker-issued reference descriptors inside the
  scoped child; the redaction policy applies to every response.
- Grants are time-bounded (default 15 minutes), use-budgeted, and revocable
  (`vb agent revoke`); revocation denies the next tool call immediately.
- Audit entries carry the MCP principal identity, never tool payloads.

## Non-goals (MVP)

HTTP/SSE transport, prompts, sampling, resource templates, and live-session
bridging (SSH PTY share, SQL transactions, streams, transfers). Session
bridging is deferred until the agent session host workstreams land.

## Verification

```bash
cargo test -p voidb-cli mcp
scripts/mcp-fixture-smoke.sh
```

The fixture smoke drives the real binary over stdio against a development
plugin: initialize handshake, `tools/list` shape, a granted call, a
policy-denied call, and secret hygiene of every frame.
