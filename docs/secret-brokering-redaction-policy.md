# Secret Brokering and Redaction Policy

This document defines the first policy boundary for secret handling in the
capability-first VoidB model. It answers three questions:

1. Which data may reach agents?
2. Which secret material may reach plugins?
3. Where must redaction happen before output, logs, traces, or audit records are
   written?

This policy does not claim absolute local isolation from an agent that has
arbitrary filesystem, process, debugger, or memory access on the same machine.
The first architecture step protects against routine and accidental disclosure
through VoidB's agent-facing contracts.

## Trust Boundary

VoidB Core owns saved connection profiles, encrypted credential storage,
credential brokering decisions, policy checks, redaction, and audit metadata.

Plugins own protocol-specific execution. A plugin may receive decrypted
credential material only when Core grants it for a specific invocation or
runtime instance. Plugins must not return plaintext secrets to Core output
channels.

Agents invoke capabilities through the CLI or plugin protocol by profile ID or
alias. Agents must not receive plaintext passwords, tokens, API keys, private
keys, decrypted credential blobs, or full connection URLs containing secrets.

The local host remains a larger trust boundary. Stronger protection would
require OS credential stores, process isolation, sandboxing, or a broker process
with a smaller attack surface.

## Data Classes

| Class | Examples | Agent-facing output | Plugin runtime access |
|---|---|---|---|
| Public profile metadata | alias, plugin ID, host, port, database, region, bucket, namespace | Allowed | Allowed |
| Sensitive metadata | usernames, account IDs, internal hostnames, tenant IDs | Allowed only when policy marks it non-sensitive or redacted | Allowed if needed for connection setup |
| Credential reference | `credential_refs` IDs and classes | Allowed | Allowed |
| Plaintext secret material | passwords, tokens, API keys, private keys, decrypted blobs | Never allowed | Allowed only through a scoped grant |
| Derived secret material | signed URLs, session tokens, temporary cloud credentials | Never allowed unless explicitly classified as output data and redacted by default | Allowed only for the invocation or instance that requested it |
| Target-system data | query rows, Redis values, object names, logs, command output | Allowed according to capability policy | Allowed |
| Diagnostics | error messages, stack traces, transport logs, plugin stderr | Redacted before display | Redacted before persistence or forwarding |

## Agent-Facing Contract

Agent-facing commands and protocol responses may include:

- profile IDs and aliases
- plugin IDs and capability IDs
- profile metadata that is not classified as secret material
- credential reference IDs and credential classes
- schema descriptions, capability metadata, validation errors, and structured
  target-system errors
- redacted placeholders such as `<redacted:password>` or
  `<redacted:private_key>`

Agent-facing commands and protocol responses must not include:

- plaintext passwords, tokens, API keys, private keys, or passphrases
- decrypted `plugin_config` blobs
- connection URLs containing embedded credentials
- unredacted authorization headers, cookies, SAS tokens, signed URLs, or cloud
  temporary credentials
- plugin stderr or target-system messages before redaction

Agents should submit invocations by profile ID or alias plus capability input.
If an invocation requires a credential, the input references the profile and
Core resolves credential access internally.

## Plugin Credential Grants

Core grants credentials to plugins by invocation or runtime instance scope.
Grants are not a general read API over saved credentials.

A grant must include:

- profile ID
- plugin ID
- capability ID or runtime instance ID
- credential reference IDs
- credential classes
- grant purpose
- grant lifetime
- actor attribution

Grant rules:

- Grant only the credential classes declared by the plugin manifest and required
  by the capability.
- Grant only the material required for this invocation or instance.
- Prefer short-lived grants for one-shot invocations.
- Long-lived interactive sessions, tunnels, and workers may keep credentials in
  plugin memory only for the session lifetime.
- Grants must be auditable without storing plaintext secret material.
- Plugins must treat granted material as write-only operational input: use it to
  connect, sign, authenticate, or refresh, but do not echo it back.

## Redaction Rules

Redaction is required before data leaves a sensitive boundary:

- before CLI stdout or stderr is written
- before plugin protocol responses are delivered to agents
- before logs or traces are written
- before audit records are persisted
- before task, error, or diagnostic text is stored
- before copied debug bundles or sync payload descriptions are generated

Redaction must cover:

- configured credential values and decrypted credential blobs
- common secret-shaped fields: `password`, `passwd`, `passphrase`, `token`,
  `access_token`, `refresh_token`, `api_key`, `secret`, `secret_key`,
  `private_key`, `authorization`, `cookie`, and provider-specific variants
- full URLs with credentials or signed query parameters
- authorization headers and connection strings
- plugin stderr and target-system messages that may echo submitted secrets

Preferred placeholders:

- `<redacted:password>`
- `<redacted:token>`
- `<redacted:api_key>`
- `<redacted:private_key>`
- `<redacted:credential>`

Redaction must preserve enough shape for debugging where possible. For example,
Core may preserve a credential class, reference ID, plugin ID, error category,
or hash fingerprint, but not the secret value itself.

## Audit Records

Audit records follow
[Audit and Structured Error Schema](audit-and-error-schema.md). They may
include invocation ID, actor attribution, profile reference, plugin ID,
capability ID, credential reference IDs and classes, grant purpose, redaction
status, result status, structured error category, target-system failure
details, and timing.

Audit records must not include plaintext secret material, decrypted
`plugin_config`, or unredacted plugin diagnostics.

## Failure Behavior

If required credential access is missing, denied, expired, or incompatible with
policy, Core should return a structured permission or credential error. It must
not include the missing secret value.

If redaction cannot be applied confidently, Core should prefer withholding the
field or replacing the entire diagnostic with a generic redacted message.

If a plugin returns a value that matches known secret material or secret-shaped
fields, Core should redact it before forwarding it to agents or persisting it.

## Migration Notes

Current v4 storage encrypts `ConnectionConfig.plugin_config` as one blob. During
the capability-first migration:

1. Treat existing `plugin_config` as storage-internal data, not an agent-facing
   API payload.
2. Expose profile metadata and credential references separately.
3. Add credential grant plumbing between Core and plugins.
4. Add centralized redaction utilities before broadening CLI output.
5. Keep plugin-owned service layers responsible for runtime credential use and
   cleanup.
