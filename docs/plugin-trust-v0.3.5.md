# Plugin trust contract for v0.3.5

Status: implementation contract; release acceptance is pending.

## Trust boundary and audit

The trusted computing base is the core executable, its embedded Ed25519 public
keys, confidential signing keys and approved publisher CI, the host OS and the
invocation environment. A compromised signing key can authorize forged packages
until a trusted core update removes that root. Writable install metadata is
an inventory cache, never an authority. This design does not protect against an
attacker who replaces the core, its trust roots, or a privileged compromised OS.

The v0.3.4 integrity gate (`process_plugin::verify_plugin_binary_integrity`)
returns success when install.toml is missing, accepts co-modification of a binary
and its recorded digest, and backfills omitted digests from untrusted bytes.
CLI domain/TUI dispatch (`main::dispatch_external_plugin`), connection tests
(`connections::test_connection_with_discovery`) and JSON-RPC health/invoke/session
startup (`ProcessPluginRuntimeHost::launch`) share this gate. Discovery parses
metadata without launching a child. Connection-test fallback launches must repeat
the gate immediately before every spawn. Credentials must never be written to a
child until successful verification. Ordinary CLI children inherit an environment;
that environment is part of the trusted invocation boundary.

The prepared core-only changes remove bundled assets from release packaging,
installation and implicit discovery. Explicit offline roots remain managed and
must satisfy the same signature contract. Onboarding and contextual installation
use the registry installer and must remove the master-password environment
variable and close stdin. Existing invalid, disabled or incompatible installations
must not be silently replaced. Partial first-launch installation stays retryable
through install-default; no automatic downloads occur on noninteractive runs.

## Authenticated package proof

Every managed package contains `provenance.json`. The envelope contains exactly
`key_id`, `payload` (a UTF-8 JSON string), and `signature` (hex Ed25519).
Sign the bytes `voidb-plugin-provenance-v1\n` followed by the exact payload bytes.
Verification authenticates bytes before interpreting identity. Payload fields:
`schema_version` (1), `plugin_id`, `version`, `protocol_version`, `target`,
`binary_path`, and `files` (relative regular-file path to SHA-256 digest map).
The map covers plugin.toml, the executable, and all schemas/assets, excluding
provenance.json itself. Digests use `sha256:<lowercase hex>`. The executable path
must be package-relative and match the command resolved during discovery.

Reject unknown signer, bad/forged signature, malformed envelope/payload, unsupported
schema, wrong ID/version/protocol/host target, absent/extra/changed payload files,
symlinks in the package or its root ancestry, nonregular payloads, and commands
outside the package. Hash all authenticated files before launch. Compare freshly
parsed manifest metadata to the discovered candidate to reject stale metadata.
Records remain mandatory for managed execution; missing, malformed, mismatched or
legacy omitted digests fail closed. Runtime never repairs or blesses them.
Proof travels inside the package so preserving a previous package preserves its
matching authenticated payload and identity.

The release root key ID is `official-2026-10`; its public key is
`2d00e2e461719c94b77cf0e9d1d49a9cf1c8dbe8f802696b801b432bfcc95ea2`.
The owner authorized a new local private key stored outside all repositories with
mode 0600 under a mode 0700 directory. Private keys must never enter plugin
packages, registry records, arguments, task comments or logs. CI provisioning is
subject to owner review before publication. Test keys are independent and never
accepted by production builds.

## Development and path policy

Unsigned development execution requires both an explicit VOIDB_PLUGIN_PATH root
and `VOIDB_ALLOW_UNSIGNED_PLUGINS=1`. Managed user/offline/system roots cannot
be downgraded by deleting records. Development roots must resolve outside the
standard user install roots. Official IDs cannot silently shadow managed copies;
the explicit development opt-in acknowledges arbitrary-code and credential risk.
CLI, TUI and RPC share the same gate, without interactive approval exceptions.
Do not persist this opt-in in install records or silently enable it in installers.

Portable path-based spawn has a residual hash-to-execution race: an attacker with
concurrent write access can replace files after verification. Rejecting symlinks
and repeating verification before each spawn reduces substitution opportunities
but does not remove that race or dynamic-library/environment substitution. No
claim of race-free execution is made. A future platform-specific descriptor or
immutable execution facility requires separate design and platform acceptance.

## Migration, update and key lifecycle

Publish new official plugin v0.3.4 packages for all 14 repositories; retain all
v0.3.3 tags/assets unchanged. Core v0.3.5 requires authenticated packages. Existing protocol 1 manifests remain supported alongside 1.1; the signature
contract does not require a new driver API. Registry
latest versions advance only when matching signed assets are available.

Legacy users explicitly run `plugin update <id>` to obtain a signed package,
including installations with missing records. Never sign or trust an existing
unsigned binary as a migration shortcut. Preserve profiles, encrypted credentials,
user data and old packages for inspection/recovery. Missing/invalid proof must fail
before activation; update rollback restores a matching package and record. A
failed or interrupted metadata write cannot authorize an unverified package;
re-running verified update must recover safely. Restoring unsigned backups does
not make them executable. Rollback to a signed older release requires explicit
allow-downgrade and the same signature check.

Trust roots are compiled into core. Rotation ships a core containing both old and
new public keys before signing with the new key; revocation ships a core that
removes the compromised key. Offline old cores cannot learn revocation. There is
no writable local key override or trust-on-first-use. v1 does not promise freshness
or prevent replay of an older legitimately signed package; explicit downgrade
policy handles ordinary updates, within the stated trusted-core boundary.

## Acceptance matrix

| Case | Expected result |
| --- | --- |
| Record deleted, malformed, or required digest omitted | Deny, no backfill |
| Binary and record digest changed together | Deny against signed file map |
| Proof deleted, corrupted, forged, or unknown signer | Deny before spawn |
| Wrong signed ID/version/protocol/target/path | Deny before spawn |
| Manifest/schema or extra payload changed | Deny before spawn |
| Symlinked root, executable, schema or package directory | Deny before spawn |
| Unsigned explicit developer root without second opt-in | Deny |
| Managed root with developer opt-in | Still deny unsigned execution |
| Health/invoke/session/TUI/test failure | No child marker or secret delivery |
| Legacy v0.3.3 recovery | Verified new package, original user data preserved |
| Interrupted update/record write and signed downgrade | Recoverable; matching proof retained |
| Core-only package and uninstall | No implicit bundled fallback |

Full workspace tests and Clippy are required after shared enforcement changes.
Native Mac ARM64 checks are local; Linux/Mac Intel CI and immutable candidate
artifact evidence remain release gates. Windows core packages contain no official
plugin support claim until signed native Windows plugin assets are available.

Managed plugin directories are immutable code trees. Keep databases, logs and
runtime caches outside them; extra files cause execution refusal. Updates retain
the complete previous tree for recovery, but legacy data stored inside an old
plugin directory must be relocated explicitly and its profile path updated.
Verification runs before each new child launch. Already authenticated live
sessions continue until their normal close/revocation; key removal requires a
core update and restart. Use absolute paths for explicit offline/development roots
so runtime working directories remain unambiguous.

The registry index builder authenticates target-qualified archives before writing
entries. Its distribution verifier can check foreign-target assets without
launching them; execution always verifies the compiled host target. Manual
candidate workflows default to `publish_release=false`, accept an exact source
ref, and upload artifacts without creating tags/releases. Publication additionally
requires an existing tag that resolves to the built source commit and uses only
`gh release create`, which cannot replace an existing release.
