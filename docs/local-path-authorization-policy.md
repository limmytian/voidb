# Local Path Authorization Policy

This document defines the normative local-filesystem boundary for agent-facing
VoidB capabilities. It complements the
[Unified Agent Authorization Contract](agent-authorization-contract.md),
[Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md),
and [Audit and Structured Error Schema](audit-and-error-schema.md).

The policy applies whenever an agent-triggered capability reads, writes, scans,
resumes, or reports on local filesystem state. A capability grant by itself does
not grant filesystem access. Every local operation also needs a narrow local
path grant, and both grants must authorize the operation.

## Security Goals And Boundary

The boundary prevents a capability from using caller-controlled paths to:

- read or inventory files outside a human-approved root;
- create, replace, truncate, or delete files outside that root;
- escape through `..`, absolute aliases, symlinks, junctions, mount aliases, or
  case-folding differences;
- race validation by replacing a checked path before it is opened or committed;
- disclose host paths or an unbounded directory inventory through results,
  diagnostics, logs, or audit records; or
- resume a transfer into a different destination or from a different source.

This is a VoidB application boundary, not a sandbox for an agent with arbitrary
host process or filesystem access. Direct human CLI/TUI operations may obtain a
local path grant from the local interactive actor, but they should reuse the
same resolver and write primitives so behavior does not diverge.

## Ownership

Responsibilities are split as follows:

- The central authorization broker owns grant creation, actor attribution,
  expiry, revocation, and operation matching. The shell does not participate.
- `voidb-core` owns driver-free grant types, stable policy errors, redacted
  audit projections, and shared path-resolution rules.
- The invoking plugin owns protocol-specific work and must call the shared
  resolver immediately before every local open, directory read, create, rename,
  or resume operation. A schema check or earlier string comparison is not an
  authorization decision.
- Plugin services own live files and transfer state. They must not persist a
  reusable raw path grant or broaden it to a whole profile, plugin, or session.

If a platform cannot enforce a required no-follow or no-replace guarantee for a
particular operation, the operation fails closed. Falling back to a string
prefix check, check-then-open sequence, or truncating create is forbidden.

## Local Path Grant

A local path grant is immutable and contains only the authority needed for one
invocation or bounded transfer session:

| Field | Contract |
|---|---|
| `grant_id` | Opaque identifier suitable for audit correlation. |
| `actor` | Human or agent identity that requested the operation. |
| `profile_id`, `plugin_id`, `capability_id` | Exact capability binding; wildcards are forbidden. |
| `root` | Canonical, existing directory selected by the local human or trusted policy. It is retained inside the broker/plugin boundary. |
| `root_fingerprint` | Stable opaque identity derived from the opened root, not its display path. |
| `access` | Exact subset of `read_file`, `scan_directory`, `create_file`, `replace_file`, and `resume_transfer`. |
| `staging_root` | Optional canonical directory on the same filesystem and inside the approved root. |
| `disclosure` | `opaque` by default; `relative_paths` is a separate explicit choice. Absolute paths are never disclosable. |
| `scan_limits` | Maximum depth, entries, and aggregate relative-path bytes. |
| `expires_at`, `remaining_uses` | Short lifetime and bounded use count. |

The default scan ceilings are 64 directory levels, 10,000 entries, and 4 MiB
of aggregate relative-path bytes. A deployment may choose lower values. Higher
limits require a new explicit grant; invocation input cannot raise them.

Grant rules:

1. The root must exist and be opened as a directory before the grant is issued.
2. Access modes are independent. `scan_directory` does not imply file-content
   reads; `read_file` does not imply recursive scanning; `create_file` does not
   imply replacement or deletion.
3. Read-only capability presets never imply local access. A target-read-only
   capability such as sync planning still needs `scan_directory` authority.
4. Any capability that creates or changes local state is not eligible for the
   read-only preset, even when the remote target is only read.
5. Revocation, expiry, use exhaustion, or actor/profile/capability mismatch
   invalidates open staging/resume state at the next safe cancellation point.
6. The caller may narrow a grant to a descendant path or lower limits, but may
   not widen it.

## Path Resolution

Paths are resolved against the opened grant root, not the process working
directory. Implementations must follow this algorithm:

1. Reject empty paths, NULs, platform device paths, environment or tilde
   expansion, and components that cannot be represented safely by the host API.
2. Treat caller input as a path relative to the grant root. Existing absolute
   inputs may be accepted only as a compatibility form after proving that their
   resolved object is beneath the same opened root; they never select a root.
3. Normalize lexical `.` components and reject any `..` component before I/O.
   Do not use Unicode normalization, lossy UTF-8 conversion, case conversion,
   or string-prefix comparison as an authorization check.
4. Traverse from the opened root one component at a time with no-follow
   semantics. Reject symlinks, Windows reparse points/junctions, aliases that
   change volume or root identity, and non-directory intermediate components.
5. For an existing read or scan target, compare the opened target's ancestry or
   platform identity with the opened root after acquisition. Validation must be
   tied to the handle used for I/O.
6. For a destination that does not exist, resolve and open its nearest existing
   ancestor under the root, validate every remaining component, and create via
   the anchored directory handle. Re-resolve from the root for each retry.
7. If an entry changes identity between resolution and use, return a conflict;
   do not silently retry against the replacement.

Directory scans must inspect entries without following links. Encountering a
link is a policy denial for that entry and makes the requested plan fail closed;
silently omitting it would produce an incomplete plan that could later cause an
unsafe delete. Mount-point traversal is denied unless the grant captured that
exact descendant filesystem as a separate root.

## Read, Scan, Write, And Resume Semantics

### Reads

`read_file` permits opening one regular file beneath the root. Directories,
links, sockets, devices, and FIFOs are rejected. The implementation records a
source fingerprint and size from the opened handle. The raw local path must not
be copied into protocol errors or capability results.

### Scans

`scan_directory` permits metadata inventory only. It does not permit opening
file bodies. A scan stops and returns a structured policy error before emitting
a partial plan when any depth, entry, path-byte, timeout, cancellation, or
symlink boundary is reached. Enumeration order must be deterministic after
authorization so repeated plans are comparable.

### Writes And Staging

`create_file` is the default download authority. It follows these rules:

- create a private, exclusive staging file inside `staging_root` or beside the
  final destination on the same filesystem;
- stream into the staging handle, apply private permissions, flush it, and
  commit with an atomic no-replace operation;
- never open the final destination with truncate semantics;
- remove the staging artifact on failure, cancellation, expiry, or checksum
  mismatch; and
- surface an existing destination as `conflict.local_path_exists`.

Replacement requires all of the following: `replace_file` in the local path
grant, `overwrite=true` in validated invocation input, capability policy that
classifies the call as mutating/destructive, and per-call human
acknowledgement. Replacement still uses a staged atomic commit. No-overwrite is
the default when the field is absent, including for legacy callers.

Parent directories may be created only when the input contract explicitly
requests it and `create_file` covers the complete descendant path. Created
directories use private-by-default permissions and the same anchored,
no-symlink traversal.

### Resume

Resume state is an opaque transfer record, never a caller-selected staging
path. It is bound to the local path grant, actor, profile, capability, canonical
destination or source fingerprint, remote object identity, expected size,
completed byte range, and expiry. Resume requires `resume_transfer` plus the
underlying read/create/replace authority. Any identity or size mismatch returns
`conflict.local_resume_mismatch` and discards the staged state.

## Agent-Facing Redaction

Absolute paths, canonical roots, home-directory names, volume names, and raw
staging paths are sensitive metadata. They must not appear in capability
output, output summaries, errors, logs, traces, task text, or audit records.

Machine output uses:

- `local_scope_id`: an invocation-scoped opaque identifier;
- count, byte, action, truncation, and limit metadata;
- `entry_ref`: a stable opaque per-invocation reference when disclosure is
  `opaque`; and
- normalized paths relative to the approved root only when the grant explicitly
  permits `relative_paths` disclosure.

Even with relative disclosure, `local_path` must never echo the submitted or
canonical absolute base. Human UI may show a locally rendered, elided path
after authorization, but that display string must not enter agent output or
audit persistence. Redaction failures withhold the whole field and set the
redaction status to `failed_closed`.

## Stable Errors

Local path enforcement uses existing `CapabilityError` categories and these
stable codes:

| Category | Code | Meaning |
|---|---|---|
| `validation` | `validation.local_path_invalid` | Empty, malformed, unsupported, or forbidden path form. |
| `permission` | `permission.local_path_scope_required` | No matching local path grant exists. |
| `permission` | `permission.local_path_access_denied` | The grant lacks the required access mode. |
| `permission` | `permission.local_path_outside_scope` | Resolution would leave the approved root. |
| `unavailable` | `unavailable.local_path_root` | The exact approved root is missing, inaccessible, or no longer a directory. |
| `policy` | `policy.local_path_link_denied` | A symlink, junction, reparse point, or ungranted mount was encountered. |
| `policy` | `policy.local_scan_limit_exceeded` | A depth, entry, or path-byte ceiling was reached. |
| `conflict` | `conflict.local_path_exists` | No-overwrite commit found an existing destination. |
| `conflict` | `conflict.local_path_changed` | An opened component changed identity during the operation. |
| `conflict` | `conflict.local_resume_mismatch` | Resume state does not match the current source/destination or remote object. |
| `unavailable` | `unavailable.local_staging` | Safe same-filesystem staging cannot be created or committed. |

Messages and details identify only the operation, access mode, opaque scope,
and failed policy phase. They do not include raw input or resolved paths.

## Audit Contract

Every allow or deny decision records:

- actor, invocation, profile, plugin, capability, and local path grant IDs;
- opaque root fingerprint and requested access mode;
- policy outcome and one stable reason/error code;
- whether the input was relative or compatibility-absolute, without its value;
- symlink/no-follow, no-replace/replace, staging, and resume decisions;
- configured and observed scan counts/depth/path bytes or transferred bytes;
- source/destination fingerprint when needed for conflict diagnosis;
- cancellation, timeout, cleanup, and commit outcome; and
- redaction status.

Audit records never include raw or canonical paths, relative entry names,
staging names, file contents, remote credentials, or unredacted target errors.

## Affected Capability Implementation

The shared baseline is implemented by `voidb_core::LocalPathScope`, the central
agent broker's capability-wide denial, and the SSH/S3/WebDAV adapters below.
`scripts/check-local-filesystem-boundaries.sh` is the aggregate regression gate;
the broader external-agent check invokes it so local filesystem authorization
cannot drift independently from the agent interaction boundary.

| Capability | Enforced local effect | Grant and classification | Agent output |
|---|---|---|---|
| `ssh.sftp_get` | Stages remote bytes under an approved root and commits with atomic no-replace. | `mutating`; exact `local_root` and relative `local_path`; capability-wide grants denied. Replacement remains unsupported. | Transfer counts plus opaque scope; no raw `local_path`. |
| `ssh.sftp_put` | Reads one regular no-link file under an approved root before remote mutation. | `destructive`; exact local scope in addition to remote-path approval; capability-wide grants denied. | Transfer counts plus opaque scope; no raw `local_path`. |
| `s3.sync_plan` | Inventories approved metadata with the default depth, entry, and path-byte ceilings. | Target-read-only with exact local scan scope; capability-wide grants denied. | Bounded plan with opaque entry refs by default; relative names require explicit disclosure approval. |
| `webdav.sync_plan` | Uses the same shared bounded scan as S3. | Same contract as `s3.sync_plan`. | Same bounded and redacted plan contract as S3. |

Shared enforcement must also cover the same operations when invoked through a
persistent agent session. Human-only service and CLI entry points should adopt
the resolver before they share a common implementation with agent execution;
they must never bypass an already-present agent grant.

## Acceptance And Adversarial Cases

Implementations are conformant only when tests prove:

- relative traversal, absolute aliases, case aliases, Unicode names, symlinks,
  junctions/reparse points, and ungranted mounts cannot escape the root;
- swapping a checked ancestor or destination produces a conflict or policy
  denial, never out-of-scope I/O;
- existing destinations are not replaced by default, concurrent creators yield
  a deterministic conflict, and failed/cancelled transfers leave no staging
  artifact;
- uploads cannot open a file outside the grant and downloads cannot commit
  outside it;
- sync planning cannot scan an unapproved root, follow links, exceed its
  ceilings, serialize a partial unsafe plan, or reveal the local base path;
- resume tokens cannot be replayed across actor, grant, capability, path,
  remote-object, or expiry boundaries; and
- audit and error projections contain stable codes and no local path material.

The aggregate gate exercises the portable contract and Unix no-follow fixture
matrix. Platform CI should add native junction/reparse-point, case-folding, and
mount-alias fixtures where the host can create them without elevated privilege.
