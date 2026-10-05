# voidb-sync-server

End-to-end encrypted sync backend for the [VoidB](../) TUI.

The server is intentionally dumb: it stores **opaque ciphertext** and **password
verifiers**. Clients hold the only keys that can decrypt configuration,
credentials, or plugin data. A full DB dump of this server does not reveal
user secrets.

Author: Limmy.

---

## Storage layout

All runtime state lives under `data_dir` (set in `config.toml`). In production
this is expected to point at a mounted NFS volume:

```
<data_dir>/
├── metadata.db                              SQLite: users, devices, blob index
└── blobs/
    └── <user_id>/
        └── <kind>/
            └── <revision>.bin               encrypted payload (opaque)
```

`<kind>` is a small ASCII label (e.g. `full`, `config`, `plugin:mysql`).
Writes use `write + rename` for atomicity on NFS.

## Security model

Passwords never leave the client. The client derives two independent values
from the master password via Argon2id, using per-user salts returned by the
server:

```
auth_hash_client = Argon2id(password, kdf_salt_auth, kdf_params_auth)
kek              = Argon2id(password, kdf_salt_kek,  kdf_params_kek)
dek              = random 32 bytes                         (generated once at signup)
wrapped_dek      = AES-256-GCM(kek, dek)
```

The server receives `auth_hash_client` and `wrapped_dek`, and:

- re-hashes `auth_hash_client` with a server-side per-user salt and stores only
  `auth_hash_stored = Argon2id(auth_hash_client, srv_salt)` — a dump of the DB
  cannot be replayed against the API.
- stores `wrapped_dek` as an opaque blob. Without the password, it is useless.

All user data (configs, plugin state, ...) is encrypted client-side with `dek`
before upload, and the server only ever sees and returns ciphertext.

> **Trade-off**: forgetting the password ≡ losing all data, because the server
> cannot unwrap the DEK. Clients are expected to show users a recovery phrase
> at signup that wraps the DEK with a secondary key.

## HTTP API (v1)

Base: `https://<host>/v1`. Authenticated endpoints take
`Authorization: Bearer <token>`.

### Auth

| Method | Path                       | Description                                |
|--------|----------------------------|--------------------------------------------|
| POST   | `/auth/register`           | Create a new account + first device        |
| POST   | `/auth/challenge`          | Return KDF params so client can login      |
| POST   | `/auth/login`              | Exchange `auth_hash_client` for a token    |
| POST   | `/auth/logout`             | Revoke the current device's token          |

### Blobs

| Method | Path                                 | Description                              |
|--------|--------------------------------------|------------------------------------------|
| PUT    | `/blobs/{kind}`                      | Upload new revision (optimistic locking) |
| GET    | `/blobs/{kind}/latest`               | Fetch latest ciphertext                  |
| GET    | `/blobs/{kind}/history?limit=N`      | Revision list (no ciphertext)            |
| GET    | `/blobs/{kind}/revisions/{revision}` | Fetch a specific revision                |

`PUT` bodies carry `expected_revision`. If it does not match the server's
current revision, the server returns **409 Conflict** with
`{ current_revision: N }`; the client should then pull, merge, and retry.

### Devices

| Method | Path                 | Description                              |
|--------|----------------------|------------------------------------------|
| GET    | `/devices`           | List all devices for the current user    |
| DELETE | `/devices/{id}`      | Revoke another device's token            |
| GET    | `/me`                | User profile + devices + current device  |

## Running

```bash
cp config.example.toml config.toml
$EDITOR config.toml           # set data_dir, bind, registration policy, ...
cargo run --release
```

The first run creates `<data_dir>/metadata.db` and applies all migrations.

### Registration policies

- `open` — anyone can sign up.
- `invite_only` — require an `invite_token` whose SHA-256 appears in
  `invite_tokens` with `used_at IS NULL`. Pre-seed tokens with SQL:
  ```sql
  INSERT INTO invite_tokens (token_hash, note, created_at)
  VALUES (X'<sha256 hex>', 'friend-a', strftime('%Y-%m-%dT%H:%M:%fZ','now'));
  ```
- `closed` — no new signups; existing users can still log in.

## Deployment notes

- **NFS**: the blob writer uses `write tmp → rename target`, which is atomic
  on most NFSv4 servers with close-to-open consistency.
- **SQLite journal**: WAL is enabled at startup; keep `metadata.db`,
  `metadata.db-wal`, and `metadata.db-shm` on the same mount.
- **Backups**: it is safe to snapshot the whole `data_dir` while the server
  runs thanks to WAL. For point-in-time recovery, prefer `.backup` via
  `sqlite3` + a filesystem snapshot of `blobs/`.

## Tests

```bash
cargo test --test smoke
```

The smoke test exercises the full register → login → put → pull → 409 flow
against an in-process HTTP server backed by a `tempdir`.
