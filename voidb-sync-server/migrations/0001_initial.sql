-- VoidB Sync Server — initial schema.
--
-- All timestamps are ISO-8601 strings (UTC, produced via chrono::Utc::now()).
-- Binary fields (salt, token_hash, ...) are stored as BLOBs.
--
-- E2E model reminder: the server stores only ciphertext + opaque auth hashes.
-- It never sees plaintext passwords, DEKs, or blob contents.

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id                  TEXT PRIMARY KEY,       -- uuid v4
    email               TEXT NOT NULL UNIQUE,
    -- Server-side password verifier.
    -- The client sends `auth_hash_client = Argon2id(password, kdf_salt_auth)`;
    -- the server stores `auth_hash_stored = Argon2id(auth_hash_client, srv_salt)`.
    srv_salt            BLOB NOT NULL,
    auth_hash_stored    BLOB NOT NULL,
    -- Client-side KDF parameters (returned on login so the client can re-derive KEK).
    kdf_salt_auth       BLOB NOT NULL,
    kdf_params_auth     TEXT NOT NULL,          -- JSON: { m_cost, t_cost, p_cost, out_len }
    kdf_salt_kek        BLOB NOT NULL,
    kdf_params_kek      TEXT NOT NULL,
    -- Client-generated DEK wrapped by KEK (AES-256-GCM). Opaque to the server.
    wrapped_dek         BLOB NOT NULL,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id              TEXT PRIMARY KEY,           -- uuid v4
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    -- SHA-256 of the bearer token. Only the hash is stored; the plaintext is
    -- returned exactly once at device creation / login.
    token_hash      BLOB NOT NULL UNIQUE,
    created_at      TEXT NOT NULL,
    last_seen_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

CREATE TABLE IF NOT EXISTS blobs (
    user_id             TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind                TEXT    NOT NULL,       -- e.g. "full", "config", "plugin:mysql"
    revision            INTEGER NOT NULL,
    device_id           TEXT    NOT NULL REFERENCES devices(id) ON DELETE SET NULL,
    -- JSON manifest of the files inside the encrypted bundle. Plaintext for
    -- debugging / selective pulls; contents are hashes + sizes, not data.
    manifest            TEXT    NOT NULL,
    -- Relative path beneath <data_dir>/blobs/.
    ciphertext_path     TEXT    NOT NULL,
    ciphertext_size     INTEGER NOT NULL,
    ciphertext_sha256   BLOB    NOT NULL,
    created_at          TEXT    NOT NULL,
    PRIMARY KEY (user_id, kind, revision)
);

CREATE INDEX IF NOT EXISTS idx_blobs_user_kind ON blobs(user_id, kind);

-- Pointer to the latest revision for a (user, kind). Updated atomically on PUT.
CREATE TABLE IF NOT EXISTS blob_latest (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (user_id, kind)
);

-- Optional registration invite tokens (used when registration == "invite_only").
CREATE TABLE IF NOT EXISTS invite_tokens (
    token_hash  BLOB PRIMARY KEY,
    note        TEXT,
    created_at  TEXT NOT NULL,
    used_at     TEXT,
    used_by     TEXT REFERENCES users(id) ON DELETE SET NULL
);

INSERT OR IGNORE INTO schema_version (version, applied_at)
VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
