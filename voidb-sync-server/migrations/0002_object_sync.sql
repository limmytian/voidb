-- Object-level sync storage.
--
-- The server stores opaque object ciphertext and redacted metadata only. It
-- never stores plaintext object payloads, local labels, hostnames, usernames,
-- or other target-system identifiers.

CREATE TABLE IF NOT EXISTS object_revisions (
    user_id                     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    object_id                   TEXT    NOT NULL,
    object_kind                 TEXT    NOT NULL,
    server_revision             INTEGER NOT NULL,
    schema_version              INTEGER NOT NULL,
    object_version              INTEGER NOT NULL,
    base_server_revision        INTEGER,
    device_id                   TEXT    NOT NULL REFERENCES devices(id) ON DELETE SET NULL,
    updated_at                  TEXT    NOT NULL,
    received_at                 TEXT    NOT NULL,
    updated_by_actor_type       TEXT    NOT NULL,
    updated_by_actor_id_redacted TEXT   NOT NULL,
    deleted                     INTEGER NOT NULL CHECK (deleted IN (0, 1)),
    redaction                   TEXT    NOT NULL,
    payload_hash                TEXT    NOT NULL,
    payload_size                INTEGER NOT NULL,
    manifest                    TEXT    NOT NULL,
    ciphertext_path             TEXT    NOT NULL,
    ciphertext_size             INTEGER NOT NULL,
    ciphertext_sha256           BLOB    NOT NULL,
    PRIMARY KEY (user_id, object_id, server_revision)
);

CREATE INDEX IF NOT EXISTS idx_object_revisions_user_kind
ON object_revisions(user_id, object_kind, server_revision);

CREATE TABLE IF NOT EXISTS object_latest (
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    object_id       TEXT NOT NULL,
    server_revision INTEGER NOT NULL,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (user_id, object_id)
);

CREATE INDEX IF NOT EXISTS idx_object_latest_user
ON object_latest(user_id, updated_at);

INSERT OR IGNORE INTO schema_version (version, applied_at)
VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
