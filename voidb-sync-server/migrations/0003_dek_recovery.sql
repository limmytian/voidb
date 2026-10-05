-- Client-side DEK recovery metadata.
--
-- Recovery is still opaque to the server. The server stores only a verifier
-- for the recovery code and a DEK wrapped under a recovery-code-derived KEK.

ALTER TABLE users ADD COLUMN recovery_srv_salt BLOB;
ALTER TABLE users ADD COLUMN recovery_hash_stored BLOB;
ALTER TABLE users ADD COLUMN kdf_salt_recovery_auth BLOB;
ALTER TABLE users ADD COLUMN kdf_params_recovery_auth TEXT;
ALTER TABLE users ADD COLUMN kdf_salt_recovery_kek BLOB;
ALTER TABLE users ADD COLUMN kdf_params_recovery_kek TEXT;
ALTER TABLE users ADD COLUMN recovery_wrapped_dek BLOB;
ALTER TABLE users ADD COLUMN recovery_updated_at TEXT;

INSERT OR IGNORE INTO schema_version (version, applied_at)
VALUES (3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
