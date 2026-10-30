//! Negative-path and policy tests for the VoidB sync server.
//!
//! Complements `smoke.rs` (happy paths). Every assertion here mirrors behavior
//! actually implemented in `src/routes/*.rs`, `src/routes/session.rs`, and
//! `src/error.rs`; nothing aspirational is asserted.
//!
//! Framework-derived status codes (axum 0.8 / tower-http 0.6) that these tests
//! pin down:
//!   - JSON body with a deserialization error (missing/unknown/wrong-typed
//!     fields) -> 422; syntactically invalid JSON -> 400.
//!   - Path parameter parse failure -> 400.
//!   - Request bodies larger than `max_blob_bytes` -> 413 from the
//!     `RequestBodyLimitLayer`. That layer fires before handlers, so the
//!     handlers' own `PayloadTooLarge` branch (decoded ciphertext size) is not
//!     reachable over HTTP: base64 always inflates the body past the same
//!     limit first.

use std::net::SocketAddr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use voidb_sync_server::{AppState, Config, RegistrationPolicy, router};

// -----------------------------------------------------------------------------
// Harness (mirrors tests/smoke.rs)
// -----------------------------------------------------------------------------

fn test_config(tmp: &TempDir) -> Config {
    toml::from_str::<Config>(&format!(
        r#"
bind = "127.0.0.1:0"
data_dir = "{}"
max_blob_bytes = 1048576
history_keep = 5
registration = "open"
log_level = "error"
"#,
        tmp.path().display()
    ))
    .unwrap()
}

async fn spawn_server(cfg: Config) -> SocketAddr {
    let state = AppState::bootstrap(cfg).await.unwrap();
    let app = router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Registration payload with fixed deterministic material. All users share the
/// same client auth hash bytes; the server salts each verifier independently.
fn registration_body(email: &str, device_name: &str) -> Value {
    json!({
        "email": email,
        "auth_hash_client": B64.encode([7u8; 32]),
        "kdf_salt_auth": B64.encode([1u8; 16]),
        "kdf_params_auth": { "m_cost": 4096, "t_cost": 3, "p_cost": 1, "out_len": 32 },
        "kdf_salt_kek": B64.encode([2u8; 16]),
        "kdf_params_kek": { "m_cost": 4096, "t_cost": 3, "p_cost": 1, "out_len": 32 },
        "wrapped_dek": B64.encode([9u8; 48]),
        "device_name": device_name,
    })
}

/// Registration payload that also carries the six mandatory recovery fields
/// (`decode_recovery_registration` rejects partial sets with 400).
fn registration_body_with_recovery(email: &str, device_name: &str) -> Value {
    let mut body = registration_body(email, device_name);
    body["recovery_hash_client"] = json!(B64.encode([3u8; 32]));
    body["kdf_salt_recovery_auth"] = json!(B64.encode([4u8; 16]));
    body["kdf_params_recovery_auth"] =
        json!({ "m_cost": 4096, "t_cost": 3, "p_cost": 1, "out_len": 32 });
    body["kdf_salt_recovery_kek"] = json!(B64.encode([5u8; 16]));
    body["kdf_params_recovery_kek"] =
        json!({ "m_cost": 4096, "t_cost": 3, "p_cost": 1, "out_len": 32 });
    body["recovery_wrapped_dek"] = json!(B64.encode([8u8; 48]));
    body
}

async fn post_json(client: &reqwest::Client, url: &str, body: &Value) -> reqwest::Response {
    client.post(url).json(body).send().await.unwrap()
}

async fn register_user(
    client: &reqwest::Client,
    base: &str,
    email: &str,
    device_name: &str,
) -> (String, String) {
    let response = post_json(
        client,
        &format!("{base}/v1/auth/register"),
        &registration_body(email, device_name),
    )
    .await;
    assert_eq!(
        response.status(),
        201,
        "register failed: {}",
        response.text().await.unwrap()
    );
    let body: Value = response.json().await.unwrap();
    (
        body["token"].as_str().unwrap().to_string(),
        body["device_id"].as_str().unwrap().to_string(),
    )
}

async fn login(
    client: &reqwest::Client,
    base: &str,
    email: &str,
    auth_hash: &[u8],
    device_name: &str,
) -> reqwest::Response {
    let body = json!({
        "email": email,
        "auth_hash_client": B64.encode(auth_hash),
        "device_name": device_name,
    });
    post_json(client, &format!("{base}/v1/auth/login"), &body).await
}

/// Valid object PUT payload. The object id travels in the URL path (the
/// `object_kind: profile` id prefix is validated there), not in the body.
/// `base_revision = None` omits the field, which the handler treats as base
/// revision 0 (fresh object).
fn object_put_body(device_id: &str, base_revision: Option<i64>) -> Value {
    json!({
        "schema_version": 1,
        "object_kind": "profile",
        "object_version": 1,
        "base_server_revision": base_revision,
        "payload_hash": format!("sha256:{}", "a".repeat(64)),
        "payload_size": 24,
        "updated_at": "2026-07-04T15:00:00Z",
        "updated_by": {
            "actor_type": "human",
            "actor_id": "tester@example.com",
            "device_id": device_id,
        },
        "deleted": false,
        "redaction": "withheld",
        "ciphertext": B64.encode(b"fake encrypted object payload"),
    })
}

// -----------------------------------------------------------------------------
// Auth negative paths
// -----------------------------------------------------------------------------

/// Wrong password and unknown user must fail identically on `/v1/auth/login`
/// (both return `ApiError::Unauthorized` before any user-specific data is
/// revealed), so the login response cannot be used to enumerate accounts.
#[tokio::test]
async fn login_rejects_wrong_credentials_and_unknown_users_identically() {
    let tmp = TempDir::new().unwrap();
    let addr = spawn_server(test_config(&tmp)).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    register_user(&client, &base, "alice@example.com", "dev-1").await;

    // Wrong credential (registered user, wrong auth hash).
    let wrong_body = json!({
        "email": "alice@example.com",
        "auth_hash_client": B64.encode([0u8; 32]),
        "device_name": "dev-wrong",
    });
    let r = post_json(&client, &format!("{base}/v1/auth/login"), &wrong_body).await;
    assert_eq!(r.status(), 401);
    let wrong_failure: Value = r.json().await.unwrap();

    // Unknown user: same status and byte-identical failure shape.
    let unknown_body = json!({
        "email": "nobody@example.com",
        "auth_hash_client": B64.encode([7u8; 32]),
        "device_name": "dev-unknown",
    });
    let r = post_json(&client, &format!("{base}/v1/auth/login"), &unknown_body).await;
    assert_eq!(r.status(), 401);
    let unknown_failure: Value = r.json().await.unwrap();
    assert_eq!(
        wrong_failure, unknown_failure,
        "login failure shape must not leak whether the account exists"
    );
    assert_eq!(wrong_failure["error"], "unauthorized");

    // Malformed credential encoding is a client error (400), not auth failure.
    let malformed = json!({
        "email": "alice@example.com",
        "auth_hash_client": "!!!not-base64!!!",
        "device_name": "dev-malformed",
    });
    let r = post_json(&client, &format!("{base}/v1/auth/login"), &malformed).await;
    assert_eq!(r.status(), 400);

    // Blank device_name is rejected before any credential work.
    let blank_device = json!({
        "email": "alice@example.com",
        "auth_hash_client": B64.encode([7u8; 32]),
        "device_name": "   ",
    });
    let r = post_json(&client, &format!("{base}/v1/auth/login"), &blank_device).await;
    assert_eq!(r.status(), 400);
}

/// Authenticated routes resolve `Authorization: Bearer <token>` through the
/// `AuthSession` extractor; anything absent, malformed, or unknown is 401.
#[tokio::test]
async fn authenticated_routes_reject_missing_or_malformed_bearer_tokens() {
    let tmp = TempDir::new().unwrap();
    let addr = spawn_server(test_config(&tmp)).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    let (token, _) = register_user(&client, &base, "alice@example.com", "dev-1").await;

    let me_url = format!("{base}/v1/me");
    let bad_headers: [Option<&str>; 6] = [
        None,                       // no Authorization header at all
        Some("Bearer"),             // missing space
        Some("Bearer "),            // empty token
        Some("Bearer   "),          // whitespace-only token
        Some("Basic dXNlcjpwYXNz"), // wrong auth scheme
        Some("Bearer not-a-real-token"),
    ];
    for header in bad_headers {
        let mut req = client.get(&me_url);
        if let Some(value) = header {
            req = req.header("Authorization", value);
        }
        let r = req.send().await.unwrap();
        assert_eq!(r.status(), 401, "header {header:?} must be rejected");
    }

    // The same rejection applies to the blob and object write routes, which
    // resolve the session before reading the body.
    let r = client
        .put(format!("{base}/v1/blobs/full"))
        .header("Authorization", "Bearer forged-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    let r = client
        .put(format!("{base}/v1/objects/sync_profile_abc123"))
        .header("Authorization", "Bearer forged-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // The genuine token still authenticates.
    let r = client
        .get(&me_url)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

/// `POST /v1/auth/logout` deletes the device row backing the presented token;
/// afterwards that token is dead but sibling device tokens keep working.
#[tokio::test]
async fn logout_invalidates_only_the_current_session() {
    let tmp = TempDir::new().unwrap();
    let addr = spawn_server(test_config(&tmp)).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    let (token_a, _) = register_user(&client, &base, "alice@example.com", "dev-a").await;

    // Second device via login.
    let r = login(&client, &base, "alice@example.com", &[7u8; 32], "dev-b").await;
    assert_eq!(r.status(), 200);
    let token_b: Value = r.json().await.unwrap();
    let token_b = token_b["token"].as_str().unwrap().to_string();

    // Logout itself requires a session.
    let r = client
        .post(format!("{base}/v1/auth/logout"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // Logout device A.
    let r = client
        .post(format!("{base}/v1/auth/logout"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    // Token A is now rejected everywhere, including a second logout attempt.
    let r = client
        .get(format!("{base}/v1/me"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = client
        .post(format!("{base}/v1/auth/logout"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // Device B is untouched.
    let r = client
        .get(format!("{base}/v1/me"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

/// `/v1/auth/challenge` validates its payload (axum JSON rejections) and
/// surfaces 404 for unknown emails. Note: unlike login, the challenge endpoint
/// deliberately returns 404 for unknown emails (documented MVP trade-off in
/// `routes/auth.rs`), so it does allow account enumeration.
#[tokio::test]
async fn challenge_endpoint_rejects_malformed_payloads_and_unknown_emails() {
    let tmp = TempDir::new().unwrap();
    let addr = spawn_server(test_config(&tmp)).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    register_user(&client, &base, "alice@example.com", "dev-1").await;

    // Missing required field -> axum JSON data rejection.
    let r = post_json(&client, &format!("{base}/v1/auth/challenge"), &json!({})).await;
    assert_eq!(r.status(), 422);

    // Syntactically invalid JSON -> axum JSON syntax rejection.
    let r = client
        .post(format!("{base}/v1/auth/challenge"))
        .header("content-type", "application/json")
        .body("this is not json")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    // Unknown email -> 404 not_found (the code's documented behavior).
    let r = post_json(
        &client,
        &format!("{base}/v1/auth/challenge"),
        &json!({ "email": "nobody@example.com" }),
    )
    .await;
    assert_eq!(r.status(), 404);
    let err: Value = r.json().await.unwrap();
    assert_eq!(err["error"], "not_found");

    // Known email returns the exact salt registered for the user.
    let r = post_json(
        &client,
        &format!("{base}/v1/auth/challenge"),
        &json!({ "email": "alice@example.com" }),
    )
    .await;
    assert_eq!(r.status(), 200);
    let challenge: Value = r.json().await.unwrap();
    assert_eq!(challenge["kdf_salt_auth"], json!(B64.encode([1u8; 16])));
}

/// Open registration still rejects duplicates and malformed payloads.
#[tokio::test]
async fn registration_rejects_duplicates_and_malformed_payloads() {
    let tmp = TempDir::new().unwrap();
    let addr = spawn_server(test_config(&tmp)).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    register_user(&client, &base, "alice@example.com", "dev-1").await;

    // Duplicate email.
    let r = post_json(
        &client,
        &format!("{base}/v1/auth/register"),
        &registration_body("alice@example.com", "dev-2"),
    )
    .await;
    assert_eq!(r.status(), 400);
    let err: Value = r.json().await.unwrap();
    assert_eq!(err["error"], "bad_request");

    // Email without '@'.
    let r = post_json(
        &client,
        &format!("{base}/v1/auth/register"),
        &registration_body("not-an-email", "dev-3"),
    )
    .await;
    assert_eq!(r.status(), 400);

    // Blank device_name.
    let r = post_json(
        &client,
        &format!("{base}/v1/auth/register"),
        &registration_body("bob@example.com", "  "),
    )
    .await;
    assert_eq!(r.status(), 400);

    // auth_hash_client that is not valid base64.
    let mut body = registration_body("bob@example.com", "dev-4");
    body["auth_hash_client"] = json!("!!!not-base64!!!");
    let r = post_json(&client, &format!("{base}/v1/auth/register"), &body).await;
    assert_eq!(r.status(), 400);

    // Partial recovery field set (one of six) is rejected.
    let mut body = registration_body("bob@example.com", "dev-5");
    body["recovery_hash_client"] = json!(B64.encode([3u8; 32]));
    let r = post_json(&client, &format!("{base}/v1/auth/register"), &body).await;
    assert_eq!(r.status(), 400);
}

/// `registration = "closed"` rejects every signup with 403
/// `registration_disabled`.
#[tokio::test]
async fn closed_registration_policy_rejects_all_signups() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = test_config(&tmp);
    cfg.registration = RegistrationPolicy::Closed;
    let addr = spawn_server(cfg).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let r = post_json(
        &client,
        &format!("{base}/v1/auth/register"),
        &registration_body("alice@example.com", "dev-1"),
    )
    .await;
    assert_eq!(r.status(), 403);
    let err: Value = r.json().await.unwrap();
    assert_eq!(err["error"], "registration_disabled");
}

/// `registration = "invite_only"` rejects signups without a valid, unused
/// invite token. Tokens are seeded directly into the metadata database (the
/// only way to mint invites); the handler matches sha256(raw token) against
/// `invite_tokens`.
#[tokio::test]
async fn invite_only_registration_rejects_missing_unknown_and_used_tokens() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = test_config(&tmp);
    cfg.registration = RegistrationPolicy::InviteOnly;
    let addr = spawn_server(cfg).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Missing invite token.
    let r = post_json(
        &client,
        &format!("{base}/v1/auth/register"),
        &registration_body("alice@example.com", "dev-1"),
    )
    .await;
    assert_eq!(r.status(), 403);
    let err: Value = r.json().await.unwrap();
    assert_eq!(err["error"], "forbidden");

    // Unknown invite token.
    let mut body = registration_body("alice@example.com", "dev-2");
    body["invite_token"] = json!("not-a-valid-invite");
    let r = post_json(&client, &format!("{base}/v1/auth/register"), &body).await;
    assert_eq!(r.status(), 403);
    let err: Value = r.json().await.unwrap();
    assert_eq!(err["error"], "forbidden");

    // Seed an already-used invite token (used_at stamped by hand).
    let mut hasher = Sha256::new();
    hasher.update(b"already-used-invite-token");
    let used_token_hash: [u8; 32] = hasher.finalize().into();
    {
        let conn = Connection::open(tmp.path().join("metadata.db")).unwrap();
        conn.execute(
            "INSERT INTO invite_tokens (token_hash, note, created_at, used_at, used_by)
             VALUES (?1, 'used invite', '2026-01-01T00:00:00Z',
                     '2026-01-01T00:00:01Z', NULL)",
            [&used_token_hash[..]],
        )
        .unwrap();
    }

    // The used token is rejected exactly like an unknown one.
    let mut body = registration_body("bob@example.com", "dev-3");
    body["invite_token"] = json!("already-used-invite-token");
    let r = post_json(&client, &format!("{base}/v1/auth/register"), &body).await;
    assert_eq!(r.status(), 403);
    let err: Value = r.json().await.unwrap();
    assert_eq!(err["error"], "forbidden");
}

/// `registration = "invite_only"` accepts a signup carrying a valid, unused
/// invite token and marks that token used in the same transaction.
///
/// Regression test: the register transaction used to stamp
/// `invite_tokens.used_by` before inserting the user row, which always failed
/// the `used_by REFERENCES users(id)` foreign key under
/// `PRAGMA foreign_keys = ON` and turned the invite happy path into a 500.
#[tokio::test]
async fn invite_only_registration_accepts_a_valid_invite_token() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = test_config(&tmp);
    cfg.registration = RegistrationPolicy::InviteOnly;
    let addr = spawn_server(cfg).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let mut hasher = Sha256::new();
    hasher.update(b"valid-unused-invite-token");
    let token_hash: [u8; 32] = hasher.finalize().into();
    {
        let conn = Connection::open(tmp.path().join("metadata.db")).unwrap();
        conn.execute(
            "INSERT INTO invite_tokens (token_hash, note, created_at, used_at, used_by)
             VALUES (?1, 'valid invite', '2026-01-01T00:00:00Z', NULL, NULL)",
            [&token_hash[..]],
        )
        .unwrap();
    }

    let mut body = registration_body("alice@example.com", "dev-1");
    body["invite_token"] = json!("valid-unused-invite-token");
    let r = post_json(&client, &format!("{base}/v1/auth/register"), &body).await;
    assert_eq!(r.status(), 201, "valid invite must register successfully");

    // The token is spent: a second signup with the same token is rejected.
    let mut body = registration_body("bob@example.com", "dev-2");
    body["invite_token"] = json!("valid-unused-invite-token");
    let r = post_json(&client, &format!("{base}/v1/auth/register"), &body).await;
    assert_eq!(r.status(), 403);
}

// -----------------------------------------------------------------------------
// Recovery flow
// -----------------------------------------------------------------------------

/// Recovery challenge + reset: the happy path replaces the auth verifier, and
/// wrong recovery secrets are rejected with 401.
///
/// Note: the server has no challenge nonce or expiry for recovery (the
/// challenge endpoint only hands back KDF params), so there is no
/// stale/expired-challenge behavior to test.
#[tokio::test]
async fn recovery_flow_roundtrip_and_rejects_wrong_secret() {
    let tmp = TempDir::new().unwrap();
    let addr = spawn_server(test_config(&tmp)).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Alice registers WITH recovery material, Bob WITHOUT.
    let r = post_json(
        &client,
        &format!("{base}/v1/auth/register"),
        &registration_body_with_recovery("alice@example.com", "dev-1"),
    )
    .await;
    assert_eq!(r.status(), 201, "recovery registration failed");
    register_user(&client, &base, "bob@example.com", "dev-2").await;

    // Recovery challenge for Alice returns the registered recovery material.
    let r = post_json(
        &client,
        &format!("{base}/v1/auth/recovery/challenge"),
        &json!({ "email": "alice@example.com" }),
    )
    .await;
    assert_eq!(r.status(), 200);
    let challenge: Value = r.json().await.unwrap();
    assert_eq!(
        challenge["kdf_salt_recovery_auth"],
        json!(B64.encode([4u8; 16]))
    );
    assert_eq!(
        challenge["recovery_wrapped_dek"],
        json!(B64.encode([8u8; 48]))
    );

    // Bob never registered recovery material -> 404, same as unknown emails.
    let r = post_json(
        &client,
        &format!("{base}/v1/auth/recovery/challenge"),
        &json!({ "email": "bob@example.com" }),
    )
    .await;
    assert_eq!(r.status(), 404);
    let r = post_json(
        &client,
        &format!("{base}/v1/auth/recovery/challenge"),
        &json!({ "email": "nobody@example.com" }),
    )
    .await;
    assert_eq!(r.status(), 404);

    // Reset with a wrong recovery secret -> 401.
    let mut reset = json!({
        "email": "alice@example.com",
        "recovery_hash_client": B64.encode([0u8; 32]),
        "auth_hash_client": B64.encode([0x11u8; 32]),
        "kdf_salt_auth": B64.encode([6u8; 16]),
        "kdf_params_auth": { "m_cost": 4096, "t_cost": 3, "p_cost": 1, "out_len": 32 },
        "kdf_salt_kek": B64.encode([2u8; 16]),
        "kdf_params_kek": { "m_cost": 4096, "t_cost": 3, "p_cost": 1, "out_len": 32 },
        "wrapped_dek": B64.encode([0x0au8; 48]),
        "device_name": "post-recovery-dev",
    });
    let r = post_json(&client, &format!("{base}/v1/auth/recovery/reset"), &reset).await;
    assert_eq!(r.status(), 401, "wrong recovery secret must be rejected");

    // Reset for a user without recovery material -> 401 (no data leak).
    reset["email"] = json!("bob@example.com");
    reset["recovery_hash_client"] = json!(B64.encode([3u8; 32]));
    let r = post_json(&client, &format!("{base}/v1/auth/recovery/reset"), &reset).await;
    assert_eq!(r.status(), 401);

    // Reset for an unknown email -> 401 (identical auth-failure shape).
    reset["email"] = json!("nobody@example.com");
    let r = post_json(&client, &format!("{base}/v1/auth/recovery/reset"), &reset).await;
    assert_eq!(r.status(), 401);

    // Correct recovery secret: the auth credential is replaced.
    reset["email"] = json!("alice@example.com");
    reset["recovery_hash_client"] = json!(B64.encode([3u8; 32]));
    let r = post_json(&client, &format!("{base}/v1/auth/recovery/reset"), &reset).await;
    assert_eq!(
        r.status(),
        200,
        "recovery reset failed: {}",
        r.text().await.unwrap()
    );
    let reset_resp: Value = r.json().await.unwrap();
    let new_token = reset_resp["token"].as_str().unwrap().to_string();

    // The fresh token authenticates.
    let r = client
        .get(format!("{base}/v1/me"))
        .bearer_auth(&new_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let me: Value = r.json().await.unwrap();
    assert_eq!(me["email"], "alice@example.com");

    // The old auth hash no longer logs in; the new one does.
    let r = login(
        &client,
        &base,
        "alice@example.com",
        &[7u8; 32],
        "old-credential-dev",
    )
    .await;
    assert_eq!(r.status(), 401, "old auth hash must stop working");
    let r = login(
        &client,
        &base,
        "alice@example.com",
        &[0x11u8; 32],
        "new-credential-dev",
    )
    .await;
    assert_eq!(r.status(), 200, "new auth hash must log in");
}

// -----------------------------------------------------------------------------
// Devices
// -----------------------------------------------------------------------------

/// Device listing is scoped to the authenticated user, revocation is scoped by
/// `user_id`, and revoking a device kills exactly its token.
///
/// Note: there is no token-rotation endpoint on `/v1/devices` (only list +
/// revoke), so rotation is not tested.
#[tokio::test]
async fn device_listing_is_scoped_and_revocation_kills_tokens() {
    let tmp = TempDir::new().unwrap();
    let addr = spawn_server(test_config(&tmp)).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let (token_a1, device_a1) = register_user(&client, &base, "alice@example.com", "dev-a1").await;
    let r = login(&client, &base, "alice@example.com", &[7u8; 32], "dev-a2").await;
    assert_eq!(r.status(), 200);
    let device_a2: Value = r.json().await.unwrap();
    let token_a2 = device_a2["token"].as_str().unwrap().to_string();
    let device_a2 = device_a2["device_id"].as_str().unwrap().to_string();
    let (token_b, device_b) = register_user(&client, &base, "bob@example.com", "dev-b").await;

    // Listing shows only the caller's devices with is_current resolved.
    let r = client
        .get(format!("{base}/v1/devices"))
        .bearer_auth(&token_a1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let devices: Vec<Value> = r.json().await.unwrap();
    assert_eq!(devices.len(), 2);
    for device in &devices {
        let is_current = device["id"] == json!(device_a1);
        assert_eq!(
            device["is_current"], is_current,
            "is_current must only flag the calling device"
        );
    }

    let r = client
        .get(format!("{base}/v1/devices"))
        .bearer_auth(&token_a2)
        .send()
        .await
        .unwrap();
    let devices: Vec<Value> = r.json().await.unwrap();
    let current: Vec<&Value> = devices
        .iter()
        .filter(|d| d["is_current"] == json!(true))
        .collect();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0]["id"], json!(device_a2));

    // Cross-user revocation is a 404: the DELETE is scoped by user_id.
    let r = client
        .delete(format!("{base}/v1/devices/{device_a1}"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    // Unknown device id -> 404.
    let r = client
        .delete(format!("{base}/v1/devices/{}", uuid::Uuid::new_v4()))
        .bearer_auth(&token_a1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    // Revoking the second device kills its token but not the first.
    let r = client
        .delete(format!("{base}/v1/devices/{device_a2}"))
        .bearer_auth(&token_a1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let r = client
        .get(format!("{base}/v1/me"))
        .bearer_auth(&token_a2)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "revoked device token must stop working");
    let r = client
        .get(format!("{base}/v1/me"))
        .bearer_auth(&token_a1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = client
        .get(format!("{base}/v1/devices"))
        .bearer_auth(&token_a1)
        .send()
        .await
        .unwrap();
    let devices: Vec<Value> = r.json().await.unwrap();
    assert_eq!(devices.len(), 1);

    // Bob's devices are untouched by Alice's revocations.
    let r = client
        .get(format!("{base}/v1/me"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let me: Value = r.json().await.unwrap();
    assert_eq!(me["device_id"], json!(device_b));

    // Revoking the current device kills its own session too.
    let r = client
        .delete(format!("{base}/v1/devices/{device_a1}"))
        .bearer_auth(&token_a1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let r = client
        .get(format!("{base}/v1/me"))
        .bearer_auth(&token_a1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

// -----------------------------------------------------------------------------
// Blobs
// -----------------------------------------------------------------------------

/// Blob route validation, 404s, and per-user isolation. Isolation here is
/// structural: every blob query is filtered by the session's user_id.
#[tokio::test]
async fn blob_negative_paths_and_per_user_isolation() {
    let tmp = TempDir::new().unwrap();
    let addr = spawn_server(test_config(&tmp)).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    let (token_a, _) = register_user(&client, &base, "alice@example.com", "dev-a").await;
    let (token_b, _) = register_user(&client, &base, "bob@example.com", "dev-b").await;

    // Seed one revision for Alice.
    let cipher_v1 = B64.encode(b"alice secret v1");
    let put1 = json!({
        "expected_revision": 0,
        "manifest": { "files": [] },
        "ciphertext": cipher_v1,
    });
    let r = client
        .put(format!("{base}/v1/blobs/full"))
        .bearer_auth(&token_a)
        .json(&put1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // Bob sees nothing of Alice's blob: latest/revision 404, history empty.
    let r = client
        .get(format!("{base}/v1/blobs/full/latest"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "user B must not read user A's blob");
    let r = client
        .get(format!("{base}/v1/blobs/full/revisions/1"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let r = client
        .get(format!("{base}/v1/blobs/full/history"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let history: Vec<Value> = r.json().await.unwrap();
    assert!(history.is_empty());

    // Invalid kind characters are rejected on both read and write.
    let r = client
        .get(format!("{base}/v1/blobs/bad!kind/latest"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let put = json!({
        "expected_revision": 0,
        "manifest": {},
        "ciphertext": B64.encode(b"x"),
    });
    let r = client
        .put(format!("{base}/v1/blobs/bad!kind"))
        .bearer_auth(&token_a)
        .json(&put)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    // Kind longer than 64 characters -> 400.
    let long_kind = "a".repeat(65);
    let r = client
        .get(format!("{base}/v1/blobs/{long_kind}/latest"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    // Invalid base64 ciphertext -> 400.
    let put = json!({
        "expected_revision": 1,
        "manifest": {},
        "ciphertext": "!!!not-base64!!!",
    });
    let r = client
        .put(format!("{base}/v1/blobs/full"))
        .bearer_auth(&token_a)
        .json(&put)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    // Empty ciphertext (decodes to zero bytes) -> 400.
    let put = json!({
        "expected_revision": 1,
        "manifest": {},
        "ciphertext": "",
    });
    let r = client
        .put(format!("{base}/v1/blobs/full"))
        .bearer_auth(&token_a)
        .json(&put)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    // Non-numeric revision path parameter -> 400 (axum Path rejection).
    let r = client
        .get(format!("{base}/v1/blobs/full/revisions/notanumber"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    // Missing revision -> 404.
    let r = client
        .get(format!("{base}/v1/blobs/full/revisions/999"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    // GET on the PUT-only collection route -> 405.
    let r = client
        .get(format!("{base}/v1/blobs/full"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 405);

    // Alice's blob is intact after all the rejected attempts.
    let r = client
        .get(format!("{base}/v1/blobs/full/latest"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let blob: Value = r.json().await.unwrap();
    assert_eq!(blob["revision"], 1);
    assert_eq!(blob["ciphertext"], json!(cipher_v1));
}

/// Bodies larger than `max_blob_bytes` are rejected with 413 by the
/// `RequestBodyLimitLayer` applied in `router()` — this holds for blob and
/// object writes alike, while small requests on the same server still succeed.
#[tokio::test]
async fn oversized_request_bodies_are_rejected_with_413() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = test_config(&tmp);
    cfg.max_blob_bytes = 1024;
    let addr = spawn_server(cfg).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Sanity: a small registration body passes the 1 KiB limit.
    let (token, device_id) = register_user(&client, &base, "alice@example.com", "dev-1").await;

    let big_ciphertext = B64.encode(vec![0u8; 3072]); // ~4 KiB of base64

    // Blob PUT beyond the limit -> 413.
    let put = json!({
        "expected_revision": 0,
        "manifest": {},
        "ciphertext": big_ciphertext,
    });
    let r = client
        .put(format!("{base}/v1/blobs/full"))
        .bearer_auth(&token)
        .json(&put)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);

    // Object PUT beyond the limit -> 413 as well.
    let mut body = object_put_body(&device_id, None);
    body["ciphertext"] = json!(big_ciphertext);
    let r = client
        .put(format!("{base}/v1/objects/sync_profile_bigobj0001"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);

    // Nothing was stored.
    let r = client
        .get(format!("{base}/v1/blobs/full/latest"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

// -----------------------------------------------------------------------------
// Objects
// -----------------------------------------------------------------------------

/// `validate_put_request` rejects malformed object payloads with 400; serde
/// shape violations (unknown fields via `deny_unknown_fields`, invalid enum
/// values) surface as axum 422 rejections.
#[tokio::test]
async fn object_put_validation_rejects_invalid_payloads() {
    let tmp = TempDir::new().unwrap();
    let addr = spawn_server(test_config(&tmp)).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    let (token, device_id) = register_user(&client, &base, "alice@example.com", "dev-1").await;

    let url = format!("{base}/v1/objects/sync_profile_testobj0001");

    // (label, object_id for the URL, body patch). The object_id cases vary the
    // URL segment itself because the id travels in the path, not the body.
    let bad_cases: Vec<(&str, &str, Value)> = vec![
        (
            // object_id prefix must match object_kind.
            "prefix mismatch",
            "sync_credref_abc123",
            json!({}),
        ),
        (
            // Prefix present but no opaque suffix.
            "missing suffix",
            "sync_profile_",
            json!({}),
        ),
        (
            // Suffix with a character outside [A-Za-z0-9_-].
            "invalid suffix character",
            "sync_profile_ab$cd",
            json!({}),
        ),
        (
            "schema_version zero",
            "sync_profile_testobj0001",
            json!({ "schema_version": 0 }),
        ),
        (
            "object_version zero",
            "sync_profile_testobj0001",
            json!({ "object_version": 0 }),
        ),
        (
            "negative base_server_revision",
            "sync_profile_testobj0001",
            json!({ "base_server_revision": -1 }),
        ),
        (
            "payload_hash wrong scheme",
            "sync_profile_testobj0001",
            json!({ "payload_hash": format!("md5:{}", "a".repeat(64)) }),
        ),
        (
            "payload_hash not hex",
            "sync_profile_testobj0001",
            json!({ "payload_hash": format!("sha256:{}", "z".repeat(64)) }),
        ),
        (
            "payload_hash too short",
            "sync_profile_testobj0001",
            json!({ "payload_hash": "sha256:abc" }),
        ),
        (
            "payload_size zero",
            "sync_profile_testobj0001",
            json!({ "payload_size": 0 }),
        ),
        (
            "actor_id blank",
            "sync_profile_testobj0001",
            json!({ "updated_by": {
                "actor_type": "human", "actor_id": " ", "device_id": device_id } }),
        ),
        (
            "device_id blank",
            "sync_profile_testobj0001",
            json!({ "updated_by": {
                "actor_type": "human", "actor_id": "tester@example.com", "device_id": "" } }),
        ),
    ];

    for (label, object_id, patch) in bad_cases {
        let mut body = object_put_body(&device_id, None);
        for (key, value) in patch.as_object().unwrap() {
            body[key] = value.clone();
        }
        let target = format!("{base}/v1/objects/{object_id}");
        let r = client
            .put(&target)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400, "case '{label}' must be rejected");
        let err: Value = r.json().await.unwrap();
        assert_eq!(err["error"], "bad_request", "case '{label}'");
    }

    // Unknown field -> serde deny_unknown_fields -> axum 422.
    let mut body = object_put_body(&device_id, None);
    body["unexpected_field"] = json!(1);
    let r = client
        .put(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422);

    // Unknown object_kind enum value -> 422.
    let mut body = object_put_body(&device_id, None);
    body["object_kind"] = json!("bogus_kind");
    let r = client
        .put(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422);

    // Non-positive server_revision path parameters -> 400.
    for revision in ["0", "-1"] {
        let r = client
            .get(format!(
                "{base}/v1/objects/sync_profile_testobj0001/revisions/{revision}"
            ))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400, "revision {revision} must be rejected");
    }

    // History of an object that has no revisions -> 404.
    let r = client
        .get(format!(
            "{base}/v1/objects/sync_profile_neverwritten/history"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    // No object survived the rejected writes.
    let r = client
        .get(format!("{base}/v1/objects/sync_profile_testobj0001/latest"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

/// The most security-relevant invariant: object storage is scoped by user_id,
/// so a second user gets 404s for another user's object and can write its own
/// namespace without clobbering anyone else's data. Stale writes conflict.
#[tokio::test]
async fn object_data_is_isolated_per_user_and_stale_writes_conflict() {
    let tmp = TempDir::new().unwrap();
    let addr = spawn_server(test_config(&tmp)).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    let (token_a, device_a) = register_user(&client, &base, "alice@example.com", "dev-a").await;
    let (token_b, device_b) = register_user(&client, &base, "bob@example.com", "dev-b").await;

    let object_id = "sync_profile_shared0001";
    let object_url = format!("{base}/v1/objects/{object_id}");
    let cipher_a = B64.encode(b"alice object payload");
    let cipher_b = B64.encode(b"bob object payload");

    // Alice creates revision 1 (base revision omitted -> 0).
    let mut put_a = object_put_body(&device_a, None);
    put_a["ciphertext"] = json!(cipher_a);
    let r = client
        .put(&object_url)
        .bearer_auth(&token_a)
        .json(&put_a)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "alice put failed");
    let created: Value = r.json().await.unwrap();
    assert_eq!(created["server_revision"], 1);

    // Bob cannot read any view of Alice's object.
    let r = client
        .get(format!("{object_url}/latest"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "user B must not read user A's object");
    let r = client
        .get(format!("{object_url}/revisions/1"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let r = client
        .get(format!("{object_url}/history"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let r = client
        .get(format!("{base}/v1/objects"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    let listed: Vec<Value> = r.json().await.unwrap();
    assert!(listed.is_empty(), "user B must not list user A's objects");

    // Bob's stale-style write (base 0) creates HIS OWN revision 1; it must not
    // touch Alice's namespace even though the object_id string matches.
    let mut put_b = object_put_body(&device_b, None);
    put_b["ciphertext"] = json!(cipher_b);
    let r = client
        .put(&object_url)
        .bearer_auth(&token_b)
        .json(&put_b)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "bob put failed: {}",
        r.text().await.unwrap()
    );
    let bob_created: Value = r.json().await.unwrap();
    assert_eq!(bob_created["server_revision"], 1);

    // Alice's object is unchanged: same revision, same ciphertext.
    let r = client
        .get(format!("{object_url}/latest"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let alice_latest: Value = r.json().await.unwrap();
    assert_eq!(alice_latest["server_revision"], 1);
    assert_eq!(alice_latest["ciphertext"], json!(cipher_a));

    // Each user lists exactly their own object, with the digest of their own
    // ciphertext; the two users' digests differ even though the object_id
    // string is identical.
    let mut digests = Vec::new();
    for (token, cipher) in [(&token_a, &cipher_a), (&token_b, &cipher_b)] {
        let r = client
            .get(format!("{base}/v1/objects"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        let listed: Vec<Value> = r.json().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["object_id"], json!(object_id));
        let digest = listed[0]["ciphertext_sha256"].as_str().unwrap().to_string();
        assert_eq!(
            digest,
            hex_of(cipher),
            "stored digest must match the caller's own ciphertext"
        );
        digests.push(digest);
    }
    assert_ne!(
        digests[0], digests[1],
        "same object_id in different user namespaces must stay independent"
    );

    // Alice's stale write (explicit base revision 0 vs current 1) conflicts
    // with the redacted conflict body.
    let stale = object_put_body(&device_a, Some(0));
    let r = client
        .put(&object_url)
        .bearer_auth(&token_a)
        .json(&stale)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    let conflict: Value = r.json().await.unwrap();
    assert_eq!(conflict["code"], "sync.conflict.object_revision_mismatch");
    assert_eq!(conflict["current_server_revision"], 1);
    assert_eq!(conflict["attempted_base_server_revision"], 0);
    assert_eq!(
        conflict["server_updated_by"]["actor_id"],
        "<redacted:actor>"
    );
}

/// SHA-256 hex digest of a base64 string's decoded bytes — used only to assert
/// that per-user object digests differ; the server computes digests itself.
fn hex_of(b64_ciphertext: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    let raw = STANDARD.decode(b64_ciphertext).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&raw);
    hex::encode(hasher.finalize())
}

// -----------------------------------------------------------------------------
// Session / misc
// -----------------------------------------------------------------------------

/// Unmatched paths fall through to axum's default 404 (empty body, not the
/// ApiError JSON shape) and unsupported methods on matched paths yield 405.
#[tokio::test]
async fn unknown_routes_and_methods_return_framework_defaults() {
    let tmp = TempDir::new().unwrap();
    let addr = spawn_server(test_config(&tmp)).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Unknown route -> 404 with an empty (non-JSON) body.
    let r = client
        .get(format!("{base}/v1/definitely-not-a-route"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let body = r.text().await.unwrap();
    assert!(
        serde_json::from_str::<Value>(&body).is_err(),
        "unmatched routes use the framework default, not the ApiError body"
    );

    // Wrong method on a matched path -> 405.
    let r = client
        .delete(format!("{base}/v1/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 405);
    let r = client
        .get(format!("{base}/v1/auth/register"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 405);

    // Health endpoint stays open (no auth required).
    let r = client
        .get(format!("{base}/v1/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}
