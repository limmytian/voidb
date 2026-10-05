//! End-to-end smoke test: register -> login -> put -> pull -> conflict.
//!
//! Author: Limmy

use std::net::SocketAddr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::json;
use tempfile::TempDir;
use tokio::net::TcpListener;
use voidb_sync_server::{AppState, Config, RegistrationPolicy, router};

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

async fn register_user(
    client: &reqwest::Client,
    base: &str,
    email: &str,
    device_name: &str,
) -> (String, String) {
    let body = json!({
        "email": email,
        "auth_hash_client": B64.encode([7u8; 32]),
        "kdf_salt_auth": B64.encode([1u8; 16]),
        "kdf_params_auth": { "m_cost": 4096, "t_cost": 3, "p_cost": 1, "out_len": 32 },
        "kdf_salt_kek": B64.encode([2u8; 16]),
        "kdf_params_kek": { "m_cost": 4096, "t_cost": 3, "p_cost": 1, "out_len": 32 },
        "wrapped_dek": B64.encode([9u8; 48]),
        "device_name": device_name,
    });

    let response = client
        .post(format!("{base}/v1/auth/register"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        201,
        "register failed: {}",
        response.text().await.unwrap()
    );
    let body: serde_json::Value = response.json().await.unwrap();
    (
        body["token"].as_str().unwrap().to_string(),
        body["device_id"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn full_flow() {
    let _ = tracing_subscriber::fmt::try_init();
    let tmp = TempDir::new().unwrap();
    let mut cfg = test_config(&tmp);
    cfg.registration = RegistrationPolicy::Open;
    let addr = spawn_server(cfg).await;

    let base = format!("http://{}", addr);
    let client = reqwest::Client::new();

    // healthz
    let r = client
        .get(format!("{base}/v1/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // register
    let auth_hash = B64.encode([7u8; 32]);
    let wrapped_dek = B64.encode([9u8; 48]);
    let kdf_salt = B64.encode([1u8; 16]);
    let body = json!({
        "email": "alice@example.com",
        "auth_hash_client": auth_hash,
        "kdf_salt_auth": kdf_salt,
        "kdf_params_auth": { "m_cost": 4096, "t_cost": 3, "p_cost": 1, "out_len": 32 },
        "kdf_salt_kek": kdf_salt,
        "kdf_params_kek": { "m_cost": 4096, "t_cost": 3, "p_cost": 1, "out_len": 32 },
        "wrapped_dek": wrapped_dek,
        "device_name": "dev-1",
    });

    let r = client
        .post(format!("{base}/v1/auth/register"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "register failed: {}", r.text().await.unwrap());
    let reg: serde_json::Value = r.json().await.unwrap();
    let token = reg["token"].as_str().unwrap().to_string();

    // me
    let r = client
        .get(format!("{base}/v1/me"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let me: serde_json::Value = r.json().await.unwrap();
    assert_eq!(me["email"], "alice@example.com");
    assert_eq!(me["devices"].as_array().unwrap().len(), 1);

    // put revision 1
    let cipher = B64.encode(b"fake encrypted bundle v1");
    let put1 = json!({
        "expected_revision": 0,
        "manifest": { "files": [{ "path": "config.toml", "sha256": "abc" }] },
        "ciphertext": cipher,
    });
    let r = client
        .put(format!("{base}/v1/blobs/full"))
        .bearer_auth(&token)
        .json(&put1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let pr: serde_json::Value = r.json().await.unwrap();
    assert_eq!(pr["revision"], 1);

    // stale put should 409
    let r = client
        .put(format!("{base}/v1/blobs/full"))
        .bearer_auth(&token)
        .json(&put1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    let err: serde_json::Value = r.json().await.unwrap();
    assert_eq!(err["current_revision"], 1);

    // put revision 2
    let cipher2 = B64.encode(b"fake encrypted bundle v2");
    let put2 = json!({
        "expected_revision": 1,
        "manifest": {},
        "ciphertext": cipher2,
    });
    let r = client
        .put(format!("{base}/v1/blobs/full"))
        .bearer_auth(&token)
        .json(&put2)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // pull latest
    let r = client
        .get(format!("{base}/v1/blobs/full/latest"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let blob: serde_json::Value = r.json().await.unwrap();
    assert_eq!(blob["revision"], 2);
    assert_eq!(blob["ciphertext"], cipher2);

    // history
    let r = client
        .get(format!("{base}/v1/blobs/full/history"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let hist: Vec<serde_json::Value> = r.json().await.unwrap();
    assert_eq!(hist.len(), 2);

    // login reuses the verifier.
    let login_body = json!({
        "email": "alice@example.com",
        "auth_hash_client": auth_hash,
        "device_name": "dev-2",
    });
    let r = client
        .post(format!("{base}/v1/auth/login"))
        .json(&login_body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "login failed: {}", r.text().await.unwrap());
    let login: serde_json::Value = r.json().await.unwrap();
    assert_eq!(login["wrapped_dek"], wrapped_dek);

    // wrong auth hash rejected.
    let login_body_bad = json!({
        "email": "alice@example.com",
        "auth_hash_client": B64.encode([0u8; 32]),
        "device_name": "dev-bad",
    });
    let r = client
        .post(format!("{base}/v1/auth/login"))
        .json(&login_body_bad)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn object_sync_flow_returns_redacted_conflicts() {
    let _ = tracing_subscriber::fmt::try_init();
    let tmp = TempDir::new().unwrap();
    let mut cfg = test_config(&tmp);
    cfg.registration = RegistrationPolicy::Open;
    let addr = spawn_server(cfg).await;

    let base = format!("http://{}", addr);
    let client = reqwest::Client::new();
    let (alice_token, alice_device_id) =
        register_user(&client, &base, "alice@example.com", "alice-dev").await;

    let object_id = "sync_profile_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V";
    let payload_hash_v1 = format!("sha256:{}", "a".repeat(64));
    let ciphertext_v1 = B64.encode(b"fake encrypted object v1");
    let put_v1 = json!({
        "schema_version": 1,
        "object_kind": "profile",
        "object_version": 1,
        "payload_hash": payload_hash_v1,
        "payload_size": 24,
        "updated_at": "2026-07-04T15:00:00Z",
        "updated_by": {
            "actor_type": "human",
            "actor_id": "alice@example.com",
            "device_id": alice_device_id,
        },
        "deleted": false,
        "redaction": "withheld",
        "ciphertext": ciphertext_v1,
    });

    let response = client
        .put(format!("{base}/v1/objects/{object_id}"))
        .bearer_auth(&alice_token)
        .json(&put_v1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "put failed: {}",
        response.text().await.unwrap()
    );
    let created: serde_json::Value = response.json().await.unwrap();
    assert_eq!(created["server_revision"], 1);
    let created_json = serde_json::to_string(&created).unwrap();
    assert!(!created_json.contains("alice@example.com"));
    assert!(!created_json.contains("ciphertext"));

    let payload_hash_v2 = format!("sha256:{}", "b".repeat(64));
    let stale_put = json!({
        "schema_version": 1,
        "object_kind": "profile",
        "object_version": 2,
        "base_server_revision": 0,
        "payload_hash": payload_hash_v2,
        "payload_size": 24,
        "updated_at": "2026-07-04T15:05:00Z",
        "updated_by": {
            "actor_type": "human",
            "actor_id": "alice@example.com",
            "device_id": alice_device_id,
        },
        "deleted": false,
        "redaction": "withheld",
        "ciphertext": B64.encode(b"fake encrypted object v2"),
    });
    let response = client
        .put(format!("{base}/v1/objects/{object_id}"))
        .bearer_auth(&alice_token)
        .json(&stale_put)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 409);
    let conflict: serde_json::Value = response.json().await.unwrap();
    assert_eq!(conflict["code"], "sync.conflict.object_revision_mismatch");
    assert_eq!(conflict["current_server_revision"], 1);
    assert_eq!(
        conflict["server_updated_by"]["actor_id"],
        "<redacted:actor>"
    );
    let conflict_json = serde_json::to_string(&conflict).unwrap();
    assert!(!conflict_json.contains("alice@example.com"));
    assert!(!conflict_json.contains("fake encrypted object"));

    let (bob_token, _) = register_user(&client, &base, "bob@example.com", "bob-dev").await;
    let response = client
        .get(format!("{base}/v1/objects/{object_id}/latest"))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);

    let tombstone_ciphertext = B64.encode(b"object tombstone marker");
    let tombstone_put = json!({
        "schema_version": 1,
        "object_kind": "profile",
        "object_version": 2,
        "base_server_revision": 1,
        "payload_hash": format!("sha256:{}", "c".repeat(64)),
        "payload_size": 23,
        "updated_at": "2026-07-04T15:10:00Z",
        "updated_by": {
            "actor_type": "human",
            "actor_id": "alice@example.com",
            "device_id": alice_device_id,
        },
        "deleted": true,
        "redaction": "withheld",
        "ciphertext": tombstone_ciphertext,
    });
    let response = client
        .put(format!("{base}/v1/objects/{object_id}"))
        .bearer_auth(&alice_token)
        .json(&tombstone_put)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "tombstone failed: {}",
        response.text().await.unwrap()
    );
    let tombstone: serde_json::Value = response.json().await.unwrap();
    assert_eq!(tombstone["server_revision"], 2);

    let response = client
        .get(format!("{base}/v1/objects/{object_id}/latest"))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let latest: serde_json::Value = response.json().await.unwrap();
    assert_eq!(latest["server_revision"], 2);
    assert_eq!(latest["deleted"], true);
    assert_eq!(latest["updated_by"]["actor_id"], "<redacted:actor>");
    assert_eq!(latest["ciphertext"], tombstone_ciphertext);
    assert!(latest["manifest"].get("ciphertext").is_none());

    let response = client
        .get(format!("{base}/v1/objects/{object_id}/history"))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let history: Vec<serde_json::Value> = response.json().await.unwrap();
    assert_eq!(history.len(), 2);

    let response = client
        .get(format!("{base}/v1/objects"))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let active_objects: Vec<serde_json::Value> = response.json().await.unwrap();
    assert!(active_objects.is_empty());

    let response = client
        .get(format!("{base}/v1/objects?include_deleted=true"))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let all_objects: Vec<serde_json::Value> = response.json().await.unwrap();
    assert_eq!(all_objects.len(), 1);
    assert!(all_objects[0].get("ciphertext").is_none());
    assert!(all_objects[0]["manifest"].get("ciphertext").is_none());
    let listed_json = serde_json::to_string(&all_objects).unwrap();
    assert!(!listed_json.contains("alice@example.com"));
    assert!(!listed_json.contains("fake encrypted object"));
}
