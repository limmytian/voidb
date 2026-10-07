use voidb_core::{CapabilityInvocation, InvocationConnectionTarget, InvocationControls};
use voidb_process_plugin_sdk::{CapabilityRouter, ProcessPluginHandler};

#[test]
fn test_ping_capability_succeeds() {
    let mut router = CapabilityRouter::new("{{plugin_name}}")
        .capability("ping", |invocation, _grants| {
            Ok(voidb_core::CapabilityInvocationResult {
                invocation_id: invocation.id,
                status: voidb_core::InvocationStatus::Succeeded,
                output: serde_json::json!({ "reply": "pong", "ok": true }),
                output_summary: serde_json::json!({ "reply": "pong" }),
                page: None,
            })
        });

    let invocation = CapabilityInvocation {
        id: "inv-001".into(),
        plugin_id: "{{plugin_name}}".into(),
        capability_id: "ping".into(),
        connection: InvocationConnectionTarget::Stateless,
        input: serde_json::json!({ "message": "hello" }),
        controls: InvocationControls::default(),
        actor: None,
        requested_at: chrono::Utc::now(),
    };

    let result = router.invoke(invocation, Vec::new()).expect("ping invocation");
    assert_eq!(result.status, voidb_core::InvocationStatus::Succeeded);
    assert_eq!(result.output["ok"], true);
}

fn main() {
    println!("Smoke test passed.");
}
