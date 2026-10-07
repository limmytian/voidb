use std::fs;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let schemas_dir = Path::new("schemas");
    fs::create_dir_all(schemas_dir)?;

    let profile_schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "{{plugin_title}} Profile",
        "type": "object",
        "properties": {
            "endpoint": { "type": "string" },
            "password": { "type": "string" }
        }
    });

    let ping_input = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "message": { "type": "string" }
        }
    });

    let ping_output = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["ok"],
        "properties": {
            "ok": { "type": "boolean" },
            "reply": { "type": "string" }
        }
    });

    fs::write(schemas_dir.join("profile.schema.json"), serde_json::to_string_pretty(&profile_schema)? + "\n")?;
    fs::write(schemas_dir.join("ping-input.schema.json"), serde_json::to_string_pretty(&ping_input)? + "\n")?;
    fs::write(schemas_dir.join("ping-output.schema.json"), serde_json::to_string_pretty(&ping_output)? + "\n")?;

    println!("Exported schemas to schemas/");
    Ok(())
}
