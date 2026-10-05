//! Shared redaction helpers for agent-facing output.
//!
//! These helpers classify legacy plugin config fields and redact values before
//! diagnostics, audit records, or CLI payloads cross into agent-visible text.

use serde_json::Value;

use crate::capability::{CredentialClass, RedactionStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactionTargetKind {
    Credential(CredentialClass),
    SensitiveMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionTarget {
    pub path: String,
    pub value: String,
    pub placeholder: &'static str,
    pub kind: RedactionTargetKind,
}

pub fn credential_class_for_key(key: &str) -> Option<CredentialClass> {
    let key = normalized_key(key);

    if contains_any(&key, &["private_key", "privatekey"]) {
        return Some(CredentialClass::PrivateKey);
    }
    if contains_any(&key, &["client_certificate", "client_cert", "certificate"]) {
        return Some(CredentialClass::ClientCertificate);
    }
    if contains_any(&key, &["secret_key", "secretkey"]) {
        return Some(CredentialClass::CloudSecretKey);
    }
    if contains_any(&key, &["access_key", "accesskey"]) {
        return Some(CredentialClass::CloudAccessKey);
    }
    if contains_any(&key, &["api_key", "apikey"]) {
        return Some(CredentialClass::ApiKey);
    }
    if contains_any(
        &key,
        &[
            "access_token",
            "refresh_token",
            "bearer_token",
            "auth_token",
            "token",
            "authorization",
            "cookie",
        ],
    ) {
        return Some(CredentialClass::Token);
    }
    if contains_any(&key, &["password", "passwd", "passphrase"]) {
        return Some(CredentialClass::Password);
    }
    if contains_any(&key, &["credential", "credentials", "secret"]) {
        return Some(CredentialClass::Other("credential".into()));
    }

    None
}

pub fn is_sensitive_metadata_key(key: &str) -> bool {
    let key = normalized_key(key);

    contains_any(
        &key,
        &[
            "host",
            "hostname",
            "endpoint",
            "url",
            "uri",
            "username",
            "user",
            "account",
            "account_id",
            "tenant",
            "tenant_id",
            "database",
            "db_name",
            "bucket",
        ],
    )
}

pub fn collect_redaction_targets(value: &Value) -> Vec<RedactionTarget> {
    let mut targets = Vec::new();
    collect_targets(value, String::new(), None, &mut targets);
    targets.sort_by(|left, right| {
        right
            .value
            .len()
            .cmp(&left.value.len())
            .then_with(|| left.path.cmp(&right.path))
    });
    targets
        .dedup_by(|left, right| left.value == right.value && left.placeholder == right.placeholder);
    targets
}

pub fn redact_text_with_json(text: &str, value: &Value) -> (String, RedactionStatus) {
    let targets = collect_redaction_targets(value);
    redact_text_with_targets(text, &targets)
}

pub fn redact_text_with_targets(
    text: &str,
    targets: &[RedactionTarget],
) -> (String, RedactionStatus) {
    let mut redacted = text.to_string();

    for target in targets {
        if target.value.len() >= 4 {
            redacted = redacted.replace(&target.value, target.placeholder);
        }
    }

    redacted = redact_credential_bearing_urls(&redacted);

    let status = if redacted == text {
        RedactionStatus::NotRequired
    } else {
        RedactionStatus::Applied
    };

    (redacted, status)
}

pub fn placeholder_for_credential_class(class: &CredentialClass) -> &'static str {
    match class {
        CredentialClass::Password => "<redacted:password>",
        CredentialClass::Token => "<redacted:token>",
        CredentialClass::ApiKey => "<redacted:api_key>",
        CredentialClass::PrivateKey => "<redacted:private_key>",
        CredentialClass::ClientCertificate
        | CredentialClass::CloudAccessKey
        | CredentialClass::CloudSecretKey
        | CredentialClass::Other(_) => "<redacted:credential>",
    }
}

fn collect_targets(
    value: &Value,
    path: String,
    inherited_kind: Option<RedactionTargetKind>,
    targets: &mut Vec<RedactionTarget>,
) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let field_path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{}.{}", path, key)
                };
                let field_kind = field_kind(key).or_else(|| inherited_kind.clone());
                collect_targets(value, field_path, field_kind, targets);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let item_path = format!("{}[{}]", path, index);
                collect_targets(item, item_path, inherited_kind.clone(), targets);
            }
        }
        Value::String(value) => {
            let Some(kind) = inherited_kind else {
                return;
            };
            if value.is_empty() {
                return;
            }
            let placeholder = match &kind {
                RedactionTargetKind::Credential(class) => placeholder_for_credential_class(class),
                RedactionTargetKind::SensitiveMetadata => "<redacted:sensitive_metadata>",
            };
            targets.push(RedactionTarget {
                path,
                value: value.clone(),
                placeholder,
                kind,
            });
        }
        _ => {}
    }
}

fn field_kind(key: &str) -> Option<RedactionTargetKind> {
    credential_class_for_key(key)
        .map(RedactionTargetKind::Credential)
        .or_else(|| {
            is_sensitive_metadata_key(key).then_some(RedactionTargetKind::SensitiveMetadata)
        })
}

fn redact_credential_bearing_urls(text: &str) -> String {
    let mut output = String::new();
    let mut token = String::new();

    for ch in text.chars() {
        if ch.is_whitespace() {
            if !token.is_empty() {
                output.push_str(&redact_credential_bearing_url_token(&token));
                token.clear();
            }
            output.push(ch);
        } else {
            token.push(ch);
        }
    }

    if !token.is_empty() {
        output.push_str(&redact_credential_bearing_url_token(&token));
    }

    output
}

fn redact_credential_bearing_url_token(token: &str) -> String {
    let Some(scheme_end) = token.find("://") else {
        return token.to_string();
    };
    let authority_start = scheme_end + 3;
    let authority_end = token[authority_start..]
        .find(['/', '?', '#'])
        .map(|offset| authority_start + offset)
        .unwrap_or(token.len());
    let authority = &token[authority_start..authority_end];
    let Some(at_index) = authority.rfind('@') else {
        return token.to_string();
    };

    format!(
        "{}<redacted:credential>@{}{}",
        &token[..authority_start],
        &authority[at_index + 1..],
        &token[authority_end..]
    )
}

fn normalized_key(key: &str) -> String {
    key.to_ascii_lowercase().replace(['-', '.'], "_")
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn classifies_common_credential_fields() {
        assert_eq!(
            credential_class_for_key("password"),
            Some(CredentialClass::Password)
        );
        assert_eq!(
            credential_class_for_key("refresh_token"),
            Some(CredentialClass::Token)
        );
        assert_eq!(
            credential_class_for_key("api-key"),
            Some(CredentialClass::ApiKey)
        );
        assert_eq!(
            credential_class_for_key("private_key"),
            Some(CredentialClass::PrivateKey)
        );
        assert_eq!(credential_class_for_key("redis_key"), None);
    }

    #[test]
    fn collects_secret_and_sensitive_metadata_values() {
        let config = json!({
            "host": "db.internal.example",
            "username": "app_user",
            "password": "secret-password",
            "auth": {
                "api_key": "api-secret"
            }
        });

        let targets = collect_redaction_targets(&config);

        assert!(
            targets
                .iter()
                .any(|target| target.value == "secret-password"
                    && target.placeholder == "<redacted:password>")
        );
        assert!(targets.iter().any(
            |target| target.value == "api-secret" && target.placeholder == "<redacted:api_key>"
        ));
        assert!(
            targets
                .iter()
                .any(|target| target.value == "db.internal.example"
                    && target.placeholder == "<redacted:sensitive_metadata>")
        );
    }

    #[test]
    fn redacts_text_with_config_values_and_credential_urls() {
        let config = json!({
            "host": "redis.internal.example",
            "password": "redis-secret"
        });

        let (redacted, status) = redact_text_with_json(
            "failed redis://:redis-secret@redis.internal.example/0 against redis.internal.example",
            &config,
        );

        assert_eq!(status, RedactionStatus::Applied);
        assert!(!redacted.contains("redis-secret"));
        assert!(!redacted.contains("redis.internal.example"));
        assert!(redacted.contains("<redacted:credential>"));
        assert!(redacted.contains("<redacted:sensitive_metadata>"));
    }
}
