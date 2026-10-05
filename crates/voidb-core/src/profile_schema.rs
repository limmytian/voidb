//! Schema-driven connection-profile form contract.
//!
//! The contract is deliberately UI-agnostic. Plugins describe fields, choices,
//! conditional visibility, and secret handling; terminal, desktop, and web
//! clients can render the same model without importing protocol drivers.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileFormSchema {
    pub plugin_id: String,
    pub title: String,
    pub fields: Vec<ProfileFormField>,
}

impl ProfileFormSchema {
    pub fn visible_fields<'a>(&'a self, config: &Value) -> Vec<&'a ProfileFormField> {
        self.fields
            .iter()
            .filter(|field| field.is_visible(config))
            .collect()
    }

    pub fn validate(&self, config: &Value) -> Vec<ProfileFormViolation> {
        let mut violations = Vec::new();
        if !config.is_object() {
            violations.push(ProfileFormViolation {
                path: "/".to_string(),
                message: "Plugin configuration must be a JSON object".to_string(),
            });
            return violations;
        }

        for field in self.visible_fields(config) {
            let value = field.current_value(config);
            let missing_required = match &field.kind {
                ProfileFormFieldKind::Select { options } => !options
                    .iter()
                    .any(|option| option.matches_config(&field.path, config)),
                _ => is_empty(value),
            };
            if field.required && missing_required {
                violations.push(ProfileFormViolation {
                    path: field.path.clone(),
                    message: format!("{} is required", field.label),
                });
                continue;
            }
            let Some(value) = value.filter(|value| !value.is_null()) else {
                continue;
            };
            let valid = match &field.kind {
                ProfileFormFieldKind::Text { .. } | ProfileFormFieldKind::Secret => {
                    value.is_string()
                }
                ProfileFormFieldKind::Integer { minimum, maximum } => value
                    .as_i64()
                    .map(|number| {
                        minimum.is_none_or(|minimum| number >= minimum)
                            && maximum.is_none_or(|maximum| number <= maximum)
                    })
                    .unwrap_or(false),
                ProfileFormFieldKind::Boolean => value.is_boolean(),
                ProfileFormFieldKind::Select { options } => options
                    .iter()
                    .any(|option| option.matches_config(&field.path, config)),
                ProfileFormFieldKind::StringList => value
                    .as_array()
                    .map(|items| items.iter().all(Value::is_string))
                    .unwrap_or(false),
            };
            if !valid {
                violations.push(ProfileFormViolation {
                    path: field.path.clone(),
                    message: format!("{} has an invalid value", field.label),
                });
            }
        }
        violations
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileFormField {
    /// RFC 6901 JSON pointer into the plugin configuration document.
    pub path: String,
    pub label: String,
    pub description: String,
    pub required: bool,
    pub kind: ProfileFormFieldKind,
    #[serde(default)]
    pub visible_when: Vec<ProfileFormCondition>,
}

impl ProfileFormField {
    pub fn is_visible(&self, config: &Value) -> bool {
        self.visible_when
            .iter()
            .all(|condition| condition.matches(config))
    }

    pub fn current_value<'a>(&'a self, config: &'a Value) -> Option<&'a Value> {
        match &self.kind {
            ProfileFormFieldKind::Select { options } => options
                .iter()
                .find(|option| option.matches_config(&self.path, config))
                .map(|option| &option.value),
            _ => config.pointer(&self.path),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProfileFormFieldKind {
    Text {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        format: Option<String>,
    },
    Secret,
    Integer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        minimum: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        maximum: Option<i64>,
    },
    Boolean,
    Select {
        options: Vec<ProfileFormOption>,
    },
    StringList,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileFormOption {
    pub label: String,
    /// Logical choice value, used for display and conditional selection.
    pub value: Value,
    /// When present, replace the field path with this complete JSON value.
    /// This represents tagged unions such as SSH authentication methods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<Value>,
}

impl ProfileFormOption {
    pub fn matches_config(&self, path: &str, config: &Value) -> bool {
        let current = config.pointer(path);
        match &self.replacement {
            Some(Value::Object(template)) => template
                .get("type")
                .map(|expected| current.and_then(|value| value.get("type")) == Some(expected))
                .unwrap_or_else(|| current == self.replacement.as_ref()),
            Some(Value::Null) => current.is_none_or(Value::is_null),
            Some(replacement) => current == Some(replacement),
            None => current == Some(&self.value),
        }
    }

    pub fn stored_value(&self) -> Value {
        self.replacement
            .clone()
            .unwrap_or_else(|| self.value.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileFormCondition {
    pub path: String,
    pub equals: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_of: Vec<Value>,
}

impl ProfileFormCondition {
    pub fn matches(&self, config: &Value) -> bool {
        let current = config.pointer(&self.path);
        if self.one_of.is_empty() {
            current == Some(&self.equals)
        } else {
            current.is_some_and(|current| self.one_of.iter().any(|value| value == current))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileFormViolation {
    pub path: String,
    pub message: String,
}

fn is_empty(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(value)) => value.trim().is_empty(),
        Some(Value::Array(items)) => items.is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn tagged_select_matches_and_validates_visible_fields() {
        let schema = ProfileFormSchema {
            plugin_id: "ssh".into(),
            title: "SSH".into(),
            fields: vec![
                ProfileFormField {
                    path: "/auth".into(),
                    label: "Authentication".into(),
                    description: String::new(),
                    required: true,
                    kind: ProfileFormFieldKind::Select {
                        options: vec![ProfileFormOption {
                            label: "Password".into(),
                            value: json!("Password"),
                            replacement: Some(json!({"type":"Password","password":""})),
                        }],
                    },
                    visible_when: Vec::new(),
                },
                ProfileFormField {
                    path: "/auth/password".into(),
                    label: "Password".into(),
                    description: String::new(),
                    required: true,
                    kind: ProfileFormFieldKind::Secret,
                    visible_when: vec![ProfileFormCondition {
                        path: "/auth/type".into(),
                        equals: json!("Password"),
                        one_of: Vec::new(),
                    }],
                },
            ],
        };

        let config = json!({"auth":{"type":"Password","password":"secret"}});
        assert_eq!(schema.visible_fields(&config).len(), 2);
        assert!(schema.validate(&config).is_empty());
        assert_eq!(
            schema.fields[0].current_value(&config),
            Some(&json!("Password"))
        );
    }

    #[test]
    fn required_visible_secret_is_validated_without_exposing_it() {
        let schema = ProfileFormSchema {
            plugin_id: "ssh".into(),
            title: "SSH".into(),
            fields: vec![ProfileFormField {
                path: "/password".into(),
                label: "Password".into(),
                description: String::new(),
                required: true,
                kind: ProfileFormFieldKind::Secret,
                visible_when: Vec::new(),
            }],
        };
        let violations = schema.validate(&json!({"password":""}));
        assert_eq!(violations[0].path, "/password");
        assert!(!format!("{violations:?}").contains("secret-value"));
    }
}
