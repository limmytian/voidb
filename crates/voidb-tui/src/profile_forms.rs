//! Built-in profile form catalog.
//!
//! This is the in-process adapter for bundled plugins. The data uses the Core
//! form contract so the Connection Manager renderer is generic. Process
//! plugins can expose the same shape from their manifest profile schema.

use serde_json::{Value, json};
use voidb_core::{
    ProfileFormCondition, ProfileFormField, ProfileFormFieldKind, ProfileFormOption,
    ProfileFormSchema,
};

pub fn default_plugin_config(plugin_id: &str) -> Value {
    match plugin_id {
        "mysql" => {
            json!({"host":"localhost","port":3306,"username":"root","password":"","database":null,"ssl_mode":"preferred"})
        }
        "postgres" => {
            json!({"host":"localhost","port":5432,"username":"postgres","password":"","database":"postgres","ssl_mode":null})
        }
        "sqlite" => json!({"path":"./data.db"}),
        "redis" => {
            json!({"host":"127.0.0.1","port":6379,"password":null,"username":null,"db":0,"tls":false})
        }
        "ssh" => {
            json!({"host":"localhost","port":22,"username":"root","auth":{"type":"Agent"},"terminal":{"term_type":"xterm-256color","scrollback":1000},"options":{"keep_alive_interval":30,"connect_timeout":10,"max_reconnect_attempts":5,"reconnect_base_delay":1}})
        }
        "docker" => json!({"connection":{"type":"Local"},"timeout":30}),
        "kubernetes" => {
            json!({"connection":{"type":"Kubeconfig","path":null,"context":null},"default_namespace":null,"timeout":30})
        }
        "webdav" => {
            json!({"url":"https://dav.example.com/","auth":{"type":"None"},"timeout":30,"verify_ssl":true})
        }
        "s3" => {
            json!({"provider":{"type":"Aws","region":"us-east-1"},"bucket":null,"auth":{"type":"Auto"},"timeout":30})
        }
        "elasticsearch" => {
            json!({"urls":["http://localhost:9200"],"auth":null,"timeout":30,"verify_ssl":true})
        }
        "mongodb" => {
            json!({"uri":"mongodb://localhost:27017","default_db":null,"auth":null,"timeout":10,"tls":{"enabled":false,"ca_file":null,"allow_invalid_certs":false}})
        }
        "duckdb" => {
            json!({"path":"./data.duckdb","read_only":false,"extensions":[],"memory_limit":null,"threads":null})
        }
        "email" => {
            json!({"email":"user@example.com","password":"","protocol":"IMAP","receive":{"host":"imap.example.com","port":993},"smtp":{"host":"smtp.example.com","port":587},"receive_security":"SSL/TLS","smtp_security":"STARTTLS","verify_tls":true})
        }
        "jenkins" => {
            json!({"url":"https://jenkins.example.com","auth":{"type":"None"},"timeout":30,"verify_ssl":true})
        }
        _ => json!({}),
    }
}

pub fn profile_form_schema(plugin_id: &str) -> ProfileFormSchema {
    let fields = match plugin_id {
        "mysql" => mysql_fields(),
        "postgres" => postgres_fields(),
        "sqlite" => sqlite_fields(),
        "redis" => redis_fields(),
        "ssh" => ssh_fields(),
        "docker" => docker_fields(),
        "kubernetes" => kubernetes_fields(),
        "webdav" => webdav_fields(),
        "s3" => s3_fields(),
        "elasticsearch" => elasticsearch_fields(),
        "mongodb" => mongodb_fields(),
        "duckdb" => duckdb_fields(),
        "email" => email_fields(),
        "jenkins" => jenkins_fields(),
        _ => Vec::new(),
    };
    ProfileFormSchema {
        plugin_id: plugin_id.to_string(),
        title: plugin_id.to_string(),
        fields,
    }
}

fn mysql_fields() -> Vec<ProfileFormField> {
    vec![
        text(
            "/host",
            "Host",
            "MySQL server hostname or IP address",
            true,
            "host",
        ),
        integer("/port", "Port", "TCP port", true, Some(1), Some(65535)),
        text(
            "/username",
            "Username",
            "Database account",
            true,
            "username",
        ),
        secret("/password", "Password", "Database password", false),
        text(
            "/database",
            "Database",
            "Optional default database",
            false,
            "database",
        ),
        select(
            "/ssl_mode",
            "TLS mode",
            "Certificate verification policy",
            false,
            vec![
                choice("Disabled", json!("disabled")),
                choice("Preferred", json!("preferred")),
                choice("Required", json!("required")),
                choice("Verify CA", json!("verify_ca")),
                choice("Verify identity", json!("verify_identity")),
                choice("Plugin default", Value::Null),
            ],
        ),
        text(
            "/charset",
            "Character set",
            "Optional connection character set",
            false,
            "text",
        ),
        integer(
            "/pool_size",
            "Pool size",
            "Optional connection pool size",
            false,
            Some(1),
            None,
        ),
        integer(
            "/connect_timeout_ms",
            "Connect timeout (ms)",
            "Optional connection timeout",
            false,
            Some(1),
            None,
        ),
    ]
}

fn postgres_fields() -> Vec<ProfileFormField> {
    vec![
        text(
            "/host",
            "Host",
            "PostgreSQL server hostname or IP address",
            true,
            "host",
        ),
        integer("/port", "Port", "TCP port", true, Some(1), Some(65535)),
        text(
            "/username",
            "Username",
            "Database account",
            true,
            "username",
        ),
        secret("/password", "Password", "Database password", false),
        text(
            "/database",
            "Database",
            "Default database",
            true,
            "database",
        ),
        select(
            "/ssl_mode",
            "TLS mode",
            "PostgreSQL SSL mode",
            false,
            vec![
                choice("Disable", json!("disable")),
                choice("Prefer", json!("prefer")),
                choice("Require", json!("require")),
                choice("Plugin default", Value::Null),
            ],
        ),
    ]
}

fn sqlite_fields() -> Vec<ProfileFormField> {
    vec![text(
        "/path",
        "Database file",
        "SQLite file path; use :memory: for an in-memory database",
        true,
        "path",
    )]
}

fn redis_fields() -> Vec<ProfileFormField> {
    vec![
        text(
            "/host",
            "Host",
            "Redis server hostname or IP address",
            true,
            "host",
        ),
        integer("/port", "Port", "TCP port", true, Some(1), Some(65535)),
        text(
            "/username",
            "Username",
            "Optional ACL username",
            false,
            "username",
        ),
        secret("/password", "Password", "Optional Redis password", false),
        integer(
            "/db",
            "Database",
            "Redis logical database number",
            true,
            Some(0),
            Some(255),
        ),
        boolean("/tls", "TLS", "Connect using rediss://"),
    ]
}

fn ssh_fields() -> Vec<ProfileFormField> {
    vec![
        text(
            "/host",
            "Host",
            "SSH server hostname or IP address",
            true,
            "host",
        ),
        integer("/port", "Port", "SSH TCP port", true, Some(1), Some(65535)),
        text(
            "/username",
            "Username",
            "Remote login user",
            true,
            "username",
        ),
        variant_select(
            "/auth",
            "Authentication",
            "Choose how VoidB authenticates to the SSH server",
            vec![
                variant(
                    "Password",
                    "Password",
                    json!({"type":"Password","password":""}),
                ),
                variant(
                    "Public key",
                    "PublicKey",
                    json!({"type":"PublicKey","private_key_path":"","passphrase":null}),
                ),
                variant("SSH agent", "Agent", json!({"type":"Agent"})),
            ],
        ),
        secret("/auth/password", "Password", "SSH account password", true)
            .when("/auth/type", json!("Password")),
        text(
            "/auth/private_key_path",
            "Private key",
            "Absolute path to an OpenSSH private key",
            true,
            "path",
        )
        .when("/auth/type", json!("PublicKey")),
        secret(
            "/auth/passphrase",
            "Key passphrase",
            "Optional private-key passphrase",
            false,
        )
        .when("/auth/type", json!("PublicKey")),
        text(
            "/terminal/term_type",
            "Terminal type",
            "TERM value sent to the server",
            true,
            "text",
        ),
        integer(
            "/terminal/scrollback",
            "Scrollback lines",
            "Local terminal scrollback capacity",
            true,
            Some(0),
            None,
        ),
        integer(
            "/options/keep_alive_interval",
            "Keep-alive (seconds)",
            "0 disables keep-alive",
            true,
            Some(0),
            None,
        ),
        integer(
            "/options/connect_timeout",
            "Connect timeout (seconds)",
            "SSH handshake timeout",
            true,
            Some(1),
            None,
        ),
        integer(
            "/options/max_reconnect_attempts",
            "Reconnect attempts",
            "0 disables automatic reconnect",
            true,
            Some(0),
            None,
        ),
        integer(
            "/options/reconnect_base_delay",
            "Reconnect delay (seconds)",
            "Initial reconnect backoff",
            true,
            Some(0),
            None,
        ),
    ]
}

fn docker_fields() -> Vec<ProfileFormField> {
    vec![
        variant_select(
            "/connection",
            "Connection",
            "Docker daemon transport",
            vec![
                variant("Local socket", "Local", json!({"type":"Local"})),
                variant(
                    "Custom socket",
                    "Socket",
                    json!({"type":"Socket","path":"/var/run/docker.sock"}),
                ),
                variant(
                    "HTTP",
                    "Http",
                    json!({"type":"Http","url":"http://localhost:2375"}),
                ),
                variant(
                    "TLS",
                    "Tls",
                    json!({"type":"Tls","url":"https://localhost:2376","ca_cert":"","cert":"","key":""}),
                ),
            ],
        ),
        text(
            "/connection/path",
            "Socket path",
            "Unix socket path",
            true,
            "path",
        )
        .when("/connection/type", json!("Socket")),
        text(
            "/connection/url",
            "Daemon URL",
            "Docker daemon endpoint",
            true,
            "url",
        )
        .when_any("/connection/type", &["Http", "Tls"]),
        text(
            "/connection/ca_cert",
            "CA certificate",
            "CA certificate file",
            true,
            "path",
        )
        .when("/connection/type", json!("Tls")),
        text(
            "/connection/cert",
            "Client certificate",
            "Client certificate file",
            true,
            "path",
        )
        .when("/connection/type", json!("Tls")),
        text(
            "/connection/key",
            "Client key",
            "Client private-key file",
            true,
            "path",
        )
        .when("/connection/type", json!("Tls")),
        integer(
            "/timeout",
            "Timeout (seconds)",
            "Docker API timeout",
            true,
            Some(1),
            None,
        ),
    ]
}

fn kubernetes_fields() -> Vec<ProfileFormField> {
    vec![
        variant_select(
            "/connection",
            "Connection",
            "Kubernetes API connection source",
            vec![
                variant(
                    "Kubeconfig",
                    "Kubeconfig",
                    json!({"type":"Kubeconfig","path":null,"context":null}),
                ),
                variant(
                    "Direct API",
                    "Direct",
                    json!({"type":"Direct","api_url":"https://localhost:6443","auth":{"type":"Token","token":""},"verify_ssl":true,"ca_cert":null}),
                ),
            ],
        ),
        text(
            "/connection/path",
            "Kubeconfig path",
            "Empty uses KUBECONFIG or ~/.kube/config; ~ is expanded",
            false,
            "path",
        )
        .when("/connection/type", json!("Kubeconfig")),
        text(
            "/connection/context",
            "Context",
            "Empty uses the current context",
            false,
            "text",
        )
        .when("/connection/type", json!("Kubeconfig")),
        text(
            "/connection/api_url",
            "API URL",
            "Kubernetes API server URL",
            true,
            "url",
        )
        .when("/connection/type", json!("Direct")),
        variant_select(
            "/connection/auth",
            "Authentication",
            "Direct API authentication method",
            vec![
                variant("Bearer token", "Token", json!({"type":"Token","token":""})),
                variant(
                    "Client certificate",
                    "ClientCert",
                    json!({"type":"ClientCert","cert_path":"","key_path":""}),
                ),
                variant(
                    "In-cluster account",
                    "InCluster",
                    json!({"type":"InCluster"}),
                ),
            ],
        )
        .when("/connection/type", json!("Direct")),
        secret(
            "/connection/auth/token",
            "Bearer token",
            "Service-account or OIDC token",
            true,
        )
        .when("/connection/type", json!("Direct"))
        .when("/connection/auth/type", json!("Token")),
        text(
            "/connection/auth/cert_path",
            "Client certificate",
            "PEM certificate path",
            true,
            "path",
        )
        .when("/connection/type", json!("Direct"))
        .when("/connection/auth/type", json!("ClientCert")),
        text(
            "/connection/auth/key_path",
            "Client key",
            "PEM private-key path",
            true,
            "path",
        )
        .when("/connection/type", json!("Direct"))
        .when("/connection/auth/type", json!("ClientCert")),
        boolean(
            "/connection/verify_ssl",
            "Verify TLS",
            "Verify the API server certificate",
        )
        .when("/connection/type", json!("Direct")),
        text(
            "/connection/ca_cert",
            "CA certificate",
            "Optional CA certificate path",
            false,
            "path",
        )
        .when("/connection/type", json!("Direct")),
        text(
            "/default_namespace",
            "Default namespace",
            "Empty means default",
            false,
            "text",
        ),
        integer(
            "/timeout",
            "Timeout (seconds)",
            "Kubernetes API timeout",
            true,
            Some(1),
            None,
        ),
    ]
}

fn webdav_fields() -> Vec<ProfileFormField> {
    vec![
        text("/url", "Server URL", "WebDAV base URL", true, "url"),
        variant_select(
            "/auth",
            "Authentication",
            "HTTP authentication method",
            vec![
                variant("None", "None", json!({"type":"None"})),
                variant(
                    "Basic",
                    "Basic",
                    json!({"type":"Basic","username":"","password":""}),
                ),
                variant(
                    "Digest",
                    "Digest",
                    json!({"type":"Digest","username":"","password":""}),
                ),
            ],
        ),
        text(
            "/auth/username",
            "Username",
            "WebDAV username",
            true,
            "username",
        )
        .when_any("/auth/type", &["Basic", "Digest"]),
        secret("/auth/password", "Password", "WebDAV password", true)
            .when_any("/auth/type", &["Basic", "Digest"]),
        integer(
            "/timeout",
            "Timeout (seconds)",
            "Request timeout",
            true,
            Some(1),
            None,
        ),
        boolean("/verify_ssl", "Verify TLS", "Verify server certificates"),
    ]
}

fn s3_fields() -> Vec<ProfileFormField> {
    vec![
        variant_select(
            "/provider",
            "Provider",
            "S3-compatible service provider",
            vec![
                variant("AWS S3", "Aws", json!({"type":"Aws","region":"us-east-1"})),
                variant(
                    "MinIO",
                    "Minio",
                    json!({"type":"Minio","endpoint":"http://localhost:9000"}),
                ),
                variant("Cloudflare R2", "R2", json!({"type":"R2","account_id":""})),
                variant(
                    "Custom",
                    "Custom",
                    json!({"type":"Custom","endpoint":"","region":"us-east-1","path_style":true}),
                ),
            ],
        ),
        text("/provider/region", "Region", "S3 region", true, "text")
            .when_any("/provider/type", &["Aws", "Custom"]),
        text(
            "/provider/endpoint",
            "Endpoint",
            "S3-compatible endpoint",
            true,
            "url",
        )
        .when_any("/provider/type", &["Minio", "Custom"]),
        text(
            "/provider/account_id",
            "Account ID",
            "Cloudflare account ID",
            true,
            "text",
        )
        .when("/provider/type", json!("R2")),
        boolean(
            "/provider/path_style",
            "Path-style URLs",
            "Use path-style bucket addressing",
        )
        .when("/provider/type", json!("Custom")),
        text(
            "/bucket",
            "Bucket",
            "Optional initial bucket",
            false,
            "text",
        ),
        variant_select(
            "/auth",
            "Authentication",
            "Credential source",
            vec![
                variant("Auto (environment/config)", "Auto", json!({"type":"Auto"})),
                variant(
                    "Access key",
                    "AccessKey",
                    json!({"type":"AccessKey","access_key":"","secret_key":""}),
                ),
                variant("Anonymous", "Anonymous", json!({"type":"Anonymous"})),
            ],
        ),
        text(
            "/auth/access_key",
            "Access key",
            "S3 access-key ID",
            true,
            "text",
        )
        .when("/auth/type", json!("AccessKey")),
        secret(
            "/auth/secret_key",
            "Secret key",
            "S3 secret access key",
            true,
        )
        .when("/auth/type", json!("AccessKey")),
        integer(
            "/timeout",
            "Timeout (seconds)",
            "Request timeout",
            true,
            Some(1),
            None,
        ),
    ]
}

fn elasticsearch_fields() -> Vec<ProfileFormField> {
    vec![
        string_list(
            "/urls",
            "Server URLs",
            "Comma-separated Elasticsearch URLs",
            true,
        ),
        variant_select(
            "/auth",
            "Authentication",
            "Elasticsearch authentication method",
            vec![
                ProfileFormOption {
                    label: "None".into(),
                    value: Value::Null,
                    replacement: Some(Value::Null),
                },
                variant(
                    "Basic",
                    "Basic",
                    json!({"type":"Basic","username":"","password":""}),
                ),
                variant(
                    "API key",
                    "ApiKey",
                    json!({"type":"ApiKey","id":"","api_key":""}),
                ),
                variant(
                    "Bearer token",
                    "Bearer",
                    json!({"type":"Bearer","token":""}),
                ),
            ],
        ),
        text(
            "/auth/username",
            "Username",
            "Basic-auth username",
            true,
            "username",
        )
        .when("/auth/type", json!("Basic")),
        secret("/auth/password", "Password", "Basic-auth password", true)
            .when("/auth/type", json!("Basic")),
        text(
            "/auth/id",
            "API key ID",
            "Elasticsearch API key ID",
            true,
            "text",
        )
        .when("/auth/type", json!("ApiKey")),
        secret("/auth/api_key", "API key", "Base64 API-key material", true)
            .when("/auth/type", json!("ApiKey")),
        secret("/auth/token", "Bearer token", "Bearer token", true)
            .when("/auth/type", json!("Bearer")),
        integer(
            "/timeout",
            "Timeout (seconds)",
            "Request timeout",
            true,
            Some(1),
            None,
        ),
        boolean("/verify_ssl", "Verify TLS", "Verify server certificates"),
    ]
}

fn mongodb_fields() -> Vec<ProfileFormField> {
    vec![
        text(
            "/uri",
            "Connection URI",
            "mongodb:// or mongodb+srv:// URI",
            true,
            "url",
        ),
        text(
            "/default_db",
            "Default database",
            "Optional initial database",
            false,
            "database",
        ),
        variant_select(
            "/auth",
            "Authentication",
            "MongoDB authentication method",
            vec![
                ProfileFormOption {
                    label: "URI / none".into(),
                    value: Value::Null,
                    replacement: Some(Value::Null),
                },
                variant(
                    "Username and password",
                    "Password",
                    json!({"type":"Password","username":"","password":"","auth_db":null}),
                ),
                variant(
                    "X.509 certificate",
                    "X509",
                    json!({"type":"X509","cert_path":"","key_path":null}),
                ),
                variant(
                    "AWS IAM",
                    "AwsIam",
                    json!({"type":"AwsIam","access_key":"","secret_key":"","session_token":null}),
                ),
            ],
        ),
        text(
            "/auth/username",
            "Username",
            "MongoDB username",
            true,
            "username",
        )
        .when("/auth/type", json!("Password")),
        secret("/auth/password", "Password", "MongoDB password", true)
            .when("/auth/type", json!("Password")),
        text(
            "/auth/auth_db",
            "Authentication DB",
            "Optional authentication database",
            false,
            "database",
        )
        .when("/auth/type", json!("Password")),
        text(
            "/auth/cert_path",
            "Certificate",
            "X.509 certificate path",
            true,
            "path",
        )
        .when("/auth/type", json!("X509")),
        text(
            "/auth/key_path",
            "Private key",
            "Optional separate private-key path",
            false,
            "path",
        )
        .when("/auth/type", json!("X509")),
        text(
            "/auth/access_key",
            "AWS access key",
            "AWS access-key ID",
            true,
            "text",
        )
        .when("/auth/type", json!("AwsIam")),
        secret(
            "/auth/secret_key",
            "AWS secret key",
            "AWS secret access key",
            true,
        )
        .when("/auth/type", json!("AwsIam")),
        secret(
            "/auth/session_token",
            "AWS session token",
            "Optional temporary session token",
            false,
        )
        .when("/auth/type", json!("AwsIam")),
        integer(
            "/timeout",
            "Timeout (seconds)",
            "Connection timeout",
            true,
            Some(1),
            None,
        ),
        boolean("/tls/enabled", "TLS", "Enable TLS"),
        text(
            "/tls/ca_file",
            "CA file",
            "Optional CA certificate path",
            false,
            "path",
        ),
        boolean(
            "/tls/allow_invalid_certs",
            "Allow invalid certificates",
            "Disable certificate validation",
        ),
    ]
}

fn duckdb_fields() -> Vec<ProfileFormField> {
    vec![
        text(
            "/path",
            "Database file",
            "DuckDB file path or :memory:",
            true,
            "path",
        ),
        boolean("/read_only", "Read only", "Open the database read-only"),
        string_list(
            "/extensions",
            "Extensions",
            "Comma-separated extensions to load",
            false,
        ),
        text(
            "/memory_limit",
            "Memory limit",
            "For example 2GB or 512MB",
            false,
            "text",
        ),
        integer(
            "/threads",
            "Threads",
            "Empty lets DuckDB choose",
            false,
            Some(1),
            None,
        ),
    ]
}

fn email_fields() -> Vec<ProfileFormField> {
    vec![
        text(
            "/email",
            "Email / username",
            "Mailbox login name",
            true,
            "username",
        ),
        secret(
            "/password",
            "Password",
            "Mailbox password or app password",
            true,
        ),
        select(
            "/protocol",
            "Receive protocol",
            "Incoming-mail protocol",
            true,
            vec![choice("IMAP", json!("IMAP")), choice("POP3", json!("POP3"))],
        ),
        text(
            "/receive/host",
            "Receive host",
            "IMAP or POP3 server",
            true,
            "host",
        ),
        integer(
            "/receive/port",
            "Receive port",
            "Incoming server port",
            true,
            Some(1),
            Some(65535),
        ),
        select(
            "/receive_security",
            "Receive security",
            "Incoming connection security",
            true,
            security_choices(),
        ),
        text(
            "/smtp/host",
            "SMTP host",
            "Outgoing SMTP server",
            true,
            "host",
        ),
        integer(
            "/smtp/port",
            "SMTP port",
            "Outgoing server port",
            true,
            Some(1),
            Some(65535),
        ),
        select(
            "/smtp_security",
            "SMTP security",
            "Outgoing connection security",
            true,
            security_choices(),
        ),
        boolean(
            "/verify_tls",
            "Verify TLS",
            "Verify mail-server certificates",
        ),
    ]
}

fn jenkins_fields() -> Vec<ProfileFormField> {
    vec![
        text("/url", "Server URL", "Jenkins base URL", true, "url"),
        variant_select(
            "/auth",
            "Authentication",
            "Jenkins authentication method",
            vec![
                variant("Anonymous", "None", json!({"type":"None"})),
                variant(
                    "Username and API token",
                    "Basic",
                    json!({"type":"Basic","username":"","token":""}),
                ),
            ],
        ),
        text(
            "/auth/username",
            "Username",
            "Jenkins username",
            true,
            "username",
        )
        .when("/auth/type", json!("Basic")),
        secret(
            "/auth/token",
            "API token",
            "Jenkins API token or password",
            true,
        )
        .when("/auth/type", json!("Basic")),
        integer(
            "/timeout",
            "Timeout (seconds)",
            "Request timeout",
            true,
            Some(1),
            None,
        ),
        boolean("/verify_ssl", "Verify TLS", "Verify server certificates"),
    ]
}

fn text(
    path: &str,
    label: &str,
    description: &str,
    required: bool,
    format: &str,
) -> ProfileFormField {
    field(
        path,
        label,
        description,
        required,
        ProfileFormFieldKind::Text {
            format: Some(format.to_string()),
        },
    )
}

fn secret(path: &str, label: &str, description: &str, required: bool) -> ProfileFormField {
    field(
        path,
        label,
        description,
        required,
        ProfileFormFieldKind::Secret,
    )
}

fn integer(
    path: &str,
    label: &str,
    description: &str,
    required: bool,
    minimum: Option<i64>,
    maximum: Option<i64>,
) -> ProfileFormField {
    field(
        path,
        label,
        description,
        required,
        ProfileFormFieldKind::Integer { minimum, maximum },
    )
}

fn boolean(path: &str, label: &str, description: &str) -> ProfileFormField {
    field(
        path,
        label,
        description,
        true,
        ProfileFormFieldKind::Boolean,
    )
}

fn string_list(path: &str, label: &str, description: &str, required: bool) -> ProfileFormField {
    field(
        path,
        label,
        description,
        required,
        ProfileFormFieldKind::StringList,
    )
}

fn select(
    path: &str,
    label: &str,
    description: &str,
    required: bool,
    options: Vec<ProfileFormOption>,
) -> ProfileFormField {
    field(
        path,
        label,
        description,
        required,
        ProfileFormFieldKind::Select { options },
    )
}

fn variant_select(
    path: &str,
    label: &str,
    description: &str,
    options: Vec<ProfileFormOption>,
) -> ProfileFormField {
    select(path, label, description, true, options)
}

fn field(
    path: &str,
    label: &str,
    description: &str,
    required: bool,
    kind: ProfileFormFieldKind,
) -> ProfileFormField {
    ProfileFormField {
        path: path.to_string(),
        label: label.to_string(),
        description: description.to_string(),
        required,
        kind,
        visible_when: Vec::new(),
    }
}

fn choice(label: &str, value: Value) -> ProfileFormOption {
    ProfileFormOption {
        label: label.to_string(),
        value,
        replacement: None,
    }
}

fn variant(label: &str, value: &str, replacement: Value) -> ProfileFormOption {
    ProfileFormOption {
        label: label.to_string(),
        value: json!(value),
        replacement: Some(replacement),
    }
}

fn security_choices() -> Vec<ProfileFormOption> {
    vec![
        choice("SSL/TLS", json!("SSL/TLS")),
        choice("STARTTLS", json!("STARTTLS")),
        choice("None", json!("None")),
    ]
}

trait FieldVisibilityExt {
    fn when(self, path: &str, equals: Value) -> Self;
    fn when_any(self, path: &str, values: &[&str]) -> Self;
}

impl FieldVisibilityExt for ProfileFormField {
    fn when(mut self, path: &str, equals: Value) -> Self {
        self.visible_when.push(ProfileFormCondition {
            path: path.to_string(),
            equals,
            one_of: Vec::new(),
        });
        self
    }

    fn when_any(mut self, path: &str, values: &[&str]) -> Self {
        self.visible_when.push(ProfileFormCondition {
            path: path.to_string(),
            equals: Value::Null,
            one_of: values.iter().map(|value| json!(value)).collect(),
        });
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bundled_default_has_valid_field_types() {
        for plugin_id in [
            "mysql",
            "postgres",
            "sqlite",
            "redis",
            "ssh",
            "docker",
            "kubernetes",
            "webdav",
            "s3",
            "elasticsearch",
            "mongodb",
            "duckdb",
            "email",
            "jenkins",
        ] {
            let schema = profile_form_schema(plugin_id);
            let violations = schema.validate(&default_plugin_config(plugin_id));
            assert!(
                violations
                    .iter()
                    .all(|violation| violation.message.ends_with("is required")),
                "{plugin_id} default type violations: {violations:?}"
            );
        }
    }

    #[test]
    fn ssh_authentication_choices_are_complete() {
        let schema = profile_form_schema("ssh");
        let auth = schema
            .fields
            .iter()
            .find(|field| field.path == "/auth")
            .expect("auth field");
        let ProfileFormFieldKind::Select { options } = &auth.kind else {
            panic!("auth must be a select")
        };
        assert_eq!(
            options
                .iter()
                .map(|option| option.value.clone())
                .collect::<Vec<_>>(),
            vec![json!("Password"), json!("PublicKey"), json!("Agent")]
        );
    }
}
