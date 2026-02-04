use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// LDAP server configuration
    pub server: ServerConfig,
    /// API endpoint configuration
    pub api: ApiConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Address to bind the LDAP server
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    /// Port to listen on
    #[serde(default = "default_port")]
    pub port: u16,
    /// Base DN for the LDAP directory
    #[serde(default = "default_base_dn")]
    pub base_dn: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiConfig {
    /// URL of the authentication API endpoint
    pub url: String,
    /// HTTP method to use (GET, POST, etc.)
    #[serde(default = "default_method")]
    pub method: String,
    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Optional API key header name
    pub api_key_header: Option<String>,
    /// Optional API key value
    pub api_key: Option<String>,
    /// Field name for username in the request body
    #[serde(default = "default_username_field")]
    pub username_field: String,
    /// Field name for password in the request body
    #[serde(default = "default_password_field")]
    pub password_field: String,
    /// Expected success field in response (optional)
    pub success_field: Option<String>,
    /// Expected success value (optional, defaults to true)
    pub success_value: Option<serde_json::Value>,
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    389
}

fn default_base_dn() -> String {
    "dc=example,dc=com".to_string()
}

fn default_method() -> String {
    "POST".to_string()
}

fn default_timeout() -> u64 {
    30
}

fn default_username_field() -> String {
    "username".to_string()
}

fn default_password_field() -> String {
    "password".to_string()
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config = config::Config::builder()
            .add_source(config::File::with_name("config").required(false))
            .add_source(config::Environment::with_prefix("LDAP_PROXY").separator("__"))
            .build()?;

        let cfg: Config = config.try_deserialize()?;
        Ok(cfg)
    }

    pub fn default_config() -> Self {
        Config {
            server: ServerConfig {
                bind_address: default_bind_address(),
                port: default_port(),
                base_dn: default_base_dn(),
            },
            api: ApiConfig {
                url: "http://localhost:8080/api/auth".to_string(),
                method: default_method(),
                timeout_secs: default_timeout(),
                api_key_header: None,
                api_key: None,
                username_field: default_username_field(),
                password_field: default_password_field(),
                success_field: Some("success".to_string()),
                success_value: Some(serde_json::Value::Bool(true)),
            },
        }
    }
}
