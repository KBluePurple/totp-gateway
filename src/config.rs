use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;
use totp_rs::Secret;

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    pub auth: AuthConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TlsConfig {
    pub cert_file: String,
    pub key_file: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub default_upstream: String,
    #[serde(default)]
    pub trusted_proxies: Vec<(String, String)>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:25000".to_string(),
            default_upstream: "127.0.0.1:25001".to_string(),
            trusted_proxies: vec![],
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthConfig {
    pub totp_secret: Option<String>,
    pub totp_secret_file: Option<String>,
    pub totp_secret_env: Option<String>,
    pub login_page_file: Option<String>,
    #[serde(default = "default_session_duration")]
    pub session_duration: u64,
}

fn default_session_duration() -> u64 {
    1800
}

impl Default for AuthConfig {
    fn default() -> Self {
        let secret = Secret::generate_secret();
        let encoded = secret.to_encoded().to_string();
        Self {
            totp_secret: Some(encoded),
            totp_secret_file: None,
            totp_secret_env: None,
            login_page_file: None,
            session_duration: default_session_duration(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BlacklistStrategy {
    Overwrite,
    Block,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SecurityConfig {
    #[serde(default = "default_security_enabled")]
    pub enabled: bool,
    #[serde(default = "default_blacklist_size")]
    pub blacklist_size: usize,
    #[serde(default = "default_blacklist_strategy")]
    pub blacklist_strategy: BlacklistStrategy,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_ip_limit_duration")]
    pub ip_limit_duration: u64,
    #[serde(default = "default_ban_duration")]
    pub ban_duration: u64,
    #[serde(default = "default_whitelist_duration")]
    pub whitelist_duration: u64,
}

fn default_security_enabled() -> bool {
    true
}

fn default_blacklist_size() -> usize {
    1000
}

fn default_blacklist_strategy() -> BlacklistStrategy {
    BlacklistStrategy::Overwrite
}

fn default_max_retries() -> u32 {
    5
}

fn default_ip_limit_duration() -> u64 {
    3600
}

fn default_ban_duration() -> u64 {
    3600
}

fn default_whitelist_duration() -> u64 {
    604800
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: default_security_enabled(),
            blacklist_size: default_blacklist_size(),
            blacklist_strategy: default_blacklist_strategy(),
            max_retries: default_max_retries(),
            ip_limit_duration: default_ip_limit_duration(),
            ban_duration: default_ban_duration(),
            whitelist_duration: default_whitelist_duration(),
        }
    }
}

impl AuthConfig {
    pub fn get_secret(&self) -> Result<String, String> {
        let secret = if let Some(s) = &self.totp_secret {
            s.clone()
        } else if let Some(path) = &self.totp_secret_file {
            fs::read_to_string(path)
                .map_err(|e| format!("Failed to read secret file {}: {}", path, e))?
                .trim()
                .to_string()
        } else if let Some(env_var) = &self.totp_secret_env {
            env::var(env_var).map_err(|_| format!("Environment variable {} not found", env_var))?
        } else {
            return Err(
                "No TOTP secret configured. Provide totp_secret, totp_secret_file, or totp_secret_env"
                    .to_string(),
            );
        };

        if secret.is_empty() {
            return Err("TOTP secret is empty".to_string());
        }

        Ok(secret.chars().filter(|c| !c.is_whitespace()).collect())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RouteConfig {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    pub upstream_addr: String,
}

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config, Box<dyn std::error::Error>> {
    if !path.as_ref().exists() {
        let example = include_str!("../example_config.toml");
        fs::write(path.as_ref(), example)?;
    }

    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}
