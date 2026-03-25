use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::WardenError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WardenConfig {
    #[serde(default = "default_vault_path")]
    pub vault_path: String,

    #[serde(default)]
    pub credentials: HashMap<String, CredentialConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfig {
    pub rate_limit: Option<RateLimitConfig>,

    #[serde(default)]
    pub allowed_agents: Vec<String>,

    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub max_calls: u32,
    pub per: TimePeriod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimePeriod {
    Second,
    Minute,
    Hour,
    Day,
}

impl TimePeriod {
    pub fn as_seconds(&self) -> u64 {
        match self {
            TimePeriod::Second => 1,
            TimePeriod::Minute => 60,
            TimePeriod::Hour => 3600,
            TimePeriod::Day => 86400,
        }
    }
}

fn default_vault_path() -> String {
    "~/.vibeguard/vault.enc".to_string()
}

impl Default for WardenConfig {
    fn default() -> Self {
        Self {
            vault_path: default_vault_path(),
            credentials: HashMap::new(),
        }
    }
}

impl WardenConfig {
    /// Load config from a TOML file. Expects a `[warden]` section.
    pub fn load(path: &Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            WardenError::Config(format!("failed to read {}: {e}", path.display()))
        })?;
        Self::from_toml(&content)
    }

    /// Parse from a TOML string. Accepts either a top-level `[warden]` section
    /// or a flat warden config.
    pub fn from_toml(content: &str) -> crate::Result<Self> {
        // Try parsing as a full vibeguard.toml with [warden] section
        #[derive(Deserialize)]
        struct Wrapper {
            warden: Option<WardenConfig>,
        }

        if let Ok(wrapper) = toml::from_str::<Wrapper>(content) {
            if let Some(config) = wrapper.warden {
                return Ok(config);
            }
        }

        // Fall back to parsing as flat warden config
        toml::from_str::<WardenConfig>(content)
            .map_err(|e| WardenError::Config(format!("parse error: {e}")))
    }

    /// Expand `~` to the user's home directory.
    pub fn vault_path_expanded(&self) -> PathBuf {
        expand_tilde(&self.vault_path)
    }
}

pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
[warden]
vault_path = "/tmp/vault.enc"

[warden.credentials.OPENAI_KEY]
rate_limit = { max_calls = 200, per = "hour" }
allowed_agents = ["researcher", "writer"]
allowed_domains = ["api.openai.com"]

[warden.credentials.ANTHROPIC_KEY]
rate_limit = { max_calls = 100, per = "hour" }
allowed_agents = ["researcher"]
allowed_domains = ["api.anthropic.com"]
"#;

        let config = WardenConfig::from_toml(toml).unwrap();
        assert_eq!(config.vault_path, "/tmp/vault.enc");
        assert_eq!(config.credentials.len(), 2);

        let openai = &config.credentials["OPENAI_KEY"];
        assert_eq!(openai.allowed_agents, vec!["researcher", "writer"]);
        assert_eq!(openai.allowed_domains, vec!["api.openai.com"]);
        assert_eq!(openai.rate_limit.as_ref().unwrap().max_calls, 200);
    }

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
[warden]
vault_path = "/tmp/vault.enc"
"#;
        let config = WardenConfig::from_toml(toml).unwrap();
        assert_eq!(config.vault_path, "/tmp/vault.enc");
        assert!(config.credentials.is_empty());
    }

    #[test]
    fn test_default_config() {
        let config = WardenConfig::default();
        assert_eq!(config.vault_path, "~/.vibeguard/vault.enc");
        assert!(config.credentials.is_empty());
    }

    #[test]
    fn test_expand_tilde() {
        let expanded = expand_tilde("~/.vibeguard/vault.enc");
        assert!(!expanded.to_str().unwrap().starts_with('~'));
        assert!(expanded.to_str().unwrap().ends_with(".vibeguard/vault.enc"));
    }

    #[test]
    fn test_expand_absolute_path() {
        let expanded = expand_tilde("/tmp/vault.enc");
        assert_eq!(expanded, PathBuf::from("/tmp/vault.enc"));
    }

    #[test]
    fn test_invalid_toml_returns_error() {
        let result = WardenConfig::from_toml("this is not valid toml {{{{");
        assert!(matches!(result, Err(WardenError::Config(_))));
    }

    #[test]
    fn test_time_period_seconds() {
        assert_eq!(TimePeriod::Second.as_seconds(), 1);
        assert_eq!(TimePeriod::Minute.as_seconds(), 60);
        assert_eq!(TimePeriod::Hour.as_seconds(), 3600);
        assert_eq!(TimePeriod::Day.as_seconds(), 86400);
    }

    #[test]
    fn test_parse_flat_config() {
        let toml = r#"
vault_path = "/tmp/vault.enc"

[credentials.MY_KEY]
allowed_agents = ["bot"]
allowed_domains = ["example.com"]
"#;
        let config = WardenConfig::from_toml(toml).unwrap();
        assert_eq!(config.vault_path, "/tmp/vault.enc");
        assert_eq!(config.credentials.len(), 1);
    }
}
