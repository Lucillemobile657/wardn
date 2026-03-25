pub mod encryption;
pub mod placeholder;
pub mod storage;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::Utc;

use encryption::{SensitiveBytes, SensitiveString};
use placeholder::{PlaceholderMap, PlaceholderToken};
use storage::{StoredCredential, VaultData};

use crate::config::CredentialConfig;
use crate::WardenError;

/// Info about a credential (no secret values).
#[derive(Debug, Clone)]
pub struct CredentialInfo {
    pub name: String,
    pub allowed_agents: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub has_rate_limit: bool,
    pub created_at: String,
    pub rotated_at: Option<String>,
}

/// The core vault: stores encrypted credentials and issues placeholder tokens.
pub struct Vault {
    credentials: HashMap<String, CredentialEntry>,
    placeholders: PlaceholderMap,
    key: SensitiveBytes,
    salt: [u8; 16],
    path: Option<PathBuf>,
}

struct CredentialEntry {
    value: SensitiveString,
    allowed_agents: Vec<String>,
    allowed_domains: Vec<String>,
    rate_limit: Option<crate::config::RateLimitConfig>,
    created_at: String,
    rotated_at: Option<String>,
}

impl Vault {
    /// Create a new vault file with a passphrase.
    pub fn create(path: &Path, passphrase: &str) -> crate::Result<Self> {
        let salt = encryption::generate_salt();
        let key = encryption::derive_key(passphrase, &salt)?;

        let vault = Self {
            credentials: HashMap::new(),
            placeholders: PlaceholderMap::new(),
            key,
            salt,
            path: Some(path.to_path_buf()),
        };

        vault.save()?;
        Ok(vault)
    }

    /// Open an existing vault file.
    pub fn open(path: &Path, passphrase: &str) -> crate::Result<Self> {
        let (data, key, salt) = storage::load(path, passphrase)?;
        Self::from_vault_data(data, key, salt, Some(path.to_path_buf()))
    }

    fn from_vault_data(
        mut data: VaultData,
        key: SensitiveBytes,
        salt: [u8; 16],
        path: Option<PathBuf>,
    ) -> crate::Result<Self> {
        data.placeholders.rebuild_reverse();

        let credentials = data
            .credentials
            .into_iter()
            .map(|(name, stored)| {
                let entry = CredentialEntry {
                    value: SensitiveString::new(stored.value),
                    allowed_agents: stored.allowed_agents,
                    allowed_domains: stored.allowed_domains,
                    rate_limit: stored.rate_limit,
                    created_at: stored.created_at,
                    rotated_at: stored.rotated_at,
                };
                (name, entry)
            })
            .collect();

        Ok(Self {
            credentials,
            placeholders: data.placeholders,
            key,
            salt,
            path,
        })
    }

    /// Create an ephemeral in-memory vault (for testing).
    pub fn ephemeral() -> Self {
        Self {
            credentials: HashMap::new(),
            placeholders: PlaceholderMap::new(),
            key: SensitiveBytes::new(vec![0u8; 32]),
            salt: [0u8; 16],
            path: None,
        }
    }

    /// Store a credential. Overwrites if it already exists.
    pub fn set(&mut self, name: &str, value: &str) -> crate::Result<()> {
        let now = Utc::now().to_rfc3339();
        self.credentials.insert(
            name.to_string(),
            CredentialEntry {
                value: SensitiveString::new(value),
                allowed_agents: Vec::new(),
                allowed_domains: Vec::new(),
                rate_limit: None,
                created_at: now,
                rotated_at: None,
            },
        );
        self.save()
    }

    /// Store a credential with full configuration.
    pub fn set_with_config(
        &mut self,
        name: &str,
        value: &str,
        config: &CredentialConfig,
    ) -> crate::Result<()> {
        let now = Utc::now().to_rfc3339();
        self.credentials.insert(
            name.to_string(),
            CredentialEntry {
                value: SensitiveString::new(value),
                allowed_agents: config.allowed_agents.clone(),
                allowed_domains: config.allowed_domains.clone(),
                rate_limit: config.rate_limit.clone(),
                created_at: now,
                rotated_at: None,
            },
        );
        self.save()
    }

    /// Get a credential value (internal only — never exposed via MCP).
    pub fn get(&self, name: &str) -> Option<&SensitiveString> {
        self.credentials.get(name).map(|e| &e.value)
    }

    /// List all credentials (names + metadata, no values).
    pub fn list(&self) -> Vec<CredentialInfo> {
        self.credentials
            .iter()
            .map(|(name, entry)| CredentialInfo {
                name: name.clone(),
                allowed_agents: entry.allowed_agents.clone(),
                allowed_domains: entry.allowed_domains.clone(),
                has_rate_limit: entry.rate_limit.is_some(),
                created_at: entry.created_at.clone(),
                rotated_at: entry.rotated_at.clone(),
            })
            .collect()
    }

    /// Rotate a credential value. Placeholders remain unchanged.
    pub fn rotate(&mut self, name: &str, new_value: &str) -> crate::Result<()> {
        let entry = self
            .credentials
            .get_mut(name)
            .ok_or_else(|| WardenError::CredentialNotFound {
                name: name.to_string(),
            })?;

        entry.value = SensitiveString::new(new_value);
        entry.rotated_at = Some(Utc::now().to_rfc3339());
        self.save()
    }

    /// Remove a credential and all its placeholders.
    pub fn remove(&mut self, name: &str) -> crate::Result<()> {
        if self.credentials.remove(name).is_none() {
            return Err(WardenError::CredentialNotFound {
                name: name.to_string(),
            });
        }
        self.placeholders.remove_credential(name);
        self.save()
    }

    /// Get or create a placeholder token for an agent.
    /// Checks that the agent is authorized for this credential.
    pub fn get_placeholder(
        &mut self,
        credential_name: &str,
        agent_id: &str,
    ) -> crate::Result<PlaceholderToken> {
        let entry = self.credentials.get(credential_name).ok_or_else(|| {
            WardenError::CredentialNotFound {
                name: credential_name.to_string(),
            }
        })?;

        // If allowed_agents is empty, all agents are authorized
        if !entry.allowed_agents.is_empty() && !entry.allowed_agents.contains(&agent_id.to_string())
        {
            return Err(WardenError::Unauthorized {
                agent_id: agent_id.to_string(),
                credential: credential_name.to_string(),
            });
        }

        let token = self.placeholders.get_or_create(credential_name, agent_id);
        self.save()?;
        Ok(token)
    }

    /// Resolve a placeholder to its credential name and decrypted value.
    pub fn resolve_placeholder(&self, placeholder: &str) -> Option<(&str, &SensitiveString)> {
        let (cred_name, _agent_id) = self.placeholders.resolve(placeholder)?;
        let entry = self.credentials.get(cred_name)?;
        Some((cred_name, &entry.value))
    }

    /// Get the placeholder string for a (credential, agent) pair without creating one.
    pub fn placeholder_for(&self, credential_name: &str, agent_id: &str) -> Option<String> {
        self.placeholders
            .lookup(credential_name, agent_id)
            .map(|s| s.to_string())
    }

    /// Check if an agent is authorized for a credential.
    pub fn is_agent_authorized(&self, credential_name: &str, agent_id: &str) -> bool {
        match self.credentials.get(credential_name) {
            Some(entry) => {
                entry.allowed_agents.is_empty()
                    || entry.allowed_agents.contains(&agent_id.to_string())
            }
            None => false,
        }
    }

    /// Check if a domain is allowed for a credential.
    pub fn is_domain_allowed(&self, credential_name: &str, domain: &str) -> bool {
        match self.credentials.get(credential_name) {
            Some(entry) => {
                entry.allowed_domains.is_empty()
                    || entry.allowed_domains.contains(&domain.to_string())
            }
            None => false,
        }
    }

    /// Get the rate limit config for a credential.
    pub fn rate_limit_config(
        &self,
        credential_name: &str,
    ) -> Option<&crate::config::RateLimitConfig> {
        self.credentials
            .get(credential_name)
            .and_then(|e| e.rate_limit.as_ref())
    }

    /// Persist vault to disk.
    pub fn save(&self) -> crate::Result<()> {
        let path = match &self.path {
            Some(p) => p,
            None => return Ok(()), // ephemeral vault, no-op
        };

        let data = self.to_vault_data();
        storage::save(path, self.key.expose(), &self.salt, &data)
    }

    /// Number of stored credentials.
    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    fn to_vault_data(&self) -> VaultData {
        let credentials = self
            .credentials
            .iter()
            .map(|(name, entry)| {
                let stored = StoredCredential {
                    value: entry.value.expose().to_string(),
                    allowed_agents: entry.allowed_agents.clone(),
                    allowed_domains: entry.allowed_domains.clone(),
                    rate_limit: entry.rate_limit.clone(),
                    created_at: entry.created_at.clone(),
                    rotated_at: entry.rotated_at.clone(),
                };
                (name.clone(), stored)
            })
            .collect();

        VaultData {
            credentials,
            placeholders: self.placeholders.clone(),
        }
    }
}

/// Test-only factory methods using fast key derivation.
#[cfg(any(test, feature = "test-fast-kdf"))]
impl Vault {
    pub fn create_fast(path: &Path, passphrase: &str) -> crate::Result<Self> {
        let salt = encryption::generate_salt();
        let key = encryption::derive_key_fast(passphrase, &salt)?;

        let vault = Self {
            credentials: HashMap::new(),
            placeholders: PlaceholderMap::new(),
            key,
            salt,
            path: Some(path.to_path_buf()),
        };

        vault.save()?;
        Ok(vault)
    }

    pub fn open_fast(path: &Path, passphrase: &str) -> crate::Result<Self> {
        let (data, key, salt) = storage::load_fast(path, passphrase)?;
        Self::from_vault_data(data, key, salt, Some(path.to_path_buf()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CredentialConfig, RateLimitConfig, TimePeriod};
    use tempfile::TempDir;

    #[test]
    fn test_create_and_open_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.enc");

        {
            let mut vault = Vault::create_fast(&path, "my-pass").unwrap();
            vault.set("OPENAI_KEY", "sk-test-123").unwrap();
            vault.set("ANTHROPIC_KEY", "sk-ant-456").unwrap();
        }

        let vault = Vault::open_fast(&path, "my-pass").unwrap();
        assert_eq!(vault.len(), 2);
        assert_eq!(vault.get("OPENAI_KEY").unwrap().expose(), "sk-test-123");
        assert_eq!(vault.get("ANTHROPIC_KEY").unwrap().expose(), "sk-ant-456");
    }

    #[test]
    fn test_set_and_get() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "value-123").unwrap();
        assert_eq!(vault.get("KEY").unwrap().expose(), "value-123");
    }

    #[test]
    fn test_set_overwrites() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "old-value").unwrap();
        vault.set("KEY", "new-value").unwrap();
        assert_eq!(vault.get("KEY").unwrap().expose(), "new-value");
    }

    #[test]
    fn test_get_nonexistent_returns_none() {
        let vault = Vault::ephemeral();
        assert!(vault.get("NOPE").is_none());
    }

    #[test]
    fn test_list_returns_names_not_values() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY_A", "secret-a").unwrap();
        vault.set("KEY_B", "secret-b").unwrap();

        let list = vault.list();
        assert_eq!(list.len(), 2);

        let names: Vec<&str> = list.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"KEY_A"));
        assert!(names.contains(&"KEY_B"));

        // CredentialInfo has no value field — this is a compile-time guarantee
    }

    #[test]
    fn test_rotate_changes_value_keeps_placeholders() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY",
                "old-secret",
                &CredentialConfig {
                    allowed_agents: vec![],
                    allowed_domains: vec![],
                    rate_limit: None,
                },
            )
            .unwrap();

        let placeholder = vault.get_placeholder("KEY", "agent-1").unwrap();

        vault.rotate("KEY", "new-secret").unwrap();

        // Placeholder unchanged
        let placeholder_after = vault.get_placeholder("KEY", "agent-1").unwrap();
        assert_eq!(placeholder, placeholder_after);

        // But resolves to new value
        let (_, value) = vault.resolve_placeholder(placeholder.as_str()).unwrap();
        assert_eq!(value.expose(), "new-secret");
    }

    #[test]
    fn test_remove_clears_credential_and_placeholders() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret").unwrap();
        let placeholder = vault.get_placeholder("KEY", "agent-1").unwrap();

        vault.remove("KEY").unwrap();

        assert!(vault.get("KEY").is_none());
        assert!(vault.resolve_placeholder(placeholder.as_str()).is_none());
    }

    #[test]
    fn test_remove_nonexistent_fails() {
        let mut vault = Vault::ephemeral();
        let result = vault.remove("NOPE");
        assert!(matches!(result, Err(WardenError::CredentialNotFound { .. })));
    }

    #[test]
    fn test_get_placeholder_unauthorized_agent() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY",
                "secret",
                &CredentialConfig {
                    allowed_agents: vec!["allowed-agent".to_string()],
                    allowed_domains: vec![],
                    rate_limit: None,
                },
            )
            .unwrap();

        let result = vault.get_placeholder("KEY", "unauthorized-agent");
        assert!(matches!(result, Err(WardenError::Unauthorized { .. })));
    }

    #[test]
    fn test_get_placeholder_open_access() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret").unwrap(); // no allowed_agents = open

        // Any agent can get a placeholder
        let t1 = vault.get_placeholder("KEY", "any-agent").unwrap();
        assert!(t1.as_str().starts_with("wdn_placeholder_"));
    }

    #[test]
    fn test_resolve_placeholder_returns_value() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret-value").unwrap();
        let placeholder = vault.get_placeholder("KEY", "agent-1").unwrap();

        let (name, value) = vault.resolve_placeholder(placeholder.as_str()).unwrap();
        assert_eq!(name, "KEY");
        assert_eq!(value.expose(), "secret-value");
    }

    #[test]
    fn test_is_agent_authorized() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY",
                "s",
                &CredentialConfig {
                    allowed_agents: vec!["a1".to_string()],
                    allowed_domains: vec![],
                    rate_limit: None,
                },
            )
            .unwrap();

        assert!(vault.is_agent_authorized("KEY", "a1"));
        assert!(!vault.is_agent_authorized("KEY", "a2"));
        assert!(!vault.is_agent_authorized("NOPE", "a1"));
    }

    #[test]
    fn test_is_domain_allowed() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY",
                "s",
                &CredentialConfig {
                    allowed_agents: vec![],
                    allowed_domains: vec!["api.openai.com".to_string()],
                    rate_limit: None,
                },
            )
            .unwrap();

        assert!(vault.is_domain_allowed("KEY", "api.openai.com"));
        assert!(!vault.is_domain_allowed("KEY", "evil.com"));
    }

    #[test]
    fn test_ephemeral_vault() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "val").unwrap();
        assert_eq!(vault.get("KEY").unwrap().expose(), "val");
        // No file I/O — save is a no-op
    }

    #[test]
    fn test_set_with_config() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY",
                "secret",
                &CredentialConfig {
                    allowed_agents: vec!["bot".to_string()],
                    allowed_domains: vec!["api.example.com".to_string()],
                    rate_limit: Some(RateLimitConfig {
                        max_calls: 100,
                        per: TimePeriod::Hour,
                    }),
                },
            )
            .unwrap();

        let info = vault.list();
        assert_eq!(info[0].allowed_agents, vec!["bot"]);
        assert_eq!(info[0].allowed_domains, vec!["api.example.com"]);
        assert!(info[0].has_rate_limit);
    }

    #[test]
    fn test_rotate_nonexistent_fails() {
        let mut vault = Vault::ephemeral();
        let result = vault.rotate("NOPE", "val");
        assert!(matches!(result, Err(WardenError::CredentialNotFound { .. })));
    }

    #[test]
    fn test_get_placeholder_nonexistent_credential() {
        let mut vault = Vault::ephemeral();
        let result = vault.get_placeholder("NOPE", "agent");
        assert!(matches!(result, Err(WardenError::CredentialNotFound { .. })));
    }

    #[test]
    fn test_placeholder_per_agent_isolation() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret").unwrap();

        let t1 = vault.get_placeholder("KEY", "agent-1").unwrap();
        let t2 = vault.get_placeholder("KEY", "agent-2").unwrap();

        assert_ne!(t1, t2);

        // Both resolve to the same credential
        let (n1, v1) = vault.resolve_placeholder(t1.as_str()).unwrap();
        let (n2, v2) = vault.resolve_placeholder(t2.as_str()).unwrap();
        assert_eq!(n1, "KEY");
        assert_eq!(n2, "KEY");
        assert_eq!(v1.expose(), v2.expose());
    }
}
