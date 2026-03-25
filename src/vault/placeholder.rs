use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const PLACEHOLDER_PREFIX: &str = "wdn_placeholder_";

/// A placeholder token that agents receive instead of real credentials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PlaceholderToken(String);

impl PlaceholderToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PlaceholderToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Bidirectional mapping between placeholders and (credential, agent) pairs.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PlaceholderMap {
    /// placeholder → (credential_name, agent_id)
    forward: HashMap<String, (String, String)>,
    /// "credential_name\0agent_id" → placeholder (using \0 as separator for JSON compat)
    #[serde(skip)]
    reverse: HashMap<(String, String), String>,
}

impl PlaceholderMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild the reverse map from forward map (called after deserialization).
    pub fn rebuild_reverse(&mut self) {
        self.reverse.clear();
        for (token, (cred, agent)) in &self.forward {
            self.reverse
                .insert((cred.clone(), agent.clone()), token.clone());
        }
    }

    /// Get or create a placeholder for a (credential, agent) pair.
    pub fn get_or_create(&mut self, credential_name: &str, agent_id: &str) -> PlaceholderToken {
        let key = (credential_name.to_string(), agent_id.to_string());

        if let Some(existing) = self.reverse.get(&key) {
            return PlaceholderToken(existing.clone());
        }

        let token = generate_placeholder();
        self.forward.insert(
            token.0.clone(),
            (credential_name.to_string(), agent_id.to_string()),
        );
        self.reverse.insert(key, token.0.clone());
        token
    }

    /// Resolve a placeholder to its (credential_name, agent_id) pair.
    pub fn resolve(&self, placeholder: &str) -> Option<(&str, &str)> {
        self.forward
            .get(placeholder)
            .map(|(c, a)| (c.as_str(), a.as_str()))
    }

    /// Look up the placeholder for a known (credential, agent) pair.
    pub fn lookup(&self, credential_name: &str, agent_id: &str) -> Option<&str> {
        let key = (credential_name.to_string(), agent_id.to_string());
        self.reverse.get(&key).map(|s| s.as_str())
    }

    /// Remove all placeholders for a credential (used on `vault remove`).
    pub fn remove_credential(&mut self, credential_name: &str) {
        let to_remove: Vec<String> = self
            .forward
            .iter()
            .filter(|(_, (c, _))| c == credential_name)
            .map(|(k, _)| k.clone())
            .collect();

        for token in &to_remove {
            if let Some((c, a)) = self.forward.remove(token) {
                self.reverse.remove(&(c, a));
            }
        }
    }

    /// Remove all placeholders for an agent.
    pub fn remove_agent(&mut self, agent_id: &str) {
        let to_remove: Vec<String> = self
            .forward
            .iter()
            .filter(|(_, (_, a))| a == agent_id)
            .map(|(k, _)| k.clone())
            .collect();

        for token in &to_remove {
            if let Some((c, a)) = self.forward.remove(token) {
                self.reverse.remove(&(c, a));
            }
        }
    }

    /// Get all placeholders (for credential stripping in proxy).
    pub fn all_placeholders(&self) -> impl Iterator<Item = (&str, &str, &str)> {
        self.forward
            .iter()
            .map(|(token, (cred, agent))| (token.as_str(), cred.as_str(), agent.as_str()))
    }
}

fn generate_placeholder() -> PlaceholderToken {
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    PlaceholderToken(format!("{PLACEHOLDER_PREFIX}{}", hex::encode(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_placeholder_format() {
        let mut map = PlaceholderMap::new();
        let token = map.get_or_create("OPENAI_KEY", "agent-1");
        let s = token.as_str();
        assert!(s.starts_with("wdn_placeholder_"), "got: {s}");
        // prefix (16) + 16 hex chars = 32
        assert_eq!(s.len(), 32, "got len: {}", s.len());
    }

    #[test]
    fn test_same_credential_same_agent_idempotent() {
        let mut map = PlaceholderMap::new();
        let t1 = map.get_or_create("KEY", "agent-1");
        let t2 = map.get_or_create("KEY", "agent-1");
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_same_credential_different_agent_unique() {
        let mut map = PlaceholderMap::new();
        let t1 = map.get_or_create("KEY", "agent-1");
        let t2 = map.get_or_create("KEY", "agent-2");
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_different_credential_same_agent_unique() {
        let mut map = PlaceholderMap::new();
        let t1 = map.get_or_create("KEY_A", "agent-1");
        let t2 = map.get_or_create("KEY_B", "agent-1");
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_resolve_returns_correct_mapping() {
        let mut map = PlaceholderMap::new();
        let token = map.get_or_create("OPENAI_KEY", "researcher");
        let (cred, agent) = map.resolve(token.as_str()).unwrap();
        assert_eq!(cred, "OPENAI_KEY");
        assert_eq!(agent, "researcher");
    }

    #[test]
    fn test_resolve_unknown_returns_none() {
        let map = PlaceholderMap::new();
        assert!(map.resolve("wdn_placeholder_nonexistent00").is_none());
    }

    #[test]
    fn test_lookup_returns_placeholder() {
        let mut map = PlaceholderMap::new();
        let token = map.get_or_create("KEY", "agent-1");
        let found = map.lookup("KEY", "agent-1").unwrap();
        assert_eq!(found, token.as_str());
    }

    #[test]
    fn test_lookup_unknown_returns_none() {
        let map = PlaceholderMap::new();
        assert!(map.lookup("KEY", "agent-1").is_none());
    }

    #[test]
    fn test_remove_credential_cleans_all_agents() {
        let mut map = PlaceholderMap::new();
        let t1 = map.get_or_create("KEY", "agent-1");
        let t2 = map.get_or_create("KEY", "agent-2");
        map.get_or_create("OTHER", "agent-1");

        map.remove_credential("KEY");

        assert!(map.resolve(t1.as_str()).is_none());
        assert!(map.resolve(t2.as_str()).is_none());
        // OTHER should still exist
        assert!(map.lookup("OTHER", "agent-1").is_some());
    }

    #[test]
    fn test_remove_agent_cleans_all_credentials() {
        let mut map = PlaceholderMap::new();
        let t1 = map.get_or_create("KEY_A", "agent-1");
        let t2 = map.get_or_create("KEY_B", "agent-1");
        map.get_or_create("KEY_A", "agent-2");

        map.remove_agent("agent-1");

        assert!(map.resolve(t1.as_str()).is_none());
        assert!(map.resolve(t2.as_str()).is_none());
        // agent-2's placeholder should still exist
        assert!(map.lookup("KEY_A", "agent-2").is_some());
    }

    #[test]
    fn test_placeholder_display() {
        let mut map = PlaceholderMap::new();
        let token = map.get_or_create("KEY", "agent");
        let displayed = format!("{token}");
        assert!(displayed.starts_with("wdn_placeholder_"));
    }
}
