use crate::vault::Vault;
use crate::WardenError;

/// Result of credential injection into a request.
#[derive(Debug)]
pub struct InjectionResult {
    /// Credential names that were injected.
    pub injected: Vec<String>,
}

/// Scan a header value for placeholder tokens and replace with real credentials.
/// Returns the replaced value and list of injected credential names.
pub fn inject_header_value(
    value: &str,
    _agent_id: &str,
    domain: &str,
    vault: &Vault,
) -> crate::Result<(String, Vec<String>)> {
    let mut result = value.to_string();
    let mut injected = Vec::new();

    // Find all wdn_placeholder_ tokens in the value
    let mut search_from = 0;
    while let Some(start) = result[search_from..].find("wdn_placeholder_") {
        let abs_start = search_from + start;
        // Token is "wdn_placeholder_" + 16 hex chars = 32 chars total
        let abs_end = abs_start + 32;
        if abs_end > result.len() {
            break;
        }

        let token = &result[abs_start..abs_end].to_string();

        if let Some((cred_name, cred_value)) = vault.resolve_placeholder(token) {
            // Check domain authorization
            if !vault.is_domain_allowed(cred_name, domain) {
                return Err(WardenError::DomainNotAllowed {
                    domain: domain.to_string(),
                    credential: cred_name.to_string(),
                });
            }

            let real_value = cred_value.expose().to_string();
            result = format!(
                "{}{}{}",
                &result[..abs_start],
                real_value,
                &result[abs_end..]
            );
            injected.push(cred_name.to_string());
            // Advance past the injected value
            search_from = abs_start + real_value.len();
        } else {
            // Unknown placeholder — skip past it
            search_from = abs_end;
        }
    }

    Ok((result, injected))
}

/// Scan a body for placeholder tokens and replace with real credentials.
pub fn inject_body(
    body: &[u8],
    agent_id: &str,
    domain: &str,
    vault: &Vault,
) -> crate::Result<(Vec<u8>, Vec<String>)> {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return Ok((body.to_vec(), vec![])), // binary body, skip
    };

    let (replaced, injected) = inject_header_value(body_str, agent_id, domain, vault)?;
    Ok((replaced.into_bytes(), injected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CredentialConfig;

    fn setup_vault() -> (Vault, String) {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "OPENAI_KEY",
                "sk-proj-real-key-123",
                &CredentialConfig {
                    allowed_agents: vec!["researcher".to_string()],
                    allowed_domains: vec!["api.openai.com".to_string()],
                    rate_limit: None,
                },
            )
            .unwrap();

        let placeholder = vault
            .get_placeholder("OPENAI_KEY", "researcher")
            .unwrap();
        (vault, placeholder.to_string())
    }

    #[test]
    fn test_inject_bearer_header() {
        let (vault, ph) = setup_vault();
        let header = format!("Bearer {ph}");

        let (result, injected) =
            inject_header_value(&header, "researcher", "api.openai.com", &vault).unwrap();

        assert_eq!(result, "Bearer sk-proj-real-key-123");
        assert_eq!(injected, vec!["OPENAI_KEY"]);
    }

    #[test]
    fn test_inject_body_json() {
        let (vault, ph) = setup_vault();
        let body = format!(r#"{{"api_key": "{ph}", "prompt": "hello"}}"#);

        let (result, injected) =
            inject_body(body.as_bytes(), "researcher", "api.openai.com", &vault).unwrap();

        let result_str = String::from_utf8(result).unwrap();
        assert!(result_str.contains("sk-proj-real-key-123"));
        assert!(!result_str.contains("wdn_placeholder_"));
        assert_eq!(injected, vec!["OPENAI_KEY"]);
    }

    #[test]
    fn test_inject_wrong_domain_fails() {
        let (vault, ph) = setup_vault();
        let header = format!("Bearer {ph}");

        let result = inject_header_value(&header, "researcher", "evil.com", &vault);
        assert!(matches!(result, Err(WardenError::DomainNotAllowed { .. })));
    }

    #[test]
    fn test_inject_no_placeholders_passthrough() {
        let (vault, _) = setup_vault();
        let header = "Bearer sk-some-other-key";

        let (result, injected) =
            inject_header_value(header, "researcher", "api.openai.com", &vault).unwrap();

        assert_eq!(result, "Bearer sk-some-other-key");
        assert!(injected.is_empty());
    }

    #[test]
    fn test_inject_unknown_placeholder_passthrough() {
        let (vault, _) = setup_vault();
        let header = "Bearer wdn_placeholder_0000000000000000";

        let (result, injected) =
            inject_header_value(header, "researcher", "api.openai.com", &vault).unwrap();

        assert_eq!(result, "Bearer wdn_placeholder_0000000000000000");
        assert!(injected.is_empty());
    }

    #[test]
    fn test_inject_multiple_placeholders() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY_A",
                "secret-a",
                &CredentialConfig {
                    allowed_agents: vec![],
                    allowed_domains: vec![],
                    rate_limit: None,
                },
            )
            .unwrap();
        vault
            .set_with_config(
                "KEY_B",
                "secret-b",
                &CredentialConfig {
                    allowed_agents: vec![],
                    allowed_domains: vec![],
                    rate_limit: None,
                },
            )
            .unwrap();

        let ph_a = vault.get_placeholder("KEY_A", "agent").unwrap().to_string();
        let ph_b = vault.get_placeholder("KEY_B", "agent").unwrap().to_string();

        let body = format!(r#"{{"a": "{ph_a}", "b": "{ph_b}"}}"#);
        let (result, injected) =
            inject_body(body.as_bytes(), "agent", "any.com", &vault).unwrap();

        let result_str = String::from_utf8(result).unwrap();
        assert!(result_str.contains("secret-a"));
        assert!(result_str.contains("secret-b"));
        assert!(!result_str.contains("wdn_placeholder_"));
        assert_eq!(injected.len(), 2);
    }

    #[test]
    fn test_inject_binary_body_passthrough() {
        let (vault, _) = setup_vault();
        let binary = vec![0xFF, 0xFE, 0x00, 0x01];

        let (result, injected) =
            inject_body(&binary, "researcher", "api.openai.com", &vault).unwrap();

        assert_eq!(result, binary);
        assert!(injected.is_empty());
    }
}
