use serde::{Deserialize, Serialize};

// -- Tool parameter types --

#[derive(Deserialize, schemars::JsonSchema)]
pub struct GetCredentialRefParams {
    /// Name of the credential to get a placeholder for (e.g. "OPENAI_KEY").
    pub credential_name: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ListCredentialsParams {}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct CheckRateLimitParams {
    /// Name of the credential to check rate limit for.
    pub credential_name: String,
}

// -- Tool response types --

#[derive(Serialize)]
pub struct GetCredentialRefResponse {
    pub credential: String,
    pub placeholder: String,
}

#[derive(Serialize)]
pub struct CredentialEntry {
    pub name: String,
    pub allowed_agents: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub has_rate_limit: bool,
}

#[derive(Serialize)]
pub struct ListCredentialsResponse {
    pub credentials: Vec<CredentialEntry>,
}

#[derive(Serialize)]
pub struct CheckRateLimitResponse {
    pub credential: String,
    pub remaining: u32,
    pub limit: u32,
    pub period: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
