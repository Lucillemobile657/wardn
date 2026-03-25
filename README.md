# wardn

Credential isolation for AI agents. Agents never see real API keys — structural guarantee, not policy.

[![Crates.io](https://img.shields.io/crates/v/wardn.svg)](https://crates.io/crates/wardn)
[![License](https://img.shields.io/crates/l/wardn.svg)](LICENSE)

## The Problem

Every AI agent framework today stores API keys in environment variables or `.env` files. A compromised agent, malicious skill, or commodity stealer gets full access to your credentials.

```
~/.env              → OPENAI_KEY=sk-proj-real-key      # plaintext, readable by anyone
agent context       → "Use OPENAI_KEY=sk-proj-real-key" # leaked into LLM context window
agent logs          → Authorization: Bearer sk-proj-... # sitting in log files
```

## The Fix

Wardn vaults credentials with AES-256-GCM encryption and gives agents useless placeholder tokens. Real keys are injected at the network layer — agents never touch them.

```
agent environment   → OPENAI_KEY=wdn_placeholder_a1b2c3d4e5f6g7h8   (useless)
wardn vault         → OPENAI_KEY=sk-proj-real-key                     (encrypted)
agent logs          → Authorization: Bearer wdn_placeholder_a1b2...   (useless)
LLM context window  → wdn_placeholder_a1b2c3d4e5f6g7h8               (useless)
```

## How It Works

```
Agent sends request with placeholder in Authorization header
         │
         ▼
┌─────────────────────────┐
│      wardn proxy        │
│    localhost:7777        │
│                         │
│  1. Identify agent      │
│  2. Resolve placeholder │
│  3. Check authorization │
│  4. Check rate limit    │
│  5. Inject real key     │
│  6. Forward request     │
│  7. Strip key from resp │
│  8. Return to agent     │
└─────────────────────────┘
         │
         ▼
   External API (only place real key exists in transit)
```

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
wardn = "0.1"
```

### Vault Operations

```rust
use wardn::{Vault, config::CredentialConfig};

// Create an encrypted vault
let vault = Vault::create("vault.enc", "my-passphrase")?;

// Store a credential
vault.set_with_config("OPENAI_KEY", "sk-proj-real-key-123", &CredentialConfig {
    allowed_agents: vec!["researcher".into(), "writer".into()],
    allowed_domains: vec!["api.openai.com".into()],
    rate_limit: Some(RateLimitConfig { max_calls: 200, per: TimePeriod::Hour }),
})?;

// Agent gets a placeholder (not the real key)
let placeholder = vault.get_placeholder("OPENAI_KEY", "researcher")?;
// → "wdn_placeholder_a1b2c3d4e5f6g7h8"

// Different agent gets a different placeholder for the same key
let other = vault.get_placeholder("OPENAI_KEY", "writer")?;
// → "wdn_placeholder_f9e8d7c6b5a4f3e2" (different)

// Rotate the real key — all placeholders keep working
vault.rotate("OPENAI_KEY", "sk-proj-new-key-456")?;
```

### HTTP Proxy

```rust
use wardn::proxy::{self, ProxyState};
use std::sync::Arc;

let state = Arc::new(ProxyState {
    vault: Arc::new(RwLock::new(vault)),
    rate_limiter: Arc::new(Mutex::new(RateLimiter::new())),
    config: WardenConfig::default(),
    http_client: reqwest::Client::new(),
});

let app = proxy::build_router(state);
let listener = tokio::net::TcpListener::bind("127.0.0.1:7777").await?;
axum::serve(listener, app).await?;
```

### MCP Server

```rust
use wardn::mcp::WardenMcpServer;

// Serve over stdio (for Claude Code, Cursor, etc.)
WardenMcpServer::serve_stdio(vault, rate_limiter, "agent-id".into()).await?;
```

MCP tools exposed (read-only, no credential values ever returned):

| Tool | Description |
|------|-------------|
| `get_credential_ref` | Get your placeholder token for a credential |
| `list_credentials` | List credentials you're authorized to access |
| `check_rate_limit` | Check your remaining quota |

## Security Properties

| Property | Guarantee |
|----------|-----------|
| No credential in agent memory | Agent process only holds placeholder strings |
| No credential on disk in plaintext | AES-256-GCM encrypted vault with Argon2id KDF |
| No credential in logs | Only placeholders appear in any log output |
| No credential in LLM context | Placeholder injected into env, real key at network layer |
| Bounded cost exposure | Token bucket rate limits per credential per agent |
| Credential echo protection | Real keys stripped from API responses before reaching agent |
| Memory safety | `SensitiveString`/`SensitiveBytes` zeroed on drop |
| Atomic persistence | Write-tmp-then-rename prevents vault corruption |

## What This Defeats

| Attack | How wardn stops it |
|--------|-------------------|
| `.env` credential theft | No `.env` files. Keys only in encrypted vault |
| Malicious skill reads `$OPENAI_KEY` | Gets `wdn_placeholder_...` — useless |
| Stealer targets agent config | Finds only placeholder tokens |
| Prompt injection exfiltrates key | Key never in agent context window |
| Agent logs contain credentials | Logs contain only placeholder strings |
| Full agent compromise | Attacker has a useless placeholder |
| Cost runaway from looping agent | Rate limit per credential per agent |

## Configuration

```toml
[warden]
vault_path = "~/.vibeguard/vault.enc"

[warden.credentials.OPENAI_KEY]
rate_limit = { max_calls = 200, per = "hour" }
allowed_agents = ["researcher", "writer"]
allowed_domains = ["api.openai.com"]

[warden.credentials.ANTHROPIC_KEY]
rate_limit = { max_calls = 100, per = "hour" }
allowed_agents = ["researcher"]
allowed_domains = ["api.anthropic.com"]
```

## Architecture

```
wardn/
├── src/
│   ├── lib.rs              # Public API, WardenError
│   ├── config.rs           # TOML configuration parsing
│   ├── vault/
│   │   ├── mod.rs          # Vault CRUD operations
│   │   ├── encryption.rs   # AES-256-GCM + Argon2id + zeroize types
│   │   ├── storage.rs      # On-disk format (WDNV), atomic writes
│   │   └── placeholder.rs  # Token generation, per-agent isolation
│   ├── proxy/
│   │   ├── mod.rs          # HTTP proxy server (axum)
│   │   ├── inject.rs       # Credential injection into requests
│   │   ├── strip.rs        # Credential stripping from responses
│   │   └── rate_limit.rs   # Token bucket rate limiter
│   └── mcp/
│       ├── mod.rs          # MCP server (rmcp, stdio transport)
│       └── tools.rs        # Tool parameter/response types
└── tests/
    ├── vault_tests.rs      # Vault integration tests
    └── proxy_tests.rs      # Proxy integration tests
```

## Vault File Format

```
Bytes 0-3:   Magic "WDNV"
Bytes 4-5:   Version (u16 LE)
Bytes 6-21:  Argon2id salt (16 bytes)
Bytes 22+:   AES-256-GCM encrypted payload (nonce ‖ ciphertext ‖ tag)
```

## Part of VibeGuard

Wardn is the credential isolation layer of [VibeGuard](https://github.com/nicholasgasior/vibeguard) — a security daemon for AI agents. Other modules:

- **Sentinel** — prompt injection firewall
- **CloakPipe** — PII redaction middleware
- **Watcher** — audit log + dashboard
- **Migrate** — credential scanner + auto-import

## License

MIT OR Apache-2.0
