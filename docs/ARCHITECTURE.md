# Wardn — Architecture

## Overview

Wardn is the credential isolation proxy for VibeGuard. Agents never see real API keys — they get useless placeholder tokens. Real credentials are injected at the network layer by the proxy.

## Core Flow

```
Agent env:   OPENAI_KEY=wdn_placeholder_a1b2c3d4e5f6g7h8  (useless)
Wardn vault: OPENAI_KEY=sk-proj-actual-key                 (AES-256-GCM encrypted)

Agent → api.openai.com:
  1. Request hits Wardn proxy (localhost:7777)
  2. Resolve placeholder → credential name + agent identity
  3. Authorization check (agent allowed? domain allowed?)
  4. Rate limit check (token bucket per credential per agent)
  5. Decrypt real key in memory (never on disk in plaintext)
  6. Inject real key into Authorization header
  7. Forward to api.openai.com
  8. Strip credential echoes from response
  9. Agent receives clean response with only placeholder strings
```

## Module Structure

```
wardn/
├── src/
│   ├── lib.rs              # Public API, WardenError, re-exports
│   ├── config.rs           # TOML config parsing
│   ├── vault/
│   │   ├── mod.rs          # Vault struct, CRUD operations
│   │   ├── encryption.rs   # AES-256-GCM, Argon2id, SensitiveString/Bytes
│   │   ├── storage.rs      # On-disk format, atomic save/load
│   │   └── placeholder.rs  # Token generation, bidirectional maps
│   ├── proxy/
│   │   ├── mod.rs          # HTTP proxy server (axum)
│   │   ├── inject.rs       # Credential injection into requests
│   │   ├── strip.rs        # Credential stripping from responses
│   │   └── rate_limit.rs   # Token bucket rate limiter
│   └── mcp/
│       ├── mod.rs          # MCP server
│       └── tools.rs        # MCP tool definitions
└── tests/
    ├── vault_tests.rs
    ├── proxy_tests.rs
    └── integration_tests.rs
```

## Encryption

- **Algorithm:** AES-256-GCM (authenticated encryption)
- **Key derivation:** Argon2id from user passphrase (m=19456, t=2, p=1)
- **Memory safety:** SensitiveString/SensitiveBytes with Zeroize on drop
- **Persistence:** Atomic file writes (write .tmp → rename)
- **File format:** `WDNV` magic | version u16 | salt 16B | encrypted payload

## Placeholder Tokens

Format: `wdn_placeholder_{random_hex_16}`

- Unique per (credential, agent) pair
- Rotatable — rotating real key doesn't change placeholders
- Auditable — maps back to which agent used which credential

## Security Properties

1. No credential in agent memory
2. No credential on disk in plaintext
3. No credential in logs
4. No credential in LLM context window
5. Bounded cost via rate limits
6. Full audit trail via Watcher integration
