# Wardn — Implementation Plan

## Phases

### Phase 1: Vault + Encryption + Placeholders (Current)

Standalone encrypted credential library. No networking.

| Step | File | What |
|------|------|------|
| 1.1 | Cargo.toml | Crate skeleton, crypto deps |
| 1.2 | vault/encryption.rs | AES-256-GCM, Argon2id, SensitiveString/Bytes |
| 1.3 | vault/storage.rs | On-disk format, atomic save/load |
| 1.4 | vault/placeholder.rs | Token generation, bidirectional maps |
| 1.5 | vault/mod.rs | Vault CRUD composing 1.2-1.4 |
| 1.6 | config.rs | TOML config parsing |
| 1.7 | lib.rs | Public API, WardenError, re-exports |
| 1.8 | tests/vault_tests.rs | Integration tests |

### Phase 2: Rate Limiting + HTTP Proxy

Network enforcement layer. Agents route traffic through Wardn.

| Step | File | What |
|------|------|------|
| 2.1 | Cargo.toml | Add tokio/axum/hyper/reqwest |
| 2.2 | proxy/rate_limit.rs | Token bucket per credential per agent |
| 2.3 | proxy/inject.rs | Credential injection into requests |
| 2.4 | proxy/strip.rs | Credential stripping from responses |
| 2.5 | proxy/mod.rs | HTTP proxy server |
| 2.6 | tests/proxy_tests.rs | Proxy integration tests |

### Phase 3: MCP Server

Native agent integration via MCP protocol.

| Step | File | What |
|------|------|------|
| 3.1 | mcp/mod.rs | MCP server (stdio/SSE) |
| 3.2 | mcp/tools.rs | get_credential_ref, list_credentials, check_rate_limit |

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Argon2id too slow on weak HW | Medium | OWASP minimum params, configurable for tests |
| Vault concurrent access | Medium | flock advisory locking + atomic writes |
| Agent identity spoofing (Phase 2) | Medium | Documented; resolved by MCP sessions (Phase 3) |
| HTTPS CONNECT requires MITM | High | Phase 2 MVP = HTTP only; HTTPS via HTTP_PROXY env |
| Credential false-positive stripping | Low | Only strip values >8 chars that were injected in same request |

## Success Criteria

- `cargo test` passes with 80%+ coverage
- `cargo clippy` clean
- Vault encrypts at rest, derives key from passphrase
- Placeholder tokens unique per (credential, agent)
- Rotation doesn't change placeholders
- Wrong passphrase = clear error
