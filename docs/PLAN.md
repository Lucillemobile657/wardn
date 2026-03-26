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

### Phase 4: Audit Logging + Observability

Per-request audit trail with agent/session tracking.

| Step | File | What | Status |
|------|------|------|--------|
| 4.1 | proxy/mod.rs | Request ID generation + structured logging per request | DONE |
| 4.2 | proxy/mod.rs | Log credential injection events with agent + domain | DONE |
| 4.3 | proxy/mod.rs | Log rate limit violations | DONE |
| 4.4 | proxy/mod.rs | Log response stripping events | DONE |
| 4.5 | mcp/mod.rs | Log MCP tool calls with agent ID | DONE |
| 4.6 | README.md | Document audit logging + RUST_LOG usage | DONE |

### Phase 5: Improvements (Roadmap)

Community-requested features from Reddit/HN feedback.

| Step | What | Source | Status |
|------|------|--------|--------|
| 5.1 | Structured JSON log output (`--log-format json`) | maxedbeech | TODO |
| 5.2 | Session ID tracking across multiple requests | maxedbeech | TODO |
| 5.3 | Log export / queryable audit trail | maxedbeech | TODO |
| 5.4 | HTTPS CONNECT support (MITM proxy for TLS) | architecture gap | TODO |
| 5.5 | Credential expiry / TTL per credential | community | TODO |
| 5.6 | Web dashboard for audit logs (Watcher module) | VibeGuard roadmap | TODO |
| 5.7 | `wardn scan` as standalone command (not just migrate) | wameisadev | TODO |

## Success Criteria

- `cargo test` passes with 80%+ coverage
- `cargo clippy` clean
- Vault encrypts at rest, derives key from passphrase
- Placeholder tokens unique per (credential, agent)
- Rotation doesn't change placeholders
- Wrong passphrase = clear error
- Every credential access logged with request ID and agent identity
