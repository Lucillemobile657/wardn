# Your AI Agent's API Keys Are Exposed. Here's the Structural Fix.

**Every agent framework stores credentials in plaintext. Wardn makes that architecturally impossible.**

---

AI agents are shipping fast. CrewAI, AutoGen, LangChain, Claude Code — they all need API keys to function. And they all store them the same way: environment variables, `.env` files, or config YAML sitting on disk in plaintext.

That's not a configuration problem. It's a **structural vulnerability**.

A compromised agent, a malicious skill, a commodity stealer, or even a prompt injection — any of these gets full, unrestricted access to your real API keys. And once a key leaks, there's no rate limit, no blast radius control, no way to know which agent was responsible.

We built [**Wardn**](https://crates.io/crates/wardn) to fix this at the architecture level.

---

## The Problem, Visualized

```
┌─────────────────────────────────────────────────────────────┐
│                    TYPICAL AGENT SETUP                       │
│                                                             │
│  ~/.env                                                     │
│  ┌─────────────────────────────────────────┐                │
│  │ OPENAI_KEY=sk-proj-real-key-abc123      │  ← plaintext   │
│  │ ANTHROPIC_KEY=sk-ant-real-key-xyz789    │  ← readable    │
│  └─────────────────────────────────────────┘  ← by anyone   │
│                                                             │
│  Agent Process Memory                                       │
│  ┌─────────────────────────────────────────┐                │
│  │ env::var("OPENAI_KEY")                  │                │
│  │ → "sk-proj-real-key-abc123"             │  ← in memory   │
│  └─────────────────────────────────────────┘                │
│                                                             │
│  LLM Context Window                                         │
│  ┌─────────────────────────────────────────┐                │
│  │ "Use Authorization: Bearer sk-proj-..." │  ← in context  │
│  └─────────────────────────────────────────┘                │
│                                                             │
│  Agent Logs                                                 │
│  ┌─────────────────────────────────────────┐                │
│  │ POST api.openai.com                     │                │
│  │ Authorization: Bearer sk-proj-real-...  │  ← in logs     │
│  └─────────────────────────────────────────┘                │
└─────────────────────────────────────────────────────────────┘

Attack surface: env files, process memory, context window, logs
Any single compromise = full credential access
```

Four places where your real API key sits exposed. Four vectors for theft. And this is the **default** in every major agent framework today.

---

## The Fix: Placeholder Tokens + Network-Layer Injection

Wardn introduces a simple but powerful architectural change: **agents never hold real credentials**. Instead, they get cryptographically random placeholder tokens that are worthless outside the local proxy.

```
┌─────────────────────────────────────────────────────────────┐
│                     WARDN ARCHITECTURE                       │
│                                                             │
│  Agent Environment                                          │
│  ┌─────────────────────────────────────────┐                │
│  │ OPENAI_KEY=wdn_placeholder_a1b2c3d4e5f6 │  ← useless    │
│  └─────────────────────────────────────────┘                │
│                                                             │
│  Agent Logs                                                 │
│  ┌─────────────────────────────────────────┐                │
│  │ Authorization: Bearer wdn_placeholder_… │  ← useless    │
│  └─────────────────────────────────────────┘                │
│                                                             │
│  LLM Context Window                                         │
│  ┌─────────────────────────────────────────┐                │
│  │ "wdn_placeholder_a1b2c3d4e5f6"         │  ← useless    │
│  └─────────────────────────────────────────┘                │
│                                                             │
│  ┌─────────────────────────────────────────┐                │
│  │           WARDN ENCRYPTED VAULT         │                │
│  │  ┌─────────────────────────────────┐    │                │
│  │  │ AES-256-GCM + Argon2id KDF     │    │                │
│  │  │ OPENAI_KEY = sk-proj-real-...   │    │  ← encrypted  │
│  │  │ ANTHROPIC_KEY = sk-ant-real-... │    │  ← on disk     │
│  │  └─────────────────────────────────┘    │                │
│  └─────────────────────────────────────────┘                │
│                                                             │
│  Attack surface: encrypted vault (passphrase-protected)     │
│  Agent compromise = attacker gets useless placeholder       │
└─────────────────────────────────────────────────────────────┘
```

The real credential exists in exactly **two places**: encrypted on disk, and briefly in the proxy's memory during request forwarding. The agent, its logs, its context window — all hold worthless placeholders.

---

## How the Proxy Works

Wardn runs a local HTTP proxy (default `localhost:7777`) that intercepts agent requests and performs a six-stage pipeline:

```
        Agent sends request
        Authorization: Bearer wdn_placeholder_a1b2c3d4...
                    │
                    ▼
    ┌───────────────────────────────┐
    │        WARDN PROXY            │
    │      localhost:7777           │
    │                               │
    │  ┌─── REQUEST PIPELINE ────┐  │
    │  │                         │  │
    │  │  ① Identify Agent       │  │  x-warden-agent header
    │  │         │               │  │
    │  │  ② Resolve Placeholder  │  │  wdn_placeholder → credential name
    │  │         │               │  │
    │  │  ③ Check Authorization  │  │  agent + domain allowed?
    │  │         │               │  │
    │  │  ④ Check Rate Limit     │  │  token bucket per agent × cred
    │  │         │               │  │
    │  │  ⑤ Inject Real Key      │  │  decrypt from vault, swap in
    │  │         │               │  │
    │  │  ⑥ Forward Request      │  │  send to external API
    │  │                         │  │
    │  └─────────────────────────┘  │
    │                               │
    │  ┌── RESPONSE PIPELINE ────┐  │
    │  │                         │  │
    │  │  ⑦ Strip Real Key       │  │  remove credential from body
    │  │         │               │  │
    │  │  ⑧ Return to Agent      │  │  clean response, placeholder only
    │  │                         │  │
    │  └─────────────────────────┘  │
    └───────────────────────────────┘
                    │
                    ▼
           External API
    (only place real key exists in transit)
```

Notice the **response pipeline** — step 7 strips real credentials from API responses before they reach the agent. Some APIs echo back your key in response headers or error messages. Wardn catches that.

---

## Per-Agent Isolation

This is where it gets interesting. Each agent gets its own **unique placeholder** for the same credential:

```
                     ┌──────────────────┐
                     │   WARDN VAULT    │
                     │                  │
                     │  OPENAI_KEY =    │
                     │  sk-proj-real... │
                     └────────┬─────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │ researcher │  │   writer   │  │  analyzer  │
     │            │  │            │  │            │
     │ wdn_plc_   │  │ wdn_plc_   │  │ wdn_plc_   │
     │ a1b2c3d4   │  │ e5f6g7h8   │  │ i9j0k1l2   │
     └────────────┘  └────────────┘  └────────────┘
      Different          Different       Different
      placeholder        placeholder     placeholder
      Same real key      Same real key   Same real key
```

If one agent is compromised, its placeholder is revoked without affecting others. You know exactly which agent leaked. And the leaked token is useless — it only works through the local proxy with the correct agent identity.

---

## Zero-Downtime Key Rotation

When you need to rotate a compromised key, agents don't even notice:

```
BEFORE ROTATION                    AFTER ROTATION

Vault:                             Vault:
  OPENAI_KEY = sk-proj-OLD         OPENAI_KEY = sk-proj-NEW  ← changed

researcher → wdn_plc_a1b2c3d4     researcher → wdn_plc_a1b2c3d4  ← same
writer     → wdn_plc_e5f6g7h8     writer     → wdn_plc_e5f6g7h8  ← same

$ wardn vault rotate OPENAI_KEY
# Enter new value → done.
# Zero agent restarts. Zero config changes. Zero downtime.
```

Placeholders are bound to credential **names**, not values. Rotate the underlying key and every agent's placeholder keeps working — now resolving to the new key.

---

## The Encryption Stack

Wardn's vault isn't a glorified JSON file with a password. It's built on serious cryptography:

```
┌────────────────────────────────────────────────────┐
│                VAULT FILE FORMAT                    │
│                                                    │
│  Bytes 0-3    "WDNV"           Magic identifier    │
│  Bytes 4-5    Version          u16 little-endian    │
│  Bytes 6-21   Salt             16 random bytes      │
│  Bytes 22+    Encrypted Payload                     │
│               ├── 12-byte nonce (random per write)  │
│               ├── ciphertext (variable length)      │
│               └── 16-byte authentication tag        │
│                                                    │
├────────────────────────────────────────────────────┤
│              KEY DERIVATION                         │
│                                                    │
│  Algorithm:  Argon2id                              │
│  Memory:     19,456 KiB (19 MiB)                   │
│  Iterations: 2                                     │
│  Parallelism: 1                                    │
│  Output:     256-bit key                           │
│                                                    │
│  (OWASP 2024 minimum parameters)                   │
│                                                    │
├────────────────────────────────────────────────────┤
│              ENCRYPTION                            │
│                                                    │
│  Algorithm:  AES-256-GCM                           │
│  Nonce:      12 bytes (random per encryption)      │
│  Tag:        16 bytes (authenticated encryption)   │
│                                                    │
├────────────────────────────────────────────────────┤
│              MEMORY SAFETY                         │
│                                                    │
│  SensitiveString  →  Zeroized on drop              │
│  SensitiveBytes   →  Zeroized on drop              │
│  Debug output     →  "[REDACTED]"                  │
│                                                    │
├────────────────────────────────────────────────────┤
│              PERSISTENCE                           │
│                                                    │
│  Atomic writes:  write to .tmp → rename            │
│  No partial state, no corruption window            │
└────────────────────────────────────────────────────┘
```

- **Argon2id** for key derivation — resistant to GPU and side-channel attacks
- **AES-256-GCM** for authenticated encryption — tamper-evident
- **Zeroize on drop** — sensitive data scrubbed from memory when no longer needed
- **Atomic writes** — vault file is never in a half-written state

---

## Built-In Credential Scanner

Already have keys scattered across your projects? Wardn finds them:

```
$ wardn migrate --source claude-code --dry-run

╔══════════════════════════════════════════════════════════════╗
║                   CREDENTIAL SCAN RESULTS                   ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Source: ~/.claude                                            ║
║  Files scanned: 47                                           ║
║                                                              ║
║  ┌──────────┬──────────────────┬──────────┬────────────┐     ║
║  │ Severity │ Pattern          │ Count    │ Score      │     ║
║  ├──────────┼──────────────────┼──────────┼────────────┤     ║
║  │ CRITICAL │ OpenAI (sk-proj) │    2     │  80 pts    │     ║
║  │ CRITICAL │ Anthropic (sk-a) │    1     │  40 pts    │     ║
║  │ HIGH     │ GitHub (ghp_)    │    3     │  60 pts    │     ║
║  │ MEDIUM   │ Slack (xoxb-)    │    1     │  10 pts    │     ║
║  └──────────┴──────────────────┴──────────┴────────────┘     ║
║                                                              ║
║  Risk Score: 190 / 400  ████████████░░░░░░░░  HIGH           ║
║                                                              ║
║  Run without --dry-run to migrate to encrypted vault         ║
╚══════════════════════════════════════════════════════════════╝
```

20+ credential patterns detected across severity levels. Supports scanning Claude Code configs, OpenClaw, or any directory. Risk scoring weights critical credentials (OpenAI, Anthropic, Stripe live keys) higher than generic tokens.

---

## MCP Integration: Agent-Native Credential Access

Wardn ships with a built-in [MCP server](https://modelcontextprotocol.io/) for direct integration with Claude Code, Cursor, and other MCP-capable tools:

```
$ wardn serve --mcp --agent my-agent

┌────────────────────────────────────────────────────┐
│              WARDN MCP SERVER                       │
│              Transport: stdio                       │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │  Tool: get_credential_ref                     │  │
│  │  → Returns placeholder token for a credential │  │
│  │  → Per-agent isolation enforced               │  │
│  │  → Real value NEVER returned                  │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │  Tool: list_credentials                       │  │
│  │  → Lists authorized credentials + metadata    │  │
│  │  → Filtered by agent's access list            │  │
│  │  → Shows: name, domains, rate_limit (bool)    │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │  Tool: check_rate_limit                       │  │
│  │  → Query remaining quota                      │  │
│  │  → Returns: remaining, limit, retry_after     │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  All tools are READ-ONLY                           │
│  No credential values ever returned                │
│  Session bound to agent_id at connection time      │
└────────────────────────────────────────────────────┘
```

Three read-only tools. An agent can check what credentials it has access to, get its placeholder token, and query its rate limit — but it can **never** retrieve the actual credential value.

---

## Rate Limiting: Blast Radius Control

A looping agent or a compromised tool can rack up thousands of API calls in minutes. Wardn enforces per-credential, per-agent token bucket rate limiting:

```
┌────────────────────────────────────────────────────┐
│             RATE LIMIT: Token Bucket                │
│                                                    │
│  Credential: OPENAI_KEY                            │
│  Config:     200 calls / hour                      │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │                                              │  │
│  │  researcher  ████████████████████░░░░  180   │  │
│  │  writer      ██████████████░░░░░░░░░  140   │  │
│  │  analyzer    ████████████████████████  200   │  │
│  │                                              │  │
│  │  ← tokens remaining (refill: 0.055/sec) →   │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Credential: ANTHROPIC_KEY                         │
│  Config:     100 calls / hour                      │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │                                              │  │
│  │  researcher  ██████████████████████░░   92   │  │
│  │                                              │  │
│  │  writer: NOT AUTHORIZED                      │  │
│  │  analyzer: NOT AUTHORIZED                    │  │
│  │                                              │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Each agent has independent token buckets          │
│  One agent hitting limit doesn't affect others     │
└────────────────────────────────────────────────────┘
```

Configuration in `wardn.toml`:

```toml
[warden.credentials.OPENAI_KEY]
rate_limit = { max_calls = 200, per = "hour" }
allowed_agents = ["researcher", "writer", "analyzer"]
allowed_domains = ["api.openai.com"]

[warden.credentials.ANTHROPIC_KEY]
rate_limit = { max_calls = 100, per = "hour" }
allowed_agents = ["researcher"]
allowed_domains = ["api.anthropic.com"]
```

---

## What This Defeats

| Attack Vector | Without Wardn | With Wardn |
|---|---|---|
| `.env` file theft | Real keys exposed | No `.env` files exist |
| Malicious skill reads `$OPENAI_KEY` | Gets `sk-proj-real-...` | Gets `wdn_placeholder_...` (useless) |
| Stealer targets agent config | Finds real credentials | Finds only placeholders |
| Prompt injection exfiltrates key | Key is in context window | Key was never in context |
| Agent logs scraped | `Authorization: Bearer sk-proj-...` | `Authorization: Bearer wdn_placeholder_...` |
| Full agent compromise | Attacker has real key | Attacker has useless token |
| Looping agent burns budget | Unlimited API calls | Rate limit per agent per credential |
| API response echoes key | Key reaches agent memory | Stripped by response pipeline |

This isn't defense in depth. It's **defense by architecture**. The real key physically cannot reach the agent process.

---

## Quick Start

```bash
# Install
cargo install wardn

# Create an encrypted vault
wardn vault create

# Store your credentials (interactive, no echo)
wardn vault set OPENAI_KEY
wardn vault set ANTHROPIC_KEY

# One-command setup for Claude Code or Cursor
wardn setup claude-code   # registers wardn as MCP server
wardn setup cursor        # same for Cursor

# Or manual setup — get placeholder tokens and start the proxy
wardn vault get OPENAI_KEY --agent researcher
# → wdn_placeholder_a1b2c3d4e5f6g7h8

wardn serve               # start proxy on localhost:7777
wardn serve --mcp --agent my-agent  # proxy + MCP server
```

After `wardn setup claude-code`, restart Claude Code and try:

```
"List my wardn credentials"         → calls list_credentials MCP tool
"Get me a reference to OPENAI_KEY"  → calls get_credential_ref, returns placeholder
"Check my rate limit for OPENAI_KEY" → calls check_rate_limit
```

The agent gets a useless placeholder. Real keys are injected at the proxy layer — never in the agent's memory, logs, or context window.

---

## The Bigger Picture

Wardn is part of VibeGuard — a security middleware layer for AI agents. Today, it solves credential isolation. The same proxy architecture extends to:

- **Request auditing** — full visibility into what agents are actually calling
- **Domain allowlisting** — agents can only reach approved APIs
- **Cost attribution** — know exactly which agent is spending what
- **Policy enforcement** — agent-specific rules beyond just rate limits

The AI agent ecosystem is growing fast. The security primitives haven't kept up. We think credential isolation is the foundation everything else builds on.

---

## Try It

```bash
cargo install wardn
```

**GitHub:** [github.com/rohansx/wardn](https://github.com/rohansx/wardn)
**Crates.io:** [crates.io/crates/wardn](https://crates.io/crates/wardn)
**License:** MIT

---

*Wardn is written in Rust. ~4,500 lines. Zero unsafe. AES-256-GCM + Argon2id. One binary, no external services.*
