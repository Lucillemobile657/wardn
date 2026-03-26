# Wardn Launch Plan: Hacker News + Reddit

---

## Hacker News

### Show HN Post

**Title** (80 char limit, optimized for HN virality):

> Show HN: Wardn – Credential isolation proxy for AI agents (Rust, AES-256-GCM)

**Alternative titles** (pick based on mood):

- `Show HN: Wardn – AI agents never see your real API keys. Structural guarantee.`
- `Show HN: Wardn – Your AI agent's API keys are exposed. Here's the fix (Rust)`
- `Show HN: Wardn – Proxy that replaces agent API keys with useless placeholders`

**URL:** `https://github.com/[your-org]/wardn` (link to repo, not blog — HN prefers source)

**Comment (post immediately after submission):**

```
Hey HN — I built Wardn because every AI agent framework stores API keys in env
vars or .env files. A compromised agent, malicious skill, or even a prompt
injection gets your real OpenAI/Anthropic keys.

Wardn fixes this architecturally, not with policy:

1. You store credentials in an AES-256-GCM encrypted vault (Argon2id KDF)
2. Agents get placeholder tokens (wdn_placeholder_...) instead of real keys
3. A local HTTP proxy swaps placeholders for real keys at the network layer
4. Real keys never touch agent memory, logs, context windows, or disk

Other things it does:
- Per-agent isolation (each agent gets a unique placeholder for the same cred)
- Zero-downtime key rotation (change the real key, placeholders keep working)
- Token bucket rate limiting per credential per agent (cost runaway protection)
- Built-in MCP server for Claude Code / Cursor integration
- Credential scanner that audits your projects for exposed keys (20+ patterns)

Single binary, ~4,500 lines of Rust, zero unsafe. `cargo install wardn`

Happy to answer questions about the crypto, the proxy architecture, or why
I think credential isolation is the missing primitive in the agent ecosystem.
```

### HN Timing

- **Best time:** Tuesday–Thursday, 8–10 AM ET (12–14 UTC)
- **Avoid:** Weekends, Fridays, Monday mornings
- **Resubmit window:** If no traction in 2 hours, you can resubmit once with a different title

### HN Virality Factors Working For You

| Factor | Why it works |
|---|---|
| Security + AI | Two of HN's highest-engagement topics |
| Rust | HN has strong Rust affinity |
| "Structural guarantee, not policy" | Contrarian framing — HN loves principled takes |
| Simple architecture | Easy to grok in 30 seconds from the diagram |
| Real problem | Anyone running agents has felt this pain |
| No SaaS / no signup | Open source, single binary — HN rewards this |
| Crypto done right | Argon2id + AES-256-GCM — HN crowd will validate |

### What to Watch For

- **"Why not just use a secrets manager?"** — Answer: secrets managers solve storage, not agent isolation. The agent still gets the real key at runtime. Wardn ensures the agent never touches it.
- **"Why not use a service mesh / sidecar?"** — Answer: those solve service-to-service auth. Wardn solves agent-to-API auth where the agent itself is untrusted.
- **"What if the proxy is compromised?"** — Answer: same trust boundary as your kernel. The proxy runs locally with your passphrase. If your local machine is owned, everything is.

---

## Reddit

### Subreddit Targets (ordered by impact)

#### Tier 1 — High Impact, Direct Audience

| Subreddit | Subscribers | Post Type | Why |
|---|---|---|---|
| r/rust | ~300k | Project announcement | Rust community loves security tools |
| r/netsec | ~500k | Technical writeup | Security-focused, appreciates crypto details |
| r/LocalLLaMA | ~500k | Tool announcement | Running local agents, credential management pain |
| r/ChatGPT | ~5M+ | PSA / tool share | Massive audience, API key theft is common topic |
| r/artificial | ~900k | Discussion | AI practitioners who build with agents |

#### Tier 2 — Strong Fit

| Subreddit | Subscribers | Post Type | Why |
|---|---|---|---|
| r/MachineLearning | ~3M | [P] Project | Research + engineering audience |
| r/cybersecurity | ~600k | Tool announcement | Professional security audience |
| r/selfhosted | ~400k | Tool share | Self-hosting crowd runs local proxies |
| r/programming | ~5M+ | Technical post | General dev audience, broad reach |
| r/commandline | ~400k | Tool share | CLI-first tool, good fit |

#### Tier 3 — Niche but Engaged

| Subreddit | Subscribers | Post Type | Why |
|---|---|---|---|
| r/LangChain | ~70k | Integration post | Direct users of agent frameworks |
| r/OpenAI | ~1M+ | Security PSA | API key theft posts get attention here |
| r/ClaudeAI | ~100k+ | MCP integration | Claude Code / MCP angle |
| r/devops | ~200k | Security tooling | Infrastructure-minded |
| r/ArtificialIntelligence | ~1M+ | Tool announcement | Broad AI audience |

---

### Reddit Posts (Tailored Per Subreddit)

#### r/rust

**Title:** `Wardn: Credential isolation proxy for AI agents — AES-256-GCM vault, Argon2id KDF, zero unsafe`

**Body:**

```
I built Wardn to solve a problem I kept hitting: every AI agent framework
stores API keys in plaintext env vars. A compromised agent gets your real keys.

Wardn fixes this structurally:
- Agents get placeholder tokens (wdn_placeholder_...) instead of real keys
- Local HTTP proxy (axum) swaps placeholders for real keys at the network layer
- AES-256-GCM encrypted vault with Argon2id KDF (OWASP 2024 minimum params)
- SensitiveString/SensitiveBytes types with Zeroize on drop
- Atomic persistence (write-tmp-then-rename)
- Per-agent token bucket rate limiting
- Built-in MCP server (rmcp crate) for Claude Code / Cursor

Tech stack: axum, aes-gcm, argon2, rmcp, clap, tokio. ~4,500 lines, zero unsafe.

`cargo install wardn`

GitHub: [link]
Crates.io: [link]

Would love feedback on the crypto implementation and proxy architecture.
The vault format and encryption code are in src/vault/encryption.rs if
anyone wants to review.
```

---

#### r/netsec

**Title:** `Wardn: Structural credential isolation for AI agents — proxy-based key injection with AES-256-GCM vault`

**Body:**

```
Problem: Every AI agent framework (LangChain, CrewAI, AutoGen, etc.) stores
API keys in env vars or .env files. A compromised agent, malicious plugin,
or prompt injection exfiltrates real credentials.

Wardn is a local HTTP proxy that gives agents useless placeholder tokens
and injects real keys at the network layer:

1. Credentials stored in AES-256-GCM vault (Argon2id KDF, OWASP 2024 params)
2. Agents receive wdn_placeholder_* tokens (cryptographically random, per-agent)
3. Proxy intercepts requests, resolves placeholder → real key, forwards
4. Response pipeline strips any echoed credentials before returning to agent

Security properties:
- No credential in agent process memory (only placeholder strings)
- No credential in LLM context window
- No credential in logs
- No plaintext on disk
- SensitiveString types zeroed on drop (Rust zeroize crate)
- Atomic vault writes (no corruption window)
- Per-agent, per-credential rate limiting (cost runaway protection)
- Domain allowlisting per credential

Attacks defeated: .env theft, malicious skill reads $API_KEY, stealer
targets config, prompt injection exfiltration, log scraping, full agent
compromise.

Written in Rust. Single binary. `cargo install wardn`

GitHub: [link]

Looking for security review feedback, especially on the vault format
and KDF parameter choices.
```

---

#### r/LocalLLaMA

**Title:** `Your AI agent's API keys are sitting in plaintext. Built a proxy that fixes this.`

**Body:**

```
If you're running AI agents (CrewAI, AutoGen, LangChain, or just scripts
calling OpenAI/Anthropic), your API keys are probably in a .env file or
env var. Any compromised tool, plugin, or prompt injection gets the real key.

I built Wardn — a local proxy that gives your agents fake placeholder
tokens. The proxy swaps in the real key at the network layer, so your
agent never touches it.

What it does:
- Encrypted vault for your API keys (AES-256-GCM)
- Agents get wdn_placeholder_... tokens instead of real keys
- Local proxy on localhost:7777 swaps placeholders for real keys
- Rate limiting per agent per credential (no more $500 surprise bills)
- Key rotation without restarting agents
- Built-in scanner finds exposed keys in your projects

Works with any agent framework — just point HTTP_PROXY at localhost:7777.
Also has an MCP server for Claude Code / Cursor.

cargo install wardn

GitHub: [link]
```

---

#### r/ChatGPT / r/OpenAI

**Title:** `PSA: Your OpenAI API key is probably exposed to every tool your AI agent uses. Built an open-source fix.`

**Body:**

```
If you use the OpenAI API with any agent framework, your sk-proj-... key
is sitting in an environment variable or .env file. Every plugin, skill,
and tool your agent loads can read it. A single malicious package = your
key is stolen.

I built Wardn (open source, Rust) to fix this:

1. Store your API keys in an encrypted vault
2. Your agent gets a fake placeholder token (wdn_placeholder_...)
3. A local proxy swaps the placeholder for your real key when making API calls
4. Your agent literally cannot access the real key

Also includes:
- Rate limiting (prevent a looping agent from burning your budget)
- Key rotation without touching agent configs
- Scanner that finds exposed keys in your projects

Free, open source, single binary: `cargo install wardn`

GitHub: [link]
```

---

#### r/cybersecurity

**Title:** `Built an open-source credential isolation proxy for AI agents — agents never touch real API keys`

**Body:**

```
The AI agent ecosystem has a credential management problem. Every framework
stores API keys in env vars or config files. Agents, their plugins, and
their LLM context windows all have direct access to real credentials.

Wardn is a local HTTP proxy that replaces this with structural isolation:

- Credentials in AES-256-GCM vault (Argon2id KDF)
- Agents hold only placeholder tokens
- Real keys injected at network layer by local proxy
- Response pipeline strips echoed credentials
- Per-agent isolation (unique placeholders per agent)
- Token bucket rate limiting per credential per agent
- Domain allowlisting per credential
- Memory-safe: SensitiveString with zeroize-on-drop

The key insight: this isn't policy ("don't put keys in env vars").
It's architecture. The agent process physically cannot access the real key.

Rust, ~4,500 lines, zero unsafe, MIT licensed.

GitHub: [link]

Would appreciate review from the security community, especially on the
threat model and crypto choices.
```

---

#### r/selfhosted

**Title:** `Wardn: Self-hosted credential proxy for AI agents — encrypted vault + placeholder tokens + rate limiting`

**Body:**

```
If you self-host AI agents or run them locally, your API keys are probably
in .env files. Wardn is a local proxy that encrypts your keys and gives
agents useless placeholder tokens.

- Single binary (Rust): `cargo install wardn`
- Encrypted vault (AES-256-GCM + Argon2id)
- Local proxy on localhost:7777
- Rate limiting per agent (prevent budget blowout)
- MCP server for Claude Code / Cursor
- Credential scanner for auditing existing projects

No cloud, no SaaS, no accounts. Everything runs locally.

GitHub: [link]
```

---

## Launch Timing Strategy

```
Day 0 (Tuesday or Wednesday):
  08:30 ET  →  Submit Show HN + first comment
  09:00 ET  →  Post to r/rust (highest signal community)
  10:00 ET  →  Post to r/netsec

Day 0 (afternoon, if HN gets traction):
  14:00 ET  →  Post to r/LocalLLaMA
  15:00 ET  →  Post to r/programming

Day 1:
  09:00 ET  →  Post to r/cybersecurity
  10:00 ET  →  Post to r/selfhosted
  14:00 ET  →  Post to r/ChatGPT or r/OpenAI (pick one, not both)

Day 2-3:
  →  Post to r/ClaudeAI (MCP angle)
  →  Post to r/LangChain (integration angle)
  →  Post to r/commandline
```

**Don't post everything at once.** Stagger over 2-3 days so you can:
1. Learn what messaging resonates from early posts
2. Adjust framing for later subreddits
3. Respond to comments without being overwhelmed
4. Cross-reference traction ("trending on HN" helps Reddit posts)

---

### Reddit Posts — Additional Subreddits

#### r/programming

**Title:** `Credential isolation for AI agents — agents get placeholder tokens, proxy injects real keys at network layer`

**Body:**

```
I've been building AI agents and noticed a fundamental problem: every
framework stores API keys in env vars or .env files. The agent process,
every plugin it loads, and the LLM context window all have direct access
to real credentials.

Wardn is a local HTTP proxy that fixes this architecturally:

- Store credentials in an encrypted vault (AES-256-GCM, Argon2id KDF)
- Agent gets a placeholder token: wdn_placeholder_a1b2c3...
- When the agent makes an API call through the proxy, the proxy swaps
  the placeholder for the real key
- Response pipeline strips any echoed credentials before returning

The agent process literally cannot access the real key — it's not in
memory, not in env vars, not in config files.

Also includes per-agent rate limiting (prevent a runaway agent from
burning your budget), key rotation without restarting agents, and a
scanner that finds exposed keys in your projects.

Written in Rust, single binary: `cargo install wardn`

GitHub: https://github.com/rohansx/wardn

Curious what people think about this approach vs just using a secrets
manager. The key difference: secrets managers solve storage, but the
agent still gets the real key at runtime. Wardn ensures it never does.
```

---

#### r/commandline

**Title:** `wardn — CLI tool that encrypts your API keys and gives AI agents fake placeholder tokens`

**Body:**

```
I built wardn to stop AI agents from seeing real API keys.

Quick overview:

  wardn vault create                  # create encrypted vault
  wardn vault set OPENAI_KEY          # store a key (prompts, no echo)
  wardn vault get OPENAI_KEY          # returns wdn_placeholder_... (not the real key)
  wardn serve                         # start local proxy on :7777
  wardn setup claude-code             # one-command MCP integration

How it works:
- Your API keys live in an AES-256-GCM encrypted vault
- Agents get placeholder tokens instead of real keys
- Local proxy swaps placeholders for real keys at the network layer
- Agent logs, memory, context window only ever contain placeholders

Also has a credential scanner that audits directories for exposed keys:

  wardn migrate --dry-run             # scan for exposed keys
  wardn migrate --source claude-code  # auto-migrate to vault

Single Rust binary: `cargo install wardn`

GitHub: https://github.com/rohansx/wardn
```

---

#### r/opensource

**Title:** `Wardn: Open-source credential isolation for AI agents — agents never see your real API keys`

**Body:**

```
Open-sourced wardn (MIT) — a tool I built to solve a problem with how
AI agent frameworks handle API keys.

The problem: Every agent framework stores API keys in env vars or .env
files. A compromised agent, malicious plugin, or prompt injection
attack can read the real key.

The fix: Wardn vaults your keys with AES-256-GCM encryption and gives
agents useless placeholder tokens. A local proxy swaps placeholders for
real keys at the network layer — the agent never touches the real key.

Features:
- Encrypted vault (AES-256-GCM + Argon2id KDF)
- Per-agent placeholder isolation
- Rate limiting per credential per agent
- Key rotation without restarting agents
- MCP server for Claude Code / Cursor
- Credential scanner for auditing projects

Written in Rust, ~4,500 lines, zero unsafe, MIT licensed.

cargo install wardn

GitHub: https://github.com/rohansx/wardn

Contributions welcome — especially around adding more credential
scanner patterns and proxy improvements.
```

---

#### r/devops

**Title:** `Wardn: Credential isolation proxy for AI agents — encrypted vault + placeholder tokens + rate limiting`

**Body:**

```
If you're running AI agents in your workflow (CI pipelines, local dev,
automated tasks), their API keys are probably in env vars or .env files.

Wardn is a local proxy that gives agents placeholder tokens instead of
real credentials. Real keys are injected at the network layer — never
in agent memory, logs, or config files.

- AES-256-GCM encrypted vault for credential storage
- Agents get wdn_placeholder_... tokens (useless without the proxy)
- Local HTTP proxy on localhost:7777 swaps tokens for real keys
- Per-agent, per-credential rate limiting
- Domain allowlisting per credential
- Key rotation without restarting anything

For CI/automation, set WARDN_PASSPHRASE env var to skip interactive
prompts:

  WARDN_PASSPHRASE=my-pass wardn vault list
  WARDN_PASSPHRASE=my-pass wardn serve &

Single binary: `cargo install wardn`

GitHub: https://github.com/rohansx/wardn
```

---

#### r/ClaudeAI

**Title:** `Built an MCP server that stops Claude Code from ever seeing your real API keys`

**Body:**

```
If you use Claude Code with API keys (OpenAI, Anthropic, etc.), those
keys sit in your environment variables. Claude can read them, they show
up in the context window, and they end up in logs.

I built wardn — it has a built-in MCP server that integrates with Claude
Code in one command:

  wardn setup claude-code

What happens:
1. Your API keys are stored in an encrypted vault
2. When Claude needs a credential, it calls the MCP tool get_credential_ref
3. It gets back a placeholder token (wdn_placeholder_...) — not the real key
4. When Claude makes an API call through the proxy, the proxy swaps in the real key
5. The real key never enters Claude's context window or your logs

MCP tools available:
- get_credential_ref — get a placeholder for a credential
- list_credentials — see what credentials you have access to
- check_rate_limit — see remaining quota

Works with Cursor too: `wardn setup cursor`

Open source, Rust: `cargo install wardn`

GitHub: https://github.com/rohansx/wardn
```

---

## Lessons Learned — First Launch Attempt

### r/rust Removal (Rule 6: Low Effort / "Slop")

**What happened:** Post removed by mods as "Slop — Rule 6: Low Effort". r/rust mods
actively filter AI-generated-looking content.

**Lessons:**
1. r/rust mods are aggressive about AI-generated content detection
2. Posts that are too polished, use bullet-heavy formatting, or sound like marketing copy get flagged
3. Need to write in a more conversational, personal tone
4. Lead with a specific technical problem you personally hit, not a product pitch
5. Show code snippets from the actual implementation, not just feature lists
6. Engage with existing r/rust discussions before posting (build comment karma first)

**Revised r/rust strategy:**
- Wait 2-3 weeks before reposting
- Write post manually in a conversational tone
- Focus on one interesting technical decision (e.g., "how I implemented zeroize-on-drop for sensitive strings in Rust")
- Post as a technical discussion, not a project announcement
- Build up some comment karma in r/rust first

### Hacker News — Show HN Flagged/Killed

**What happened:** Show HN post appears killed — blank page when visiting the item URL.
Friends cannot see it.

**Likely causes:**
1. **New account + low karma:** HN's anti-spam system aggressively filters posts from new/low-karma accounts
2. **Possible flag by users:** If early viewers flagged the post, it gets killed quickly
3. **URL domain reputation:** First post from this GitHub repo URL
4. **Title too marketing-y:** HN penalizes titles that sound like ad copy
5. **Rapid self-promotion detection:** Posting + immediately commenting can trigger spam filters

**HN Relaunch Strategy:**

1. **Build karma first (1-2 weeks):**
   - Comment thoughtfully on security, Rust, and AI posts
   - Aim for 50+ karma before resubmitting
   - Upvote and engage genuinely with the community

2. **Resubmission rules:**
   - You can resubmit a Show HN after it falls off (no traction = OK to retry)
   - Use a different title
   - Don't submit and comment within the same minute

3. **Better title options (less marketing, more technical):**
   - `Show HN: Wardn – Local proxy that gives AI agents placeholder tokens instead of real API keys`
   - `Show HN: I built a credential isolation proxy so AI agents can't see real API keys`
   - `Show HN: Wardn – Agents get useless tokens, proxy injects real keys at network layer`

4. **First comment strategy:**
   - Wait 2-3 minutes after submission before commenting
   - Start with "I built this because..." (personal story)
   - Mention specific technical choices and trade-offs, not just features
   - Ask a genuine question: "Curious what the security folks here think about the threat model"

5. **Timing:**
   - Tuesday–Thursday, 8:30–9:30 AM ET
   - Avoid big tech news days (Apple events, major launches)

6. **If it gets flagged again:**
   - Email hn@ycombinator.com and ask why — they do respond
   - Ask: "My Show HN for [project] seems to have been flagged. Could you review?"
   - They can un-flag legitimate Show HN posts

### Addressing makurayami's Feedback

makurayami raised valid points. Prepare answers for these:

**"This is basically a self-hosted OpenRouter"**
- Response: OpenRouter is a routing layer that still gives you API keys to manage. Wardn's
  point is that the agent never touches the real key at all — it's a different trust model.
  OpenRouter trusts the client with a key. Wardn doesn't.

**"Placeholder tokens are effectively API keys to the proxy"**
- Response: Fair point — the placeholder is a bearer token to the proxy. The difference:
  (1) the placeholder only works through localhost:7777, not against real APIs,
  (2) each agent gets unique placeholders, so you can revoke per-agent,
  (3) rate limits are per-placeholder, not per-key,
  (4) if a placeholder leaks, the attacker still needs access to your local machine.
  It's defense in depth, not a silver bullet.

---

## Pre-Launch Checklist

- [x] README has clear install instructions (`cargo install wardn`)
- [x] Demo GIF / asciinema cast linked in README
- [x] GitHub repo is public with LICENSE (MIT)
- [x] Crates.io page is up to date (v0.3.0)
- [ ] Publish v0.4.0 with `wardn setup` commands
- [ ] Blog post published (link in HN comment, not main URL)
- [x] `wardn --help` output is clean and helpful
- [x] At least one happy-path example works end-to-end
- [x] Response prepared for "why not just use X?" questions
- [ ] HN karma > 50 before resubmitting Show HN
- [ ] Build r/rust comment history before reposting

## Post-Launch Engagement Rules

1. **Reply to every comment** within the first 2 hours
2. **Don't be defensive** — acknowledge valid criticism (like makurayami's)
3. **Don't cross-post links** ("check out my post on r/netsec") — each community is separate
4. **Thank people for feedback** even if they're wrong
5. **If someone asks "why not X?"** — give a genuine, technical answer, not a sales pitch
6. **Update the post** if you ship improvements based on feedback
