#!/bin/bash
# wardn interactive demo script
# Simulates typing for a polished asciinema recording

VAULT_PATH="/tmp/wardn-demo-vault.enc"
export WARDN_PASSPHRASE="demo-passphrase"
export RUST_LOG="error"

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Simulate typing a command
type_cmd() {
    echo ""
    printf "${GREEN}❯${NC} "
    for (( i=0; i<${#1}; i++ )); do
        printf "%s" "${1:$i:1}"
        sleep 0.04
    done
    echo ""
    sleep 0.3
}

# Print a comment/explanation
comment() {
    echo ""
    printf "${DIM}${CYAN}# %s${NC}\n" "$1"
    sleep 1
}

# Run a command (type it, then execute)
run() {
    type_cmd "$1"
    eval "$1"
    sleep 1.5
}

# Section header
section() {
    echo ""
    echo ""
    printf "${BOLD}${YELLOW}━━━ %s ━━━${NC}\n" "$1"
    sleep 1.5
}

# Cleanup from any previous run
rm -f "$VAULT_PATH"

# ─── INTRO ───
clear
echo ""
printf "${BOLD}${CYAN}"
cat << 'BANNER'
                          _
 __      ____ _ _ __ ___ | |_ __
 \ \ /\ / / _` | '__/ _ \| | '_ \
  \ V  V / (_| | | | (_) | | | | |
   \_/\_/ \__,_|_|  \___/|_|_| |_|

BANNER
printf "${NC}"
printf "${DIM}  credential isolation for AI agents${NC}\n"
printf "${DIM}  agents never see real API keys — structural guarantee, not policy${NC}\n"
sleep 3

# ─── THE PROBLEM ───
section "THE PROBLEM"
comment "Every AI agent stores API keys in .env files or environment variables."
comment "A compromised agent, malicious skill, or stealer gets full access."
sleep 1
echo ""
printf "  ${DIM}~/.env → OPENAI_KEY=sk-proj-real-key-here     ${CYAN}# plaintext!${NC}\n"
printf "  ${DIM}agent  → Authorization: Bearer sk-proj-real... ${CYAN}# leaked in logs!${NC}\n"
printf "  ${DIM}LLM    → \"Use key sk-proj-real...\"             ${CYAN}# in context window!${NC}\n"
sleep 3

# ─── THE FIX ───
section "THE FIX"
comment "wardn encrypts credentials and gives agents useless placeholder tokens."
comment "Real keys are injected at the network proxy layer — agents never touch them."
sleep 2

# ─── VAULT CREATE ───
section "VAULT MANAGEMENT"

comment "Create an AES-256-GCM encrypted vault with Argon2id key derivation"
run "wardn vault create --vault $VAULT_PATH"

# ─── STORE CREDENTIALS ───
comment "Store API keys — values are never echoed to the terminal"
export WARDN_VALUE="sk-proj-abc123def456ghi789jkl012mno345"
run "wardn vault set OPENAI_KEY --vault $VAULT_PATH"

export WARDN_VALUE="sk-ant-xyz789abc123def456ghi789jkl012"
run "wardn vault set ANTHROPIC_KEY --vault $VAULT_PATH"

export WARDN_VALUE="ghp_1234567890abcdef1234567890abcdef12345678"
run "wardn vault set GITHUB_TOKEN --vault $VAULT_PATH"
unset WARDN_VALUE

# ─── LIST ───
comment "List credentials — shows names and metadata, NEVER the actual values"
run "wardn vault list --vault $VAULT_PATH"

# ─── PLACEHOLDER TOKENS ───
section "PLACEHOLDER TOKENS"

comment "Agents get useless placeholder tokens instead of real keys"
run "wardn vault get OPENAI_KEY --vault $VAULT_PATH"

comment "Different agents get different placeholders for the same key"
run "wardn vault get OPENAI_KEY --agent researcher --vault $VAULT_PATH"
run "wardn vault get OPENAI_KEY --agent writer --vault $VAULT_PATH"

comment "Even if an agent is compromised, the attacker only has: wdn_placeholder_..."
comment "This token is useless outside the wardn proxy."
sleep 2

# ─── ROTATE ───
section "KEY ROTATION"

comment "Rotate a key — the real value changes, but all placeholders keep working"
export WARDN_VALUE="sk-proj-brand-new-rotated-key-999"
run "wardn vault rotate OPENAI_KEY --vault $VAULT_PATH"
unset WARDN_VALUE

comment "Agents don't need to update anything — their placeholders still work"
run "wardn vault get OPENAI_KEY --agent researcher --vault $VAULT_PATH"

# ─── MIGRATE ───
section "CREDENTIAL SCANNER"

comment "Scan for exposed credentials in your projects"
mkdir -p /tmp/wardn-demo-scan
echo 'OPENAI_KEY=sk-proj-abc123def456ghi789
ANTHROPIC_KEY=sk-ant-xyz789abc123def456
STRIPE_KEY=sk_live_FAKE_DEMO_KEY_NOT_REAL_000000' > /tmp/wardn-demo-scan/.env

run "wardn migrate --source directory --path /tmp/wardn-demo-scan --dry-run"

comment "Found exposed keys! wardn can migrate them into the encrypted vault."
sleep 2

# ─── PROXY ───
section "HTTP PROXY"
comment "wardn serve starts a proxy on localhost:7777"
comment "It intercepts requests, swaps placeholders for real keys,"
comment "forwards to the API, then strips real keys from responses."
echo ""
printf "  ${DIM}Agent → wdn_placeholder_a1b2... → ${GREEN}wardn proxy${NC} → ${DIM}sk-proj-real... → API${NC}\n"
printf "  ${DIM}Agent ← wdn_placeholder_a1b2... ← ${GREEN}wardn proxy${NC} ← ${DIM}sk-proj-real... ← API${NC}\n"
sleep 2

comment "Start with: wardn serve"
comment "Or with MCP for Claude Code: wardn serve --mcp --agent my-agent"
sleep 2

# ─── CLEANUP ───
section "SECURITY PROPERTIES"
echo ""
printf "  ${GREEN}✓${NC} No credential in agent memory — only placeholders\n"
printf "  ${GREEN}✓${NC} No credential on disk in plaintext — AES-256-GCM vault\n"
printf "  ${GREEN}✓${NC} No credential in logs — only placeholder strings\n"
printf "  ${GREEN}✓${NC} No credential in LLM context — injected at network layer\n"
printf "  ${GREEN}✓${NC} Bounded cost exposure — rate limits per agent\n"
printf "  ${GREEN}✓${NC} Credential echo protection — stripped from responses\n"
printf "  ${GREEN}✓${NC} Memory safety — zeroed on drop via Zeroize\n"
sleep 3

echo ""
echo ""
printf "${BOLD}${CYAN}  Install:${NC}  cargo install wardn\n"
printf "${BOLD}${CYAN}  GitHub:${NC}   github.com/rohansx/wardn\n"
printf "${BOLD}${CYAN}  Crate:${NC}    crates.io/crates/wardn\n"
echo ""
sleep 3

# Cleanup
rm -f "$VAULT_PATH"
rm -rf /tmp/wardn-demo-scan
