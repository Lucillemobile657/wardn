#!/bin/bash
# wardn demo — before/after credential isolation
# Shows what agents see with and without wardn

VAULT_PATH="/tmp/wardn-demo-vault.enc"
export WARDN_PASSPHRASE="demo-passphrase"
export RUST_LOG="error"

# Colors
RED='\033[0;31m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

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

run() {
    type_cmd "$1"
    eval "$1"
    sleep 1.5
}

comment() {
    echo ""
    printf "${DIM}${CYAN}# %s${NC}\n" "$1"
    sleep 1
}

section() {
    echo ""
    echo ""
    printf "${BOLD}${YELLOW}━━━ %s ━━━${NC}\n" "$1"
    sleep 1.5
}

warn() {
    printf "${RED}  ⚠ %s${NC}\n" "$1"
}

ok() {
    printf "${GREEN}  ✓ %s${NC}\n" "$1"
}

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
echo ""
sleep 3

# ═══════════════════════════════════════════════════
# PART 1: THE PROBLEM — WITHOUT WARDN
# ═══════════════════════════════════════════════════

section "WITHOUT WARDN — the problem"

comment "Typical setup: real API keys stored in .env or shell environment"
echo ""
printf "${DIM}  # .env file sitting on disk${NC}\n"
printf "  OPENAI_KEY=${RED}sk-proj-abc123def456ghi789jkl012mno345${NC}\n"
sleep 2

comment "Any process, agent, or skill can read the real key:"
export OPENAI_KEY="sk-proj-abc123def456ghi789jkl012mno345"
run "echo \$OPENAI_KEY"

comment "An agent's API call contains the real key:"
run "echo \"Authorization: Bearer \$OPENAI_KEY\""

comment "If the agent is compromised, the attacker has your real key."
comment "If the agent logs requests, your key is in plaintext in logs."
comment "If an LLM sees the context, your key is in the context window."
echo ""
warn "Real key exposed everywhere: memory, logs, context, disk"
sleep 3

unset OPENAI_KEY

# ═══════════════════════════════════════════════════
# PART 2: THE FIX — WITH WARDN
# ═══════════════════════════════════════════════════

section "WITH WARDN — the fix"

comment "Step 1: Create an encrypted vault (AES-256-GCM + Argon2id)"
run "wardn vault create --vault $VAULT_PATH"

comment "Step 2: Store the real key in the vault (value never echoed)"
export WARDN_VALUE="sk-proj-abc123def456ghi789jkl012mno345"
run "wardn vault set OPENAI_KEY --vault $VAULT_PATH"
unset WARDN_VALUE

comment "Step 3: Get a placeholder token for the agent"
run "wardn vault get OPENAI_KEY --agent claude-code --vault $VAULT_PATH"

comment "This is what the agent sees instead of the real key:"
PLACEHOLDER=$(wardn vault get OPENAI_KEY --agent claude-code --vault $VAULT_PATH)
export OPENAI_KEY="$PLACEHOLDER"
echo ""
run "echo \$OPENAI_KEY"

comment "The agent's API call now contains a useless placeholder:"
run "echo \"Authorization: Bearer \$OPENAI_KEY\""

echo ""
ok "Agent memory: only wdn_placeholder_... (useless)"
ok "Agent logs: only wdn_placeholder_... (useless)"
ok "LLM context: only wdn_placeholder_... (useless)"
ok "Disk (.env): nothing — key is in encrypted vault"
sleep 3

unset OPENAI_KEY

# ═══════════════════════════════════════════════════
# PART 3: HOW THE PROXY WORKS
# ═══════════════════════════════════════════════════

section "HOW THE PROXY WORKS"

comment "wardn runs a local proxy on localhost:7777"
comment "The agent sends requests through the proxy with placeholder tokens."
comment "The proxy swaps placeholders for real keys, forwards the request,"
comment "then strips real keys from the response before returning to the agent."
echo ""
echo ""
printf "  ${BOLD}Request flow:${NC}\n"
printf "  ${DIM}Agent${NC} ─── ${RED}wdn_placeholder_a1b2...${NC} ──→ ${GREEN}wardn proxy${NC} ──→ ${BOLD}sk-proj-real...${NC} ──→ ${DIM}API${NC}\n"
echo ""
printf "  ${BOLD}Response flow:${NC}\n"
printf "  ${DIM}Agent${NC} ←── ${RED}wdn_placeholder_a1b2...${NC} ←── ${GREEN}wardn proxy${NC} ←── ${BOLD}sk-proj-real...${NC} ←── ${DIM}API${NC}\n"
echo ""
echo ""
printf "  ${DIM}The real key exists only inside the proxy process and on the wire to the API.${NC}\n"
printf "  ${DIM}The agent never sees, logs, or stores the real key.${NC}\n"
sleep 4

# ═══════════════════════════════════════════════════
# PART 4: PER-AGENT ISOLATION
# ═══════════════════════════════════════════════════

section "PER-AGENT ISOLATION"

comment "Each agent gets a unique placeholder for the same credential."
comment "If one agent's token leaks, other agents are unaffected."
echo ""
run "wardn vault get OPENAI_KEY --agent claude-code --vault $VAULT_PATH"
run "wardn vault get OPENAI_KEY --agent cursor --vault $VAULT_PATH"
run "wardn vault get OPENAI_KEY --agent devin --vault $VAULT_PATH"

comment "Three agents, three different tokens, same underlying key."
comment "Revoke one without affecting the others."
sleep 2

# ═══════════════════════════════════════════════════
# PART 5: KEY ROTATION
# ═══════════════════════════════════════════════════

section "ZERO-DOWNTIME KEY ROTATION"

comment "Rotate the real key — all agent placeholders keep working"
export WARDN_VALUE="sk-proj-new-rotated-key-after-breach"
run "wardn vault rotate OPENAI_KEY --vault $VAULT_PATH"
unset WARDN_VALUE

comment "Agents don't need to update anything:"
run "wardn vault get OPENAI_KEY --agent claude-code --vault $VAULT_PATH"

echo ""
ok "Same placeholder, new real key behind it. Zero agent changes."
sleep 2

# ═══════════════════════════════════════════════════
# PART 6: CREDENTIAL SCANNER
# ═══════════════════════════════════════════════════

section "FIND EXPOSED CREDENTIALS"

comment "Scan your projects for leaked API keys"
mkdir -p /tmp/wardn-demo-scan
cat > /tmp/wardn-demo-scan/.env << 'ENVFILE'
OPENAI_KEY=sk-proj-abc123def456ghi789
ANTHROPIC_KEY=sk-ant-xyz789abc123def456
DATABASE_URL=postgres://admin:password@db:5432/app
ENVFILE

run "wardn migrate --source directory --path /tmp/wardn-demo-scan --dry-run"

comment "Scan your Claude Code config for exposed keys:"
run "wardn migrate --source claude-code --dry-run"

sleep 2

# ═══════════════════════════════════════════════════
# PART 7: SUMMARY
# ═══════════════════════════════════════════════════

section "WHAT WARDN DEFEATS"
echo ""
printf "  ${RED}Attack${NC}                                ${GREEN}wardn protection${NC}\n"
printf "  ${DIM}─────────────────────────────────────  ────────────────────────────────${NC}\n"
printf "  .env credential theft                  Keys in encrypted vault, not .env\n"
printf "  Malicious skill reads \$OPENAI_KEY      Gets wdn_placeholder_... (useless)\n"
printf "  Prompt injection exfiltrates key        Key never in LLM context\n"
printf "  Agent logs contain real keys            Logs only contain placeholders\n"
printf "  Full agent compromise                   Attacker has a useless token\n"
printf "  Cost runaway from looping agent         Rate limits per agent per key\n"
sleep 4

echo ""
echo ""
printf "${BOLD}${CYAN}  Install:${NC}   cargo install wardn\n"
printf "${BOLD}${CYAN}  GitHub:${NC}    github.com/rohansx/wardn\n"
printf "${BOLD}${CYAN}  Crate:${NC}     crates.io/crates/wardn\n"
echo ""
sleep 3

# Cleanup
rm -f "$VAULT_PATH"
rm -rf /tmp/wardn-demo-scan
