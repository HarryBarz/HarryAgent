#!/bin/bash
# HarryAgent Installer — Blockchain Infrastructure Security Auditor
# Installs HarryAgent into Claude Code's global config (~/.claude/)
# so /audit, /scan, /hunt, /shutdown commands work from any directory.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLAUDE_DIR="$HOME/.claude"

echo ""
echo "  ██╗  ██╗ █████╗ ██████╗ ██████╗ ██╗   ██╗"
echo "  ██║  ██║██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝"
echo "  ███████║███████║██████╔╝██████╔╝ ╚████╔╝ "
echo "  ██╔══██║██╔══██║██╔══██╗██╔══██╗  ╚██╔╝  "
echo "  ██║  ██║██║  ██║██║  ██║██║  ██║   ██║   "
echo "  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   "
echo "  Autonomous Blockchain Infrastructure Auditor"
echo ""

# Create directories
echo "[*] Creating directories..."
mkdir -p "$CLAUDE_DIR/commands"
mkdir -p "$CLAUDE_DIR/rules"
mkdir -p "$CLAUDE_DIR/agents/dlt-infra"
mkdir -p "$CLAUDE_DIR/agents/shared"
mkdir -p "$CLAUDE_DIR/patterns/dlt-infra/real-exploits"
mkdir -p "$CLAUDE_DIR/references/dlt-infra"

# Install CLAUDE.md (global system prompt)
echo "[*] Installing system prompt (CLAUDE.md)..."
cp "$SCRIPT_DIR/CLAUDE.md" "$CLAUDE_DIR/CLAUDE.md"

# Install commands (registers /audit, /shutdown, /scan, /hunt as slash commands)
echo "[*] Installing slash commands..."
cp "$SCRIPT_DIR/commands/audit.md" "$CLAUDE_DIR/commands/audit.md"
cp "$SCRIPT_DIR/commands/shutdown.md" "$CLAUDE_DIR/commands/shutdown.md"

# Install rules
echo "[*] Installing rules..."
cp "$SCRIPT_DIR/rules/gates.md" "$CLAUDE_DIR/rules/gates.md"
cp "$SCRIPT_DIR/rules/anti-hallucination.md" "$CLAUDE_DIR/rules/anti-hallucination.md"

# Install agent specs
echo "[*] Installing hunter agents..."
for f in "$SCRIPT_DIR/agents/dlt-infra/"*.md; do
    cp "$f" "$CLAUDE_DIR/agents/dlt-infra/$(basename "$f")"
done
for f in "$SCRIPT_DIR/agents/shared/"*.md; do
    cp "$f" "$CLAUDE_DIR/agents/shared/$(basename "$f")"
done

# Install pattern files (tech-stack specific)
echo "[*] Installing vulnerability patterns..."
for f in "$SCRIPT_DIR/patterns/dlt-infra/"*.md; do
    cp "$f" "$CLAUDE_DIR/patterns/dlt-infra/$(basename "$f")"
done

# Install real-exploit datasets (the 148 battle-tested patterns)
echo "[*] Installing real-exploit datasets (148 patterns)..."
cp "$SCRIPT_DIR/patterns/dlt-infra/real-exploits/node-crash.md" "$CLAUDE_DIR/patterns/dlt-infra/real-exploits/node-crash.md"
cp "$SCRIPT_DIR/patterns/dlt-infra/real-exploits/p2p.md" "$CLAUDE_DIR/patterns/dlt-infra/real-exploits/p2p.md"
cp "$SCRIPT_DIR/patterns/dlt-infra/real-exploits/rpc-crash.md" "$CLAUDE_DIR/patterns/dlt-infra/real-exploits/rpc-crash.md"

# Install references
echo "[*] Installing reference materials..."
cp "$SCRIPT_DIR/references/dlt-infra/attack-vectors.md" "$CLAUDE_DIR/references/dlt-infra/attack-vectors.md"
cp "$SCRIPT_DIR/references/dlt-infra/bounty-targets.md" "$CLAUDE_DIR/references/dlt-infra/bounty-targets.md"

echo ""
echo "[+] HarryAgent installed successfully!"
echo ""
echo "  Usage:"
echo "    cd /path/to/any/blockchain/codebase"
echo "    claude"
echo ""
echo "  Then type:"
echo "    /shutdown    - Hunt for network shutdown bugs (highest value)"
echo "    /audit       - Full 6-phase security audit"
echo "    /hunt p2p    - Deep dive into P2P attack surface"
echo "    /hunt rpc    - Deep dive into RPC attack surface"
echo ""
echo "  Installed to: $CLAUDE_DIR"
echo "  Files: $(find "$CLAUDE_DIR/agents" "$CLAUDE_DIR/patterns" "$CLAUDE_DIR/rules" "$CLAUDE_DIR/commands" "$CLAUDE_DIR/references" -name '*.md' 2>/dev/null | wc -l) markdown files"
echo "  Patterns: 148 battle-tested exploit patterns from real bug bounties"
echo ""
