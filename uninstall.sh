#!/bin/bash
# HarryAgent Uninstaller — removes all HarryAgent files from ~/.claude/
set -e

CLAUDE_DIR="$HOME/.claude"

echo "[*] Removing HarryAgent from $CLAUDE_DIR..."

rm -f "$CLAUDE_DIR/CLAUDE.md"
rm -f "$CLAUDE_DIR/commands/audit.md"
rm -f "$CLAUDE_DIR/commands/shutdown.md"
rm -rf "$CLAUDE_DIR/rules"
rm -rf "$CLAUDE_DIR/agents"
rm -rf "$CLAUDE_DIR/patterns"
rm -rf "$CLAUDE_DIR/references"

echo "[+] HarryAgent uninstalled."
