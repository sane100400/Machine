#!/bin/bash
# Block orchestrator from directly writing solve files
# Only agents should create solve.py, sat_solve.py, etc.
# This hook runs on PreToolUse for Write/Edit

# Read the tool input from stdin
INPUT=$(cat)

# Extract file path from the tool call
FILE_PATH=$(echo "$INPUT" | jq -r '.file_path // .path // empty' 2>/dev/null)

if [ -z "$FILE_PATH" ]; then
    exit 0  # Can't determine path, allow
fi

BASENAME=$(basename "$FILE_PATH" 2>/dev/null)

# Check if this is a solve-related file being written
case "$BASENAME" in
    solve*.py|sat_solve*.py|exploit*.py|attack*.py|crack*.py|pwn*.py)
        # Check if we're inside a subagent (CLAUDE_AGENT env var or similar)
        # If the tool_use_id suggests main session, block it
        echo "⚠️ ORCHESTRATOR WARNING: You are writing '$BASENAME' directly."
        echo "CLAUDE.md Rule 1: Never solve directly. Spawn an agent instead."
        echo "Use: Agent(subagent_type='crypto', prompt='...')"
        echo ""
        echo "If the previous agent failed, re-spawn with better context:"
        echo "  1. Analyze WHY it failed"  
        echo "  2. Add failure details to HANDOFF"
        echo "  3. Spawn agent again"
        # Don't block (exit 0), just warn strongly
        exit 0
        ;;
esac

exit 0
