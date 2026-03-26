#!/bin/bash
# PreToolUse hook: warn orchestrator when it directly runs solve code
# Agents are fine — this only matters for the main orchestrator session

INPUT=$(cat)

TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)

case "$TOOL_NAME" in
    Write|Edit)
        FILE_PATH=$(echo "$INPUT" | jq -r '.file_path // empty' 2>/dev/null)
        BASENAME=$(basename "$FILE_PATH" 2>/dev/null)
        case "$BASENAME" in
            solve*.py|sat_solve*.py|exploit*.py|attack*.py|crack*.py|pwn*.py|*.sage)
                echo "⚠️ ORCHESTRATOR: You are writing '$BASENAME' directly."
                echo "→ CLAUDE.md Rule 1: Spawn an agent. Re-spawn crypto/pwn/rev agent with failure context."
                ;;
        esac
        ;;
    Bash)
        COMMAND=$(echo "$INPUT" | jq -r '.command // empty' 2>/dev/null)
        # Detect inline solve code (heredoc or long python/sage one-liners)
        case "$COMMAND" in
            *"<< '"*|*"<< \""*|*"<<PYEOF"*|*"<<'PYEOF'"*|*"<<'SAGE'"*|*"<<SAGE"*)
                # Heredoc = writing code inline
                echo "⚠️ ORCHESTRATOR: You are running inline solve code via heredoc."
                echo "→ CLAUDE.md Rule 1: Spawn an agent instead. You are a manager, not an engineer."
                echo "→ Analyze the failure, enrich HANDOFF context, re-spawn the agent."
                ;;
            *"python3 solve"*|*"python3 sat_"*|*"python3 exploit"*|*"sage solve"*|*"sage /tmp/solve"*)
                # Running solve scripts directly
                # This is OK if testing — but creating new ones is not
                ;;
        esac
        ;;
esac

exit 0
