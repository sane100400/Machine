#!/bin/bash
# PostToolUse hook: auto-invoke decision_tree.py on repeated Bash failures
# Detects when an agent's Bash commands keep failing and injects next-action guidance

MACHINE_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null || echo /home/sane100400/Machine)"
DT="$MACHINE_ROOT/tools/decision_tree.py"
CHALLENGE_DIR="${CHALLENGE_DIR:-$(pwd)}"

# Read tool result from stdin
INPUT=$(cat)

# Only act on Bash tool results
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)
[ "$TOOL_NAME" = "Bash" ] || exit 0

# Check exit code
EXIT_CODE=$(echo "$INPUT" | jq -r '.exit_code // "0"' 2>/dev/null)
[ "$EXIT_CODE" != "0" ] || exit 0

# Track failure count in a temp file per challenge
FAIL_FILE="/tmp/machine_fail_count_$(echo "$CHALLENGE_DIR" | md5sum | cut -c1-8)"
COUNT=$(cat "$FAIL_FILE" 2>/dev/null || echo 0)
COUNT=$((COUNT + 1))
echo "$COUNT" > "$FAIL_FILE"

# After 3+ consecutive failures, inject decision_tree guidance
if [ "$COUNT" -ge 3 ]; then
    # Detect agent type from context
    AGENT=""
    TRIGGER=""
    
    # Try to detect from recent commands
    COMMAND=$(echo "$INPUT" | jq -r '.command // empty' 2>/dev/null)
    
    case "$COMMAND" in
        *solve*|*sat_solve*|*z3*|*sage*)
            AGENT="crypto"
            TRIGGER="custom_cipher"
            ;;
        *exploit*|*pwn*)
            AGENT="pwn"
            TRIGGER="payload_failure"
            ;;
        *angr*|*ghidra*)
            AGENT="rev"
            TRIGGER="solver_fallback"
            ;;
    esac
    
    if [ -n "$AGENT" ] && [ -f "$DT" ]; then
        echo ""
        echo "═══════════════════════════════════════════════"
        echo "⚠️  $COUNT consecutive failures detected."
        echo "═══════════════════════════════════════════════"
        echo ""
        echo "Decision tree recommendation:"
        CHALLENGE_DIR="$CHALLENGE_DIR" python3 "$DT" next --agent "$AGENT" --trigger "$TRIGGER" 2>/dev/null || true
        echo ""
        echo "Record this failure and get next action:"
        echo "  python3 $DT record --agent $AGENT --trigger $TRIGGER --action-id <current_action>"
        echo "  python3 $DT next --agent $AGENT --trigger $TRIGGER"
        echo ""
        echo "After 5 total failures, search writeups:"
        echo "  python3 $MACHINE_ROOT/tools/knowledge.py search '<challenge> <technique>'"
        echo "═══════════════════════════════════════════════"
    fi
fi

# Reset counter on success (handled by exit 0 check above)
exit 0
