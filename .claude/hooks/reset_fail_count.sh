#!/bin/bash
# PostToolUse hook: reset failure counter on Bash success
CHALLENGE_DIR="${CHALLENGE_DIR:-$(pwd)}"
INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)
[ "$TOOL_NAME" = "Bash" ] || exit 0
EXIT_CODE=$(echo "$INPUT" | jq -r '.exit_code // "0"' 2>/dev/null)
if [ "$EXIT_CODE" = "0" ]; then
    FAIL_FILE="/tmp/machine_fail_count_$(echo "$CHALLENGE_DIR" | md5sum | cut -c1-8)"
    echo "0" > "$FAIL_FILE" 2>/dev/null
fi
exit 0
