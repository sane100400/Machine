#!/bin/bash
# gemini_query.sh — Gemini summarization wrapper
# Usage: echo "large text" | bash tools/gemini_query.sh [mode]
# Modes: summarize (default), reverse, analyze
# NOTE: run `chmod +x tools/gemini_query.sh` to make executable

set -euo pipefail

MODE="${1:-summarize}"
API_KEY="${GEMINI_API_KEY:-}"

if [[ -z "$API_KEY" ]]; then
    echo "[gemini] ERROR: GEMINI_API_KEY not set" >&2
    exit 1
fi

INPUT=$(cat)

# Truncate to 30000 chars to stay within limits
INPUT="${INPUT:0:30000}"

case "$MODE" in
    summarize)
        SYSTEM_PROMPT="Summarize the following technical output concisely. Focus on: key findings, addresses, vulnerabilities, flags, errors. Output in bullet points. Max 50 lines."
        ;;
    reverse)
        SYSTEM_PROMPT="Analyze this binary analysis output. Extract: architecture, protections, key functions, potential vulnerabilities. Max 50 lines."
        ;;
    analyze)
        SYSTEM_PROMPT="Analyze this security tool output. Extract: findings by severity, affected components, suggested next steps. Max 50 lines."
        ;;
    *)
        SYSTEM_PROMPT="Summarize this output concisely. Max 50 lines."
        ;;
esac

# Call Gemini API
curl -s "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=$API_KEY" \
    -H "Content-Type: application/json" \
    -d "$(python3 -c "
import json, sys
text = sys.stdin.read()
payload = {
    'contents': [{'parts': [{'text': '''$SYSTEM_PROMPT''' + '\n\n' + text}]}],
    'generationConfig': {'maxOutputTokens': 2048, 'temperature': 0.1}
}
print(json.dumps(payload))
" <<< "$INPUT")" | python3 -c "
import json, sys
try:
    resp = json.load(sys.stdin)
    text = resp['candidates'][0]['content']['parts'][0]['text']
    print(text)
except Exception as e:
    print(f'[gemini] Parse error: {e}', file=sys.stderr)
    sys.exit(1)
"
