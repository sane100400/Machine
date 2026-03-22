#!/bin/bash
# knowledge_inject.sh — PreToolUse hook (Task|Agent matcher)
# 에이전트 스폰 직전에 관련 CTF 기법 문서를 자동으로 systemMessage에 주입

set -euo pipefail

MACHINE_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
KNOWLEDGE_PY="$MACHINE_ROOT/tools/knowledge.py"
CHALLENGES_DIR="$MACHINE_ROOT/knowledge/challenges"

INPUT=$(cat)

# Python3으로 JSON 파싱
read TOOL_NAME SUBAGENT_TYPE PROMPT < <(python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    ti = d.get('tool_input', {})
    print(
        d.get('tool_name', ''),
        ti.get('subagent_type', ''),
        (ti.get('prompt', '') or ti.get('description', ''))[:300].replace('\n', ' ')
    )
except:
    print('', '', '')
" <<< "$INPUT")

if [[ "$TOOL_NAME" != "Task" && "$TOOL_NAME" != "Agent" ]]; then
    echo '{}'
    exit 0
fi
if [[ -z "$SUBAGENT_TYPE" ]]; then
    echo '{}'
    exit 0
fi

# ── 에이전트 타입 → 검색 쿼리 매핑 ──────────────────────────────────────
QUERY=""
COMBINED="${SUBAGENT_TYPE} ${PROMPT}"

case "$SUBAGENT_TYPE" in
    pwn*)       QUERY="heap exploitation tcache ROP binary pwn" ;;
    rev*)       QUERY="reverse engineering GDB oracle custom VM algorithm" ;;
    web*)       QUERY="XSS SSRF SSTI SQLi prototype pollution deserialization web" ;;
    crypto*)    QUERY="RSA cipher hash attack crypto" ;;
    forensics*) QUERY="steganography pcap memory forensics binwalk" ;;
    web3*)      QUERY="smart contract reentrancy DeFi EVM Solidity" ;;
    critic*)    QUERY="verification cross-check audit review" ;;
    reporter*)  QUERY="report writeup disclosure submission" ;;
esac

# 프롬프트에서 기술 키워드 추출해서 쿼리 보강
TECH_KEYWORDS=$(echo "$PROMPT" | grep -oiE 'heap|tcache|rop|format.string|overflow|uaf|use.after.free|fsop|xss|ssrf|ssti|sqli|jwt|prototype|deserialization|reentrancy|kernel|wasm' | sort -u | tr '\n' ' ')
if [[ -n "$TECH_KEYWORDS" ]]; then
    QUERY="${QUERY} ${TECH_KEYWORDS}"
fi

# ── knowledge.py FTS 검색 ────────────────────────────────────────────────
KB_RESULTS=""
if [[ -n "$QUERY" ]] && python3 "$KNOWLEDGE_PY" status &>/dev/null; then
    KB_RESULTS=$(python3 "$KNOWLEDGE_PY" search "$QUERY" --top 4 2>/dev/null || true)
fi

# ── 유사 과거 챌린지 검색 ────────────────────────────────────────────────
CHALLENGE_HITS=""
if [[ -d "$CHALLENGES_DIR" ]]; then
    KEYWORDS=$(echo "$PROMPT" | grep -oE '[a-zA-Z]{4,}' | head -5 | tr '\n' '|' | sed 's/|$//')
    if [[ -n "$KEYWORDS" ]]; then
        while IFS= read -r hit; do
            name=$(basename "$hit" .md)
            result=$(grep -E "flag|FLAG|DH\{|PASS|FAIL" "$hit" 2>/dev/null | head -3 || true)
            [[ -n "$result" ]] && CHALLENGE_HITS="${CHALLENGE_HITS}
- ${name}: ${result}"
        done < <(grep -rl -E "$KEYWORDS" "$CHALLENGES_DIR" 2>/dev/null | head -3)
    fi
fi

# ── 아무것도 없으면 빈 응답 ──────────────────────────────────────────────
if [[ -z "$KB_RESULTS" && -z "$CHALLENGE_HITS" ]]; then
    echo '{}'
    exit 0
fi

# ── systemMessage 조립 ───────────────────────────────────────────────────
MSG="[AUTO-INJECTED CTF KNOWLEDGE — ${SUBAGENT_TYPE}]"
MSG="${MSG}

> 더 검색: python3 \$MACHINE_ROOT/tools/knowledge.py search \"<query>\""

[[ -n "$KB_RESULTS" ]] && MSG="${MSG}

## Relevant Techniques (FTS)
${KB_RESULTS}"

[[ -n "$CHALLENGE_HITS" ]] && MSG="${MSG}

## Similar Past Challenges
${CHALLENGE_HITS}"

python3 -c "
import json, sys
msg = sys.stdin.read()
print(json.dumps({'systemMessage': msg}))
" <<< "$MSG"
