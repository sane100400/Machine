#!/bin/bash
# check_agent_completion.sh — SubagentStop hook
# 에이전트 종료 시 checkpoint.json을 읽어 실제 완료 여부 자동 검증
#
# 감지:
#   - FAKE IDLE: status=in_progress인데 종료됨 (compaction/에러로 중단)
#   - 할루시네이션: status=completed인데 expected artifact 없음
#   - 에러: status=error

set -euo pipefail

MACHINE_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE_PY="$MACHINE_ROOT/tools/state.py"

INPUT=$(cat)
CWD=$(python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    print(d.get('cwd', ''))
except:
    print('')
" <<< "$INPUT")

if [[ -z "$CWD" ]]; then
    echo '{}'
    exit 0
fi

WARNINGS=""
FOUND_INCOMPLETE=false

while IFS= read -r cp; do
    [[ -f "$cp" ]] || continue
    DIR=$(dirname "$cp")

    # Python3으로 checkpoint.json 파싱
    eval "$(python3 -c "
import json, sys
try:
    d = json.load(open('$cp'))
    status = d.get('status', 'unknown')
    agent = d.get('agent', 'unknown')
    phase = str(d.get('phase_name', d.get('phase', '?')))
    error = d.get('error', '')
    completed = ', '.join(d.get('completed', []))
    artifacts = ' '.join(d.get('expected_artifacts', []))
    print(f'STATUS={json.dumps(status)}')
    print(f'AGENT={json.dumps(agent)}')
    print(f'PHASE={json.dumps(phase)}')
    print(f'ERROR={json.dumps(error)}')
    print(f'COMPLETED={json.dumps(completed)}')
    print(f'ARTIFACTS={json.dumps(artifacts)}')
except Exception as e:
    print('STATUS=\"unknown\"')
    print('AGENT=\"unknown\"')
    print('PHASE=\"?\"')
    print('ERROR=\"\"')
    print('COMPLETED=\"\"')
    print('ARTIFACTS=\"\"')
" 2>/dev/null)"

    # state.db verified fact 수
    VERIFIED_COUNT=0
    if [[ -f "$DIR/state.db" ]]; then
        VERIFIED_COUNT=$(CHALLENGE_DIR="$DIR" python3 "$STATE_PY" facts 2>/dev/null \
            | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for f in d if f.get('verified')))" \
            2>/dev/null || echo 0)
    fi

    case "$STATUS" in
        completed)
            MISSING=""
            for artifact in $ARTIFACTS; do
                [[ -z "$artifact" ]] && continue
                [[ ! -f "$DIR/$artifact" ]] && MISSING="${MISSING} ${artifact}"
            done
            if [[ -n "$MISSING" ]]; then
                WARNINGS="${WARNINGS}
[WARN] ${AGENT}: status=completed but missing artifacts:${MISSING}
  → 할루시네이션 의심. 산출물 없이 완료 선언함.
  → verified facts in state.db: ${VERIFIED_COUNT}"
                FOUND_INCOMPLETE=true
            fi
            ;;
        in_progress)
            WARNINGS="${WARNINGS}
[ALERT] ${AGENT}: FAKE IDLE — status=in_progress at phase=${PHASE}
  completed so far: ${COMPLETED:-none}
  verified facts in state.db: ${VERIFIED_COUNT}
  → compaction 또는 에러로 중단됨.
  → 오케스트레이터: state.py checkpoint --read 확인 후 resume 또는 재스폰 필요."
            FOUND_INCOMPLETE=true
            ;;
        error)
            WARNINGS="${WARNINGS}
[ERROR] ${AGENT}: status=error at phase=${PHASE}
  error: ${ERROR}
  → 환경 문제 해결 후 재스폰 필요."
            FOUND_INCOMPLETE=true
            ;;
    esac

done < <(find "$CWD" -maxdepth 4 -name "checkpoint.json" -mmin -10 2>/dev/null | head -5)

if [[ "$FOUND_INCOMPLETE" == true ]]; then
    python3 -c "
import json, sys
msg = sys.stdin.read()
print(json.dumps({'additionalContext': msg}))
" <<< "$WARNINGS"
else
    echo '{}'
fi

exit 0
