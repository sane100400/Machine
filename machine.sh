#!/bin/bash
# Machine - Autonomous CTF Agent Launcher
# Uses Claude Code with bypassPermissions for fully autonomous operation
#
# Usage:
#   ./machine.sh [--json] [--timeout N] [--dry-run] ctf /path/to/challenge[.zip]
#   ./machine.sh status                         (check running sessions)
#   ./machine.sh logs                           (tail latest session log)

set -euo pipefail

# Exit codes
EXIT_CLEAN=0
EXIT_CRITICAL=1
EXIT_HIGH=2
EXIT_MEDIUM=3
EXIT_ERROR=10

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODEL="${MACHINE_MODEL:-opus}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_DIR="$SCRIPT_DIR/reports/$TIMESTAMP"
PID_FILE="$SCRIPT_DIR/.machine.pid"
LOG_FILE="$SCRIPT_DIR/.machine.log"

# --- Parse global flags ---
JSON_OUTPUT=false
TIMEOUT=0
DRY_RUN=false

while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --json) JSON_OUTPUT=true; shift ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    *) break ;;
  esac
done

MODE="${1:-help}"
TARGET="${2:-}"
SCOPE="${3:-}"
SERVER="${4:-}"

# --- Banner ---

show_banner() {
  local mode_label="$1"
  cat <<'BANNER'

  ███╗   ███╗ █████╗  ██████╗██╗  ██╗██╗███╗   ██╗███████╗
  ████╗ ████║██╔══██╗██╔════╝██║  ██║██║████╗  ██║██╔════╝
  ██╔████╔██║███████║██║     ███████║██║██╔██╗ ██║█████╗
  ██║╚██╔╝██║██╔══██║██║     ██╔══██║██║██║╚██╗██║██╔══╝
  ██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║██║██║ ╚████║███████╗
  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝
BANNER
  echo "  Autonomous Security Agent System — $mode_label"
  echo ""
}

# --- Helper functions ---

extract_if_zip() {
  local target="$1"
  if [[ "$target" == *.zip ]]; then
    local basename="$(basename "$target" .zip)"
    local extract_dir="$SCRIPT_DIR/challenges/extracted/$basename"
    if [ -d "$extract_dir" ]; then
      echo "[*] Already extracted: $extract_dir" >&2
    else
      echo "[*] Extracting $target → $extract_dir" >&2
      mkdir -p "$extract_dir"
      unzip -o -q "$target" -d "$extract_dir"
    fi
    echo "$extract_dir"
  elif [ -d "$target" ]; then
    echo "$(realpath "$target")"
  else
    echo "[!] Not a zip or directory: $target" >&2
    exit 1
  fi
}

generate_summary() {
  local report_dir="$1"
  local mode="$2"
  local target="$3"
  local start_ts="$4"
  local exit_code="$5"
  local status="$6"

  local end_ts
  end_ts="$(date +%s)"
  local duration=$(( end_ts - start_ts ))

  local iso_ts
  iso_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Count flags
  local flags_json="[]"
  if [ -f "$report_dir/flags.txt" ]; then
    flags_json="$(python3 -c "
import json
lines = open('$report_dir/flags.txt').read().strip().splitlines()
flags = [l.strip() for l in lines if l.strip()]
print(json.dumps(flags))
" 2>/dev/null || echo '[]')"
  fi

  # Count findings by severity from session.log
  local cnt_critical=0 cnt_high=0 cnt_medium=0 cnt_low=0 cnt_info=0
  if [ -f "$report_dir/session.log" ]; then
    cnt_critical=$(grep -c '\[CRITICAL\]' "$report_dir/session.log" 2>/dev/null || true)
    cnt_high=$(grep -c '\[HIGH\]' "$report_dir/session.log" 2>/dev/null || true)
    cnt_medium=$(grep -c '\[MEDIUM\]' "$report_dir/session.log" 2>/dev/null || true)
    cnt_low=$(grep -c '\[LOW\]' "$report_dir/session.log" 2>/dev/null || true)
    cnt_info=$(grep -c '\[INFO\]' "$report_dir/session.log" 2>/dev/null || true)
  fi

  # List generated files
  local files_json
  files_json="$(python3 -c "
import json, os
files = []
report_dir = '$report_dir'
try:
    for f in os.listdir(report_dir):
        fpath = os.path.join(report_dir, f)
        if os.path.isfile(fpath):
            files.append(f)
except Exception:
    pass
print(json.dumps(sorted(files)))
" 2>/dev/null || echo '[]')"

  python3 -c "
import json
summary = {
    'timestamp': '$iso_ts',
    'mode': '$mode',
    'target': '$target',
    'duration_seconds': $duration,
    'exit_code': $exit_code,
    'flags_found': $flags_json,
    'findings': {
        'critical': $cnt_critical,
        'high': $cnt_high,
        'medium': $cnt_medium,
        'low': $cnt_low,
        'info': $cnt_info
    },
    'files_generated': $files_json,
    'status': '$status'
}
print(json.dumps(summary, indent=2))
" > "$report_dir/summary.json" 2>/dev/null || true
}

determine_exit_code() {
  local report_dir="$1"
  local exit_code=$EXIT_CLEAN

  if [ -f "$report_dir/session.log" ]; then
    if grep -q '\[CRITICAL\]' "$report_dir/session.log" 2>/dev/null; then
      exit_code=$EXIT_CRITICAL
    elif grep -q '\[HIGH\]' "$report_dir/session.log" 2>/dev/null; then
      exit_code=$EXIT_HIGH
    elif grep -q '\[MEDIUM\]' "$report_dir/session.log" 2>/dev/null; then
      exit_code=$EXIT_MEDIUM
    fi
  fi

  echo "$exit_code"
}

# --- Internal commands (called from background jobs) ---

if [[ "$MODE" == "_summary" ]]; then
  generate_summary "$2" "$3" "$4" "$5" "$6" "$7"
  exit 0
fi

if [[ "$MODE" == "_exit_code" ]]; then
  determine_exit_code "$2"
  exit 0
fi

# --- Main ---

case "$MODE" in
  ctf)
    if [ -z "$TARGET" ]; then
      echo "Usage: ./machine.sh ctf /path/to/challenge[.zip] [category]"
      echo "  category: pwn, rev, web, crypto, forensics, web3 (생략 시 자동 감지)"
      exit $EXIT_ERROR
    fi

    CHALLENGE_DIR="$(extract_if_zip "$(realpath "$TARGET")")"
    CATEGORY="${SCOPE:-}"
    FILES=$(ls -1 "$CHALLENGE_DIR" 2>/dev/null | head -30)
    mkdir -p "$REPORT_DIR"

    # Validate category if provided
    if [ -n "$CATEGORY" ]; then
      case "$CATEGORY" in
        pwn|rev|web|crypto|forensics|web3) ;;
        *)
          echo "[!] Invalid category: $CATEGORY"
          echo "    Valid: pwn, rev, web, crypto, forensics, web3"
          exit $EXIT_ERROR
          ;;
      esac
    fi

    if [ "$DRY_RUN" = true ]; then
      if [ "$JSON_OUTPUT" = true ]; then
        python3 -c "
import json
plan = {
    'dry_run': True,
    'mode': 'ctf',
    'target': '$CHALLENGE_DIR',
    'category': '${CATEGORY:-auto-detect}',
    'model': '$MODEL',
    'report_dir': '$REPORT_DIR',
    'timeout': $TIMEOUT
}
print(json.dumps(plan, indent=2))
"
      else
        echo "[DRY-RUN] CTF mode"
        echo "  Challenge: $CHALLENGE_DIR"
        echo "  Category:  ${CATEGORY:-auto-detect}"
        [ -n "$SERVER" ] && echo "  Server:    $SERVER"
        echo "  Files:     $FILES"
        echo "  Model:     $MODEL"
        echo "  Report:    $REPORT_DIR"
        echo "  Timeout:   ${TIMEOUT}s (0=none)"
      fi
      exit $EXIT_CLEAN
    fi

    if [ "$JSON_OUTPUT" = false ]; then
      show_banner "CTF Mode"
      echo "╔══════════════════════════════════════════════╗"
      echo "║  Challenge: $(basename "$CHALLENGE_DIR")"
      echo "║  Category:  ${CATEGORY:-auto-detect}"
      [ -n "$SERVER" ] && echo "║  Server:    $SERVER"
      echo "║  Files:     $FILES"
      echo "║  Model:     $MODEL"
      echo "║  Report:    $REPORT_DIR"
      echo "║  Log:       $REPORT_DIR/session.log"
      echo "╠══════════════════════════════════════════════╣"
      echo "║  Running in background...                    ║"
      echo "║  Monitor:  tail -f $REPORT_DIR/session.log"
      echo "║  Status:   ./machine.sh status               ║"
      echo "╚══════════════════════════════════════════════╝"
    fi

    START_TS="$(date +%s)"

    # Build claude command (with optional timeout wrapper)
    CLAUDE_CMD="claude -p"
    if [ "$TIMEOUT" -gt 0 ] 2>/dev/null; then
      CLAUDE_CMD="timeout $TIMEOUT claude -p"
    fi

    # Write prompt to file (avoids heredoc escaping hell in nohup)
    PROMPT_FILE="$REPORT_DIR/prompt.txt"
    cat > "$PROMPT_FILE" <<PROMPT_EOF
You are Machine Orchestrator. Use Agent Teams to solve this CTF challenge.

Challenge directory: $CHALLENGE_DIR
Files found: $FILES
Report directory: $REPORT_DIR
Category: ${CATEGORY:-NOT SPECIFIED — you must detect it}
$([ -n "$SERVER" ] && echo "Target server: $SERVER")

MANDATORY: Follow CLAUDE.md pipeline rules.

STEP 1: Read knowledge/index.md — check if already solved
STEP 2: Pre-check (file, strings, checksec on binaries)
$(if [ -n "$CATEGORY" ]; then
echo "STEP 3: Category is $CATEGORY (user-specified). Skip detection."
echo "STEP 4: Immediately spawn the $CATEGORY pipeline:"
echo "  @$CATEGORY → @critic → @verifier → @reporter"
else
echo "STEP 3: Determine category: pwn / rev / web / crypto / forensics / web3"
echo "STEP 4: Spawn pipeline agents (Agent tool with subagent_type)"
echo ""
echo "Pipeline by category:"
echo "  PWN:       @pwn → @critic → @verifier → @reporter"
echo "  REV:       @rev → @critic → @verifier → @reporter"
echo "  WEB:       @web → @critic → @verifier → @reporter"
echo "  CRYPTO:    @crypto → @critic → @verifier → @reporter"
echo "  FORENSICS: @forensics → @critic → @verifier → @reporter"
echo "  WEB3:      @web3 → @critic → @verifier → @reporter"
fi)
$([ -n "$SERVER" ] && echo "
IMPORTANT: The challenge server is running at $SERVER
- For web challenges: send HTTP requests to $SERVER
- For pwn challenges: use remote('HOST', PORT) in pwntools
- Flags obtained from this server are REAL flags")

Pass each agent's output to the next via structured HANDOFF.
Save solve.py to $CHALLENGE_DIR/solve.py
Save writeup to $REPORT_DIR/writeup.md

STEP 5: Collect results — Update knowledge/index.md

Flag formats: DH{...}, FLAG{...}, flag{...}, CTF{...}, GoN{...}, CYAI{...}
PROMPT_EOF

    # Write runner script (avoids nohup escaping issues)
    RUNNER="$REPORT_DIR/runner.sh"
    cat > "$RUNNER" <<RUNNER_EOF
#!/bin/bash
START_TS=$START_TS
PROMPT_FILE="$PROMPT_FILE"
REPORT_DIR="$REPORT_DIR"
SCRIPT_DIR="$SCRIPT_DIR"
PID_FILE="$PID_FILE"
MODEL="$MODEL"
CHALLENGE_DIR="$CHALLENGE_DIR"
TIMEOUT_VAL=$TIMEOUT

CLAUDE_CMD="claude -p"
if [ "\$TIMEOUT_VAL" -gt 0 ] 2>/dev/null; then
  CLAUDE_CMD="timeout \$TIMEOUT_VAL claude -p"
fi

\$CLAUDE_CMD "\$(cat "\$PROMPT_FILE")" --permission-mode bypassPermissions --model "\$MODEL" --output-format stream-json --verbose 2>&1 | python3 -u "\$SCRIPT_DIR/tools/stream_parser.py" "\$REPORT_DIR/session.log"
CLAUDE_EXIT=\$?

echo '' >> "\$REPORT_DIR/session.log"
echo '=== SESSION COMPLETE ===' >> "\$REPORT_DIR/session.log"
echo "Timestamp: \$(date)" >> "\$REPORT_DIR/session.log"

FLAGS=\$(grep -oE '(DH|FLAG|flag|CTF|GoN|CYAI)\{[^}]+\}' "\$REPORT_DIR/session.log" 2>/dev/null | sort -u || true)
if [ -n "\$FLAGS" ]; then
  echo "FLAGS FOUND:" >> "\$REPORT_DIR/session.log"
  echo "\$FLAGS" >> "\$REPORT_DIR/session.log"
  echo "\$FLAGS" > "\$REPORT_DIR/flags.txt"
else
  echo 'NO FLAGS FOUND' >> "\$REPORT_DIR/session.log"
fi

FINAL_EXIT=\$(bash "\$SCRIPT_DIR/machine.sh" _exit_code "\$REPORT_DIR" 2>/dev/null || echo 0)
echo "\$FINAL_EXIT" > "\$REPORT_DIR/exit_code"

SESSION_STATUS='completed'
[ "\$CLAUDE_EXIT" -eq 124 ] 2>/dev/null && SESSION_STATUS='timeout'
[ "\$CLAUDE_EXIT" -ne 0 ] 2>/dev/null && SESSION_STATUS='failed'
bash "\$SCRIPT_DIR/machine.sh" _summary "\$REPORT_DIR" ctf "\$CHALLENGE_DIR" "\$START_TS" "\$FINAL_EXIT" "\$SESSION_STATUS" 2>/dev/null || true

rm -f "\$PID_FILE"
RUNNER_EOF
    chmod +x "$RUNNER"

    # Run in background
    nohup bash "$RUNNER" > /dev/null 2>&1 &

    BGPID=$!
    echo "$BGPID" > "$PID_FILE"
    echo "$BGPID $REPORT_DIR $TIMESTAMP ctf $START_TS" >> "$SCRIPT_DIR/.machine.history"

    if [ "$JSON_OUTPUT" = true ]; then
      echo "$REPORT_DIR/summary.json"
    else
      echo ""
      echo "[*] PID: $BGPID"
      echo "[*] To monitor: tail -f $REPORT_DIR/session.log"
    fi
    ;;


  learn)
    # Learn mode — solve a challenge AND produce a structured writeup for the knowledge DB
    # The key difference from 'ctf' mode:
    #   ctf:   goal = capture flag (speed priority)
    #   learn: goal = deep understanding + writeup (learning priority)

    if [ -z "$TARGET" ]; then
      echo "Usage:"
      echo "  ./machine.sh learn /path/to/challenge[.zip]   Solve + writeup + index to DB"
      echo "  ./machine.sh learn --import <file.md|dir|url>  Import existing writeup(s)"
      echo "  ./machine.sh learn --reindex                   Force reindex all knowledge"
      exit $EXIT_ERROR
    fi

    KNOWLEDGE_PY="$SCRIPT_DIR/tools/knowledge.py"
    CHALLENGES_DIR="$SCRIPT_DIR/knowledge/challenges"
    TEMPLATE="$SCRIPT_DIR/knowledge/challenges/_template.md"
    TEMPLATE_CONTENT="$(cat "$TEMPLATE" 2>/dev/null || echo '')"
    mkdir -p "$CHALLENGES_DIR"

    # --- Sub-modes: --import, --reindex ---
    case "$TARGET" in
      --reindex)
        echo "[*] Force reindexing all knowledge..."
        python3 "$KNOWLEDGE_PY" index --force
        python3 "$KNOWLEDGE_PY" index-external 2>/dev/null || true
        echo ""
        python3 "$KNOWLEDGE_PY" stats
        exit $EXIT_CLEAN
        ;;

      --import)
        IMPORT_TARGET="${SCOPE:-}"
        if [ -z "$IMPORT_TARGET" ]; then
          echo "Usage: ./machine.sh learn --import <file.md|directory|url>"
          exit $EXIT_ERROR
        fi

        case "$IMPORT_TARGET" in
          http://*|https://*)
            SLUG="$(echo "$IMPORT_TARGET" | sed 's|https\?://||;s|[^a-zA-Z0-9._-]|_|g' | cut -c1-80)"
            OUT_FILE="$CHALLENGES_DIR/${SLUG}.md"
            echo "[*] Fetching: $IMPORT_TARGET"
            curl -sL "https://r.jina.ai/$IMPORT_TARGET" > "$OUT_FILE" 2>/dev/null
            if [ -s "$OUT_FILE" ]; then
              python3 "$KNOWLEDGE_PY" add "$OUT_FILE"
              echo "[*] Imported + indexed: $OUT_FILE"
            else
              echo "[!] Fetch failed"; rm -f "$OUT_FILE"; exit $EXIT_ERROR
            fi
            ;;
          *)
            IMPORT_PATH="$(realpath "$IMPORT_TARGET" 2>/dev/null || echo "$IMPORT_TARGET")"
            if [ -f "$IMPORT_PATH" ]; then
              NAME="$(basename "$IMPORT_PATH")"
              cp "$IMPORT_PATH" "$CHALLENGES_DIR/$NAME"
              python3 "$KNOWLEDGE_PY" add "$CHALLENGES_DIR/$NAME"
              echo "[*] Imported: $NAME"
            elif [ -d "$IMPORT_PATH" ]; then
              COUNT=0
              for md in "$IMPORT_PATH"/*.md; do
                [ -f "$md" ] || continue
                NAME="$(basename "$md")"
                [ "$NAME" = "_template.md" ] && continue
                cp "$md" "$CHALLENGES_DIR/$NAME"
                python3 "$KNOWLEDGE_PY" add "$CHALLENGES_DIR/$NAME" 2>/dev/null
                echo "  + $NAME"; COUNT=$((COUNT + 1))
              done
              echo "[*] Imported $COUNT writeup(s)"
            else
              echo "[!] Not found: $IMPORT_PATH"; exit $EXIT_ERROR
            fi
            ;;
        esac
        python3 "$KNOWLEDGE_PY" stats 2>/dev/null || true
        exit $EXIT_CLEAN
        ;;
    esac

    # --- Main learn mode: solve challenge + produce writeup ---
    CHALLENGE_DIR="$(extract_if_zip "$(realpath "$TARGET")")"
    CHALLENGE_NAME="$(basename "$CHALLENGE_DIR")"
    CATEGORY="${SCOPE:-}"
    FILES=$(ls -1 "$CHALLENGE_DIR" 2>/dev/null | head -30)
    WRITEUP_FILE="$CHALLENGES_DIR/${CHALLENGE_NAME}.md"
    mkdir -p "$REPORT_DIR"

    # Validate category if provided
    if [ -n "$CATEGORY" ]; then
      case "$CATEGORY" in
        pwn|rev|web|crypto|forensics|web3) ;;
        *)
          echo "[!] Invalid category: $CATEGORY"
          echo "    Valid: pwn, rev, web, crypto, forensics, web3"
          exit $EXIT_ERROR
          ;;
      esac
    fi

    if [ "$DRY_RUN" = true ]; then
      echo "[DRY-RUN] Learn mode"
      echo "  Challenge: $CHALLENGE_DIR"
      echo "  Category:  ${CATEGORY:-auto-detect}"
      [ -n "$SERVER" ] && echo "  Server:    $SERVER"
      echo "  Files:     $FILES"
      echo "  Model:     $MODEL"
      echo "  Writeup:   $WRITEUP_FILE"
      echo "  Report:    $REPORT_DIR"
      exit $EXIT_CLEAN
    fi

    if [ "$JSON_OUTPUT" = false ]; then
      show_banner "Learn Mode"
      echo "╔══════════════════════════════════════════════╗"
      echo "║  Challenge: $(basename "$CHALLENGE_DIR")"
      echo "║  Category:  ${CATEGORY:-auto-detect}"
      [ -n "$SERVER" ] && echo "║  Server:    $SERVER"
      echo "║  Files:     $FILES"
      echo "║  Model:     $MODEL"
      echo "║  Writeup:   $WRITEUP_FILE"
      echo "║  Report:    $REPORT_DIR"
      echo "╠══════════════════════════════════════════════╣"
      echo "║  Solving + writing up in background...       ║"
      echo "║  Monitor:  tail -f $REPORT_DIR/session.log"
      echo "╚══════════════════════════════════════════════╝"
    fi

    START_TS="$(date +%s)"

    # Write prompt to file
    PROMPT_FILE="$REPORT_DIR/prompt.txt"
    cat > "$PROMPT_FILE" <<PROMPT_EOF
You are Machine Orchestrator in LEARN MODE.

Your goal is to SOLVE this CTF challenge AND produce a detailed WRITEUP for the knowledge database.
This is a learning exercise — prioritize understanding over speed.

Challenge directory: $CHALLENGE_DIR
Challenge name: $CHALLENGE_NAME
Files found: $FILES
Report directory: $REPORT_DIR
Writeup output: $WRITEUP_FILE
Category: ${CATEGORY:-NOT SPECIFIED — you must detect it}
$([ -n "$SERVER" ] && echo "Target server: $SERVER")

MANDATORY: Follow CLAUDE.md pipeline rules.

═══ PHASE 1: SOLVE ═══

STEP 1: Read knowledge/index.md — check if already solved
STEP 2: Pre-check (file, strings, checksec on binaries)
$(if [ -n "$CATEGORY" ]; then
echo "STEP 3: Category is $CATEGORY (user-specified). Skip detection."
else
echo "STEP 3: Determine category: pwn / rev / web / crypto / forensics / web3"
fi)
STEP 4: Spawn pipeline agents:
  PWN:       @pwn → @critic → @verifier → @reporter
  REV:       @rev → @critic → @verifier → @reporter
  WEB:       @web → @critic → @verifier → @reporter
  CRYPTO:    @crypto → @critic → @verifier → @reporter
  FORENSICS: @forensics → @critic → @verifier → @reporter
  WEB3:      @web3 → @critic → @verifier → @reporter

Save solve.py to $CHALLENGE_DIR/solve.py

═══ PHASE 2: WRITEUP ═══

After solving (or after best attempt), write a detailed writeup to $WRITEUP_FILE
following this EXACT template:

$TEMPLATE_CONTENT

WRITEUP RULES:
- 한국어로 작성
- 분류: 카테고리 / 세부 기법 구체적으로 (예: pwn / heap / tcache poisoning / glibc 2.35)
- 환경: checksec 결과, libc 버전, 아키텍처 전부 기록
- 취약점: 한 줄로 핵심 취약점 요약
- 풀이 흐름: 번호 매겨서 단계별로. 구체적 주소/오프셋 포함
- 핵심 커맨드: 실제 사용한 exploit 코드의 핵심 부분 발췌
- 삽질 포인트: 처음에 틀렸던 가정, 실패한 접근, 시간 소모한 부분 솔직하게 기록
- 참고: 유사 문제, 사용한 기법의 참고 자료
- Flag: 실제 획득한 플래그 (못 풀었으면 "미해결" + 이유)

═══ PHASE 3: INDEX ═══

STEP 5: After writing $WRITEUP_FILE, run:
  python3 $SCRIPT_DIR/tools/knowledge.py add $WRITEUP_FILE
STEP 6: Update knowledge/index.md with this challenge entry

Flag formats: DH{...}, FLAG{...}, flag{...}, CTF{...}, GoN{...}, CYAI{...}
PROMPT_EOF

    # Write runner script
    RUNNER="$REPORT_DIR/runner.sh"
    cat > "$RUNNER" <<RUNNER_EOF
#!/bin/bash
START_TS=$START_TS
PROMPT_FILE="$PROMPT_FILE"
REPORT_DIR="$REPORT_DIR"
SCRIPT_DIR="$SCRIPT_DIR"
PID_FILE="$PID_FILE"
MODEL="$MODEL"
CHALLENGE_DIR="$CHALLENGE_DIR"
WRITEUP_FILE="$WRITEUP_FILE"
KNOWLEDGE_PY="$KNOWLEDGE_PY"
TIMEOUT_VAL=$TIMEOUT

CLAUDE_CMD="claude -p"
if [ "\$TIMEOUT_VAL" -gt 0 ] 2>/dev/null; then
  CLAUDE_CMD="timeout \$TIMEOUT_VAL claude -p"
fi

\$CLAUDE_CMD "\$(cat "\$PROMPT_FILE")" --permission-mode bypassPermissions --model "\$MODEL" --output-format stream-json --verbose 2>&1 | python3 -u "\$SCRIPT_DIR/tools/stream_parser.py" "\$REPORT_DIR/session.log"
CLAUDE_EXIT=\$?

echo '=== SESSION COMPLETE ===' >> "\$REPORT_DIR/session.log"

FLAGS=\$(grep -oE '(DH|FLAG|flag|CTF|GoN|CYAI)\{[^}]+\}' "\$REPORT_DIR/session.log" 2>/dev/null | sort -u || true)
if [ -n "\$FLAGS" ]; then
  echo "\$FLAGS" > "\$REPORT_DIR/flags.txt"
fi

if [ ! -s "\$WRITEUP_FILE" ]; then
  echo '[*] Writeup not found, generating from artifacts...' >> "\$REPORT_DIR/session.log"
  for md in "\$CHALLENGE_DIR"/*.md "\$REPORT_DIR"/*.md; do
    [ -f "\$md" ] && python3 "\$KNOWLEDGE_PY" add "\$md" 2>/dev/null || true
  done
else
  python3 "\$KNOWLEDGE_PY" add "\$WRITEUP_FILE" 2>/dev/null || true
  echo '[*] Writeup indexed to knowledge DB' >> "\$REPORT_DIR/session.log"
fi

FINAL_EXIT=\$(bash "\$SCRIPT_DIR/machine.sh" _exit_code "\$REPORT_DIR" 2>/dev/null || echo 0)
SESSION_STATUS='completed'
[ "\$CLAUDE_EXIT" -eq 124 ] 2>/dev/null && SESSION_STATUS='timeout'
[ "\$CLAUDE_EXIT" -ne 0 ] 2>/dev/null && SESSION_STATUS='failed'
bash "\$SCRIPT_DIR/machine.sh" _summary "\$REPORT_DIR" learn "\$CHALLENGE_DIR" "\$START_TS" "\$FINAL_EXIT" "\$SESSION_STATUS" 2>/dev/null || true
rm -f "\$PID_FILE"
RUNNER_EOF
    chmod +x "$RUNNER"

    # Run in background
    nohup bash "$RUNNER" > /dev/null 2>&1 &

    BGPID=$!
    echo "$BGPID" > "$PID_FILE"
    echo "$BGPID $REPORT_DIR $TIMESTAMP learn $START_TS" >> "$SCRIPT_DIR/.machine.history"

    if [ "$JSON_OUTPUT" = true ]; then
      echo "$REPORT_DIR/summary.json"
    else
      echo ""
      echo "[*] PID: $BGPID"
      echo "[*] To monitor: tail -f $REPORT_DIR/session.log"
      echo "[*] Writeup will be saved to: $WRITEUP_FILE"
    fi
    ;;

  status)
    # Parse last history entry
    LAST_START_TS=""
    LAST_DIR=""
    LAST_MODE=""
    if [ -f "$SCRIPT_DIR/.machine.history" ]; then
      LAST="$(tail -1 "$SCRIPT_DIR/.machine.history")"
      LAST_DIR="$(echo "$LAST" | awk '{print $2}')"
      LAST_MODE="$(echo "$LAST" | awk '{print $4}')"
      LAST_START_TS="$(echo "$LAST" | awk '{print $5}')"
    fi

    # Calculate elapsed time
    format_elapsed() {
      local secs="$1"
      local mins=$((secs / 60))
      local hrs=$((mins / 60))
      mins=$((mins % 60))
      secs=$((secs % 60))
      if [ "$hrs" -gt 0 ]; then
        printf "%dh %dm %ds" "$hrs" "$mins" "$secs"
      elif [ "$mins" -gt 0 ]; then
        printf "%dm %ds" "$mins" "$secs"
      else
        printf "%ds" "$secs"
      fi
    }

    if [ ! -f "$PID_FILE" ]; then
      echo "[*] No active Machine session."
      if [ -n "$LAST_DIR" ] && [ -f "$LAST_DIR/summary.json" ]; then
        echo "[*] Last session summary:"
        cat "$LAST_DIR/summary.json"
      fi
      exit $EXIT_CLEAN
    fi

    RUNNING_PID="$(cat "$PID_FILE")"
    if kill -0 "$RUNNING_PID" 2>/dev/null; then
      NOW_TS="$(date +%s)"
      ELAPSED=""
      if [ -n "$LAST_START_TS" ] && [ "$LAST_START_TS" -gt 0 ] 2>/dev/null; then
        ELAPSED_SECS=$((NOW_TS - LAST_START_TS))
        ELAPSED="$(format_elapsed $ELAPSED_SECS)"
      fi

      echo "[*] Machine session ACTIVE"
      echo "    PID:      $RUNNING_PID"
      [ -n "$LAST_MODE" ] && echo "    Mode:     $LAST_MODE"
      [ -n "$ELAPSED" ] && echo "    Elapsed:  $ELAPSED"
      [ -n "$LAST_DIR" ] && echo "    Report:   $LAST_DIR"
      if [ -n "$LAST_DIR" ] && [ -f "$LAST_DIR/session.log" ]; then
        LOG_LINES=$(wc -l < "$LAST_DIR/session.log" 2>/dev/null || echo 0)
        LOG_SIZE=$(du -h "$LAST_DIR/session.log" 2>/dev/null | awk '{print $1}')
        echo "    Log:      $LOG_LINES lines ($LOG_SIZE)"
      fi
    else
      echo "[*] Machine session FINISHED (stale PID: $RUNNING_PID)"
      rm -f "$PID_FILE"
      if [ -n "$LAST_DIR" ] && [ -f "$LAST_DIR/summary.json" ]; then
        echo "[*] Session summary:"
        cat "$LAST_DIR/summary.json"
      fi
    fi
    ;;

  stop|kill)
    # Kill active Machine session and all child claude processes
    if [ ! -f "$PID_FILE" ]; then
      # Check for orphaned claude -p processes anyway
      ORPHANS=$(pgrep -f "claude -p.*Machine Orchestrator" 2>/dev/null || true)
      if [ -n "$ORPHANS" ]; then
        echo "[*] No PID file, but found orphaned Machine processes:"
        echo "$ORPHANS" | while read pid; do
          echo "    Killing PID $pid"
          kill "$pid" 2>/dev/null || true
        done
        sleep 1
        # Force kill if still alive
        echo "$ORPHANS" | while read pid; do
          kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null && echo "    Force killed PID $pid" || true
        done
        echo "[*] Orphaned processes cleaned up."
      else
        echo "[*] No active Machine session to stop."
      fi
      exit $EXIT_CLEAN
    fi

    RUNNING_PID="$(cat "$PID_FILE")"
    echo "[*] Stopping Machine session (PID: $RUNNING_PID)..."

    # Kill the nohup wrapper
    kill "$RUNNING_PID" 2>/dev/null || true

    # Kill any child claude -p processes
    CHILD_PIDS=$(pgrep -f "claude -p.*Machine Orchestrator" 2>/dev/null || true)
    if [ -n "$CHILD_PIDS" ]; then
      echo "$CHILD_PIDS" | while read pid; do
        echo "    Killing claude process PID $pid"
        kill "$pid" 2>/dev/null || true
      done
    fi

    # Kill stream_parser.py if running
    pkill -f "stream_parser.py" 2>/dev/null || true

    sleep 1

    # Force kill anything still alive
    kill -0 "$RUNNING_PID" 2>/dev/null && kill -9 "$RUNNING_PID" 2>/dev/null && echo "    Force killed wrapper PID $RUNNING_PID" || true
    if [ -n "$CHILD_PIDS" ]; then
      echo "$CHILD_PIDS" | while read pid; do
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null && echo "    Force killed PID $pid" || true
      done
    fi

    rm -f "$PID_FILE"
    echo "[*] Session stopped."

    # Show partial results if available
    if [ -f "$SCRIPT_DIR/.machine.history" ]; then
      LAST="$(tail -1 "$SCRIPT_DIR/.machine.history")"
      LAST_DIR="$(echo "$LAST" | awk '{print $2}')"
      if [ -f "$LAST_DIR/session.log" ]; then
        LOG_LINES=$(wc -l < "$LAST_DIR/session.log" 2>/dev/null || echo 0)
        echo "    Log saved: $LAST_DIR/session.log ($LOG_LINES lines)"
      fi
    fi
    ;;

  logs)
    # Find latest session.log
    if [ -f "$SCRIPT_DIR/.machine.history" ]; then
      LAST="$(tail -1 "$SCRIPT_DIR/.machine.history")"
      LAST_DIR="$(echo "$LAST" | awk '{print $2}')"
      if [ -f "$LAST_DIR/session.log" ]; then
        echo "[*] Tailing: $LAST_DIR/session.log"
        tail -f "$LAST_DIR/session.log"
      else
        echo "[!] No session.log found at $LAST_DIR"
        exit $EXIT_ERROR
      fi
    else
      echo "[!] No session history found. Run a ctf session first."
      exit $EXIT_ERROR
    fi
    ;;

  help|--help|-h)
    show_banner "Help"
    echo "Usage:"
    echo "  ./machine.sh [flags] ctf <challenge> [category] [server]   Solve CTF"
    echo "  ./machine.sh [flags] learn <challenge> [category] [server]  Solve + writeup + DB 저장"
    echo ""
    echo "Categories: pwn, rev, web, crypto, forensics, web3 (생략 시 자동 감지)"
    echo "Server:     http://host:port or host:port (웹/pwn 문제의 접속 대상)"
    echo "  ./machine.sh learn --import <file|dir|url>           기존 writeup 임포트"
    echo "  ./machine.sh learn --reindex                         Knowledge DB 재인덱싱"
    echo "  ./machine.sh status                                  Check running session"
    echo "  ./machine.sh stop                                    Stop running session"
    echo "  ./machine.sh logs                                    Tail latest session log"
    echo ""
    echo "Global flags:"
    echo "  --json       Output in JSON format"
    echo "  --timeout N  Set timeout in seconds"
    echo "  --dry-run    Show plan without executing"
    echo ""
    echo "Exit codes:"
    echo "  0  = clean"
    echo "  1  = CRITICAL finding"
    echo "  2  = HIGH finding"
    echo "  3  = MEDIUM finding"
    echo "  10 = error"
    echo ""
    echo "Environment:"
    echo "  MACHINE_MODEL  Model to use (default: opus)"
    ;;

  *)
    echo "[!] Unknown command: $MODE"
    echo "Run ./machine.sh help for usage."
    exit $EXIT_ERROR
    ;;
esac
