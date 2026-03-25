#!/bin/bash
# Machine - Autonomous CTF Agent Launcher
# Uses Claude Code with bypassPermissions for fully autonomous operation
#
# Usage:
#   ./machine.sh [--json] [--timeout N] [--dry-run] [--flag FORMAT] [--max-retries N] ctf /path/to/challenge[.zip]
#   ./machine.sh status                         (check running sessions)
#   ./machine.sh logs                           (tail latest session log)
#   --flag FORMAT: add a flag prefix (e.g., --flag NEWCTF → matches NEWCTF{...})
#   --max-retries N: max retry attempts (0 = unlimited, default). Retries until flag found.
#   --mem-limit N: memory limit in GB (default: 12). OOM watchdog kills children if exceeded.

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
PID_DIR="$SCRIPT_DIR/.machine.pids"
mkdir -p "$PID_DIR"
# Legacy single PID file (for backward compat cleanup)
OLD_PID_FILE="$SCRIPT_DIR/.machine.pid"
[ -f "$OLD_PID_FILE" ] && rm -f "$OLD_PID_FILE"

# --- Parse global flags ---
JSON_OUTPUT=false
TIMEOUT=0
DRY_RUN=false
FLAG_FORMAT=""
MAX_RETRIES=0  # 0 = unlimited retries (keep trying until flag found)
MEM_LIMIT_GB=12  # Default: 12GB (leave ~4GB for OS on 16GB system)

while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --json) JSON_OUTPUT=true; shift ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --flag) FLAG_FORMAT="$2"; shift 2 ;;
    --max-retries) MAX_RETRIES="$2"; shift 2 ;;
    --mem-limit) MEM_LIMIT_GB="$2"; shift 2 ;;
    *) break ;;
  esac
done

# Resolve flag format: --flag arg > config.json > default
_resolve_flag_config() {
  local config_file="$SCRIPT_DIR/config.json"
  if [ -n "$FLAG_FORMAT" ]; then
    # User specified --flag PREFIX{...} or just PREFIX
    local prefix="${FLAG_FORMAT%%\{*}"
    # Read existing config, add if not present, update regex
    if [ -f "$config_file" ]; then
      python3 -c "
import json, sys
c = json.load(open('$config_file'))
prefix = '$prefix'
fmt = prefix + '{...}'
if fmt not in c['flag_formats']:
    c['flag_formats'].append(fmt)
prefixes = [f.split('{')[0] for f in c['flag_formats']]
c['flag_regex'] = '(' + '|'.join(prefixes) + r')\\{[^}]+\\}'
json.dump(c, open('$config_file', 'w'), indent=2)
"
    fi
  fi
  # Load from config
  if [ -f "$config_file" ]; then
    FLAG_REGEX="$(python3 -c "import json; print(json.load(open('$config_file'))['flag_regex'])")"
    FLAG_DISPLAY="$(python3 -c "import json; print(', '.join(json.load(open('$config_file'))['flag_formats']))")"
  else
    FLAG_REGEX='(DH|FLAG|flag|CTF|GoN|CYAI)\{[^}]+\}'
    FLAG_DISPLAY="DH{...}, FLAG{...}, flag{...}, CTF{...}, GoN{...}, CYAI{...}"
  fi
}
_resolve_flag_config

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
    SESSION_ID="$TIMESTAMP"
    PID_FILE="$PID_DIR/${SESSION_ID}.pid"
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

    # Read challenge.md if present (description, flag format, constraints)
    CHALLENGE_META=""
    for desc_file in "$CHALLENGE_DIR/challenge.md" "$CHALLENGE_DIR/CHALLENGE.md" "$CHALLENGE_DIR/README.md" "$CHALLENGE_DIR/description.md"; do
      if [ -f "$desc_file" ]; then
        CHALLENGE_META="$(cat "$desc_file")"
        # Auto-detect flag format from challenge.md
        CUSTOM_FLAG_FMT="$(grep -oP '(?i)flag\s*(format|regex|형식)[^`]*`([^`]+)`' "$desc_file" 2>/dev/null | grep -oP '`[^`]+`' | tr -d '`' | head -1)"
        if [ -n "$CUSTOM_FLAG_FMT" ]; then
          echo "[*] Flag format from challenge.md: $CUSTOM_FLAG_FMT" >> "$REPORT_DIR/session.log" 2>/dev/null
        fi
        echo "[*] Loaded challenge description from $(basename "$desc_file")" >> "$REPORT_DIR/session.log" 2>/dev/null
        break
      fi
    done

    # Write prompt to file (avoids heredoc escaping hell in nohup)
    PROMPT_FILE="$REPORT_DIR/prompt.txt"
    cat > "$PROMPT_FILE" <<PROMPT_EOF
You are Machine Orchestrator. Use Agent Teams to solve this CTF challenge.

Challenge directory: $CHALLENGE_DIR
Files found: $FILES
Report directory: $REPORT_DIR
Category: ${CATEGORY:-NOT SPECIFIED — you must detect it}
$([ -n "$SERVER" ] && echo "Target server: $SERVER")
$(if [ -n "$CHALLENGE_META" ]; then
echo "
=== CHALLENGE DESCRIPTION (from challenge.md) ===
$CHALLENGE_META
=== END DESCRIPTION ===

IMPORTANT: Use any flag format regex, charset constraints, or server info from the description above.
These are CRITICAL constraints — apply them to your solver from the start."
fi)

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
echo "  WEB:       @web → @web-docker → @web-remote → @critic → @verifier → @reporter"
echo "  CRYPTO:    @crypto → @critic → @verifier → @reporter"
echo "  FORENSICS: @forensics → @critic → @verifier → @reporter"
echo "  WEB3:      @web3 → @critic → @verifier → @reporter"
fi)
$(if [ -n "$SERVER" ]; then
echo "
IMPORTANT: Remote server = $SERVER
- This is the REAL flag server. But DO NOT hit it first.
- For WEB challenges, you MUST follow this order:
  1. Source code analysis ONLY (no requests to any server)
  2. docker compose up -d → exploit on localhost FIRST
  3. Only after local success → run solve.py against $SERVER
- For PWN challenges: use remote() in pwntools only after local binary test passes
- Flags obtained from $SERVER are REAL flags"
else
echo "
IMPORTANT: No remote server address provided yet.
- Complete analysis and local verification WITHOUT remote server.
- When the pipeline reaches the REMOTE stage (web-remote or verifier remote execution):
  → Use AskUserQuestion to ask the user for the remote server address.
  → Message: '로컬 검증 완료. 리모트 서버 주소를 입력해주세요 (예: host1.dreamhack.games:12345)'
  → Wait for the user's response before proceeding.
- This allows the user to start the VM fresh right before the remote stage, avoiding VM timeout issues."
fi)

Pass each agent's output to the next via structured HANDOFF.
Save solve.py to $CHALLENGE_DIR/solve.py
Save writeup to $REPORT_DIR/writeup.md

STEP 5: Collect results — Update knowledge/index.md

Flag formats: $FLAG_DISPLAY
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
MAX_RETRIES_VAL=$MAX_RETRIES
MEM_LIMIT_GB=$MEM_LIMIT_GB
MY_TTY="$(tty 2>/dev/null || echo '')"

# --- OOM Prevention ---
MEM_LIMIT_KB=\$((MEM_LIMIT_GB * 1024 * 1024))
ulimit -v \$MEM_LIMIT_KB 2>/dev/null || true
echo "[*] Memory limit: \${MEM_LIMIT_GB}GB (ulimit -v \${MEM_LIMIT_KB}KB)" >> "\$REPORT_DIR/session.log"

# Background memory watchdog: kill child tree if RSS exceeds limit
_oom_watchdog() {
  local limit_kb=\$((MEM_LIMIT_GB * 1024 * 1024))
  while true; do
    sleep 10
    # Sum RSS of all children of this runner process
    local rss_total=0
    for pid in \$(pgrep -P \$\$ 2>/dev/null); do
      local rss=\$(awk '/VmRSS/{print \$2}' /proc/\$pid/status 2>/dev/null || echo 0)
      rss_total=\$((rss_total + rss))
    done
    if [ "\$rss_total" -gt "\$limit_kb" ] 2>/dev/null; then
      echo "[!] OOM WATCHDOG: children RSS \${rss_total}KB > limit \${limit_kb}KB — killing child processes" >> "\$REPORT_DIR/session.log"
      pkill -TERM -P \$\$ 2>/dev/null || true
      sleep 2
      pkill -KILL -P \$\$ 2>/dev/null || true
      break
    fi
  done
}
_oom_watchdog &
OOM_WATCHDOG_PID=\$!

CLAUDE_CMD="claude -p"
if [ "\$TIMEOUT_VAL" -gt 0 ] 2>/dev/null; then
  CLAUDE_CMD="timeout \$TIMEOUT_VAL claude -p"
fi

# === Retry loop: keep trying until flag found ===
ATTEMPT=0
FLAGS=""

while true; do
  ATTEMPT=\$((ATTEMPT + 1))
  echo "" >> "\$REPORT_DIR/session.log"
  echo "═══════════════════════════════════════" >> "\$REPORT_DIR/session.log"
  echo "=== ATTEMPT \$ATTEMPT (started \$(date)) ===" >> "\$REPORT_DIR/session.log"
  echo "═══════════════════════════════════════" >> "\$REPORT_DIR/session.log"

  # Build prompt: on retry, append previous failure context
  if [ \$ATTEMPT -gt 1 ]; then
    CURRENT_PROMPT="\$REPORT_DIR/prompt_attempt_\${ATTEMPT}.txt"
    cp "\$PROMPT_FILE" "\$CURRENT_PROMPT"
    {
      echo ""
      echo "═══ RETRY ATTEMPT \$ATTEMPT ═══"
      echo "Previous \$((ATTEMPT - 1)) attempt(s) FAILED to capture the flag."
      echo ""
      echo "=== Previous session log (last 150 lines) ==="
      tail -150 "\$REPORT_DIR/session.log" 2>/dev/null || true
      echo ""
      if [ -f "\$CHALLENGE_DIR/checkpoint.json" ]; then
        echo "=== Checkpoint from previous attempt ==="
        cat "\$CHALLENGE_DIR/checkpoint.json"
        echo ""
      fi
      if [ -f "\$CHALLENGE_DIR/solve.py" ]; then
        echo "=== Previous solve.py ==="
        cat "\$CHALLENGE_DIR/solve.py"
        echo ""
      fi
      echo "CRITICAL INSTRUCTIONS FOR RETRY:"
      echo "1. You MUST try a FUNDAMENTALLY DIFFERENT approach than previous attempts."
      echo "2. Analyze WHY the previous attempt failed before starting."
      echo "3. Read any existing artifacts in \$CHALLENGE_DIR for context."
      echo "4. Do NOT repeat the same strategy that already failed."
      echo "5. Consider: different vulnerability class, different exploit technique, re-analyzing the binary/source."
    } >> "\$CURRENT_PROMPT"
  else
    CURRENT_PROMPT="\$PROMPT_FILE"
  fi

  \$CLAUDE_CMD "\$(cat "\$CURRENT_PROMPT")" --permission-mode bypassPermissions --model "\$MODEL" --output-format stream-json --verbose 2>&1 | python3 -u "\$SCRIPT_DIR/tools/stream_parser.py" "\$REPORT_DIR/session.log"
  CLAUDE_EXIT=\$?

  # Check for flags — prioritize verified remote flags over session.log grep
  FLAGS=""
  FLAG_SOURCE=""

  # Priority 1: flag_captured.txt (written by verifier after remote execution)
  if [ -f "\$CHALLENGE_DIR/flag_captured.txt" ]; then
    VERIFIED_FLAGS=\$(grep -oE '$FLAG_REGEX' "\$CHALLENGE_DIR/flag_captured.txt" 2>/dev/null | sort -u || true)
    if [ -n "\$VERIFIED_FLAGS" ]; then
      FLAGS="\$VERIFIED_FLAGS"
      FLAG_SOURCE="remote_verified"
    fi
  fi

  # Priority 2: remote_output.txt (verifier's remote execution output)
  if [ -z "\$FLAGS" ] && [ -f "\$CHALLENGE_DIR/remote_output.txt" ]; then
    REMOTE_FLAGS=\$(grep -oE '$FLAG_REGEX' "\$CHALLENGE_DIR/remote_output.txt" 2>/dev/null | grep -vE '\{(\.\.\.|\.\.\.|xxx|test|PLACEHOLDER|REDACTED|fake_flag)\}' | sort -u || true)
    if [ -n "\$REMOTE_FLAGS" ]; then
      FLAGS="\$REMOTE_FLAGS"
      FLAG_SOURCE="remote_output"
    fi
  fi

  # Priority 3: session.log — if checkpoint shows pipeline completed
  if [ -z "\$FLAGS" ]; then
    CHECKPOINT_OK=false
    if [ -f "\$CHALLENGE_DIR/checkpoint.json" ]; then
      CP_STATUS=\$(python3 -c "import json; d=json.load(open('\$CHALLENGE_DIR/checkpoint.json')); print(d.get('status',''))" 2>/dev/null || echo "")
      CP_AGENT=\$(python3 -c "import json; d=json.load(open('\$CHALLENGE_DIR/checkpoint.json')); print(d.get('agent',''))" 2>/dev/null || echo "")
      if [ "\$CP_STATUS" = "completed" ] && { [ "\$CP_AGENT" = "verifier" ] || [ "\$CP_AGENT" = "reporter" ]; }; then
        CHECKPOINT_OK=true
      fi
    fi

    if [ "\$CHECKPOINT_OK" = true ]; then
      SESSION_FLAGS=\$(grep -oE '$FLAG_REGEX' "\$REPORT_DIR/session.log" 2>/dev/null | grep -vE '\{(\.\.\.|\.\.\.|xxx|test|PLACEHOLDER|REDACTED|fake_flag)\}' | sort -u || true)
      if [ -n "\$SESSION_FLAGS" ]; then
        FLAGS="\$SESSION_FLAGS"
        FLAG_SOURCE="session_log_verified"
      fi
    fi
  fi

  # Priority 4: session.log fallback — no checkpoint required
  if [ -z "\$FLAGS" ]; then
    FALLBACK_FLAGS=\$(grep -oE '$FLAG_REGEX' "\$REPORT_DIR/session.log" 2>/dev/null | grep -vE '\{(\.\.\.|\.\.\.|xxx|test|PLACEHOLDER|REDACTED|fake_flag)\}' | sort -u || true)
    if [ -n "\$FALLBACK_FLAGS" ]; then
      FLAGS="\$FALLBACK_FLAGS"
      FLAG_SOURCE="session_log_fallback"
    fi
  fi

  if [ -n "\$FLAGS" ]; then
    echo "" >> "\$REPORT_DIR/session.log"
    echo "FLAGS FOUND on attempt \$ATTEMPT (source: \$FLAG_SOURCE):" >> "\$REPORT_DIR/session.log"
    echo "\$FLAGS" >> "\$REPORT_DIR/session.log"
    echo "\$FLAGS" > "\$REPORT_DIR/flags.txt"
    break
  fi

  echo "" >> "\$REPORT_DIR/session.log"
  echo "NO FLAGS FOUND (attempt \$ATTEMPT)" >> "\$REPORT_DIR/session.log"

  # Stop if pipeline fully completed (reporter done) — no point retrying
  if [ -f "\$CHALLENGE_DIR/checkpoint.json" ]; then
    _CP_AGENT=\$(python3 -c "import json; d=json.load(open('\$CHALLENGE_DIR/checkpoint.json')); print(d.get('agent',''))" 2>/dev/null || echo "")
    _CP_STATUS=\$(python3 -c "import json; d=json.load(open('\$CHALLENGE_DIR/checkpoint.json')); print(d.get('status',''))" 2>/dev/null || echo "")
    if [ "\$_CP_STATUS" = "completed" ] && [ "\$_CP_AGENT" = "reporter" ]; then
      echo "Pipeline fully completed (reporter done) but no flag captured. Stopping." >> "\$REPORT_DIR/session.log"
      break
    fi
  fi

  # Check retry limit (0 = unlimited)
  if [ "\$MAX_RETRIES_VAL" -gt 0 ] 2>/dev/null && [ \$ATTEMPT -ge "\$MAX_RETRIES_VAL" ]; then
    echo "MAX RETRIES (\$MAX_RETRIES_VAL) reached. Giving up." >> "\$REPORT_DIR/session.log"
    break
  fi

  echo "=== RETRYING in 5 seconds... ===" >> "\$REPORT_DIR/session.log"
  sleep 5
done

echo '' >> "\$REPORT_DIR/session.log"
echo '=== SESSION COMPLETE ===' >> "\$REPORT_DIR/session.log"
echo "Timestamp: \$(date)" >> "\$REPORT_DIR/session.log"
echo "Total attempts: \$ATTEMPT" >> "\$REPORT_DIR/session.log"

FINAL_EXIT=\$(bash "\$SCRIPT_DIR/machine.sh" _exit_code "\$REPORT_DIR" 2>/dev/null || echo 0)
echo "\$FINAL_EXIT" > "\$REPORT_DIR/exit_code"

# Determine session status
SESSION_STATUS='completed'
if [ -z "\$FLAGS" ]; then
  SESSION_STATUS='incomplete'
fi

bash "\$SCRIPT_DIR/machine.sh" _summary "\$REPORT_DIR" ctf "\$CHALLENGE_DIR" "\$START_TS" "\$FINAL_EXIT" "\$SESSION_STATUS" 2>/dev/null || true

# === Terminal notification ===
END_TS=\$(date +%s)
ELAPSED=\$(( END_TS - START_TS ))
MINS=\$(( ELAPSED / 60 ))
SECS=\$(( ELAPSED % 60 ))

NOTIFY_FILE="\$REPORT_DIR/result.txt"
echo "" > "\$NOTIFY_FILE"
echo "════════════════════════════════════════" >> "\$NOTIFY_FILE"
if [ -n "\$FLAGS" ]; then
  echo "  MACHINE — CTF Session Complete" >> "\$NOTIFY_FILE"
else
  echo "  MACHINE — CTF Session Failed" >> "\$NOTIFY_FILE"
fi
echo "════════════════════════════════════════" >> "\$NOTIFY_FILE"
echo "  Challenge: \$(basename "\$CHALLENGE_DIR")" >> "\$NOTIFY_FILE"
echo "  Duration:  \${MINS}m \${SECS}s" >> "\$NOTIFY_FILE"
echo "  Attempts:  \$ATTEMPT" >> "\$NOTIFY_FILE"
echo "  Status:    \$SESSION_STATUS" >> "\$NOTIFY_FILE"
if [ -n "\$FLAGS" ]; then
  echo "" >> "\$NOTIFY_FILE"
  echo "  ✓ FLAG CAPTURED:" >> "\$NOTIFY_FILE"
  echo "\$FLAGS" | while read f; do echo "    \$f" >> "\$NOTIFY_FILE"; done
else
  echo "" >> "\$NOTIFY_FILE"
  echo "  ✗ No flags found" >> "\$NOTIFY_FILE"
fi
echo "════════════════════════════════════════" >> "\$NOTIFY_FILE"

# Print to session.log
cat "\$NOTIFY_FILE" >> "\$REPORT_DIR/session.log"

# Try to notify user's terminal
# Notify only the terminal that started this session
if [ -n "\$MY_TTY" ] && [ -w "\$MY_TTY" ]; then
  cat "\$NOTIFY_FILE" > "\$MY_TTY" 2>/dev/null
  printf '\a' > "\$MY_TTY" 2>/dev/null
fi

kill \$OOM_WATCHDOG_PID 2>/dev/null || true
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
    SESSION_ID="$TIMESTAMP"
    PID_FILE="$PID_DIR/${SESSION_ID}.pid"
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

    # Read challenge.md if present
    CHALLENGE_META=""
    for desc_file in "$CHALLENGE_DIR/challenge.md" "$CHALLENGE_DIR/CHALLENGE.md" "$CHALLENGE_DIR/README.md" "$CHALLENGE_DIR/description.md"; do
      if [ -f "$desc_file" ]; then
        CHALLENGE_META="$(cat "$desc_file")"
        CUSTOM_FLAG_FMT="$(grep -oP '(?i)flag\s*(format|regex|형식)[^`]*`([^`]+)`' "$desc_file" 2>/dev/null | grep -oP '`[^`]+`' | tr -d '`' | head -1)"
        [ -n "$CUSTOM_FLAG_FMT" ] && echo "[*] Flag format from challenge.md: $CUSTOM_FLAG_FMT" >> "$REPORT_DIR/session.log" 2>/dev/null
        echo "[*] Loaded challenge description from $(basename "$desc_file")" >> "$REPORT_DIR/session.log" 2>/dev/null
        break
      fi
    done

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
$([ -n "$SERVER" ] && echo "Remote server: $SERVER (DO NOT access until local Docker exploit succeeds)")
$(if [ -n "$CHALLENGE_META" ]; then
echo "
=== CHALLENGE DESCRIPTION (from challenge.md) ===
$CHALLENGE_META
=== END DESCRIPTION ===

IMPORTANT: Use any flag format regex, charset constraints, or server info from the description above.
These are CRITICAL constraints — apply them to your solver from the start."
fi)

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
  WEB:       @web → @web-docker → @web-remote → @critic → @verifier → @reporter
  CRYPTO:    @crypto → @critic → @verifier → @reporter
  FORENSICS: @forensics → @critic → @verifier → @reporter
  WEB3:      @web3 → @critic → @verifier → @reporter

$([ -n "$SERVER" ] && echo "CRITICAL — WEB CHALLENGE 3-PHASE RULE:
  Phase 1: Read ALL source code first. NO requests to any server.
  Phase 2: docker compose up -d → exploit localhost. Verify 2/2 success.
  Phase 3: ONLY after local success → run solve.py against $SERVER for real flag.
  solve.py must have TARGET variable (LOCAL/REMOTE) for easy switching.")

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

Flag formats: $FLAG_DISPLAY
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
MAX_RETRIES_VAL=$MAX_RETRIES
MEM_LIMIT_GB=$MEM_LIMIT_GB
MY_TTY="$(tty 2>/dev/null || echo '')"

# --- OOM Prevention ---
MEM_LIMIT_KB=\$((MEM_LIMIT_GB * 1024 * 1024))
ulimit -v \$MEM_LIMIT_KB 2>/dev/null || true
echo "[*] Memory limit: \${MEM_LIMIT_GB}GB (ulimit -v \${MEM_LIMIT_KB}KB)" >> "\$REPORT_DIR/session.log"

_oom_watchdog() {
  local limit_kb=\$((MEM_LIMIT_GB * 1024 * 1024))
  while true; do
    sleep 10
    local rss_total=0
    for pid in \$(pgrep -P \$\$ 2>/dev/null); do
      local rss=\$(awk '/VmRSS/{print \$2}' /proc/\$pid/status 2>/dev/null || echo 0)
      rss_total=\$((rss_total + rss))
    done
    if [ "\$rss_total" -gt "\$limit_kb" ] 2>/dev/null; then
      echo "[!] OOM WATCHDOG: children RSS \${rss_total}KB > limit \${limit_kb}KB — killing child processes" >> "\$REPORT_DIR/session.log"
      pkill -TERM -P \$\$ 2>/dev/null || true
      sleep 2
      pkill -KILL -P \$\$ 2>/dev/null || true
      break
    fi
  done
}
_oom_watchdog &
OOM_WATCHDOG_PID=\$!

CLAUDE_CMD="claude -p"
if [ "\$TIMEOUT_VAL" -gt 0 ] 2>/dev/null; then
  CLAUDE_CMD="timeout \$TIMEOUT_VAL claude -p"
fi

# === Retry loop: keep trying until flag found ===
ATTEMPT=0
FLAGS=""

while true; do
  ATTEMPT=\$((ATTEMPT + 1))
  echo "" >> "\$REPORT_DIR/session.log"
  echo "═══════════════════════════════════════" >> "\$REPORT_DIR/session.log"
  echo "=== ATTEMPT \$ATTEMPT (started \$(date)) ===" >> "\$REPORT_DIR/session.log"
  echo "═══════════════════════════════════════" >> "\$REPORT_DIR/session.log"

  # Build prompt: on retry, append previous failure context
  if [ \$ATTEMPT -gt 1 ]; then
    CURRENT_PROMPT="\$REPORT_DIR/prompt_attempt_\${ATTEMPT}.txt"
    cp "\$PROMPT_FILE" "\$CURRENT_PROMPT"
    {
      echo ""
      echo "═══ RETRY ATTEMPT \$ATTEMPT ═══"
      echo "Previous \$((ATTEMPT - 1)) attempt(s) FAILED to capture the flag."
      echo ""
      echo "=== Previous session log (last 150 lines) ==="
      tail -150 "\$REPORT_DIR/session.log" 2>/dev/null || true
      echo ""
      if [ -f "\$CHALLENGE_DIR/checkpoint.json" ]; then
        echo "=== Checkpoint from previous attempt ==="
        cat "\$CHALLENGE_DIR/checkpoint.json"
        echo ""
      fi
      if [ -f "\$CHALLENGE_DIR/solve.py" ]; then
        echo "=== Previous solve.py ==="
        cat "\$CHALLENGE_DIR/solve.py"
        echo ""
      fi
      echo "CRITICAL INSTRUCTIONS FOR RETRY:"
      echo "1. You MUST try a FUNDAMENTALLY DIFFERENT approach than previous attempts."
      echo "2. Analyze WHY the previous attempt failed before starting."
      echo "3. Read any existing artifacts in \$CHALLENGE_DIR for context."
      echo "4. Do NOT repeat the same strategy that already failed."
      echo "5. Consider: different vulnerability class, different exploit technique, re-analyzing the binary/source."
    } >> "\$CURRENT_PROMPT"
  else
    CURRENT_PROMPT="\$PROMPT_FILE"
  fi

  \$CLAUDE_CMD "\$(cat "\$CURRENT_PROMPT")" --permission-mode bypassPermissions --model "\$MODEL" --output-format stream-json --verbose 2>&1 | python3 -u "\$SCRIPT_DIR/tools/stream_parser.py" "\$REPORT_DIR/session.log"
  CLAUDE_EXIT=\$?

  # Check for flags — prioritize verified remote flags over session.log grep
  FLAGS=""
  FLAG_SOURCE=""

  # Priority 1: flag_captured.txt (written by verifier after remote execution)
  if [ -f "\$CHALLENGE_DIR/flag_captured.txt" ]; then
    VERIFIED_FLAGS=\$(grep -oE '$FLAG_REGEX' "\$CHALLENGE_DIR/flag_captured.txt" 2>/dev/null | sort -u || true)
    if [ -n "\$VERIFIED_FLAGS" ]; then
      FLAGS="\$VERIFIED_FLAGS"
      FLAG_SOURCE="remote_verified"
    fi
  fi

  # Priority 2: remote_output.txt (verifier's remote execution output)
  if [ -z "\$FLAGS" ] && [ -f "\$CHALLENGE_DIR/remote_output.txt" ]; then
    REMOTE_FLAGS=\$(grep -oE '$FLAG_REGEX' "\$CHALLENGE_DIR/remote_output.txt" 2>/dev/null | grep -vE '\{(\.\.\.|\.\.\.|xxx|test|PLACEHOLDER|REDACTED|fake_flag)\}' | sort -u || true)
    if [ -n "\$REMOTE_FLAGS" ]; then
      FLAGS="\$REMOTE_FLAGS"
      FLAG_SOURCE="remote_output"
    fi
  fi

  # Priority 3: session.log — if checkpoint shows pipeline completed
  if [ -z "\$FLAGS" ]; then
    CHECKPOINT_OK=false
    if [ -f "\$CHALLENGE_DIR/checkpoint.json" ]; then
      CP_STATUS=\$(python3 -c "import json; d=json.load(open('\$CHALLENGE_DIR/checkpoint.json')); print(d.get('status',''))" 2>/dev/null || echo "")
      CP_AGENT=\$(python3 -c "import json; d=json.load(open('\$CHALLENGE_DIR/checkpoint.json')); print(d.get('agent',''))" 2>/dev/null || echo "")
      if [ "\$CP_STATUS" = "completed" ] && { [ "\$CP_AGENT" = "verifier" ] || [ "\$CP_AGENT" = "reporter" ]; }; then
        CHECKPOINT_OK=true
      fi
    fi

    if [ "\$CHECKPOINT_OK" = true ]; then
      SESSION_FLAGS=\$(grep -oE '$FLAG_REGEX' "\$REPORT_DIR/session.log" 2>/dev/null | grep -vE '\{(\.\.\.|\.\.\.|xxx|test|PLACEHOLDER|REDACTED|fake_flag)\}' | sort -u || true)
      if [ -n "\$SESSION_FLAGS" ]; then
        FLAGS="\$SESSION_FLAGS"
        FLAG_SOURCE="session_log_verified"
      fi
    fi
  fi

  # Priority 4: session.log fallback — no checkpoint required
  if [ -z "\$FLAGS" ]; then
    FALLBACK_FLAGS=\$(grep -oE '$FLAG_REGEX' "\$REPORT_DIR/session.log" 2>/dev/null | grep -vE '\{(\.\.\.|\.\.\.|xxx|test|PLACEHOLDER|REDACTED|fake_flag)\}' | sort -u || true)
    if [ -n "\$FALLBACK_FLAGS" ]; then
      FLAGS="\$FALLBACK_FLAGS"
      FLAG_SOURCE="session_log_fallback"
    fi
  fi

  if [ -n "\$FLAGS" ]; then
    echo "" >> "\$REPORT_DIR/session.log"
    echo "FLAGS FOUND on attempt \$ATTEMPT (source: \$FLAG_SOURCE):" >> "\$REPORT_DIR/session.log"
    echo "\$FLAGS" >> "\$REPORT_DIR/session.log"
    echo "\$FLAGS" > "\$REPORT_DIR/flags.txt"
    break
  fi

  echo "" >> "\$REPORT_DIR/session.log"
  echo "NO FLAGS FOUND (attempt \$ATTEMPT)" >> "\$REPORT_DIR/session.log"

  # Stop if pipeline fully completed (reporter done) — no point retrying
  if [ -f "\$CHALLENGE_DIR/checkpoint.json" ]; then
    _CP_AGENT=\$(python3 -c "import json; d=json.load(open('\$CHALLENGE_DIR/checkpoint.json')); print(d.get('agent',''))" 2>/dev/null || echo "")
    _CP_STATUS=\$(python3 -c "import json; d=json.load(open('\$CHALLENGE_DIR/checkpoint.json')); print(d.get('status',''))" 2>/dev/null || echo "")
    if [ "\$_CP_STATUS" = "completed" ] && [ "\$_CP_AGENT" = "reporter" ]; then
      echo "Pipeline fully completed (reporter done) but no flag captured. Stopping." >> "\$REPORT_DIR/session.log"
      break
    fi
  fi

  # Check retry limit (0 = unlimited)
  if [ "\$MAX_RETRIES_VAL" -gt 0 ] 2>/dev/null && [ \$ATTEMPT -ge "\$MAX_RETRIES_VAL" ]; then
    echo "MAX RETRIES (\$MAX_RETRIES_VAL) reached. Giving up." >> "\$REPORT_DIR/session.log"
    break
  fi

  echo "=== RETRYING in 5 seconds... ===" >> "\$REPORT_DIR/session.log"
  sleep 5
done

echo '' >> "\$REPORT_DIR/session.log"
echo '=== SESSION COMPLETE ===' >> "\$REPORT_DIR/session.log"
echo "Timestamp: \$(date)" >> "\$REPORT_DIR/session.log"
echo "Total attempts: \$ATTEMPT" >> "\$REPORT_DIR/session.log"

# Index writeup if exists
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

# Determine session status: flag found = completed, otherwise incomplete
SESSION_STATUS='completed'
if [ -z "\$FLAGS" ]; then
  SESSION_STATUS='incomplete'
fi

bash "\$SCRIPT_DIR/machine.sh" _summary "\$REPORT_DIR" learn "\$CHALLENGE_DIR" "\$START_TS" "\$FINAL_EXIT" "\$SESSION_STATUS" 2>/dev/null || true

# === Terminal notification ===
END_TS=\$(date +%s)
ELAPSED=\$(( END_TS - START_TS ))
MINS=\$(( ELAPSED / 60 ))
SECS=\$(( ELAPSED % 60 ))

NOTIFY_FILE="\$REPORT_DIR/result.txt"
echo "" > "\$NOTIFY_FILE"
echo "════════════════════════════════════════" >> "\$NOTIFY_FILE"
if [ -n "\$FLAGS" ]; then
  echo "  MACHINE — Learn Session Complete" >> "\$NOTIFY_FILE"
else
  echo "  MACHINE — Learn Session Failed" >> "\$NOTIFY_FILE"
fi
echo "════════════════════════════════════════" >> "\$NOTIFY_FILE"
echo "  Challenge: \$(basename "\$CHALLENGE_DIR")" >> "\$NOTIFY_FILE"
echo "  Duration:  \${MINS}m \${SECS}s" >> "\$NOTIFY_FILE"
echo "  Attempts:  \$ATTEMPT" >> "\$NOTIFY_FILE"
echo "  Status:    \$SESSION_STATUS" >> "\$NOTIFY_FILE"
if [ -n "\$FLAGS" ]; then
  echo "" >> "\$NOTIFY_FILE"
  echo "  ✓ FLAG CAPTURED:" >> "\$NOTIFY_FILE"
  echo "\$FLAGS" | while read f; do echo "    \$f" >> "\$NOTIFY_FILE"; done
else
  echo "" >> "\$NOTIFY_FILE"
  echo "  ✗ No flags found" >> "\$NOTIFY_FILE"
fi
if [ -s "\$WRITEUP_FILE" ]; then
  echo "  ✓ Writeup saved: \$WRITEUP_FILE" >> "\$NOTIFY_FILE"
else
  echo "  ✗ Writeup not generated" >> "\$NOTIFY_FILE"
fi
echo "════════════════════════════════════════" >> "\$NOTIFY_FILE"

cat "\$NOTIFY_FILE" >> "\$REPORT_DIR/session.log"

# Notify only the terminal that started this session
if [ -n "\$MY_TTY" ] && [ -w "\$MY_TTY" ]; then
  cat "\$NOTIFY_FILE" > "\$MY_TTY" 2>/dev/null
  printf '\a' > "\$MY_TTY" 2>/dev/null
fi

kill \$OOM_WATCHDOG_PID 2>/dev/null || true
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

    ACTIVE_COUNT=0
    STALE_COUNT=0

    for pidfile in "$PID_DIR"/*.pid; do
      [ -f "$pidfile" ] || continue
      SID="$(basename "$pidfile" .pid)"
      SPID="$(cat "$pidfile")"

      # Find matching history entry
      S_DIR="" S_MODE="" S_START=""
      if [ -f "$SCRIPT_DIR/.machine.history" ]; then
        HLINE="$(grep "$SID" "$SCRIPT_DIR/.machine.history" | tail -1)"
        if [ -n "$HLINE" ]; then
          S_DIR="$(echo "$HLINE" | awk '{print $2}')"
          S_MODE="$(echo "$HLINE" | awk '{print $4}')"
          S_START="$(echo "$HLINE" | awk '{print $5}')"
        fi
      fi

      if kill -0 "$SPID" 2>/dev/null; then
        ACTIVE_COUNT=$((ACTIVE_COUNT + 1))
        NOW_TS="$(date +%s)"
        ELAPSED=""
        if [ -n "$S_START" ] && [ "$S_START" -gt 0 ] 2>/dev/null; then
          ELAPSED="$(format_elapsed $((NOW_TS - S_START)))"
        fi
        CHALLENGE_NAME=""
        [ -n "$S_DIR" ] && CHALLENGE_NAME="$(basename "$(grep "$SID" "$SCRIPT_DIR/.machine.history" | awk '{print $2}')" 2>/dev/null)"

        echo "[*] Session ACTIVE [$SID]"
        echo "    PID:       $SPID"
        [ -n "$S_MODE" ] && echo "    Mode:      $S_MODE"
        [ -n "$CHALLENGE_NAME" ] && echo "    Challenge: $CHALLENGE_NAME"
        [ -n "$ELAPSED" ] && echo "    Elapsed:   $ELAPSED"
        [ -n "$S_DIR" ] && echo "    Report:    $S_DIR"
        if [ -n "$S_DIR" ] && [ -f "$S_DIR/session.log" ]; then
          LOG_LINES=$(wc -l < "$S_DIR/session.log" 2>/dev/null || echo 0)
          LOG_SIZE=$(du -h "$S_DIR/session.log" 2>/dev/null | awk '{print $1}')
          echo "    Log:       $LOG_LINES lines ($LOG_SIZE)"
        fi
        echo ""
      else
        STALE_COUNT=$((STALE_COUNT + 1))
        echo "[*] Session FINISHED [$SID] (stale PID: $SPID)"
        rm -f "$pidfile"
        if [ -n "$S_DIR" ] && [ -f "$S_DIR/summary.json" ]; then
          # Show flags if found
          FOUND_FLAGS="$(python3 -c "import json; d=json.load(open('$S_DIR/summary.json')); flags=d.get('flags_found',[]); print(' '.join(flags)) if flags else None" 2>/dev/null || true)"
          if [ -n "$FOUND_FLAGS" ]; then
            echo "    FLAGS: $FOUND_FLAGS"
          fi
          DUR="$(python3 -c "import json; print(json.load(open('$S_DIR/summary.json')).get('duration_seconds',0))" 2>/dev/null || echo "?")"
          echo "    Duration: ${DUR}s"
        fi
        echo ""
      fi
    done

    if [ "$ACTIVE_COUNT" -eq 0 ] && [ "$STALE_COUNT" -eq 0 ]; then
      echo "[*] No active Machine sessions."
      # Show last session from history
      if [ -f "$SCRIPT_DIR/.machine.history" ]; then
        LAST="$(tail -1 "$SCRIPT_DIR/.machine.history")"
        LAST_DIR="$(echo "$LAST" | awk '{print $2}')"
        if [ -n "$LAST_DIR" ] && [ -f "$LAST_DIR/summary.json" ]; then
          echo "[*] Last session:"
          cat "$LAST_DIR/summary.json"
        fi
      fi
    else
      echo "[*] Total: $ACTIVE_COUNT active, $STALE_COUNT finished"
    fi
    ;;

  stop|kill)
    # Optional: stop specific session by ID
    STOP_TARGET="${TARGET:-}"

    ACTIVE_PIDS=()
    for pidfile in "$PID_DIR"/*.pid; do
      [ -f "$pidfile" ] || continue
      SID="$(basename "$pidfile" .pid)"
      SPID="$(cat "$pidfile")"

      # If specific session requested, skip others
      if [ -n "$STOP_TARGET" ] && [ "$SID" != "$STOP_TARGET" ] && [ "$SPID" != "$STOP_TARGET" ]; then
        continue
      fi

      if kill -0 "$SPID" 2>/dev/null; then
        echo "[*] Stopping session [$SID] (PID: $SPID)..."
        kill "$SPID" 2>/dev/null || true
        ACTIVE_PIDS+=("$SPID")
      else
        echo "[*] Session [$SID] already finished, cleaning up PID file."
      fi
      rm -f "$pidfile"
    done

    # Kill child claude -p processes
    CHILD_PIDS=$(pgrep -f "claude -p.*Machine Orchestrator" 2>/dev/null || true)
    if [ -n "$CHILD_PIDS" ]; then
      echo "$CHILD_PIDS" | while read pid; do
        # If specific session, only kill children of that session
        if [ -n "$STOP_TARGET" ]; then
          # Check if this pid is a child of one of our active pids
          DOMINATED=false
          for ap in "${ACTIVE_PIDS[@]}"; do
            if pgrep -P "$ap" 2>/dev/null | grep -q "$pid"; then
              DOMINATED=true; break
            fi
          done
          [ "$DOMINATED" = false ] && continue
        fi
        echo "    Killing claude PID $pid"
        kill "$pid" 2>/dev/null || true
      done
    fi

    # Kill stream_parser.py
    if [ -z "$STOP_TARGET" ]; then
      pkill -f "stream_parser.py" 2>/dev/null || true
    fi

    sleep 1

    # Force kill
    for pid in "${ACTIVE_PIDS[@]}"; do
      kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null && echo "    Force killed PID $pid" || true
    done

    if [ "${#ACTIVE_PIDS[@]}" -eq 0 ]; then
      # Check orphans
      ORPHANS=$(pgrep -f "claude -p.*Machine Orchestrator" 2>/dev/null || true)
      if [ -n "$ORPHANS" ]; then
        echo "[*] Found orphaned processes:"
        echo "$ORPHANS" | while read pid; do
          echo "    Killing PID $pid"
          kill "$pid" 2>/dev/null || true
        done
      else
        echo "[*] No active sessions to stop."
      fi
    else
      echo "[*] ${#ACTIVE_PIDS[@]} session(s) stopped."
    fi
    ;;

  logs)
    # Optional: logs <session_id> to tail specific session
    LOG_TARGET="${TARGET:-}"

    if [ -n "$LOG_TARGET" ]; then
      # Specific session
      LOG_DIR="$SCRIPT_DIR/reports/$LOG_TARGET"
      if [ -f "$LOG_DIR/session.log" ]; then
        echo "[*] Tailing: $LOG_DIR/session.log"
        tail -f "$LOG_DIR/session.log"
      else
        echo "[!] No session.log found for session $LOG_TARGET"
        exit $EXIT_ERROR
      fi
    else
      # All active sessions — tail latest, or list if multiple active
      ACTIVE_LOGS=()
      for pidfile in "$PID_DIR"/*.pid; do
        [ -f "$pidfile" ] || continue
        SPID="$(cat "$pidfile")"
        kill -0 "$SPID" 2>/dev/null || continue
        SID="$(basename "$pidfile" .pid)"
        SLOG="$SCRIPT_DIR/reports/$SID/session.log"
        [ -f "$SLOG" ] && ACTIVE_LOGS+=("$SLOG")
      done

      if [ "${#ACTIVE_LOGS[@]}" -gt 1 ]; then
        echo "[*] Multiple active sessions. Tailing all:"
        for l in "${ACTIVE_LOGS[@]}"; do echo "    $l"; done
        echo ""
        tail -f "${ACTIVE_LOGS[@]}"
      elif [ "${#ACTIVE_LOGS[@]}" -eq 1 ]; then
        echo "[*] Tailing: ${ACTIVE_LOGS[0]}"
        tail -f "${ACTIVE_LOGS[0]}"
      else
        # No active, show latest from history
        if [ -f "$SCRIPT_DIR/.machine.history" ]; then
          LAST="$(tail -1 "$SCRIPT_DIR/.machine.history")"
          LAST_DIR="$(echo "$LAST" | awk '{print $2}')"
          if [ -f "$LAST_DIR/session.log" ]; then
            echo "[*] No active sessions. Showing last: $LAST_DIR/session.log"
            tail -f "$LAST_DIR/session.log"
          else
            echo "[!] No session.log found"
            exit $EXIT_ERROR
          fi
        else
          echo "[!] No session history found."
          exit $EXIT_ERROR
        fi
      fi
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
    echo "  ./machine.sh status                                  Check all sessions"
    echo "  ./machine.sh stop [session_id|pid]                   Stop session(s)"
    echo "  ./machine.sh logs [session_id]                       Tail session log(s)"
    echo ""
    echo "Global flags:"
    echo "  --json         Output in JSON format"
    echo "  --timeout N    Set timeout in seconds"
    echo "  --dry-run      Show plan without executing"
    echo "  --flag FORMAT  Add flag prefix (e.g., --flag NEWCTF → matches NEWCTF{...})"
    echo "                 Saved to config.json for future runs"
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
