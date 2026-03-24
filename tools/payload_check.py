#!/usr/bin/env python3
"""Payload Check — JS payload validator for web CTF exploits.

Catches common bugs BEFORE deployment:
1. String quoting collisions (quote inside same-type quote)
2. Side-effect debug calls (POST to /api/report spawns bots)
3. Resource abuse (too many concurrent requests)

Usage:
    payload_check.py --js "var x='test'" --check-all
    payload_check.py --file payload.js --check-syntax
    payload_check.py --extract solve.py --check-all
    payload_check.py --self-test

Exit: 0=PASS, 1=FAIL (blocks pipeline)
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class Finding:
    severity: str       # ERROR | WARN
    check: str          # syntax | sideeffect | resource
    message: str
    line: Optional[int]
    snippet: str


def _result(passed: bool, findings: list, json_output: bool = False):
    status = "PASS" if passed else "FAIL"
    if json_output:
        out = {
            "result": status,
            "findings": [asdict(f) for f in findings],
            "error_count": sum(1 for f in findings if f.severity == "ERROR"),
            "warn_count": sum(1 for f in findings if f.severity == "WARN"),
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        if not findings:
            print(f"{status}: All checks passed")
        else:
            print(f"{status}: {len(findings)} issue(s) found")
            for f in findings:
                loc = f"L{f.line}" if f.line else "  "
                print(f"  [{f.severity}][{f.check}] {loc}: {f.message}")
                if f.snippet:
                    print(f"    → {f.snippet[:100]}")
    return 0 if passed else 1


# =============================================================================
# Check 1: String quoting — state machine
# =============================================================================

class _State(Enum):
    CODE = 0
    SINGLE_Q = 1
    DOUBLE_Q = 2
    BACKTICK = 3
    LINE_COMMENT = 4
    BLOCK_COMMENT = 5


def check_syntax(js_code: str) -> list:
    """Detect unescaped quote collisions in JS string literals."""
    findings = []
    state = _State.CODE
    escape = False
    template_depth = 0  # for ${...} in backticks
    brace_depth = 0
    line = 1
    i = 0
    n = len(js_code)

    # Track string start for error reporting
    string_start_line = 0
    string_start_pos = 0

    while i < n:
        ch = js_code[i]
        if ch == '\n':
            line += 1

        # Handle escape in string states
        if escape:
            escape = False
            i += 1
            continue

        if state in (_State.SINGLE_Q, _State.DOUBLE_Q, _State.BACKTICK):
            if ch == '\\':
                escape = True
                i += 1
                continue

        # State transitions
        if state == _State.CODE:
            if ch == "'":
                state = _State.SINGLE_Q
                string_start_line = line
                string_start_pos = i
            elif ch == '"':
                state = _State.DOUBLE_Q
                string_start_line = line
                string_start_pos = i
            elif ch == '`':
                state = _State.BACKTICK
                string_start_line = line
                string_start_pos = i
                template_depth += 1
            elif ch == '/' and i + 1 < n:
                if js_code[i + 1] == '/':
                    state = _State.LINE_COMMENT
                    i += 2
                    continue
                elif js_code[i + 1] == '*':
                    state = _State.BLOCK_COMMENT
                    i += 2
                    continue

        elif state == _State.SINGLE_Q:
            if ch == "'":
                state = _State.CODE

        elif state == _State.DOUBLE_Q:
            if ch == '"':
                state = _State.CODE

        elif state == _State.BACKTICK:
            if ch == '`':
                template_depth -= 1
                state = _State.CODE
            elif ch == '$' and i + 1 < n and js_code[i + 1] == '{':
                # Enter template expression — parse as CODE until matching }
                brace_depth += 1
                i += 2
                # Simplified: we skip template expression tracking
                # (full implementation would recurse)
                continue

        elif state == _State.LINE_COMMENT:
            if ch == '\n':
                state = _State.CODE

        elif state == _State.BLOCK_COMMENT:
            if ch == '*' and i + 1 < n and js_code[i + 1] == '/':
                state = _State.CODE
                i += 2
                continue

        i += 1

    # Check for unclosed strings
    if state in (_State.SINGLE_Q, _State.DOUBLE_Q, _State.BACKTICK):
        quote_char = {"SINGLE_Q": "'", "DOUBLE_Q": '"', "BACKTICK": '`'}[state.name]
        findings.append(Finding(
            severity="ERROR", check="syntax",
            message=f"Unclosed {quote_char} string starting at line {string_start_line}",
            line=string_start_line,
            snippet=js_code[string_start_pos:string_start_pos + 60],
        ))

    # Check 2: Nested quote collision (the go_through_me bug)
    # Pattern: var x = 'outer...inner='value'...outer'
    # This finds single-quoted strings that contain unescaped single quotes
    findings.extend(_check_nested_quotes(js_code))

    return findings


def _check_nested_quotes(js_code: str) -> list:
    """Detect string delimiter collision patterns in nested JS.

    Two heuristics:
    1. After a var assignment string closes, if next token is a statement keyword,
       the string probably closed too early (go_through_me bug).
    2. Pattern ='' or ="" inside a string — quote collision.
    """
    findings = []
    stmt_keywords = {'try', 'catch', 'if', 'else', 'for', 'while', 'var', 'let',
                     'const', 'function', 'return', 'throw', 'await', 'class', 'switch'}

    # Heuristic 1: string assignment followed by statement keyword
    assign_pattern = re.compile(r"(?:var|let|const)\s+(\w+)\s*=\s*(['\"])")
    for m in assign_pattern.finditer(js_code):
        var_name = m.group(1)
        quote = m.group(2)
        start = m.end()

        # Walk to first unescaped close quote (how JS parses)
        pos = start
        while pos < len(js_code):
            if js_code[pos] == '\\':
                pos += 2
                continue
            if js_code[pos] == quote:
                break
            pos += 1
        if pos >= len(js_code):
            continue

        # Check what follows the string close
        after = js_code[pos + 1:pos + 80].lstrip()
        # Skip semicolons, empty strings, operators
        after = re.sub(r"^[;,\s]+", "", after)
        after = re.sub(r"^['\"][^'\"]*['\"][;,\s]*", "", after)

        next_word = re.match(r'([a-zA-Z_]\w*)', after)
        if next_word and next_word.group(1) in stmt_keywords:
            line_num = js_code[:pos].count('\n') + 1
            findings.append(Finding(
                severity="ERROR", check="syntax",
                message=f"String '{var_name}' likely closed too early — "
                        f"'{next_word.group(1)}' keyword follows, suggesting "
                        f"unescaped {quote} inside {quote}-delimited string",
                line=line_num,
                snippet=js_code[max(0, pos - 25):pos + 25],
            ))

    # Heuristic 2: ='' or ="" inside a string (quote collision)
    for quote in ("'", '"'):
        # Find ={quote}{quote} patterns and check if inside a string
        pattern = re.compile(re.escape(f"={quote}{quote}"))
        for m in pattern.finditer(js_code):
            pos = m.start()
            before = js_code[:pos]
            # Count unescaped quotes before this position
            count = 0
            i = 0
            while i < len(before):
                if before[i] == '\\':
                    i += 2
                    continue
                if before[i] == quote:
                    count += 1
                i += 1
            if count % 2 == 1:  # odd = inside a string
                line_num = js_code[:pos].count('\n') + 1
                findings.append(Finding(
                    severity="ERROR", check="syntax",
                    message=f"Quote collision: ={quote}{quote} inside "
                            f"{quote}-delimited string",
                    line=line_num,
                    snippet=js_code[max(0, pos - 15):pos + 15],
                ))

    return findings


# =============================================================================
# Check 2: Side-effect detection
# =============================================================================

# Endpoints that trigger actions (bot spawn, etc.)
DANGEROUS_ENDPOINTS = [
    r'/api/report',
    r'/report\b',
    r'/admin/report',
    r'/bot',
    r'/crawl',
    r'/visit',
]

DANGEROUS_RE = re.compile(
    r'(?:fetch|XMLHttpRequest|\.ajax|\.post|\.get|navigator\.sendBeacon)\s*\('
    r'[^)]{0,200}?(?:' + '|'.join(DANGEROUS_ENDPOINTS) + r')',
    re.IGNORECASE | re.DOTALL
)


def check_sideeffects(js_code: str, allowed_endpoints: list = None) -> list:
    """Detect debug/logging calls that trigger side effects (bot spawns etc.)."""
    findings = []
    if allowed_endpoints is None:
        allowed_endpoints = ['/register', '/login']

    for m in DANGEROUS_RE.finditer(js_code):
        matched = m.group(0)
        # Check if it's in an allowed context
        is_allowed = any(ep in matched for ep in allowed_endpoints)
        if is_allowed:
            continue

        line_num = js_code[:m.start()].count('\n') + 1
        findings.append(Finding(
            severity="ERROR", check="sideeffect",
            message="Request to bot-triggering endpoint detected. "
                    "Use /register for debug instead of /api/report",
            line=line_num,
            snippet=matched[:80],
        ))

    return findings


# =============================================================================
# Check 3: Resource abuse detection
# =============================================================================

def check_resources(js_code: str, max_threads: int = 3) -> list:
    """Detect patterns that could overwhelm a remote server."""
    findings = []

    # Check for high thread/worker counts in Python code
    thread_patterns = [
        (r'NUM_SPRAY_THREADS\s*=\s*(\d+)', 'spray threads'),
        (r'ThreadPoolExecutor\s*\(\s*max_workers\s*=\s*(\d+)', 'thread pool workers'),
        (r'range\s*\(\s*(\d+)\s*\).*Thread\s*\(', 'thread spawn loop'),
    ]
    for pattern, desc in thread_patterns:
        for m in re.finditer(pattern, js_code, re.DOTALL):
            count = int(m.group(1))
            if count > max_threads:
                line_num = js_code[:m.start()].count('\n') + 1
                findings.append(Finding(
                    severity="WARN" if count <= max_threads * 2 else "ERROR",
                    check="resource",
                    message=f"{desc}: {count} exceeds limit of {max_threads}",
                    line=line_num,
                    snippet=m.group(0)[:80],
                ))

    # Detect tight loops with fetch
    tight_loop = re.compile(
        r'(?:while\s*\(\s*(?:true|1)\s*\)|for\s*\(;;\))\s*\{[^}]*fetch\s*\(',
        re.DOTALL
    )
    for m in tight_loop.finditer(js_code):
        line_num = js_code[:m.start()].count('\n') + 1
        findings.append(Finding(
            severity="ERROR", check="resource",
            message="Infinite loop with fetch() — will overwhelm server",
            line=line_num,
            snippet=m.group(0)[:80],
        ))

    return findings


# =============================================================================
# Extract JS from Python solve files
# =============================================================================

def extract_js_from_python(py_code: str) -> list:
    """Extract JS string assignments from Python solve.py files.

    Finds patterns like:
        STAGE2_JS = "...js code..."
        stage1_js = ('...' '...' '...')
        rce = 'var cb=...'
    """
    js_blocks = []

    # Pattern 1: Multi-line parenthesized string concatenation
    # e.g., TEMPLATE = ("part1" "part2" ...)
    paren_pattern = re.compile(
        r'(\w*(?:JS|js|TEMPLATE|template|payload|PAYLOAD|rce|RCE)\w*)\s*=\s*\(',
        re.IGNORECASE
    )
    for m in paren_pattern.finditer(py_code):
        name = m.group(1)
        start = m.end()
        depth = 1
        pos = start
        while pos < len(py_code) and depth > 0:
            if py_code[pos] == '(':
                depth += 1
            elif py_code[pos] == ')':
                depth -= 1
            pos += 1
        if depth == 0:
            block = py_code[start:pos - 1]
            # Join Python string literals: remove quotes and concatenation
            # "str1" \n "str2" -> str1str2
            js = _join_python_strings(block)
            if js and len(js) > 20:
                js_blocks.append((name, js))

    return js_blocks


def _join_python_strings(block: str) -> str:
    """Join Python consecutive string literals into one JS string.

    Input: '"part1"\n    "part2"\n    "part3"'
    Output: 'part1part2part3'
    """
    result = []
    # Find all string literals
    str_pattern = re.compile(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'')
    for m in str_pattern.finditer(block):
        s = m.group(1) if m.group(1) is not None else m.group(2)
        # Unescape Python escapes that map to literal chars in JS
        s = s.replace('\\"', '"')
        s = s.replace("\\'", "'")
        # Keep \\n, \\t etc. as-is (they're JS escapes)
        result.append(s)
    return ''.join(result)


# =============================================================================
# Self-test
# =============================================================================

SELF_TESTS = [
    # Bug 1: single quote collision (the go_through_me bug)
    {
        "name": "quote_collision",
        "js": "var rce='var flag='';try{x();}catch(e){}'",
        "expect_check": "syntax",
        "expect_fail": True,
    },
    # Bug 2: /api/report side effect
    {
        "name": "report_sideeffect",
        "js": "fetch('/api/report',{method:'POST',body:'path=/test'})",
        "expect_check": "sideeffect",
        "expect_fail": True,
    },
    # Clean payload should pass
    {
        "name": "clean_payload",
        "js": "fetch('/register',{method:'POST',body:'username=test'})",
        "expect_check": None,
        "expect_fail": False,
    },
    # Double-quoted string with ="" collision
    {
        "name": "double_quote_collision",
        "js": 'var x="flag=""test""',
        "expect_check": "syntax",
        "expect_fail": True,
    },
    # Escaped quotes should pass
    {
        "name": "escaped_quotes_ok",
        "js": "var x='hello \\'world\\''",
        "expect_check": None,
        "expect_fail": False,
    },
]


def run_self_test():
    passed = 0
    failed = 0
    for test in SELF_TESTS:
        findings = check_syntax(test["js"]) + check_sideeffects(test["js"])
        has_errors = any(f.severity == "ERROR" for f in findings)
        has_expected_check = test["expect_check"] is None or any(
            f.check == test["expect_check"] for f in findings
        )

        ok = (has_errors == test["expect_fail"]) and has_expected_check
        status = "✓" if ok else "✗"
        if ok:
            passed += 1
        else:
            failed += 1
        print(f"  {status} {test['name']}: "
              f"{'FAIL' if has_errors else 'PASS'} "
              f"(expected {'FAIL' if test['expect_fail'] else 'PASS'})"
              f"{'' if ok else ' ← MISMATCH'}")
        if not ok:
            for f in findings:
                print(f"    [{f.severity}][{f.check}] {f.message}")

    print(f"\nSelf-test: {passed}/{passed + failed} passed")
    return 0 if failed == 0 else 1


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="JS payload validator for web CTF exploits"
    )
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("--js", help="JS code string to check")
    input_group.add_argument("--file", help="JS file to check")
    input_group.add_argument("--extract", help="Python solve.py to extract JS from")
    input_group.add_argument("--self-test", action="store_true",
                             help="Run built-in tests")

    parser.add_argument("--check-syntax", action="store_true")
    parser.add_argument("--check-sideeffects", action="store_true")
    parser.add_argument("--check-resources", action="store_true")
    parser.add_argument("--check-all", action="store_true")
    parser.add_argument("--allow-endpoint", action="append", default=[],
                        help="Endpoints OK to POST to (repeatable)")
    parser.add_argument("--max-threads", type=int, default=3)
    parser.add_argument("--json", action="store_true")

    args = parser.parse_args()

    if args.self_test:
        sys.exit(run_self_test())

    # Determine what to check
    do_syntax = args.check_syntax or args.check_all
    do_sideeffects = args.check_sideeffects or args.check_all
    do_resources = args.check_resources or args.check_all

    if not (do_syntax or do_sideeffects or do_resources):
        do_syntax = do_sideeffects = do_resources = True  # default: all

    allowed = args.allow_endpoint or ['/register', '/login']

    # Get code to check
    if args.extract:
        py_code = open(args.extract).read()
        blocks = extract_js_from_python(py_code)
        if not blocks:
            print("No JS blocks found in Python file")
            sys.exit(0)
        all_findings = []
        for name, js in blocks:
            print(f"Checking {name} ({len(js)} chars)...", file=sys.stderr)
            findings = []
            if do_syntax:
                findings.extend(check_syntax(js))
            if do_sideeffects:
                findings.extend(check_sideeffects(js))
            if do_resources:
                findings.extend(check_resources(js))
            all_findings.extend(findings)
        # Also check the Python code itself for resource issues
        if do_resources:
            all_findings.extend(check_resources(py_code, args.max_threads))

        has_errors = any(f.severity == "ERROR" for f in all_findings)
        sys.exit(_result(not has_errors, all_findings, args.json))

    elif args.js:
        code = args.js
    elif args.file:
        code = open(args.file).read()
    else:
        parser.print_help()
        sys.exit(1)

    findings = []
    if do_syntax:
        findings.extend(check_syntax(code))
    if do_sideeffects:
        findings.extend(check_sideeffects(code))
    if do_resources:
        findings.extend(check_resources(code, args.max_threads))

    has_errors = any(f.severity == "ERROR" for f in findings)
    sys.exit(_result(not has_errors, findings, args.json))


if __name__ == "__main__":
    main()
