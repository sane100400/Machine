#!/usr/bin/env python3
"""Context digest — compacts large outputs for agent context efficiency.

Integrates with Machine's Observation Masking rules:
  < 100 lines  → full inline
  100-500 lines → key findings + file reference
  500+ lines    → must mask (elide middle, extract key patterns)

Usage:
  cat large_output.txt | python3 tools/context_digest.py --max-lines 100
  python3 tools/context_digest.py --file /path/to/output.txt --max-lines 50
  python3 tools/context_digest.py --dir /path/to/challenge/ --max-lines 200
  python3 tools/context_digest.py --file output.txt --prefer-gemini
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Key patterns for rule-based extraction
KEY_PATTERNS = [
    re.compile(r"0x[0-9a-fA-F]{4,16}"),                          # hex addresses
    re.compile(r"(DH|FLAG|flag|CTF|GoN|CYAI)\{[^}]+\}"),         # flag patterns
    re.compile(r"(ERROR|WARN|FAIL|SEGV|SIGSEGV|Traceback)", re.I),  # errors
    re.compile(r"(def \w+|function \w+|int \w+\(|void \w+\()"),   # function sigs
    re.compile(r"CVE-\d{4}-\d+"),                                  # CVE patterns
    re.compile(r"\d+\.\d+\.\d+\.\d+:\d+"),                        # IP:port
]

HEAD_LINES = 20
TAIL_LINES = 20


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()


def _extract_key_lines(lines: list[str]) -> list[str]:
    """Extract lines matching key patterns from the middle section."""
    key_lines: list[str] = []
    for line in lines:
        for pat in KEY_PATTERNS:
            if pat.search(line):
                key_lines.append(line)
                break
    return key_lines


def _rule_based_truncate(lines: list[str], max_lines: int) -> str:
    """Truncate with head/tail preservation and key pattern extraction."""
    head = lines[:HEAD_LINES]
    tail = lines[-TAIL_LINES:]
    middle = lines[HEAD_LINES:-TAIL_LINES] if len(lines) > HEAD_LINES + TAIL_LINES else []

    key_lines = _extract_key_lines(middle)
    # Budget for key lines: max_lines minus head/tail
    budget = max(0, max_lines - HEAD_LINES - TAIL_LINES)
    key_lines = key_lines[:budget]

    elided_count = len(middle) - len(key_lines)
    parts = head
    if key_lines:
        parts.append(f"\n[--- Key patterns extracted from middle ({len(key_lines)} matches) ---]")
        parts.extend(key_lines)
    if elided_count > 0:
        parts.append(f"\n[... {elided_count} lines elided. Key patterns extracted above ...]")
    parts.append("")
    parts.extend(tail)
    return "\n".join(parts)


def _run_gemini(text: str, project_root: Path) -> str | None:
    """Try Gemini summarization via gemini_query.sh."""
    script = project_root / "tools" / "gemini_query.sh"
    if not script.exists() or not os.environ.get("GEMINI_API_KEY"):
        return None
    try:
        result = subprocess.run(
            ["bash", str(script), "summarize"],
            input=text, capture_output=True, text=True, timeout=90,
            cwd=str(project_root),
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def _read_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _read_dir(path: Path) -> str:
    """Concatenate key files from a directory."""
    extensions = {".py", ".c", ".h", ".txt", ".md", ".json", ".sh", ".sol", ".js"}
    parts: list[str] = []
    for f in sorted(path.rglob("*")):
        if f.is_file() and f.suffix in extensions and f.stat().st_size < 500_000:
            parts.append(f"=== {f.relative_to(path)} ===")
            parts.append(f.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def _get_cache_path(cache_dir: Path, key: str) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / f"{key}.txt"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Context digest — compact large outputs")
    p.add_argument("--max-lines", type=int, default=100)
    p.add_argument("--file", type=str, help="Input file path")
    p.add_argument("--dir", type=str, help="Input directory path")
    p.add_argument("--prefer-gemini", action="store_true")
    p.add_argument("--cache-dir", type=str, default="/tmp/machine_digest_cache")
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--json", action="store_true", help="Output as JSON with metadata")
    return p


def main() -> int:
    args = build_parser().parse_args()

    # Read input
    if args.file:
        raw = _read_file(Path(args.file))
        source = args.file
    elif args.dir:
        raw = _read_dir(Path(args.dir))
        source = args.dir
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
        source = "stdin"
    else:
        print("Error: provide --file, --dir, or pipe to stdin", file=sys.stderr)
        return 1

    lines = raw.splitlines()
    total = len(lines)

    # Check cache
    cache_dir = Path(args.cache_dir)
    cache_key = _sha256(raw + str(args.max_lines))
    if not args.no_cache:
        cached = _get_cache_path(cache_dir, cache_key)
        if cached.exists():
            output = cached.read_text(encoding="utf-8")
            if args.json:
                print(json.dumps({"source": source, "total_lines": total,
                                  "digest_lines": len(output.splitlines()),
                                  "method": "cached", "digest": output}))
            else:
                print(output)
            return 0

    # Apply observation masking rules
    if total <= args.max_lines:
        output = raw
        method = "full"
    else:
        # Try Gemini first if requested
        gemini_result = None
        if args.prefer_gemini:
            gemini_result = _run_gemini(raw, PROJECT_ROOT)
        if gemini_result:
            output = gemini_result
            method = "gemini"
        else:
            output = _rule_based_truncate(lines, args.max_lines)
            method = "rule_based"

    # Cache result
    if not args.no_cache:
        cached = _get_cache_path(cache_dir, cache_key)
        cached.write_text(output, encoding="utf-8")

    if args.json:
        print(json.dumps({"source": source, "total_lines": total,
                          "digest_lines": len(output.splitlines()),
                          "method": method, "digest": output}))
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
