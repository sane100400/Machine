#!/usr/bin/env python3
"""
Machine v2 — Learning Loop
============================
Post-solve learning: auto-generate writeups, record failures, extract techniques,
update knowledge/index.md. Runs ALWAYS — success or failure.

Usage:
  learn.py record --challenge-dir DIR --status success --flag "FLAG{...}" [--category web]
  learn.py record --challenge-dir DIR --status failed --notes "stuck on heap layout"
  learn.py extract-technique --challenge-dir DIR --name "technique_name"
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

MACHINE_ROOT = Path(__file__).resolve().parent.parent
KNOWLEDGE_DIR = MACHINE_ROOT / "knowledge"
CHALLENGES_DIR = KNOWLEDGE_DIR / "challenges"
TECHNIQUES_DIR = KNOWLEDGE_DIR / "techniques"
INDEX_PATH = KNOWLEDGE_DIR / "index.md"
KB_SCRIPT = MACHINE_ROOT / "tools" / "knowledge.py"


# ---------------------------------------------------------------------------
# Writeup Generation
# ---------------------------------------------------------------------------

def find_artifacts(challenge_dir: Path) -> dict:
    """Find all relevant artifacts in the challenge directory."""
    artifacts = {}
    names = {
        "solve.py": "solve_script",
        "solve.sage": "solve_script",
        "exploit.py": "solve_script",
        "Exploit.t.sol": "solve_script",
        "web_analysis.md": "analysis",
        "forensics_report.md": "analysis",
        "critic_review.md": "critic_review",
        "reversal_map.md": "reversal_map",
        "chain_report.md": "chain_report",
        "docker_test_report.md": "docker_report",
        "remote_output.txt": "remote_output",
        "checkpoint.json": "checkpoint",
        "state.db": "state_db",
    }
    for fname, key in names.items():
        fpath = challenge_dir / fname
        if fpath.exists():
            artifacts[key] = fpath
    return artifacts


def read_file_safe(path: Path, max_chars: int = 5000) -> str:
    """Read file with truncation."""
    try:
        text = path.read_text(errors="replace")
        if len(text) > max_chars:
            return text[:max_chars] + "\n[... truncated]"
        return text
    except OSError:
        return ""


def extract_technique_from_solve(solve_path: Path, category: str) -> str:
    """Extract technique description from solve script."""
    if not solve_path.exists():
        return ""
    code = read_file_safe(solve_path, 3000)

    techniques = []

    # Pattern matching for common CTF techniques
    patterns = {
        "pwn": [
            (r"ROP|rop_chain|ROPgadget", "ROP chain"),
            (r"tcache|fastbin|unsorted", "heap exploitation"),
            (r"format.*string|%p|%n|%s", "format string"),
            (r"ret2libc|system.*binsh", "ret2libc"),
            (r"canary|stack.*cookie", "stack canary bypass"),
            (r"one_gadget", "one_gadget"),
            (r"ret2dlresolve", "ret2dlresolve"),
        ],
        "web": [
            (r"sqli|sql.*inject|union.*select", "SQL injection"),
            (r"ssrf|server.*side.*request", "SSRF"),
            (r"ssti|template.*inject", "SSTI"),
            (r"xss|cross.*site.*script", "XSS"),
            (r"deserializ|pickle|unserialize", "deserialization"),
            (r"jwt|json.*web.*token", "JWT attack"),
            (r"prototype.*pollut", "prototype pollution"),
            (r"path.*travers|lfi|local.*file", "path traversal / LFI"),
            (r"xxe|xml.*external", "XXE"),
            (r"race.*cond|toctou", "race condition"),
        ],
        "crypto": [
            (r"rsa|factori[zs]", "RSA attack"),
            (r"lll|lattice|bkz", "lattice reduction"),
            (r"ecc|elliptic.*curve|discrete.*log", "ECC attack"),
            (r"aes|ecb|cbc|padding.*oracle", "symmetric crypto attack"),
            (r"xor", "XOR-based attack"),
            (r"z3|smt|constraint", "constraint solving"),
            (r"pohlig.*hellman", "Pohlig-Hellman"),
        ],
        "rev": [
            (r"z3|smt|constraint", "z3 constraint solving"),
            (r"angr|symbolic", "symbolic execution"),
            (r"frida|hook", "dynamic instrumentation"),
            (r"wasm|webassembly", "WebAssembly analysis"),
            (r"gdb.*oracle|side.*channel", "GDB oracle"),
        ],
        "forensics": [
            (r"steg|lsb|zsteg", "steganography"),
            (r"volatility|memory.*dump", "memory forensics"),
            (r"pcap|wireshark|tshark", "PCAP analysis"),
            (r"binwalk|foremost", "file carving"),
        ],
    }

    code_lower = code.lower()
    for pattern, name in patterns.get(category, []):
        if re.search(pattern, code_lower, re.IGNORECASE):
            techniques.append(name)

    return " / ".join(techniques[:4]) if techniques else category


def generate_writeup(challenge_dir: Path, category: str, flag: str,
                     artifacts: dict) -> str:
    """Generate a writeup from artifacts."""
    name = challenge_dir.name
    technique = ""

    # Read solve script to identify technique
    if "solve_script" in artifacts:
        technique = extract_technique_from_solve(artifacts["solve_script"], category)

    # Read analysis if available
    analysis = ""
    if "analysis" in artifacts:
        analysis = read_file_safe(artifacts["analysis"], 2000)

    # Read solve script
    solve_code = ""
    if "solve_script" in artifacts:
        solve_code = read_file_safe(artifacts["solve_script"], 3000)

    # Read checkpoint for phase history
    phases = ""
    if "checkpoint" in artifacts:
        try:
            cp = json.loads(artifacts["checkpoint"].read_text())
            if isinstance(cp, dict) and "phases" in cp:
                phases = json.dumps(cp["phases"], indent=2)
        except (json.JSONDecodeError, OSError):
            pass

    writeup = f"""# {name}

## Overview
- **Category**: {category}
- **Technique**: {technique}
- **Flag**: `{flag}`
- **Date**: {datetime.now().strftime('%Y-%m-%d')}

## Vulnerability / Key Insight

{analysis if analysis else '[Auto-generated — manual enrichment recommended]'}

## Solve Script

```python
{solve_code if solve_code else '[No solve script found]'}
```

## Notes

- Auto-generated by Machine v2 learn.py
- Challenge directory: {challenge_dir}
"""

    return writeup


def generate_failure_record(challenge_dir: Path, category: str,
                            notes: str, artifacts: dict) -> str:
    """Generate a failure record."""
    name = challenge_dir.name

    # Read what was attempted
    attempted = []
    if "solve_script" in artifacts:
        technique = extract_technique_from_solve(
            artifacts["solve_script"], category)
        attempted.append(f"Attempted technique: {technique}")
    if "analysis" in artifacts:
        attempted.append("Analysis was generated")
    if "critic_review" in artifacts:
        review = read_file_safe(artifacts["critic_review"], 500)
        attempted.append(f"Critic review: {review[:200]}")

    return f"""# {name} (FAILED)

## Overview
- **Category**: {category}
- **Status**: Failed
- **Date**: {datetime.now().strftime('%Y-%m-%d')}

## What Was Tried

{chr(10).join('- ' + a for a in attempted) if attempted else '- No significant artifacts found'}

## Failure Notes

{notes if notes else 'No failure notes provided.'}

## Lessons

[TODO: Manual analysis of why this failed — what should the agent have done differently?]
"""


# ---------------------------------------------------------------------------
# Index Update
# ---------------------------------------------------------------------------

def update_index(name: str, category: str, technique: str,
                 flag: str = "", status: str = "success"):
    """Add entry to knowledge/index.md."""
    if not INDEX_PATH.exists():
        return

    content = INDEX_PATH.read_text()

    # Check if already exists
    if name in content:
        return  # Already recorded

    if status == "success":
        # Add to Solved Challenges table
        entry = f"| [{name}](challenges/{name}.md) | {category} | {technique} | {flag} |"
        # Find the end of the solved table
        marker = "## Attempted / Failed"
        if marker in content:
            content = content.replace(
                marker,
                f"{entry}\n\n{marker}"
            )
    else:
        # Add to Attempted / Failed table
        entry = f"| {name} | {category} | {technique} | failed |"
        # Find the end of the attempted table
        marker = "## Techniques"
        if marker in content:
            content = content.replace(
                marker,
                f"{entry}\n\n{marker}"
            )

    INDEX_PATH.write_text(content)


# ---------------------------------------------------------------------------
# Knowledge DB Indexing
# ---------------------------------------------------------------------------

def index_to_kb(writeup_path: Path):
    """Add writeup to the FTS5 knowledge base."""
    if KB_SCRIPT.exists():
        try:
            subprocess.run(
                [sys.executable, str(KB_SCRIPT), "add", str(writeup_path)],
                capture_output=True, timeout=30,
                cwd=str(MACHINE_ROOT)
            )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_record(args):
    """Record challenge result (success or failure)."""
    challenge_dir = Path(args.challenge_dir).resolve()
    if not challenge_dir.is_dir():
        print(f"Error: {challenge_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    name = challenge_dir.name
    category = args.category or "unknown"
    status = args.status
    artifacts = find_artifacts(challenge_dir)

    CHALLENGES_DIR.mkdir(parents=True, exist_ok=True)
    writeup_path = CHALLENGES_DIR / f"{name}.md"

    if status == "success":
        flag = args.flag or ""
        writeup = generate_writeup(challenge_dir, category, flag, artifacts)
        writeup_path.write_text(writeup)
        print(f"[learn] Writeup saved: {writeup_path}")

        # Extract technique name for index
        technique = ""
        if "solve_script" in artifacts:
            technique = extract_technique_from_solve(
                artifacts["solve_script"], category)

        # Update index
        update_index(name, category, technique, flag, "success")
        print(f"[learn] Index updated: {name} → solved")

        # Index to KB
        index_to_kb(writeup_path)
        print(f"[learn] KB indexed: {name}")

    elif status == "failed":
        notes = args.notes or ""
        record = generate_failure_record(challenge_dir, category, notes, artifacts)
        # Save failure record (don't overwrite success writeup if exists)
        failure_path = CHALLENGES_DIR / f"{name}_failed.md"
        failure_path.write_text(record)
        print(f"[learn] Failure record saved: {failure_path}")

        technique = ""
        if "solve_script" in artifacts:
            technique = extract_technique_from_solve(
                artifacts["solve_script"], category)

        update_index(name, category, technique or "unknown", "", "failed")
        print(f"[learn] Index updated: {name} → failed")

        # Index failure too (useful for avoiding repeat mistakes)
        index_to_kb(failure_path)

    else:
        print(f"Error: unknown status '{status}'", file=sys.stderr)
        sys.exit(1)

    # Summary
    print(json.dumps({
        "challenge": name,
        "category": category,
        "status": status,
        "artifacts_found": list(artifacts.keys()),
        "writeup": str(writeup_path) if status == "success" else str(
            CHALLENGES_DIR / f"{name}_failed.md"),
    }, indent=2))


def cmd_extract_technique(args):
    """Extract a technique doc from a solved challenge."""
    challenge_dir = Path(args.challenge_dir).resolve()
    name = args.name
    artifacts = find_artifacts(challenge_dir)

    if "solve_script" not in artifacts:
        print("Error: No solve script found", file=sys.stderr)
        sys.exit(1)

    TECHNIQUES_DIR.mkdir(parents=True, exist_ok=True)
    solve_code = read_file_safe(artifacts["solve_script"], 5000)

    # Generate technique doc
    tech_doc = f"""# {name}

## Category
{args.category or 'unknown'}

## Description
[Auto-extracted technique — manual enrichment recommended]

## Key Code Pattern

```python
{solve_code}
```

## When to Use
- [TODO: describe when this technique applies]

## References
- Challenge: {challenge_dir.name}
"""

    tech_path = TECHNIQUES_DIR / f"{name}.md"
    tech_path.write_text(tech_doc)
    print(f"[learn] Technique saved: {tech_path}")

    # Index
    index_to_kb(tech_path)
    print(f"[learn] KB indexed: {name}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Machine v2 Learning Loop")
    sub = p.add_subparsers(dest="cmd", required=True)

    # record
    s = sub.add_parser("record", help="Record challenge result")
    s.add_argument("--challenge-dir", required=True)
    s.add_argument("--status", required=True, choices=["success", "failed"])
    s.add_argument("--flag", default="")
    s.add_argument("--category", default="")
    s.add_argument("--notes", default="")

    # extract-technique
    s = sub.add_parser("extract-technique", help="Extract technique doc")
    s.add_argument("--challenge-dir", required=True)
    s.add_argument("--name", required=True)
    s.add_argument("--category", default="")

    args = p.parse_args()
    if args.cmd == "record":
        cmd_record(args)
    elif args.cmd == "extract-technique":
        cmd_extract_technique(args)


if __name__ == "__main__":
    main()
