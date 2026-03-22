#!/usr/bin/env python3
"""
Machine CTF State Store
=======================
SQLite-backed fact store + artifact verifier for agent pipelines.
Prevents hallucination by requiring every fact to cite a real source file.

Usage (agents call this via shell):
  state.py set   --key <k> --val <v> --src <file> --agent <name>
  state.py get   --key <k>
  state.py facts                          # JSON dump of all facts
  state.py verify --artifacts <f1> <f2>   # exit 1 if any missing/empty
  state.py checkpoint --phase <n> --status <s> --agent <name> [--phase-name <s>]
  state.py checkpoint --read              # print current checkpoint JSON

CHALLENGE_DIR env var sets the working directory (default: cwd).
"""

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def challenge_dir() -> Path:
    d = Path(os.environ.get("CHALLENGE_DIR", ".")).resolve()
    d.mkdir(parents=True, exist_ok=True)
    return d


def db_path() -> Path:
    return challenge_dir() / "state.db"


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS facts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            key       TEXT NOT NULL,
            value     TEXT NOT NULL,
            source    TEXT,           -- path to tool output file that proves this fact
            agent     TEXT,
            ts        TEXT NOT NULL,
            verified  INTEGER NOT NULL DEFAULT 0  -- 1 if source file existed at write time
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_facts_key ON facts(key)")
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_set(args):
    """Write a verified fact. Source file must exist."""
    src = args.src
    verified = 0

    if src:
        src_path = Path(src)
        if not src_path.is_absolute():
            src_path = challenge_dir() / src_path
        if not src_path.exists():
            print(f"[state] ERROR: source file not found: {src_path}", file=sys.stderr)
            sys.exit(1)
        if src_path.stat().st_size == 0:
            print(f"[state] ERROR: source file is empty: {src_path}", file=sys.stderr)
            sys.exit(1)
        verified = 1
        src = str(src_path)
    else:
        print(f"[state] WARN: fact '{args.key}' has no source — marked unverified", file=sys.stderr)

    conn = get_conn()
    conn.execute(
        "INSERT INTO facts (key, value, source, agent, ts, verified) VALUES (?,?,?,?,?,?)",
        (args.key, args.val, src, args.agent, utcnow(), verified),
    )
    conn.commit()
    status = "verified" if verified else "unverified"
    print(f"[state] SET {args.key}={args.val!r} ({status})")


def cmd_get(args):
    """Get the latest value for a key. Prints value or exits 1 if not found."""
    conn = get_conn()
    row = conn.execute(
        "SELECT value, source, agent, ts, verified FROM facts WHERE key=? ORDER BY id DESC LIMIT 1",
        (args.key,),
    ).fetchone()
    if row is None:
        print(f"[state] NOT FOUND: {args.key}", file=sys.stderr)
        sys.exit(1)
    result = {
        "key": args.key,
        "value": row["value"],
        "source": row["source"],
        "agent": row["agent"],
        "ts": row["ts"],
        "verified": bool(row["verified"]),
    }
    print(json.dumps(result, indent=2))


def cmd_facts(args):
    """Dump all facts as JSON (latest value per key)."""
    conn = get_conn()
    rows = conn.execute("""
        SELECT key, value, source, agent, ts, verified
        FROM facts
        WHERE id IN (SELECT MAX(id) FROM facts GROUP BY key)
        ORDER BY key
    """).fetchall()
    facts = [dict(r) for r in rows]
    for f in facts:
        f["verified"] = bool(f["verified"])
    print(json.dumps(facts, indent=2))


def cmd_verify(args):
    """
    Check that all required artifact files exist and are non-empty.
    Exits 0 on success, 1 on failure (prints missing files).
    """
    base = challenge_dir()
    missing = []
    for artifact in args.artifacts:
        p = Path(artifact)
        if not p.is_absolute():
            p = base / p
        if not p.exists():
            missing.append(f"MISSING: {artifact}")
        elif p.stat().st_size == 0:
            missing.append(f"EMPTY:   {artifact}")

    if missing:
        print("[state] VERIFY FAILED — handoff blocked:", file=sys.stderr)
        for m in missing:
            print(f"  {m}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"[state] VERIFY OK — {len(args.artifacts)} artifact(s) confirmed")


def cmd_checkpoint(args):
    """Read or write checkpoint.json for the current challenge."""
    cp_path = challenge_dir() / "checkpoint.json"

    if args.read:
        if not cp_path.exists():
            print("{}", file=sys.stderr)
            sys.exit(1)
        print(cp_path.read_text())
        return

    # Write / update
    cp = {}
    if cp_path.exists():
        try:
            cp = json.loads(cp_path.read_text())
        except json.JSONDecodeError:
            cp = {}

    # Update fields
    if args.agent:
        cp["agent"] = args.agent
    if args.status:
        cp["status"] = args.status
    if args.phase is not None:
        cp["phase"] = args.phase
    if args.phase_name:
        cp["phase_name"] = args.phase_name

    # Track completed phases
    completed = cp.get("completed", [])
    if args.status == "completed" and args.phase_name:
        entry = f"phase{args.phase}:{args.phase_name}"
        if entry not in completed:
            completed.append(entry)
    cp["completed"] = completed

    cp["timestamp"] = utcnow()
    cp["state_db"] = str(db_path())

    cp_path.write_text(json.dumps(cp, indent=2))
    print(f"[state] CHECKPOINT written: phase={cp.get('phase')} status={cp.get('status')}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Machine CTF State Store",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # set
    p_set = sub.add_parser("set", help="Write a fact (requires source file)")
    p_set.add_argument("--key", required=True)
    p_set.add_argument("--val", required=True)
    p_set.add_argument("--src", default=None, help="Path to tool output file proving this fact")
    p_set.add_argument("--agent", default="unknown")

    # get
    p_get = sub.add_parser("get", help="Read a fact by key")
    p_get.add_argument("--key", required=True)

    # facts
    sub.add_parser("facts", help="Dump all facts as JSON")

    # verify
    p_verify = sub.add_parser("verify", help="Check artifact files exist before handoff")
    p_verify.add_argument("--artifacts", nargs="+", required=True, metavar="FILE")

    # checkpoint
    p_cp = sub.add_parser("checkpoint", help="Read/write checkpoint.json")
    p_cp.add_argument("--read", action="store_true")
    p_cp.add_argument("--phase", type=int, default=None)
    p_cp.add_argument("--phase-name", default=None)
    p_cp.add_argument("--status", choices=["in_progress", "completed", "error"], default=None)
    p_cp.add_argument("--agent", default=None)

    args = parser.parse_args()

    dispatch = {
        "set": cmd_set,
        "get": cmd_get,
        "facts": cmd_facts,
        "verify": cmd_verify,
        "checkpoint": cmd_checkpoint,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
