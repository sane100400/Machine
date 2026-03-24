#!/usr/bin/env python3
"""
Machine CTF Decision Tree Engine
=================================
Replaces inline decision-tree text in agent .md files with a callable tool.
Agents call this when they hit a failure to get the next action to try.

Usage:
  decision_tree.py next   --agent pwn --trigger leak_failure [--context '{"glibc":"2.35"}']
  decision_tree.py record --agent pwn --trigger leak_failure --action-id got_leak
  decision_tree.py status --agent pwn
  decision_tree.py reset  --agent pwn

Exit codes: 0 = action available, 1 = all exhausted (FAIL), 2 = error
"""

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# State DB helpers (reuses state.py's DB)
# ---------------------------------------------------------------------------

def challenge_dir() -> Path:
    d = Path(os.environ.get("CHALLENGE_DIR", ".")).resolve()
    d.mkdir(parents=True, exist_ok=True)
    return d

def get_conn() -> sqlite3.Connection:
    db = challenge_dir() / "state.db"
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS facts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL, value TEXT NOT NULL,
        source TEXT, agent TEXT, ts TEXT NOT NULL,
        verified INTEGER NOT NULL DEFAULT 0)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_facts_key ON facts(key)")
    conn.commit()
    return conn

def dt_key(agent: str, trigger: str, action_id: str) -> str:
    return f"dt_{agent}_{trigger}_{action_id}"

def get_attempt_count(conn, agent: str, trigger: str, action_id: str) -> int:
    key = dt_key(agent, trigger, action_id)
    row = conn.execute(
        "SELECT value FROM facts WHERE key=? ORDER BY id DESC LIMIT 1", (key,)
    ).fetchone()
    return int(row["value"]) if row else 0

def set_attempt_count(conn, agent: str, trigger: str, action_id: str, count: int):
    from datetime import datetime, timezone
    key = dt_key(agent, trigger, action_id)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        "INSERT INTO facts (key, value, source, agent, ts, verified) VALUES (?,?,?,?,?,?)",
        (key, str(count), "decision_tree.py", agent, ts, 1)
    )
    conn.commit()

def get_total_failures(conn, agent: str) -> int:
    rows = conn.execute(
        "SELECT value FROM facts WHERE key LIKE ? ORDER BY id DESC",
        (f"dt_{agent}_%",)
    ).fetchall()
    seen = {}
    for r in rows:
        # deduplicate by key (latest value wins)
        pass
    # simpler: count all dt_ records for this agent
    row = conn.execute(
        "SELECT COALESCE(SUM(CAST(value AS INTEGER)),0) as total FROM "
        "(SELECT key, value FROM facts WHERE key LIKE ? GROUP BY key HAVING id=MAX(id))",
        (f"dt_{agent}_%",)
    ).fetchone()
    return row["total"] if row else 0

# ---------------------------------------------------------------------------
# Decision Trees — all agent branches
# ---------------------------------------------------------------------------

TREES = {
    "pwn": {
        "leak_failure": [
            {"id": "got_leak", "desc": "puts/printf GOT leak via ROP (PIE OFF)", "max": 2},
            {"id": "fmt_leak", "desc": "Format string %p leak (if printf with user input)", "max": 2},
            {"id": "partial_overwrite", "desc": "Partial overwrite (PIE ON, 12-bit brute)", "max": 2},
            {"id": "ret2dlresolve", "desc": "ret2dlresolve (no leak needed)", "max": 2},
            {"id": "heap_leak", "desc": "Unsorted bin fd pointer leak", "max": 2},
        ],
        "rip_failure": [
            {"id": "verify_offset", "desc": "Re-verify offset with cyclic pattern in GDB", "max": 2},
            {"id": "check_canary", "desc": "Check for stack canary at rbp-0x8, add leak step if present", "max": 2},
            {"id": "stack_pivot", "desc": "Buffer too small for ROP — pivot to .bss/heap", "max": 2},
            {"id": "pie_leak", "desc": "PIE enabled — need base address leak first", "max": 2},
        ],
        "payload_failure": [
            {"id": "stack_align", "desc": "Add extra ret gadget before system/execve (movaps fix)", "max": 2},
            {"id": "one_gadget", "desc": "Try all one_gadget results with -l 2", "max": 2},
            {"id": "execve_rop", "desc": "Build execve ROP: pop rdi; pop rsi; pop rdx; syscall", "max": 2},
            {"id": "fsop", "desc": "FSOP via _IO_list_all overwrite (glibc >= 2.34)", "max": 2},
            {"id": "ret2dlresolve_payload", "desc": "ret2dlresolve to bypass FULL RELRO", "max": 2},
        ],
        "heap_selection": [
            {"id": "tcache_poison", "desc": "tcache poisoning (glibc 2.26+)", "max": 2, "ctx": {"glibc_min": "2.26"}},
            {"id": "fastbin_dup", "desc": "fastbin dup → __malloc_hook (glibc < 2.26)", "max": 2, "ctx": {"glibc_max": "2.26"}},
            {"id": "safe_link_bypass", "desc": "tcache + safe-linking bypass + heap leak (glibc >= 2.32)", "max": 2, "ctx": {"glibc_min": "2.32"}},
            {"id": "unsorted_bin", "desc": "Unsorted bin attack", "max": 2},
            {"id": "house_of_orange", "desc": "House of Orange (no free needed)", "max": 2},
            {"id": "large_bin_attack", "desc": "Large bin attack", "max": 2},
        ],
        "remote_failure": [
            {"id": "libc_mismatch", "desc": "Check libc version on remote (strings/leak + database)", "max": 2},
            {"id": "timeout_fix", "desc": "Increase sleep/recv timeouts in solve.py", "max": 2},
            {"id": "aslr_brute", "desc": "Run in loop (max 100 iterations for partial overwrite)", "max": 3},
            {"id": "binary_diff", "desc": "Re-check remote binary if downloadable", "max": 1},
        ],
    },
    "rev": {
        "solver_fallback": [
            {"id": "z3_smt", "desc": "z3 SMT solver — encode all constraints, check sat", "max": 2},
            {"id": "angr_symex", "desc": "angr symbolic execution — explore(find=OK, avoid=FAIL)", "max": 2},
            {"id": "gdb_oracle", "desc": "GDB oracle — binary as black-box, byte-by-byte", "max": 2},
            {"id": "sage_math", "desc": "Manual math inverse in SageMath", "max": 2},
            {"id": "brute_force", "desc": "Brute force (ONLY if keyspace < 2^24)", "max": 1},
        ],
        "unpack_failure": [
            {"id": "upx", "desc": "UPX: upx -d ./binary -o ./unpacked", "max": 1},
            {"id": "packer_id", "desc": "Check strings for packer ID → use specific unpacker", "max": 2},
            {"id": "gdb_oep", "desc": "GDB hardware breakpoint on OEP after unpacking stub", "max": 2},
            {"id": "frida_dump", "desc": "Frida runtime dump: attach after unpacking, dump .text", "max": 2},
            {"id": "manual_trace", "desc": "Trace execution until original code, dump memory region", "max": 2},
        ],
        "custom_vm": [
            {"id": "map_opcodes", "desc": "Map opcodes: Ghidra switch/case → opcode_map.md", "max": 1},
            {"id": "trace_exec", "desc": "GDB breakpoint on dispatch → log opcode sequence", "max": 2},
            {"id": "decompile_vm", "desc": "Opcode sequence → pseudocode", "max": 1},
            {"id": "pattern_match", "desc": "Identify algorithm (XOR, TEA, AES-like, matrix)", "max": 2},
            {"id": "vm_oracle", "desc": "GDB oracle on VM as black box (side-channel)", "max": 2},
        ],
        "z3_unsat": [
            {"id": "remove_constraint", "desc": "Remove constraints one-by-one → find conflicting pair", "max": 2},
            {"id": "verify_expected", "desc": "Verify expected output bytes in GDB (may have read wrong data)", "max": 2},
            {"id": "check_signedness", "desc": "Check BitVec signed vs unsigned operations", "max": 1},
            {"id": "check_modular", "desc": "Check missing modulo in constraint", "max": 1},
            {"id": "test_known", "desc": "Test with known input/output pair first", "max": 1},
        ],
    },
    "crypto": {
        "rsa_attack": [
            {"id": "rsactftool", "desc": "RsaCtfTool --attack all (5 min timeout)", "max": 1},
            {"id": "factordb", "desc": "factordb.com lookup via WebFetch", "max": 1},
            {"id": "small_e", "desc": "e-th root attack / Hastad broadcast", "max": 2, "ctx": {"e_max": 17}},
            {"id": "wiener", "desc": "Wiener attack (continued fraction) for large e / small d", "max": 2},
            {"id": "fermat", "desc": "Fermat factorization for close primes (p ≈ q)", "max": 2},
            {"id": "coppersmith", "desc": "Coppersmith small_roots for partial key", "max": 2},
            {"id": "common_factor", "desc": "GCD across multiple n values (batch gcd)", "max": 1},
            {"id": "lattice_boneh", "desc": "Boneh-Durfee lattice attack (SageMath LLL)", "max": 2},
            {"id": "knowledge_search", "desc": "Search knowledge base for RSA technique", "max": 1},
        ],
        "symmetric_attack": [
            {"id": "ecb_oracle", "desc": "ECB block shuffling / byte-at-a-time oracle", "max": 2},
            {"id": "cbc_padding", "desc": "Vaudenay CBC padding oracle attack", "max": 2},
            {"id": "ctr_reuse", "desc": "CTR/OFB nonce reuse — keystream XOR", "max": 2},
            {"id": "length_ext", "desc": "Length extension attack (hashpumpy)", "max": 2},
            {"id": "z3_custom", "desc": "z3 constraint solving for custom cipher", "max": 2},
        ],
        "custom_cipher": [
            {"id": "reread_impl", "desc": "Re-read implementation, verify z3 model matches code", "max": 2},
            {"id": "partial_solve", "desc": "Solve partial constraints (first N bytes) to validate", "max": 2},
            {"id": "differential", "desc": "Differential cryptanalysis: input pairs with predictable diffs", "max": 2},
            {"id": "known_pt", "desc": "Known-plaintext: use flag format prefix as constraint", "max": 2},
            {"id": "partial_brute", "desc": "Fix known bytes, brute remaining (keyspace < 2^24)", "max": 1},
        ],
        "hash_crack": [
            {"id": "rockyou", "desc": "hashcat/john with rockyou.txt", "max": 1},
            {"id": "rules", "desc": "hashcat -r best64.rule", "max": 1},
            {"id": "custom_wordlist", "desc": "Extract strings from challenge files as wordlist", "max": 1},
            {"id": "mask", "desc": "hashcat -a 3 mask attack (if format hints)", "max": 1},
            {"id": "reverse_hash", "desc": "Reverse the hash function instead of cracking", "max": 2},
        ],
        "math_failure": [
            {"id": "verify_constants", "desc": "Re-read and re-parse all constants from challenge", "max": 1},
            {"id": "check_ring", "desc": "Check field/ring: GF(p) vs ZZ vs QQ", "max": 1},
            {"id": "exact_arith", "desc": "Use exact arithmetic (Sage Fraction) not float", "max": 1},
            {"id": "mod_inverse", "desc": "Verify gcd(a, n) == 1 for modular inverse", "max": 1},
            {"id": "alt_formulation", "desc": "Try alternative formulation of same math", "max": 2},
        ],
    },
    "web": {
        "no_vuln_found": [
            {"id": "check_deps", "desc": "Re-examine dependencies for known CVEs", "max": 1},
            {"id": "check_config", "desc": "Check debug mode, default creds, exposed admin routes", "max": 1},
            {"id": "logic_bugs", "desc": "Race conditions, TOCTOU, business logic bypass", "max": 1},
            {"id": "multi_step", "desc": "Multi-step chains: SSRF→LFI, SQLi→file read, auth→admin→RCE", "max": 1},
            {"id": "client_side", "desc": "DOM XSS, postMessage, service worker, WebSocket", "max": 1},
        ],
        "ambiguous_vuln": [
            {"id": "trace_dataflow", "desc": "Trace data flow: user input → sanitization → sink", "max": 2},
            {"id": "bypass_sanitize", "desc": "Check sanitization bypass (encoding, type confusion)", "max": 2},
            {"id": "search_bypass", "desc": "Search knowledge for framework-specific bypass", "max": 1},
            {"id": "ctf_meta", "desc": "WebSearch for known CTF pattern with this framework", "max": 1},
        ],
    },
    "forensics": {
        "unknown_filetype": [
            {"id": "magic_bytes", "desc": "xxd | head -30 → check magic bytes manually", "max": 1},
            {"id": "binwalk_sig", "desc": "binwalk -B → check for embedded signatures", "max": 1},
            {"id": "try_extensions", "desc": "Try common extensions: .zip/.gz/.png/.pdf", "max": 1},
            {"id": "entropy", "desc": "Entropy check: >7.5=encrypted, <4.0=text/sparse", "max": 1},
            {"id": "foremost", "desc": "foremost file carving → photorec", "max": 1},
        ],
        "stego_deadend": [
            {"id": "zsteg_steghide", "desc": "zsteg -a (PNG) / steghide -p '' (JPEG)", "max": 1},
            {"id": "lsb_manual", "desc": "LSB manual: all channel combos R,G,B,A,RGB,BGR", "max": 1},
            {"id": "password_stego", "desc": "steghide with passwords: filename, challenge name, metadata", "max": 1},
            {"id": "palette_idat", "desc": "Palette-based hiding, IDAT chunk manipulation", "max": 1},
            {"id": "appended_data", "desc": "Compare file size vs expected (IHDR dimensions)", "max": 1},
            {"id": "not_stego", "desc": "Re-examine: may NOT be stego. Check zip trailer, ADS, etc.", "max": 1},
        ],
        "memory_failure": [
            {"id": "fix_profile", "desc": "vol3 windows.info → verify OS → correct profile", "max": 2},
            {"id": "try_other_os", "desc": "Try both windows.* and linux.* plugins", "max": 1},
            {"id": "strings_grep", "desc": "strings + grep for direct flag search", "max": 1},
            {"id": "manual_dd", "desc": "Extract process memory with dd, then binwalk/strings", "max": 1},
        ],
        "pcap_deadend": [
            {"id": "protocol_hier", "desc": "tshark -qz io,phs → focus unusual protocols", "max": 1},
            {"id": "export_objects", "desc": "Export all objects: HTTP, FTP, SMB, TFTP", "max": 1},
            {"id": "dns_exfil", "desc": "Check DNS query names for encoded data", "max": 1},
            {"id": "tcp_streams", "desc": "Follow each TCP stream manually", "max": 1},
            {"id": "tls_keylog", "desc": "Check for keylog file in challenge files", "max": 1},
            {"id": "timing", "desc": "Timing analysis: unusual intervals → covert channel", "max": 1},
        ],
    },
    "web3": {
        "forge_failure": [
            {"id": "fix_pragma", "desc": "Fix Solidity syntax, check compiler version (pragma)", "max": 2},
            {"id": "fix_revert", "desc": "Read require() message, fix exploit logic", "max": 2},
            {"id": "increase_gas", "desc": "forge test --gas-limit 30000000", "max": 1},
            {"id": "fix_fork", "desc": "Check RPC_URL validity and block number", "max": 2},
            {"id": "fix_setup", "desc": "Verify setUp() deploys contracts in correct order", "max": 2},
        ],
        "vuln_misid": [
            {"id": "check_guards", "desc": "Re-read all modifiers: nonReentrant, onlyOwner, require()", "max": 1},
            {"id": "check_version", "desc": "Solidity <0.8 allows overflow, >=0.8 needs unchecked{}", "max": 1},
            {"id": "check_inherit", "desc": "Check inheritance chain for hidden functionality", "max": 1},
            {"id": "check_storage", "desc": "Proxy contracts: check storage slot collisions", "max": 1},
            {"id": "check_external", "desc": "Which external contracts are called and controllable?", "max": 1},
        ],
        "onchain_failure": [
            {"id": "gas_estimate", "desc": "cast estimate → use returned gas + 20%", "max": 2},
            {"id": "fix_nonce", "desc": "cast nonce <wallet> → correct nonce", "max": 1},
            {"id": "block_timing", "desc": "Check block.number dependency timing", "max": 2},
            {"id": "flashbots", "desc": "Use Flashbots bundle for MEV protection", "max": 1},
            {"id": "reread_state", "desc": "Re-read current state with cast call before retry", "max": 2},
        ],
    },
    "web-docker": {
        "docker_failure": [
            {"id": "test_endpoint", "desc": "Manual curl to vulnerable endpoint with simple payload", "max": 1},
            {"id": "fix_payload", "desc": "PAYLOAD WRONG: adjust encoding/escaping/content-type", "max": 3},
            {"id": "report_vuln_wrong", "desc": "VULN WRONG: FAIL to web agent with evidence", "max": 1},
            {"id": "fix_docker", "desc": "ENV ISSUE: fix Docker config and retry", "max": 2},
        ],
    },
    "verifier": {
        "retry_resolution": [
            {"id": "type_a_race", "desc": "TYPE A (Timing/Race): prescribe retry loop / sleep increase", "max": 1},
            {"id": "type_b_aslr", "desc": "TYPE B (ASLR Partial): run 16x, pass if >=4/16 (25%)", "max": 1},
            {"id": "type_c_flaky", "desc": "TYPE C (Environment): restart binary between runs", "max": 1},
            {"id": "reject_unchanged", "desc": "Same solve.py re-sent → FAIL (no re-verify)", "max": 1},
        ],
    },
}

# Framework-specific vulnerability priority (for web agent)
FRAMEWORK_VULN_PRIORITY = {
    "flask":   ["SSTI (Jinja2)", "Pickle deserialization", "SQLi", "SSRF", "Path traversal"],
    "django":  ["ORM injection", "SSTI (rare)", "SSRF", "Auth bypass"],
    "express": ["Prototype pollution", "SSRF", "NoSQLi", "SSTI (Pug/EJS)", "Path traversal"],
    "php":     ["LFI/RFI", "SQLi", "Deserialization", "Type juggling", "XXE"],
    "spring":  ["SpEL injection", "XXE", "Deserialization", "SSRF", "SQLi"],
    "go":      ["SSRF", "Template injection", "Path traversal", "Race condition"],
    "rails":   ["Deserialization", "SSTI (ERB)", "SQLi", "Mass assignment"],
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_next(args):
    agent = args.agent
    trigger = args.trigger
    context = json.loads(args.context) if args.context else {}

    if agent not in TREES or trigger not in TREES[agent]:
        print(json.dumps({"error": f"Unknown agent/trigger: {agent}/{trigger}"}), file=sys.stderr)
        sys.exit(2)

    conn = get_conn()
    actions = TREES[agent][trigger]

    for i, action in enumerate(actions):
        # Context filtering (e.g., glibc version)
        if "ctx" in action:
            ctx = action["ctx"]
            if "glibc_min" in ctx and context.get("glibc", "0") < ctx["glibc_min"]:
                continue
            if "glibc_max" in ctx and context.get("glibc", "99") >= ctx["glibc_max"]:
                continue
            if "e_max" in ctx and int(context.get("e", 99999)) > ctx["e_max"]:
                continue

        count = get_attempt_count(conn, agent, trigger, action["id"])
        if count < action["max"]:
            fallback = actions[i + 1]["id"] if i + 1 < len(actions) else "EXHAUSTED"
            total = get_total_failures(conn, agent)
            result = {
                "action": action["id"],
                "description": action["desc"],
                "attempt": count + 1,
                "max_attempts": action["max"],
                "fallback": fallback,
                "exhausted": False,
                "total_failures": total,
                "search_hint": None,
            }
            if total >= 5:
                result["search_hint"] = f"{agent} {trigger} writeup technique"
            print(json.dumps(result, indent=2))
            sys.exit(0)

    # All exhausted
    total = get_total_failures(conn, agent)
    result = {
        "action": "FAIL",
        "description": f"All {len(actions)} methods exhausted for {trigger}",
        "exhausted": True,
        "total_failures": total,
        "search_hint": f"{agent} {trigger} alternative approach writeup",
    }
    print(json.dumps(result, indent=2))
    sys.exit(1)


def cmd_record(args):
    conn = get_conn()
    count = get_attempt_count(conn, args.agent, args.trigger, args.action_id)
    set_attempt_count(conn, args.agent, args.trigger, args.action_id, count + 1)
    print(json.dumps({
        "recorded": True,
        "agent": args.agent,
        "trigger": args.trigger,
        "action_id": args.action_id,
        "attempts": count + 1,
    }))


def cmd_status(args):
    conn = get_conn()
    agent = args.agent
    if agent not in TREES:
        print(json.dumps({"error": f"Unknown agent: {agent}"}), file=sys.stderr)
        sys.exit(2)

    status = {"agent": agent, "triggers": {}}
    for trigger, actions in TREES[agent].items():
        trigger_status = []
        for action in actions:
            count = get_attempt_count(conn, agent, trigger, action["id"])
            trigger_status.append({
                "id": action["id"],
                "attempts": count,
                "max": action["max"],
                "exhausted": count >= action["max"],
            })
        status["triggers"][trigger] = trigger_status
    status["total_failures"] = get_total_failures(conn, agent)
    print(json.dumps(status, indent=2))


def cmd_reset(args):
    conn = get_conn()
    conn.execute("DELETE FROM facts WHERE key LIKE ?", (f"dt_{args.agent}_%",))
    conn.commit()
    print(json.dumps({"reset": True, "agent": args.agent}))


def cmd_vuln_priority(args):
    """Return framework-specific vulnerability priority list."""
    fw = args.framework.lower()
    if fw in FRAMEWORK_VULN_PRIORITY:
        print(json.dumps({"framework": fw, "priority": FRAMEWORK_VULN_PRIORITY[fw]}))
    else:
        print(json.dumps({"framework": fw, "priority": [], "note": "Unknown framework, check manually"}))


def cmd_list(args):
    """List available triggers for an agent."""
    agent = args.agent
    if agent not in TREES:
        print(json.dumps({"error": f"Unknown agent: {agent}"}), file=sys.stderr)
        sys.exit(2)
    triggers = list(TREES[agent].keys())
    print(json.dumps({"agent": agent, "triggers": triggers}))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Machine CTF Decision Tree Engine")
    sub = p.add_subparsers(dest="cmd", required=True)

    # next
    s = sub.add_parser("next", help="Get next action for a failure trigger")
    s.add_argument("--agent", required=True)
    s.add_argument("--trigger", required=True)
    s.add_argument("--context", default=None, help="JSON context (e.g., glibc version)")

    # record
    s = sub.add_parser("record", help="Record a failure attempt")
    s.add_argument("--agent", required=True)
    s.add_argument("--trigger", required=True)
    s.add_argument("--action-id", required=True)

    # status
    s = sub.add_parser("status", help="Show failure state for an agent")
    s.add_argument("--agent", required=True)

    # reset
    s = sub.add_parser("reset", help="Clear failure tracking for an agent")
    s.add_argument("--agent", required=True)

    # vuln-priority
    s = sub.add_parser("vuln-priority", help="Get vulnerability priority for a web framework")
    s.add_argument("--framework", required=True)

    # list
    s = sub.add_parser("list", help="List available triggers for an agent")
    s.add_argument("--agent", required=True)

    args = p.parse_args()
    dispatch = {
        "next": cmd_next,
        "record": cmd_record,
        "status": cmd_status,
        "reset": cmd_reset,
        "vuln-priority": cmd_vuln_priority,
        "list": cmd_list,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
