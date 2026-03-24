#!/usr/bin/env python3
"""Quality Gate — CTF pipeline gate.

Blocks pipeline transitions with exit codes. Exit 0 = PASS, Exit 1 = FAIL.

CTF Gates:
    quality_gate.py ctf-verify <challenge_dir> [--json]
    quality_gate.py artifact-check <challenge_dir> --stage <critic|verifier|reporter> [--json]

Exit: 0=PASS, 1=FAIL
Created: 2026-03-22 (Machine CTF quality gate)
"""

import argparse
import json
import sqlite3
import subprocess
import sys
from pathlib import Path


# =============================================================================
# Utility
# =============================================================================

def _result(passed: bool, msg: str, details: dict = None, json_output: bool = False):
    """Print result and return exit code."""
    status = "PASS" if passed else "FAIL"
    if json_output:
        out = {"result": status, "message": msg}
        if details:
            out.update(details)
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"{status}: {msg}")
    return 0 if passed else 1


# =============================================================================
# CTF Gates
# =============================================================================

def ctf_verify(challenge_dir: str, json_output: bool = False) -> int:
    """CTF pipeline verification gate.

    Checks:
    1. checkpoint.json exists and status == "completed"
    2. state.db exists and has verified facts
    3. solve.py exists and is non-empty
    """
    cdir = Path(challenge_dir)
    checks = {}
    all_pass = True

    # --- Check 1: checkpoint.json ---
    cp_path = cdir / "checkpoint.json"
    if not cp_path.exists():
        checks["checkpoint"] = {"pass": False, "reason": "checkpoint.json 없음 — 에이전트가 시작되지 않았거나 checkpoint를 기록하지 않음"}
        all_pass = False
    else:
        try:
            cp_data = json.loads(cp_path.read_text())
            status = cp_data.get("status", "unknown")
            if status == "completed":
                checks["checkpoint"] = {"pass": True, "reason": f"status={status}"}
            else:
                checks["checkpoint"] = {"pass": False, "reason": f"status={status} — 'completed' 필요"}
                all_pass = False
        except (json.JSONDecodeError, OSError) as e:
            checks["checkpoint"] = {"pass": False, "reason": f"checkpoint.json 파싱 실패: {e}"}
            all_pass = False

    # --- Check 2: state.db with verified facts ---
    db_path = cdir / "state.db"
    if not db_path.exists():
        checks["state_db"] = {"pass": False, "reason": "state.db 없음 — state.py로 fact 기록 필요"}
        all_pass = False
    else:
        try:
            conn = sqlite3.connect(str(db_path))
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='facts'")
            if not cur.fetchone():
                checks["state_db"] = {"pass": False, "reason": "state.db에 facts 테이블 없음"}
                all_pass = False
            else:
                cur.execute("SELECT COUNT(*) FROM facts WHERE src IS NOT NULL AND src != ''")
                verified_count = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM facts")
                total_count = cur.fetchone()[0]
                if verified_count > 0:
                    checks["state_db"] = {"pass": True, "reason": f"verified facts: {verified_count}/{total_count}"}
                else:
                    checks["state_db"] = {"pass": False, "reason": f"verified facts 없음 (total: {total_count}) — --src 옵션으로 fact 기록 필요"}
                    all_pass = False
            conn.close()
        except (sqlite3.Error, OSError) as e:
            checks["state_db"] = {"pass": False, "reason": f"state.db 읽기 실패: {e}"}
            all_pass = False

    # --- Check 3: solve.py ---
    solve_path = cdir / "solve.py"
    if not solve_path.exists():
        checks["solve_script"] = {"pass": False, "reason": "solve.py 없음"}
        all_pass = False
    else:
        size = solve_path.stat().st_size
        if size == 0:
            checks["solve_script"] = {"pass": False, "reason": "solve.py가 비어 있음 (0 bytes)"}
            all_pass = False
        else:
            checks["solve_script"] = {"pass": True, "reason": f"solve.py exists ({size} bytes)"}

    # --- Output ---
    if json_output:
        print(json.dumps({"result": "PASS" if all_pass else "FAIL", "checks": checks}, indent=2, ensure_ascii=False))
    else:
        for name, info in checks.items():
            status = "PASS" if info["pass"] else "FAIL"
            print(f"  [{status}] {name}: {info['reason']}")
        print()
        if all_pass:
            print(f"PASS: CTF verification — all checks passed for {challenge_dir}")
        else:
            failed = [k for k, v in checks.items() if not v["pass"]]
            print(f"FAIL: CTF verification — {len(failed)} check(s) failed: {', '.join(failed)}")

    return 0 if all_pass else 1


def artifact_check(challenge_dir: str, stage: str, json_output: bool = False) -> int:
    """Check required artifacts exist for a given pipeline stage.

    Stages:
    - critic: requires solve.py (or forensics_report.md or Exploit.t.sol)
    - verifier: requires solve.py + critic_review.md with "APPROVED"
    - reporter: requires verification_report.md (or flag evidence)
    """
    cdir = Path(challenge_dir)
    missing = []
    details = {}

    if stage == "critic":
        primary_artifacts = ["solve.py", "forensics_report.md", "Exploit.t.sol"]
        found = [a for a in primary_artifacts if (cdir / a).exists() and (cdir / a).stat().st_size > 0]
        if not found:
            missing.append(f"하나 이상 필요: {', '.join(primary_artifacts)}")
        details["found_artifacts"] = found

        # Auto-run payload_check on solve.py if it exists (catches JS bugs before critic)
        solve_path = cdir / "solve.py"
        if solve_path.exists() and solve_path.stat().st_size > 0:
            payload_checker = Path(__file__).parent / "payload_check.py"
            if payload_checker.exists():
                try:
                    result = subprocess.run(
                        [sys.executable, str(payload_checker),
                         "--extract", str(solve_path),
                         "--check-syntax", "--check-sideeffects", "--json"],
                        capture_output=True, text=True, timeout=10
                    )
                    pc_data = json.loads(result.stdout) if result.stdout.strip() else {}
                    error_count = pc_data.get("error_count", 0)
                    if error_count > 0:
                        findings_summary = []
                        for f in pc_data.get("findings", []):
                            if f.get("severity") == "ERROR":
                                findings_summary.append(f"[{f['check']}] {f['message']}")
                        missing.append(
                            f"payload_check FAIL: {error_count} JS error(s) in solve.py — "
                            + "; ".join(findings_summary[:3])
                        )
                        details["payload_check"] = "FAIL"
                    else:
                        details["payload_check"] = "PASS"
                except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
                    details["payload_check"] = "SKIP (error running checker)"

    elif stage == "verifier":
        primary_artifacts = ["solve.py", "forensics_report.md", "Exploit.t.sol"]
        found = [a for a in primary_artifacts if (cdir / a).exists() and (cdir / a).stat().st_size > 0]
        if not found:
            missing.append(f"solve script 필요: {', '.join(primary_artifacts)}")
        details["found_artifacts"] = found

        critic_path = cdir / "critic_review.md"
        if not critic_path.exists():
            missing.append("critic_review.md 없음 — critic 에이전트 먼저 실행 필요")
        else:
            content = critic_path.read_text(errors="replace")
            if "APPROVED" not in content.upper():
                missing.append("critic_review.md에 'APPROVED' 없음 — critic가 승인하지 않음")
                details["critic_status"] = "NOT APPROVED"
            else:
                details["critic_status"] = "APPROVED"

    elif stage == "reporter":
        vr_path = cdir / "verification_report.md"
        flag_evidence = any(
            (cdir / f).exists()
            for f in ["flag.txt", "flag_captured.txt", "remote_output.txt"]
        )
        if not vr_path.exists() and not flag_evidence:
            missing.append("verification_report.md 또는 flag evidence 파일 필요")
        details["has_verification_report"] = vr_path.exists()
        details["has_flag_evidence"] = flag_evidence

    else:
        print(f"FAIL: Unknown stage '{stage}' — critic, verifier, reporter 중 선택")
        return 1

    passed = len(missing) == 0

    if json_output:
        print(json.dumps({
            "result": "PASS" if passed else "FAIL",
            "stage": stage,
            "missing": missing,
            "details": details,
        }, indent=2, ensure_ascii=False))
    else:
        if passed:
            print(f"PASS: artifact-check [{stage}] — all required artifacts present")
        else:
            print(f"FAIL: artifact-check [{stage}] — missing artifacts:")
            for m in missing:
                print(f"  → {m}")

    return 0 if passed else 1


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Quality Gate — CTF pipeline gate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    subparsers = parser.add_subparsers(dest="command", help="Gate subcommand")

    p_ctf = subparsers.add_parser("ctf-verify", help="CTF pipeline verification gate")
    p_ctf.add_argument("challenge_dir", help="Challenge directory path")
    p_ctf.add_argument("--json", action="store_true", dest="json_output", help="JSON output")

    p_art = subparsers.add_parser("artifact-check", help="Check artifacts for pipeline stage")
    p_art.add_argument("challenge_dir", help="Challenge directory path")
    p_art.add_argument("--stage", required=True, choices=["critic", "verifier", "reporter"],
                       help="Pipeline stage")
    p_art.add_argument("--json", action="store_true", dest="json_output", help="JSON output")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "ctf-verify":
        sys.exit(ctf_verify(args.challenge_dir, args.json_output))
    elif args.command == "artifact-check":
        sys.exit(artifact_check(args.challenge_dir, args.stage, args.json_output))


if __name__ == "__main__":
    main()
