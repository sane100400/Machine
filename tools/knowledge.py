#!/usr/bin/env python3
"""
Machine CTF Knowledge Base
===========================
SQLite FTS5 기반 자체 지식 검색 시스템.
knowledge/techniques/*.md 를 청크로 분할 → FTS5 인덱싱 → 에이전트가 언제든 검색.

Usage:
  knowledge.py index                        # 인덱스 빌드/재빌드
  knowledge.py search "<query>" [--top N]   # 검색 (기본 top 5)
  knowledge.py status                       # 인덱스 현황
  knowledge.py add <file.md>                # 단일 파일 추가/갱신
"""

import argparse
import hashlib
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

MACHINE_ROOT = Path(__file__).resolve().parent.parent
TECHNIQUES_DIR = MACHINE_ROOT / "knowledge" / "techniques"
CHALLENGES_DIR = MACHINE_ROOT / "knowledge" / "challenges"
KB_PATH = MACHINE_ROOT / "knowledge" / "kb.db"

CHUNK_SIZE = 40       # 청크당 최대 줄 수
CHUNK_OVERLAP = 5     # 청크 간 오버랩 줄 수
DEFAULT_TOP = 5


# ── DB 초기화 ────────────────────────────────────────────────────────────────

def get_conn() -> sqlite3.Connection:
    KB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(KB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS sources (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            path     TEXT NOT NULL UNIQUE,
            sha256   TEXT NOT NULL,
            indexed  TEXT NOT NULL
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS chunks USING fts5(
            source_path,
            heading,
            body,
            tokenize = "unicode61 remove_diacritics 1"
        );
    """)
    conn.commit()
    return conn


# ── 파일 파싱 & 청킹 ─────────────────────────────────────────────────────────

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_chunks(path: Path) -> list[dict]:
    """MD 파일을 헤딩 기준으로 섹션 분리 후 줄 단위 청킹."""
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    # 헤딩 기준 섹션 분리
    sections: list[tuple[str, list[str]]] = []
    current_heading = path.stem
    current_lines: list[str] = []

    for line in lines:
        m = re.match(r'^(#{1,4})\s+(.+)', line)
        if m:
            if current_lines:
                sections.append((current_heading, current_lines))
            current_heading = m.group(2).strip()
            current_lines = []
        else:
            current_lines.append(line)
    if current_lines:
        sections.append((current_heading, current_lines))

    # 섹션을 CHUNK_SIZE 줄 단위로 청킹
    chunks = []
    for heading, sec_lines in sections:
        # 빈 섹션 스킵
        content = [l for l in sec_lines if l.strip()]
        if not content:
            continue

        i = 0
        while i < len(content):
            chunk_lines = content[i:i + CHUNK_SIZE]
            body = "\n".join(chunk_lines).strip()
            if body:
                chunks.append({
                    "source_path": str(path.relative_to(MACHINE_ROOT)),
                    "heading": heading,
                    "body": body,
                })
            i += max(1, CHUNK_SIZE - CHUNK_OVERLAP)

    return chunks


# ── 인덱싱 ───────────────────────────────────────────────────────────────────

def index_file(conn: sqlite3.Connection, path: Path, force: bool = False) -> int:
    """파일 하나를 인덱싱. 변경 없으면 스킵. 추가된 청크 수 반환."""
    digest = sha256(path)
    rel = str(path.relative_to(MACHINE_ROOT))
    now = datetime.now(timezone.utc).isoformat()

    row = conn.execute("SELECT sha256 FROM sources WHERE path=?", (rel,)).fetchone()
    if row and row["sha256"] == digest and not force:
        return 0  # 변경 없음

    # 기존 청크 삭제
    conn.execute("DELETE FROM chunks WHERE source_path=?", (rel,))

    chunks = parse_chunks(path)
    conn.executemany(
        "INSERT INTO chunks (source_path, heading, body) VALUES (?,?,?)",
        [(c["source_path"], c["heading"], c["body"]) for c in chunks],
    )
    conn.execute(
        "INSERT OR REPLACE INTO sources (path, sha256, indexed) VALUES (?,?,?)",
        (rel, digest, now),
    )
    conn.commit()
    return len(chunks)


def cmd_index(args):
    conn = get_conn()
    dirs = [TECHNIQUES_DIR, CHALLENGES_DIR]
    total_files = 0
    total_chunks = 0

    for d in dirs:
        if not d.exists():
            continue
        for path in sorted(d.glob("*.md")):
            n = index_file(conn, path, force=getattr(args, "force", False))
            if n > 0:
                print(f"  indexed {path.name} → {n} chunks")
                total_files += 1
                total_chunks += n

    if total_files == 0:
        print("[knowledge] 모든 파일이 최신 상태 (변경 없음)")
    else:
        print(f"[knowledge] {total_files}개 파일, {total_chunks}개 청크 인덱싱 완료")
    print(f"  DB: {KB_PATH}")


def cmd_add(args):
    path = Path(args.file).resolve()
    if not path.exists():
        print(f"[knowledge] ERROR: 파일 없음: {path}", file=sys.stderr)
        sys.exit(1)
    conn = get_conn()
    n = index_file(conn, path, force=True)
    print(f"[knowledge] {path.name} → {n} chunks 인덱싱")


# ── 검색 ─────────────────────────────────────────────────────────────────────

def cmd_search(args):
    conn = get_conn()
    query = args.query.strip()
    top = args.top

    # FTS5 match 쿼리: 각 토큰을 prefix 검색으로 변환
    tokens = re.findall(r'\w+', query)
    if not tokens:
        print("[]")
        return

    fts_query = " OR ".join(f'"{t}"*' for t in tokens)

    rows = conn.execute(
        """
        SELECT source_path, heading, body,
               rank
        FROM chunks
        WHERE chunks MATCH ?
        ORDER BY rank
        LIMIT ?
        """,
        (fts_query, top),
    ).fetchall()

    if not rows:
        # fallback: 단순 LIKE 검색
        like = f"%{query}%"
        rows = conn.execute(
            """
            SELECT source_path, heading, body, 0 as rank
            FROM chunks
            WHERE heading LIKE ? OR body LIKE ?
            LIMIT ?
            """,
            (like, like, top),
        ).fetchall()

    if not rows:
        print(f"[knowledge] 검색 결과 없음: {query!r}", file=sys.stderr)
        print("  → WebSearch로 폴백 권장", file=sys.stderr)
        sys.exit(1)

    # 출력
    results = []
    for r in rows:
        results.append({
            "source": r["source_path"],
            "heading": r["heading"],
            "snippet": r["body"][:600],
        })

    # 에이전트가 읽기 좋은 텍스트 포맷
    out_lines = [f"[knowledge search: {query!r} — top {len(results)}]"]
    for i, res in enumerate(results, 1):
        out_lines.append(f"\n--- {i}. {res['source']} § {res['heading']} ---")
        out_lines.append(res["snippet"])

    print("\n".join(out_lines))


# ── 상태 ─────────────────────────────────────────────────────────────────────

def cmd_status(args):
    if not KB_PATH.exists():
        print("[knowledge] 인덱스 없음 — `knowledge.py index` 실행 필요")
        return

    conn = get_conn()
    sources = conn.execute("SELECT path, indexed FROM sources ORDER BY path").fetchall()
    chunk_count = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]

    print(f"[knowledge] DB: {KB_PATH}")
    print(f"  파일: {len(sources)}개 | 청크: {chunk_count}개")
    print()
    for s in sources:
        print(f"  {s['path']}")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Machine CTF Knowledge Base (FTS5)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("index", help="인덱스 빌드/갱신").add_argument(
        "--force", action="store_true", help="변경 여부 무시하고 강제 재인덱싱"
    )

    p_search = sub.add_parser("search", help="지식 검색")
    p_search.add_argument("query", help="검색어")
    p_search.add_argument("--top", type=int, default=DEFAULT_TOP, metavar="N")

    sub.add_parser("status", help="인덱스 현황")

    p_add = sub.add_parser("add", help="단일 파일 추가/갱신")
    p_add.add_argument("file", help="MD 파일 경로")

    args = parser.parse_args()
    {"index": cmd_index, "search": cmd_search, "status": cmd_status, "add": cmd_add}[args.cmd](args)


if __name__ == "__main__":
    main()
