#!/usr/bin/env python3
"""
Machine CTF Knowledge Base
===========================
SQLite FTS5 기반 자체 지식 검색 시스템.
knowledge/techniques/*.md 를 청크로 분할 → FTS5 인덱싱 → 에이전트가 언제든 검색.

External sources: ExploitDB, Nuclei templates, PoC-in-GitHub, PayloadsAllTheThings.

Usage:
  knowledge.py index                        # 인덱스 빌드/갱신
  knowledge.py search "<query>" [--top N]   # 검색 (기본 top 5)
  knowledge.py status                       # 인덱스 현황
  knowledge.py add <file.md>                # 단일 파일 추가/갱신
  knowledge.py index-external [--force]     # 외부 소스 인덱싱
  knowledge.py search-all "<query>" [--top N]  # 전체 테이블 통합 검색
  knowledge.py search-exploits "<query>" [--top N]  # exploit/CVE 전용 검색
  knowledge.py stats                        # 상세 통계
"""

import argparse
import csv
import hashlib
import json
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
HOME = Path.home()

CHUNK_SIZE = 40       # 청크당 최대 줄 수
CHUNK_OVERLAP = 5     # 청크 간 오버랩 줄 수
DEFAULT_TOP = 5
BATCH_SIZE = 1000     # batch insert size
MAX_FILE_BYTES = 50 * 1024  # 50KB cap for large external files


# ── Synonym Expansion ────────────────────────────────────────────────────────

SYNONYMS = {
    "uaf": '"use" "after" "free"',
    "bof": '"buffer" "overflow"',
    "rce": '"remote" "code" "execution"',
    "sqli": '"sql" "injection"',
    "xss": '"cross" "site" "scripting"',
    "ssrf": '"server" "side" "request" "forgery"',
    "ssti": '"server" "side" "template" "injection"',
    "lfi": '"local" "file" "inclusion"',
    "rfi": '"remote" "file" "inclusion"',
    "idor": '"insecure" "direct" "object" "reference"',
    "xxe": '"xml" "external" "entity"',
    "csrf": '"cross" "site" "request" "forgery"',
    "rop": '"return" "oriented" "programming"',
    "fsop": '"file" "stream" "oriented" "programming"',
    "got": '"global" "offset" "table"',
    "plt": '"procedure" "linkage" "table"',
}


def expand_query(query: str) -> str:
    """Build FTS5 query with synonym expansion, CVE/CWE exact match."""
    q = query.strip()
    if not q:
        return q

    # CVE exact match
    if re.match(r'^CVE-\d{4}-\d{4,}$', q, re.IGNORECASE):
        return f'"{q}"'

    # CWE exact match
    if re.match(r'^CWE-\d+$', q, re.IGNORECASE):
        return f'"{q}"'

    # Whole-query synonym match
    q_lower = q.lower().strip()
    if q_lower in SYNONYMS:
        original = f'"{q_lower}"'
        expanded = SYNONYMS[q_lower]
        return f'{original} OR ({expanded})'

    # Per-token expansion
    tokens = re.findall(r'\w+', q)
    if not tokens:
        return q

    parts = []
    for t in tokens:
        t_lower = t.lower()
        if t_lower in SYNONYMS:
            parts.append(f'({SYNONYMS[t_lower]})')
        else:
            parts.append(f'"{t}"*')

    return " OR ".join(parts)


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

        CREATE VIRTUAL TABLE IF NOT EXISTS exploitdb USING fts5(
            edb_id, platform, description, path,
            tokenize = "unicode61 remove_diacritics 1"
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS nuclei USING fts5(
            template_id, name, severity, description, tags,
            tokenize = "unicode61 remove_diacritics 1"
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS poc_github USING fts5(
            cve_id, description, github_url,
            tokenize = "unicode61 remove_diacritics 1"
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS external_techniques USING fts5(
            source_path, heading, body,
            tokenize = "unicode61 remove_diacritics 1"
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS cisa_kev USING fts5(
            cve_id, vendor, product, vulnerability_name, description,
            date_added, due_date, known_ransomware,
            tokenize = "unicode61 remove_diacritics 1"
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS cve_db USING fts5(
            cve_id, state, date_published, description,
            affected_products, cvss_score, cwe_ids,
            tokenize = "unicode61 remove_diacritics 1"
        );
    """)
    conn.commit()
    return conn


# ── 파일 파싱 & 청킹 ─────────────────────────────────────────────────────────

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_chunks(path: Path, base_root: Path = None) -> list[dict]:
    """MD 파일을 헤딩 기준으로 섹션 분리 후 줄 단위 청킹."""
    if base_root is None:
        base_root = MACHINE_ROOT

    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            text = path.read_text(encoding="utf-8", errors="replace")[:MAX_FILE_BYTES]
        else:
            text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return []

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
    try:
        rel_path = str(path.relative_to(base_root))
    except ValueError:
        rel_path = str(path)

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
                    "source_path": rel_path,
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


# ── External Indexing ─────────────────────────────────────────────────────────

def _index_exploitdb(conn: sqlite3.Connection) -> int:
    """Index ExploitDB CSV from ~/exploitdb/files_exploits.csv."""
    csv_path = HOME / "exploitdb" / "files_exploits.csv"
    if not csv_path.exists():
        print(f"[index-external] WARNING: ExploitDB not found at {csv_path}, skipping")
        return 0

    conn.execute("DELETE FROM exploitdb")
    count = 0
    batch = []

    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            edb_id = row.get("id", "").strip()
            platform = row.get("platform", "").strip()
            description = row.get("description", "").strip()
            file_path = row.get("file", "").strip()

            if not edb_id or not description:
                continue

            batch.append((edb_id, platform, description, file_path))
            if len(batch) >= BATCH_SIZE:
                conn.executemany(
                    "INSERT INTO exploitdb (edb_id, platform, description, path) VALUES (?,?,?,?)",
                    batch,
                )
                count += len(batch)
                batch = []

    if batch:
        conn.executemany(
            "INSERT INTO exploitdb (edb_id, platform, description, path) VALUES (?,?,?,?)",
            batch,
        )
        count += len(batch)

    conn.commit()
    print(f"  exploitdb: {count} entries indexed")
    return count


def _parse_nuclei_yaml(text: str) -> dict:
    """Parse nuclei template YAML using regex (zero-dep)."""
    def extract(pattern: str) -> str:
        m = re.search(pattern, text, re.MULTILINE)
        return m.group(1).strip() if m else ""

    tid = extract(r"^id:\s*(.+)$")
    name = extract(r"^\s*name:\s*(.+)$")
    severity = extract(r"^\s*severity:\s*(.+)$")
    tags = extract(r"^\s*tags:\s*(.+)$")

    # description: can be inline or multi-line block scalar
    desc_match = re.search(
        r"^\s*description:\s*[|>]\s*\n((?:\s{4,}.+\n?)+)", text, re.MULTILINE
    )
    if desc_match:
        lines = desc_match.group(1).split("\n")
        description = "\n".join(l.strip() for l in lines).strip()
    else:
        description = extract(r"^\s*description:\s*(.+)$")

    return {
        "template_id": tid,
        "name": name,
        "severity": severity,
        "description": description,
        "tags": tags,
    }


def _index_nuclei(conn: sqlite3.Connection) -> int:
    """Index Nuclei templates from ~/nuclei-templates/."""
    templates_dir = HOME / "nuclei-templates"
    if not templates_dir.is_dir():
        print(f"[index-external] WARNING: Nuclei templates not found at {templates_dir}, skipping")
        return 0

    conn.execute("DELETE FROM nuclei")
    count = 0
    batch = []

    for yaml_path in sorted(templates_dir.glob("**/*.yaml")):
        try:
            size = yaml_path.stat().st_size
            if size > MAX_FILE_BYTES:
                continue
            text = yaml_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            continue

        parsed = _parse_nuclei_yaml(text)
        if not parsed["template_id"]:
            continue

        batch.append((
            parsed["template_id"],
            parsed["name"],
            parsed["severity"],
            parsed["description"],
            parsed["tags"],
        ))

        if len(batch) >= BATCH_SIZE:
            conn.executemany(
                "INSERT INTO nuclei (template_id, name, severity, description, tags) VALUES (?,?,?,?,?)",
                batch,
            )
            count += len(batch)
            batch = []

    if batch:
        conn.executemany(
            "INSERT INTO nuclei (template_id, name, severity, description, tags) VALUES (?,?,?,?,?)",
            batch,
        )
        count += len(batch)

    conn.commit()
    print(f"  nuclei: {count} entries indexed")
    return count


def _index_poc_github(conn: sqlite3.Connection) -> int:
    """Index PoC-in-GitHub from ~/PoC-in-GitHub/."""
    poc_dir = HOME / "PoC-in-GitHub"
    if not poc_dir.is_dir():
        print(f"[index-external] WARNING: PoC-in-GitHub not found at {poc_dir}, skipping")
        return 0

    conn.execute("DELETE FROM poc_github")
    count = 0
    batch = []

    for json_path in sorted(poc_dir.glob("**/*.json")):
        try:
            text = json_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(text)
        except (OSError, PermissionError, json.JSONDecodeError):
            continue

        # PoC-in-GitHub JSON files can be a list of entries or a single dict
        if isinstance(data, dict):
            entries = [data]
        elif isinstance(data, list):
            entries = data
        else:
            continue

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            # Extract CVE ID from filename or entry
            cve_id = entry.get("cve_id", "") or entry.get("id", "")
            if not cve_id:
                # Try extracting from filename (e.g., CVE-2021-12345.json)
                stem = json_path.stem
                if re.match(r'CVE-\d{4}-\d+', stem, re.IGNORECASE):
                    cve_id = stem

            description = entry.get("description", "") or entry.get("name", "")
            github_url = entry.get("html_url", "") or entry.get("github_url", "") or entry.get("url", "")

            if not cve_id and not description:
                continue

            batch.append((str(cve_id), str(description), str(github_url)))

            if len(batch) >= BATCH_SIZE:
                conn.executemany(
                    "INSERT INTO poc_github (cve_id, description, github_url) VALUES (?,?,?)",
                    batch,
                )
                count += len(batch)
                batch = []

    if batch:
        conn.executemany(
            "INSERT INTO poc_github (cve_id, description, github_url) VALUES (?,?,?)",
            batch,
        )
        count += len(batch)

    conn.commit()
    print(f"  poc_github: {count} entries indexed")
    return count


def _index_md_repo(conn: sqlite3.Connection, repo_dir: Path, repo_name: str,
                   table: str = "external_techniques", skip_readmes: bool = True) -> int:
    """Index markdown files from a repo directory into an FTS5 table.
    source_path is prefixed with repo_name for identification."""
    if not repo_dir.is_dir():
        print(f"[index-external] WARNING: {repo_name} not found at {repo_dir}, skipping")
        return 0

    count = 0
    batch = []

    for md_path in sorted(repo_dir.glob("**/*.md")):
        try:
            rel = md_path.relative_to(repo_dir)
        except ValueError:
            continue
        # Skip root-level READMEs and common non-content files
        rel_str = str(rel)
        if skip_readmes and rel_str in ("README.md", "CONTRIBUTING.md", "DISCLAIMER.md", "LICENSE.md"):
            continue

        chunks = parse_chunks(md_path, base_root=repo_dir)
        for c in chunks:
            # Prefix source_path with repo name for identification
            prefixed_path = f"[{repo_name}] {c['source_path']}"
            batch.append((prefixed_path, c["heading"], c["body"]))

            if len(batch) >= BATCH_SIZE:
                conn.executemany(
                    f"INSERT INTO {table} (source_path, heading, body) VALUES (?,?,?)",
                    batch,
                )
                count += len(batch)
                batch = []

    if batch:
        conn.executemany(
            f"INSERT INTO {table} (source_path, heading, body) VALUES (?,?,?)",
            batch,
        )
        count += len(batch)

    conn.commit()
    print(f"  {repo_name}: {count} entries indexed")
    return count


# All external MD repos to index
EXTERNAL_MD_REPOS = [
    ("PayloadsAllTheThings", HOME / "PayloadsAllTheThings"),
    ("HackTricks",          HOME / "HackTricks"),
    ("ctf-wiki",            HOME / "ctf-wiki"),
    ("pwn-notes",           HOME / "pwn-notes"),
    ("p4-ctf",              HOME / "p4-ctf"),
]


def _index_external_techniques(conn: sqlite3.Connection) -> int:
    """Index all external MD repos into external_techniques table."""
    conn.execute("DELETE FROM external_techniques")
    total = 0
    for repo_name, repo_dir in EXTERNAL_MD_REPOS:
        total += _index_md_repo(conn, repo_dir, repo_name)
    print(f"  external_techniques total: {total} entries")
    return total


def _index_cisa_kev(conn: sqlite3.Connection) -> int:
    """Index CISA Known Exploited Vulnerabilities catalog."""
    kev_path = HOME / "cve-data" / "kev.json"
    if not kev_path.exists():
        print(f"[index-external] WARNING: CISA KEV not found at {kev_path}, skipping")
        return 0

    conn.execute("DELETE FROM cisa_kev")
    count = 0
    batch = []

    with open(kev_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for entry in data.get("vulnerabilities", []):
        cve_id = entry.get("cveID", "")
        vendor = entry.get("vendorProject", "")
        product = entry.get("product", "")
        vuln_name = entry.get("vulnerabilityName", "")
        description = entry.get("shortDescription", "")
        date_added = entry.get("dateAdded", "")
        due_date = entry.get("dueDate", "")
        ransomware = entry.get("knownRansomwareCampaignUse", "")

        if not cve_id:
            continue

        batch.append((cve_id, vendor, product, vuln_name, description,
                       date_added, due_date, ransomware))

        if len(batch) >= BATCH_SIZE:
            conn.executemany(
                "INSERT INTO cisa_kev (cve_id, vendor, product, vulnerability_name, "
                "description, date_added, due_date, known_ransomware) VALUES (?,?,?,?,?,?,?,?)",
                batch,
            )
            count += len(batch)
            batch = []

    if batch:
        conn.executemany(
            "INSERT INTO cisa_kev (cve_id, vendor, product, vulnerability_name, "
            "description, date_added, due_date, known_ransomware) VALUES (?,?,?,?,?,?,?,?)",
            batch,
        )
        count += len(batch)

    conn.commit()
    print(f"  cisa_kev: {count} entries indexed")
    return count


def _parse_cve_json(data: dict) -> dict | None:
    """Parse a single CVE record from cvelistV5 JSON format."""
    cve_meta = data.get("cveMetadata", {})
    cve_id = cve_meta.get("cveId", "")
    state = cve_meta.get("state", "")
    date_published = cve_meta.get("datePublished", "")

    if not cve_id:
        return None

    # Extract description (English preferred)
    containers = data.get("containers", {})
    cna = containers.get("cna", {})
    descriptions = cna.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang", "").startswith("en"):
            description = desc.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    # Extract affected products
    affected = cna.get("affected", [])
    affected_parts = []
    for a in affected[:5]:  # Limit to avoid huge strings
        vendor = a.get("vendor", "")
        product = a.get("product", "")
        versions = a.get("versions", [])
        ver_str = ""
        if versions:
            v0 = versions[0]
            ver_str = v0.get("version", "")
            less_than = v0.get("lessThan", "")
            if less_than:
                ver_str = f"{ver_str} - {less_than}"
        if vendor and product:
            affected_parts.append(f"{vendor}/{product} {ver_str}".strip())
    affected_str = "; ".join(affected_parts)

    # Extract CVSS score
    metrics = cna.get("metrics", [])
    cvss_score = ""
    for m in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
            if key in m:
                score = m[key].get("baseScore", "")
                severity = m[key].get("baseSeverity", "")
                if score:
                    cvss_score = f"{score} ({severity})" if severity else str(score)
                    break
        if cvss_score:
            break

    # Extract CWE IDs
    problem_types = cna.get("problemTypes", [])
    cwe_ids = []
    for pt in problem_types:
        for desc in pt.get("descriptions", []):
            cwe_id = desc.get("cweId", "")
            if cwe_id:
                cwe_ids.append(cwe_id)
    cwe_str = ", ".join(cwe_ids)

    return {
        "cve_id": cve_id,
        "state": state,
        "date_published": date_published[:10] if date_published else "",
        "description": description[:2000],  # Cap description length
        "affected_products": affected_str,
        "cvss_score": cvss_score,
        "cwe_ids": cwe_str,
    }


def _index_cve_db(conn: sqlite3.Connection) -> int:
    """Index cvelistV5 JSON files into cve_db table."""
    cve_dir = HOME / "cvelistV5" / "cves"
    if not cve_dir.is_dir():
        print(f"[index-external] WARNING: cvelistV5 not found at {cve_dir}, skipping")
        return 0

    conn.execute("DELETE FROM cve_db")
    count = 0
    batch = []
    errors = 0

    for json_path in sorted(cve_dir.glob("**/*.json")):
        try:
            text = json_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(text)
        except (OSError, json.JSONDecodeError):
            errors += 1
            continue

        if isinstance(data, list):
            continue  # skip non-standard files
        parsed = _parse_cve_json(data)
        if not parsed:
            continue

        batch.append((
            parsed["cve_id"], parsed["state"], parsed["date_published"],
            parsed["description"], parsed["affected_products"],
            parsed["cvss_score"], parsed["cwe_ids"],
        ))

        if len(batch) >= BATCH_SIZE:
            conn.executemany(
                "INSERT INTO cve_db (cve_id, state, date_published, description, "
                "affected_products, cvss_score, cwe_ids) VALUES (?,?,?,?,?,?,?)",
                batch,
            )
            count += len(batch)
            batch = []

    if batch:
        conn.executemany(
            "INSERT INTO cve_db (cve_id, state, date_published, description, "
            "affected_products, cvss_score, cwe_ids) VALUES (?,?,?,?,?,?,?)",
            batch,
        )
        count += len(batch)

    conn.commit()
    if errors:
        print(f"  cve_db: {count} entries indexed ({errors} parse errors skipped)")
    else:
        print(f"  cve_db: {count} entries indexed")
    return count


def cmd_index_external(args):
    conn = get_conn()
    force = getattr(args, "force", False)

    print("[index-external] Indexing external sources...")
    total = 0

    if force:
        # Force clears all external tables (handled inside each indexer via DELETE)
        pass

    total += _index_exploitdb(conn)
    total += _index_nuclei(conn)
    total += _index_poc_github(conn)
    total += _index_external_techniques(conn)
    total += _index_cisa_kev(conn)
    total += _index_cve_db(conn)

    print(f"\n[index-external] Total: {total} entries indexed")
    print(f"  DB: {KB_PATH}")


# ── 검색 ─────────────────────────────────────────────────────────────────────

def _search_table(conn: sqlite3.Connection, table: str, fts_query: str,
                  top: int, columns: list[str] = None) -> list[dict]:
    """Generic FTS5 search on a table. Returns list of row dicts with rank."""
    if columns is None:
        # Get column names from table
        try:
            row = conn.execute(f"SELECT * FROM {table} LIMIT 0").description
            columns = [r[0] for r in row]
        except Exception:
            return []

    col_str = ", ".join(columns)
    try:
        rows = conn.execute(
            f"SELECT {col_str}, rank FROM {table} WHERE {table} MATCH ? ORDER BY rank LIMIT ?",
            (fts_query, top),
        ).fetchall()
    except Exception:
        return []

    results = []
    for r in rows:
        d = {c: r[c] for c in columns}
        d["_rank"] = r["rank"]
        d["_table"] = table
        results.append(d)
    return results


def cmd_search(args):
    conn = get_conn()
    query = args.query.strip()
    top = args.top

    # Apply synonym expansion
    fts_query = expand_query(query)

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


def _format_result(idx: int, result: dict) -> str:
    """Format a single search result for display."""
    table = result["_table"]

    if table == "chunks":
        header = f"[technique] {result.get('source_path', '')} § {result.get('heading', '')}"
        snippet = result.get("body", "")[:400]
    elif table == "exploitdb":
        header = f"[exploitdb] EDB-{result.get('edb_id', '')} ({result.get('platform', '')})"
        snippet = result.get("description", "")[:400]
    elif table == "nuclei":
        header = f"[nuclei] {result.get('template_id', '')} ({result.get('severity', '')})"
        snippet = result.get("name", "")
        desc = result.get("description", "")
        if desc:
            snippet += f"\n{desc[:350]}"
        tags = result.get("tags", "")
        if tags:
            snippet += f"\ntags: {tags}"
    elif table == "poc_github":
        header = f"[poc_github] {result.get('cve_id', '')}"
        snippet = result.get("description", "")[:300]
        url = result.get("github_url", "")
        if url:
            snippet += f"\n{url}"
    elif table == "external_techniques":
        header = f"[external] {result.get('source_path', '')} § {result.get('heading', '')}"
        snippet = result.get("body", "")[:400]
    elif table == "cisa_kev":
        cve = result.get("cve_id", "")
        vendor = result.get("vendor", "")
        product = result.get("product", "")
        header = f"[KEV] {cve} — {vendor} {product}"
        snippet = result.get("vulnerability_name", "")
        desc = result.get("description", "")
        if desc:
            snippet += f"\n{desc[:350]}"
        ransomware = result.get("known_ransomware", "")
        if ransomware and ransomware.lower() != "unknown":
            snippet += f"\nRansomware: {ransomware}"
    elif table == "cve_db":
        cve = result.get("cve_id", "")
        cvss = result.get("cvss_score", "")
        cwe = result.get("cwe_ids", "")
        header = f"[CVE] {cve} (CVSS: {cvss})" if cvss else f"[CVE] {cve}"
        snippet = result.get("description", "")[:400]
        affected = result.get("affected_products", "")
        if affected:
            snippet += f"\nAffected: {affected}"
        if cwe:
            snippet += f"\nCWE: {cwe}"
    else:
        header = f"[{table}] result"
        snippet = str(result)[:400]

    return f"--- {idx}. {header} ---\n{snippet}"


def cmd_search_all(args):
    """Search across ALL tables with merged results."""
    conn = get_conn()
    query = args.query.strip()
    top = args.top
    fts_query = expand_query(query)

    if not fts_query:
        print("[]")
        return

    all_results = []

    # Search each table
    for tbl in ["chunks", "exploitdb", "nuclei", "poc_github",
                "external_techniques", "cisa_kev", "cve_db"]:
        all_results.extend(_search_table(conn, tbl, fts_query, top * 2))

    # CVE exact match boost: if query matches CVE pattern, do exact search too
    cve_match = re.match(r'(CVE-\d{4}-\d+)', query, re.IGNORECASE)
    if cve_match:
        cve_q = f'"{cve_match.group(1)}"'
        for tbl in ["exploitdb", "nuclei", "poc_github", "cisa_kev", "cve_db"]:
            all_results.extend(_search_table(conn, tbl, cve_q, top))

    # CWE exact match: search nuclei tags + cve_db cwe_ids
    cwe_match = re.match(r'(CWE-\d+)', query, re.IGNORECASE)
    if cwe_match:
        cwe_q = f'"{cwe_match.group(1)}"'
        all_results.extend(_search_table(conn, "nuclei", cwe_q, top))
        all_results.extend(_search_table(conn, "cve_db", cwe_q, top))

    # Deduplicate (by table + key fields)
    seen = set()
    unique = []
    for r in all_results:
        tbl = r["_table"]
        if tbl == "chunks":
            key = (tbl, r.get("source_path", ""), r.get("heading", ""), r.get("body", "")[:100])
        elif tbl == "exploitdb":
            key = (tbl, r.get("edb_id", ""))
        elif tbl == "nuclei":
            key = (tbl, r.get("template_id", ""))
        elif tbl == "poc_github":
            key = (tbl, r.get("cve_id", ""), r.get("github_url", ""))
        elif tbl == "external_techniques":
            key = (tbl, r.get("source_path", ""), r.get("heading", ""), r.get("body", "")[:100])
        elif tbl in ("cisa_kev", "cve_db"):
            key = (tbl, r.get("cve_id", ""))
        else:
            key = (tbl, str(r)[:200])

        if key not in seen:
            seen.add(key)
            unique.append(r)

    # Sort by rank (lower = better in FTS5)
    unique.sort(key=lambda x: x["_rank"])

    # Take top N
    results = unique[:top]

    if not results:
        print(f"[knowledge] 검색 결과 없음: {query!r}", file=sys.stderr)
        print("  → WebSearch로 폴백 권장", file=sys.stderr)
        sys.exit(1)

    out_lines = [f"[knowledge search-all: {query!r} — top {len(results)}]"]
    for i, res in enumerate(results, 1):
        out_lines.append(f"\n{_format_result(i, res)}")

    print("\n".join(out_lines))


def cmd_search_exploits(args):
    """Search only exploit-related tables: exploitdb, nuclei, poc_github."""
    conn = get_conn()
    query = args.query.strip()
    top = args.top
    fts_query = expand_query(query)

    if not fts_query:
        print("[]")
        return

    all_results = []

    # Search exploit + CVE tables
    for tbl in ["exploitdb", "nuclei", "poc_github", "cisa_kev", "cve_db"]:
        all_results.extend(_search_table(conn, tbl, fts_query, top * 2))

    # CVE exact match boost
    cve_match = re.match(r'(CVE-\d{4}-\d+)', query, re.IGNORECASE)
    if cve_match:
        cve_q = f'"{cve_match.group(1)}"'
        for tbl in ["exploitdb", "nuclei", "poc_github", "cisa_kev", "cve_db"]:
            all_results.extend(_search_table(conn, tbl, cve_q, top))

    # CWE exact match
    cwe_match = re.match(r'(CWE-\d+)', query, re.IGNORECASE)
    if cwe_match:
        cwe_q = f'"{cwe_match.group(1)}"'
        all_results.extend(_search_table(conn, "nuclei", cwe_q, top))
        all_results.extend(_search_table(conn, "cve_db", cwe_q, top))

    # Deduplicate
    seen = set()
    unique = []
    for r in all_results:
        tbl = r["_table"]
        if tbl == "exploitdb":
            key = (tbl, r.get("edb_id", ""))
        elif tbl == "nuclei":
            key = (tbl, r.get("template_id", ""))
        elif tbl == "poc_github":
            key = (tbl, r.get("cve_id", ""), r.get("github_url", ""))
        elif tbl in ("cisa_kev", "cve_db"):
            key = (tbl, r.get("cve_id", ""))
        else:
            key = (tbl, str(r)[:200])

        if key not in seen:
            seen.add(key)
            unique.append(r)

    unique.sort(key=lambda x: x["_rank"])
    results = unique[:top]

    if not results:
        print(f"[knowledge] 검색 결과 없음: {query!r}", file=sys.stderr)
        print("  → WebSearch로 폴백 권장", file=sys.stderr)
        sys.exit(1)

    out_lines = [f"[knowledge search-exploits: {query!r} — top {len(results)}]"]
    for i, res in enumerate(results, 1):
        out_lines.append(f"\n{_format_result(i, res)}")

    print("\n".join(out_lines))


# ── 상태 / 통계 ──────────────────────────────────────────────────────────────

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


def _safe_count(conn: sqlite3.Connection, table: str) -> int:
    """Count rows in a table, returning 0 if table doesn't exist."""
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    except Exception:
        return 0


def cmd_stats(args):
    """Enhanced stats showing per-table counts."""
    if not KB_PATH.exists():
        print("[knowledge] 인덱스 없음 — `knowledge.py index` 실행 필요")
        return

    conn = get_conn()

    chunks_count = _safe_count(conn, "chunks")
    sources_count = _safe_count(conn, "sources")
    exploitdb_count = _safe_count(conn, "exploitdb")
    nuclei_count = _safe_count(conn, "nuclei")
    poc_github_count = _safe_count(conn, "poc_github")
    ext_tech_count = _safe_count(conn, "external_techniques")
    kev_count = _safe_count(conn, "cisa_kev")
    cve_count = _safe_count(conn, "cve_db")

    # Count unique source_paths in external_techniques
    try:
        ext_files = conn.execute(
            "SELECT COUNT(DISTINCT source_path) FROM external_techniques"
        ).fetchone()[0]
    except Exception:
        ext_files = 0

    total = (chunks_count + exploitdb_count + nuclei_count + poc_github_count
             + ext_tech_count + kev_count + cve_count)

    db_size = KB_PATH.stat().st_size
    if db_size > 1024 * 1024:
        size_str = f"{db_size / (1024*1024):.1f} MB"
    else:
        size_str = f"{db_size / 1024:.1f} KB"

    print(f"[knowledge] DB: {KB_PATH} ({size_str})")
    print(f"  chunks:              {chunks_count:>8} entries ({sources_count} files)")
    print(f"  exploitdb:           {exploitdb_count:>8} entries")
    print(f"  nuclei:              {nuclei_count:>8} entries")
    print(f"  poc_github:          {poc_github_count:>8} entries")
    print(f"  external_techniques: {ext_tech_count:>8} entries ({ext_files} files)")
    print(f"  cisa_kev:            {kev_count:>8} entries")
    print(f"  cve_db:              {cve_count:>8} entries")
    print(f"  {'─' * 35}")
    print(f"  Total:               {total:>8} entries")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Machine CTF Knowledge Base (FTS5)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # index
    sub.add_parser("index", help="인덱스 빌드/갱신").add_argument(
        "--force", action="store_true", help="변경 여부 무시하고 강제 재인덱싱"
    )

    # search (existing)
    p_search = sub.add_parser("search", help="지식 검색")
    p_search.add_argument("query", help="검색어")
    p_search.add_argument("--top", type=int, default=DEFAULT_TOP, metavar="N")

    # status (existing)
    sub.add_parser("status", help="인덱스 현황")

    # add (existing)
    p_add = sub.add_parser("add", help="단일 파일 추가/갱신")
    p_add.add_argument("file", help="MD 파일 경로")

    # index-external (new)
    p_idx_ext = sub.add_parser("index-external", help="외부 소스 인덱싱 (ExploitDB, Nuclei, PoC-in-GitHub, PayloadsAllTheThings)")
    p_idx_ext.add_argument("--force", action="store_true", help="강제 재인덱싱")

    # search-all (new)
    p_search_all = sub.add_parser("search-all", help="전체 테이블 통합 검색")
    p_search_all.add_argument("query", help="검색어")
    p_search_all.add_argument("--top", type=int, default=DEFAULT_TOP, metavar="N")

    # search-exploits (new)
    p_search_exp = sub.add_parser("search-exploits", help="exploit/CVE 전용 검색")
    p_search_exp.add_argument("query", help="검색어")
    p_search_exp.add_argument("--top", type=int, default=DEFAULT_TOP, metavar="N")

    # stats (new)
    sub.add_parser("stats", help="상세 통계")

    args = parser.parse_args()
    cmd_map = {
        "index": cmd_index,
        "search": cmd_search,
        "status": cmd_status,
        "add": cmd_add,
        "index-external": cmd_index_external,
        "search-all": cmd_search_all,
        "search-exploits": cmd_search_exploits,
        "stats": cmd_stats,
    }
    cmd_map[args.cmd](args)


if __name__ == "__main__":
    main()
