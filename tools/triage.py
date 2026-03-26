#!/usr/bin/env python3
"""
Machine v2 — Challenge Triage Engine
======================================
Automatically classifies CTF challenges and retrieves relevant knowledge.

Usage:
  triage.py <challenge_dir> [--category CAT]  # full triage → JSON
  triage.py <challenge_dir> --context          # output knowledge context block only

Output: JSON with category, difficulty, pipeline mode, and knowledge context.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

MACHINE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(MACHINE_ROOT / "tools"))

# ---------------------------------------------------------------------------
# Category Detection
# ---------------------------------------------------------------------------

BINARY_EXTENSIONS = {".elf", ".exe", ".out", ".bin", ".so", ".dll", ".dylib"}
WEB_FILES = {"docker-compose.yml", "docker-compose.yaml", "Dockerfile",
             "app.py", "server.js", "index.js", "index.php", "main.go",
             "pom.xml", "build.gradle"}
CRYPTO_FILES = {"encrypt.py", "cipher.py", "rsa.py", "aes.py", "chall.py",
                "output.txt", "enc.txt", "encrypted.txt", "ciphertext.txt"}
FORENSICS_EXTENSIONS = {".pcap", ".pcapng", ".mem", ".raw", ".img", ".E01",
                        ".vmdk", ".ad1", ".dmp"}
WEB3_EXTENSIONS = {".sol", ".abi"}
WEB3_FILES = {"foundry.toml", "hardhat.config.js", "hardhat.config.ts",
              "truffle-config.js", "brownie-config.yaml"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff", ".wav"}


def detect_category(challenge_dir: Path, hint: str = None) -> str:
    """Detect challenge category from files. Returns category string."""
    if hint and hint in ("pwn", "rev", "web", "crypto", "forensics", "web3", "misc"):
        return hint

    files = []
    for f in challenge_dir.rglob("*"):
        if f.is_file() and ".git" not in f.parts:
            files.append(f)

    names = {f.name for f in files}
    suffixes = {f.suffix.lower() for f in files}
    rel_names = {f.name.lower() for f in files}

    # Web3 — check first (most specific)
    if suffixes & WEB3_EXTENSIONS or names & WEB3_FILES:
        return "web3"

    # Web — docker-compose or web framework files
    if names & WEB_FILES:
        return "web"

    # Forensics — pcap, memory dumps, images with no binary
    if suffixes & FORENSICS_EXTENSIONS:
        return "forensics"

    # Check for ELF/PE binaries
    has_binary = False
    binary_path = None
    for f in files:
        if f.suffix.lower() in BINARY_EXTENSIONS:
            has_binary = True
            binary_path = f
            break
        # Check ELF magic for extensionless files
        if not f.suffix and f.stat().st_size > 4:
            try:
                with open(f, "rb") as fh:
                    magic = fh.read(4)
                if magic == b"\x7fELF" or magic[:2] == b"MZ":
                    has_binary = True
                    binary_path = f
                    break
            except (OSError, PermissionError):
                pass

    # Crypto — python files with crypto-like names, no binary
    if not has_binary and (names & CRYPTO_FILES or
            any(n.endswith(".sage") for n in rel_names)):
        return "crypto"
    # Also crypto if output.txt + *.py but no binary
    if not has_binary and "output.txt" in names and any(
            f.suffix == ".py" for f in files):
        return "crypto"

    # Image stego → forensics
    if suffixes & IMAGE_EXTENSIONS and not has_binary:
        return "forensics"

    # Binary present — pwn vs rev
    if has_binary and binary_path:
        # Check for network functions → pwn
        try:
            strings_out = subprocess.run(
                ["strings", str(binary_path)],
                capture_output=True, text=True, timeout=10
            ).stdout.lower()
            network_hints = ["socket", "bind", "listen", "accept", "recv",
                             "send", "connect", "htons", "inet"]
            vuln_hints = ["gets", "strcpy", "sprintf", "system", "execve",
                          "/bin/sh", "flag"]
            rev_hints = ["correct", "wrong", "invalid", "enter the",
                         "input:", "password:", "key:"]

            net_score = sum(1 for h in network_hints if h in strings_out)
            vuln_score = sum(1 for h in vuln_hints if h in strings_out)
            rev_score = sum(1 for h in rev_hints if h in strings_out)

            if net_score >= 2 or vuln_score >= 2:
                return "pwn"
            if rev_score >= 2:
                return "rev"
            # Default binary → rev (more common in CTF)
            return "rev"
        except Exception:
            return "rev"

    # Fallback
    return "misc"


# ---------------------------------------------------------------------------
# Difficulty Estimation
# ---------------------------------------------------------------------------

def estimate_difficulty(challenge_dir: Path, category: str,
                        similar_count: int = 0) -> str:
    """Estimate difficulty: easy / medium / hard."""
    score = 0

    # Category baseline
    cat_base = {"forensics": 0, "misc": 0, "crypto": 1, "web": 1,
                "rev": 2, "pwn": 2, "web3": 3}
    score += cat_base.get(category, 2)

    # Similar solved challenges → easier
    if similar_count >= 2:
        score -= 2
    elif similar_count >= 1:
        score -= 1

    # File complexity
    files = list(challenge_dir.rglob("*"))
    file_count = sum(1 for f in files if f.is_file())
    if file_count > 15:
        score += 1

    # Docker multi-container
    compose = challenge_dir / "docker-compose.yml"
    if not compose.exists():
        compose = challenge_dir / "docker-compose.yaml"
    if compose.exists():
        try:
            content = compose.read_text()
            services = content.count("image:") + content.count("build:")
            if services > 2:
                score += 1
        except OSError:
            pass

    # Binary protections (pwn/rev)
    if category in ("pwn", "rev"):
        for f in files:
            if f.is_file() and not f.suffix:
                try:
                    with open(f, "rb") as fh:
                        if fh.read(4) == b"\x7fELF":
                            result = subprocess.run(
                                ["checksec", "--file=" + str(f), "--output=json"],
                                capture_output=True, text=True, timeout=10
                            )
                            if result.returncode == 0:
                                data = json.loads(result.stdout)
                                # checksec JSON format varies
                                props = {}
                                if isinstance(data, dict):
                                    for v in data.values():
                                        if isinstance(v, dict):
                                            props = v
                                            break
                                pie = "pie" in str(props).lower()
                                canary = "canary" in str(props).lower() and "no" not in str(props.get("canary", "")).lower()
                                if pie and canary:
                                    score += 1
                            break
                except Exception:
                    pass

    # Custom libc → harder
    if any(f.name.startswith("libc") for f in files if f.is_file()):
        score += 1

    if score <= 1:
        return "easy"
    if score <= 3:
        return "medium"
    return "hard"


# ---------------------------------------------------------------------------
# Knowledge Retrieval
# ---------------------------------------------------------------------------

def search_knowledge(category: str, challenge_dir: Path) -> dict:
    """Search knowledge DB for similar challenges and relevant techniques.
    Returns {similar_challenges: [...], techniques: [...], decision_branches: {...}}
    """
    result = {
        "similar_challenges": [],
        "techniques": [],
        "decision_branches": [],
    }

    kb_script = MACHINE_ROOT / "tools" / "knowledge.py"
    if not kb_script.exists():
        return result

    # Build search queries from challenge content
    queries = [category]

    # Extract keywords from challenge description
    for desc_name in ("challenge.md", "CHALLENGE.md", "README.md", "description.md"):
        desc_path = challenge_dir / desc_name
        if desc_path.exists():
            try:
                text = desc_path.read_text(errors="replace")[:2000]
                # Extract meaningful words
                words = re.findall(r'[a-zA-Z]{4,}', text)
                # Take most common non-stop words
                from collections import Counter
                stop = {"this", "that", "with", "from", "your", "have", "will",
                        "been", "they", "their", "what", "when", "where", "which",
                        "there", "about", "into", "more", "some", "than", "them",
                        "each", "make", "like", "just", "over", "such", "only",
                        "also", "after", "before", "through", "between", "flag",
                        "challenge", "file", "find", "given", "server"}
                filtered = [w.lower() for w in words if w.lower() not in stop]
                common = Counter(filtered).most_common(5)
                queries.extend([w for w, _ in common])
            except OSError:
                pass
            break

    # Detect tech stack for web
    if category == "web":
        for f in challenge_dir.rglob("*"):
            if f.name == "requirements.txt":
                try:
                    deps = f.read_text(errors="replace").lower()
                    for fw in ("flask", "django", "fastapi", "express"):
                        if fw in deps:
                            queries.append(fw)
                except OSError:
                    pass
            elif f.name == "package.json":
                try:
                    pkg = json.loads(f.read_text(errors="replace"))
                    deps_all = {**pkg.get("dependencies", {}),
                                **pkg.get("devDependencies", {})}
                    for fw in ("express", "koa", "hapi", "next", "nuxt"):
                        if fw in deps_all:
                            queries.append(fw)
                except (OSError, json.JSONDecodeError):
                    pass

    # Search knowledge DB
    query_str = " ".join(queries[:8])
    try:
        out = subprocess.run(
            [sys.executable, str(kb_script), "search", query_str, "--top", "5"],
            capture_output=True, text=True, timeout=15,
            cwd=str(MACHINE_ROOT)
        )
        if out.returncode == 0:
            # Parse output: knowledge.py prints formatted results
            lines = out.stdout.strip().split("\n")
            for line in lines:
                line = line.strip()
                if not line or line.startswith("[knowledge]"):
                    continue
                # Technique results contain source_path and heading
                if "techniques/" in line:
                    result["techniques"].append(line)
                elif "challenges/" in line:
                    result["similar_challenges"].append(line)
    except Exception:
        pass

    # Get decision tree branches for this category
    try:
        from decision_tree import TREES, FRAMEWORK_VULN_PRIORITY
        if category in TREES:
            branches = {}
            for trigger, actions in TREES[category].items():
                branches[trigger] = [
                    f"{a['id']}: {a['desc']}" for a in actions[:3]
                ]
            result["decision_branches"] = branches

        # Framework vulnerability priority for web
        if category == "web":
            result["framework_priority"] = FRAMEWORK_VULN_PRIORITY
    except ImportError:
        pass

    return result


def load_technique_snippets(techniques: list, max_per_technique: int = 500) -> list:
    """Load actual content from technique files referenced in search results."""
    snippets = []
    seen_paths = set()

    for t in techniques:
        # Extract file path from search result line
        match = re.search(r'(knowledge/techniques/\S+\.md)', t)
        if not match:
            continue
        rel_path = match.group(1)
        if rel_path in seen_paths:
            continue
        seen_paths.add(rel_path)

        full_path = MACHINE_ROOT / rel_path
        if not full_path.exists():
            continue

        try:
            content = full_path.read_text(errors="replace")
            # Skip frontmatter
            if content.startswith("---"):
                end = content.find("---", 3)
                if end > 0:
                    content = content[end + 3:].strip()
            # Truncate
            if len(content) > max_per_technique:
                content = content[:max_per_technique] + "\n[... truncated]"
            snippets.append({
                "path": rel_path,
                "content": content
            })
        except OSError:
            pass

        if len(snippets) >= 3:
            break

    return snippets


def load_similar_writeups(challenges: list, max_per: int = 400) -> list:
    """Load snippets from similar solved challenge writeups."""
    snippets = []
    seen = set()

    for c in challenges:
        match = re.search(r'(knowledge/challenges/\S+\.md)', c)
        if not match:
            continue
        rel_path = match.group(1)
        if rel_path in seen:
            continue
        seen.add(rel_path)

        full_path = MACHINE_ROOT / rel_path
        if not full_path.exists():
            continue

        try:
            content = full_path.read_text(errors="replace")
            # Extract key sections: Technique, Vulnerability, Key Insight
            sections = {}
            current = None
            for line in content.split("\n"):
                hm = re.match(r'^##\s+(.+)', line)
                if hm:
                    current = hm.group(1).strip().lower()
                    sections[current] = []
                elif current:
                    sections[current].append(line)

            # Build summary
            summary_parts = []
            for key in ("technique", "vulnerability", "key insight",
                        "attack flow", "solve steps"):
                if key in sections:
                    text = "\n".join(sections[key][:10]).strip()
                    if text:
                        summary_parts.append(f"**{key.title()}**: {text}")

            name = Path(rel_path).stem
            summary = "\n".join(summary_parts)[:max_per] if summary_parts else ""
            if summary:
                snippets.append({"name": name, "path": rel_path, "summary": summary})
        except OSError:
            pass

        if len(snippets) >= 3:
            break

    return snippets


# ---------------------------------------------------------------------------
# Pipeline Selection
# ---------------------------------------------------------------------------

def select_pipeline(difficulty: str) -> str:
    """Select pipeline mode based on difficulty."""
    if difficulty == "easy":
        return "lightweight"  # solver only
    elif difficulty == "medium":
        return "lightweight"  # solver + optional critic escalation
    else:
        return "full"  # solver → critic → remote-verifier


# ---------------------------------------------------------------------------
# Format Knowledge Context Block
# ---------------------------------------------------------------------------

def format_knowledge_context(knowledge: dict, technique_snippets: list,
                             challenge_snippets: list,
                             category: str, difficulty: str) -> str:
    """Format the knowledge context block that gets injected into solver prompt."""
    lines = []
    lines.append("[KNOWLEDGE CONTEXT — auto-retrieved by triage.py]")
    lines.append("")

    # Similar solved challenges
    if challenge_snippets:
        lines.append("## Similar Solved Challenges")
        for i, cs in enumerate(challenge_snippets, 1):
            lines.append(f"\n### {i}. {cs['name']} ({cs['path']})")
            lines.append(cs["summary"])
        lines.append("")

    # Relevant techniques
    if technique_snippets:
        lines.append("## Relevant Techniques")
        for i, ts in enumerate(technique_snippets, 1):
            lines.append(f"\n### {i}. {ts['path']}")
            lines.append(ts["content"])
        lines.append("")

    # Decision tree branches
    if knowledge.get("decision_branches"):
        lines.append("## Decision Tree (pre-loaded)")
        lines.append("If you get stuck, try these approaches in order:")
        for trigger, actions in knowledge["decision_branches"].items():
            lines.append(f"\n**{trigger}:**")
            for a in actions:
                lines.append(f"  - {a}")
        lines.append("")

    # Framework vulnerability priority (web only)
    if category == "web" and knowledge.get("framework_priority"):
        lines.append("## Framework Vulnerability Priority")
        for fw, vulns in knowledge["framework_priority"].items():
            lines.append(f"  {fw}: {' → '.join(vulns[:4])}")
        lines.append("")

    if not any([challenge_snippets, technique_snippets,
                knowledge.get("decision_branches")]):
        lines.append("No relevant knowledge found. Use WebSearch if stuck.")
        lines.append("")

    lines.append(f"[Difficulty: {difficulty} | Pipeline: {select_pipeline(difficulty)}]")
    lines.append("[END KNOWLEDGE CONTEXT]")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main Triage
# ---------------------------------------------------------------------------

def triage(challenge_dir: str, category_hint: str = None) -> dict:
    """Run full triage on a challenge directory."""
    cdir = Path(challenge_dir).resolve()
    if not cdir.is_dir():
        return {"error": f"Not a directory: {cdir}"}

    # 1. Detect category
    category = detect_category(cdir, category_hint)

    # 2. Search knowledge
    knowledge = search_knowledge(category, cdir)

    # 3. Load technique and challenge snippets
    technique_snippets = load_technique_snippets(knowledge["techniques"])
    challenge_snippets = load_similar_writeups(knowledge["similar_challenges"])

    # 4. Estimate difficulty
    similar_count = len(challenge_snippets)
    difficulty = estimate_difficulty(cdir, category, similar_count)

    # 5. Select pipeline
    pipeline = select_pipeline(difficulty)

    # 6. Format knowledge context
    context_block = format_knowledge_context(
        knowledge, technique_snippets, challenge_snippets,
        category, difficulty
    )

    return {
        "challenge_dir": str(cdir),
        "category": category,
        "difficulty": difficulty,
        "pipeline": pipeline,
        "similar_challenges": [cs["name"] for cs in challenge_snippets],
        "techniques": [ts["path"] for ts in technique_snippets],
        "knowledge_context": context_block,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Machine v2 Challenge Triage")
    p.add_argument("challenge_dir", help="Path to challenge directory")
    p.add_argument("--category", "-c", default=None,
                   help="Override category detection")
    p.add_argument("--context", action="store_true",
                   help="Output only the knowledge context block (for prompt injection)")
    p.add_argument("--json", action="store_true",
                   help="Output full JSON (default)")

    args = p.parse_args()
    result = triage(args.challenge_dir, args.category)

    if "error" in result:
        print(json.dumps(result), file=sys.stderr)
        sys.exit(1)

    if args.context:
        print(result["knowledge_context"])
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
