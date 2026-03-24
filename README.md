<div align="center">

# ⚙️ Machine

**Autonomous CTF Agent System**

*Multi-agent pipeline powered by Claude Code — analyzes, solves, and learns from CTF challenges autonomously*

[![EK-Machine](https://img.shields.io/badge/🎵_EK--Machine-YouTube-red?style=for-the-badge)](https://www.youtube.com/watch?v=TFZOIueIBmU)
&nbsp;
![Agents](https://img.shields.io/badge/Agents-12-blue?style=for-the-badge)
&nbsp;
![Categories](https://img.shields.io/badge/Categories-6-green?style=for-the-badge)
&nbsp;
![Model](https://img.shields.io/badge/Model-Opus-purple?style=for-the-badge)
&nbsp;
![Knowledge](https://img.shields.io/badge/Knowledge_DB-FTS5-orange?style=for-the-badge)

```
  ███╗   ███╗ █████╗  ██████╗██╗  ██╗██╗███╗   ██╗███████╗
  ████╗ ████║██╔══██╗██╔════╝██║  ██║██║████╗  ██║██╔════╝
  ██╔████╔██║███████║██║     ███████║██║██╔██╗ ██║█████╗
  ██║╚██╔╝██║██╔══██║██║     ██╔══██║██║██║╚██╗██║██╔══╝
  ██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║██║██║ ╚████║███████╗
  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝
```

*"Feed it a challenge, get a flag."* 🏴

</div>

---

## 🚀 Quick Start

```bash
# Install everything
./setup.sh

# Solve a CTF challenge (fully autonomous)
./machine.sh ctf ./challenge.zip

# Specify category manually
./machine.sh ctf ./challenge.zip pwn

# Learn mode — solve + generate writeup + store in knowledge DB
./machine.sh learn ./challenge.zip

# Watch it work
./machine.sh logs
```

---

## 🧠 What Is This?

Machine is an autonomous agent system that **analyzes and solves CTF challenges on its own**.

```
Challenge in → Category detection → Specialist agent pipeline → Solution → Verification → Report
```

It spawns specialized agents (pwn, rev, web, crypto, forensics, web3), coordinates them through a structured pipeline with quality gates, and learns from every attempt.

### Design Principles

| Principle | How |
|-----------|-----|
| **Anti-hallucination** | Every address/offset must be verified against real tool output (`--src` flag) |
| **Programmatic quality gates** | `quality_gate.py` blocks pipeline transitions with exit codes, not rules |
| **Auto knowledge injection** | FTS5 search injects relevant technique docs before each agent spawns |
| **Fake idle detection** | Checkpoint-based agent completion verification |
| **Learning loop** | Every solve generates a writeup → stored in DB → referenced in future challenges |

---

## 🤖 Agent Pipeline

### Per-Category Pipelines

```
PWN        🔨  @pwn → @critic → @verifier → @reporter
REV        🔍  @rev → @critic → @verifier → @reporter
WEB        🌐  @web → @web-docker → @web-remote → @critic → @verifier → @reporter
CRYPTO     🔐  @crypto → @critic → @verifier → @reporter
FORENSICS  🔬  @forensics → @critic → @verifier → @reporter
WEB3       ⛓️  @web3 → @critic → @verifier → @reporter
```

All agents run on **Opus**.

### Agent Roles

| Agent | Role | Key Tools |
|-------|------|-----------|
| `pwn` | Binary exploitation | Ghidra MCP, GDB+GEF, pwntools, ROPgadget |
| `rev` | Reverse engineering | Ghidra MCP, GDB, Frida, z3, angr |
| `web` | Web vuln analysis (source only) | Read, Grep, Glob (no network!) |
| `web-docker` | Local Docker exploit verification | docker compose, curl, python3 |
| `web-remote` | Remote flag capture | Verified solve.py against live target |
| `crypto` | Cryptanalysis | SageMath, z3, RsaCtfTool, hashcat |
| `forensics` | Forensics & stego | binwalk, volatility3, tshark, zsteg |
| `web3` | Smart contracts | Slither, Mythril, Foundry |
| `critic` | Cross-verification | Re-verifies all addresses/offsets with GDB/Ghidra |
| `verifier` | Final verification | 3x local run → remote flag capture |
| `reporter` | Writeup generation | Template-based documentation |

### Quality Gates

Pipeline stages are blocked programmatically — not by rules in markdown, but by **exit codes**:

```
worker → [quality_gate.py --stage critic]   → critic
critic → [quality_gate.py --stage verifier] → verifier
verifier → [quality_gate.py --stage reporter] → reporter
```

The quality gate also auto-runs `payload_check.py` on web exploits — catching JS bugs (quote collisions, accidental bot spawns, resource abuse) **before** they waste hours of debugging.

---

## 🔧 Core Tools

### `state.py` — Verified Fact Store

SQLite-backed state management that prevents hallucination between agents.
Every fact requires a source file (`--src`) pointing to real tool output.

```bash
export CHALLENGE_DIR=/path/to/challenge

# Record a fact (--src required)
python3 tools/state.py set --key main_addr --val 0x401234 \
    --src /tmp/gdb.txt --agent pwn

# Query
python3 tools/state.py get --key main_addr
python3 tools/state.py facts

# Verify artifacts before handoff (blocks pipeline if missing)
python3 tools/state.py verify --artifacts solve.py reversal_map.md

# Checkpoint management
python3 tools/state.py checkpoint --agent pwn --phase 2 \
    --phase-name gdb_verify --status in_progress
```

### `knowledge.py` — FTS5 Knowledge Search

Agents can search techniques, vulnerabilities, and exploits at any time during analysis.

```bash
# Technique search
python3 tools/knowledge.py search "tcache poisoning glibc 2.35"

# Cross-source search (techniques + ExploitDB + Nuclei + PoC-in-GitHub)
python3 tools/knowledge.py search-all "CVE-2024-1234"

# Exploit DB search
python3 tools/knowledge.py search-exploits "apache RCE"

# Index external sources (one-time setup)
python3 tools/knowledge.py index-external

# Stats
python3 tools/knowledge.py stats
```

**Auto synonym expansion**: `uaf` → `use after free`, `bof` → `buffer overflow`, `sqli` → `sql injection`, etc.

### `payload_check.py` — JS Payload Validator

Catches common web exploit bugs **before deployment**. Integrated into quality gates — runs automatically.

```bash
# Check a solve.py for JS payload issues
python3 tools/payload_check.py --extract solve.py --check-all

# Direct JS check
python3 tools/payload_check.py --js "var rce='...'" --check-syntax

# Self-test
python3 tools/payload_check.py --self-test
```

Detects:
- **Quote collisions** — `flag=''` inside `'`-delimited string (SyntaxError at runtime)
- **Side-effect debug** — `fetch('/api/report')` accidentally spawning bot processes
- **Resource abuse** — too many threads/workers overwhelming remote servers

### `quality_gate.py` — Pipeline Gate

Programmatic blocking between stages. Exit 0 = PASS, Exit 1 = FAIL.

```bash
python3 tools/quality_gate.py ctf-verify <challenge_dir>
python3 tools/quality_gate.py artifact-check <dir> --stage critic
```

### `context_digest.py` — Output Compression

Extracts key patterns (addresses, flags, errors) from 500+ line outputs.

```bash
cat large_output.txt | python3 tools/context_digest.py --max-lines 100
```

---

## 📚 Knowledge Base

### Structure

```
knowledge/
├── kb.db                    # FTS5 index (auto-generated)
├── index.md                 # Challenge index (solved / attempted)
├── techniques/              # Technique docs (12+)
│   ├── heap_house_of_x.md
│   ├── web_ctf_techniques.md
│   ├── gdb_oracle_reverse.md
│   └── ...
└── challenges/              # Solve records (gitignored)
    ├── _template.md
    └── <challenge>.md       # Auto-generated by learn mode
```

### Knowledge Accumulation Flow

```
Solve challenge in learn mode
        ↓
Auto-generate writeup from template
        ↓
Save to knowledge/challenges/<name>.md
        ↓
FTS5 auto-indexing (kb.db)
        ↓
Next CTF → agent auto-references past solves
```

### External Source Indexing

```bash
python3 tools/knowledge.py index-external
```

| Source | Path | Description |
|--------|------|-------------|
| ExploitDB | `~/exploitdb/` | Public exploit CSV database |
| Nuclei | `~/nuclei-templates/` | Vulnerability scan templates |
| PoC-in-GitHub | `~/PoC-in-GitHub/` | CVE-linked PoC collection |
| PayloadsAllTheThings | `~/PayloadsAllTheThings/` | Payloads & technique docs |

---

## 🪝 Hooks

| Hook | Trigger | Purpose |
|------|---------|---------|
| `knowledge_inject.sh` | PreToolUse (Agent) | FTS5 search for relevant techniques → inject into agent's system message |
| `check_agent_completion.sh` | SubagentStop | Detect fake idle / hallucination / errors via checkpoint.json |

---

## 📁 Directory Structure

```
Machine/
├── machine.sh                       # Autonomous launcher (ctf / learn / status / logs)
├── CLAUDE.md                        # Orchestrator rules + pipeline definitions
├── setup.sh                         # One-command tool installer
│
├── .claude/
│   ├── agents/                      # Agent definitions (12 agents, all Opus)
│   │   ├── pwn.md                   # PWN: Ghidra + GDB + pwntools
│   │   ├── rev.md                   # REV: Ghidra + GDB + Frida + z3
│   │   ├── web.md                   # WEB Phase 1: source analysis only
│   │   ├── web-docker.md            # WEB Phase 2: local Docker verification
│   │   ├── web-remote.md            # WEB Phase 3: remote flag capture
│   │   ├── crypto.md                # CRYPTO: SageMath + z3 + hashcat
│   │   ├── forensics.md             # FORENSICS: binwalk + volatility3
│   │   ├── web3.md                  # WEB3: Slither + Mythril + Foundry
│   │   ├── critic.md                # Cross-verification
│   │   ├── verifier.md              # Local 3x + remote flag
│   │   └── reporter.md              # Writeup generation
│   ├── hooks/                       # Auto-triggers
│   │   ├── knowledge_inject.sh
│   │   └── check_agent_completion.sh
│   ├── rules/
│   │   └── ctf_pipeline.md          # Per-category pipeline + gates
│   └── settings.json                # Tool permissions + hook registration
│
├── tools/
│   ├── state.py                     # SQLite fact store + checkpoint
│   ├── knowledge.py                 # FTS5 knowledge search (synonym expansion)
│   ├── quality_gate.py              # Pipeline quality gate
│   ├── payload_check.py             # JS payload validator (auto-integrated)
│   ├── context_digest.py            # Large output compression
│   └── gemini_query.sh              # Gemini summarization wrapper
│
├── knowledge/
│   ├── index.md                     # Challenge index
│   ├── kb.db                        # FTS5 index (gitignored)
│   ├── techniques/                  # Technique docs (12+)
│   └── challenges/                  # Solve records (gitignored)
│
├── reports/                         # Session report output
└── challenges/                      # Extracted challenge files
```

---

## 🛠 Installation

### Requirements

- Ubuntu 24.04 LTS (WSL2 supported)
- Python 3.12+
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) (authenticated)

### One-Command Setup

```bash
git clone https://github.com/sane100400/Machine.git
cd Machine
./setup.sh
```

### Installed Tools

| Category | Tools |
|----------|-------|
| **PWN/REV** | gdb, GEF, Ghidra, checksec, patchelf, pwntools, ROPgadget, one_gadget |
| **Web** | sqlmap, ffuf, dalfox, commix |
| **Crypto** | hashcat, john, SageMath, z3, RsaCtfTool |
| **Forensics** | binwalk, tshark, steghide, zsteg, exiftool, foremost, volatility3 |
| **Web3** | Slither, Mythril, Foundry (forge/cast/anvil) |
| **RE** | Frida, angr, Ghidra MCP |

---

<div align="center">

**Machine** — *solve it, record it, learn from it* 🏴

</div>
