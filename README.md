<div align="center">

# ⚙️ Machine

**CTF Autonomous Agent System**

*Claude Code 기반 멀티 에이전트 파이프라인으로 CTF 문제를 자율적으로 분석·풀이·학습*

[![EK-Machine](https://img.shields.io/badge/🎵_EK--Machine-YouTube-red?style=for-the-badge)](https://www.youtube.com/watch?v=TFZOIueIBmU)
&nbsp;
![Agents](https://img.shields.io/badge/Agents-9-blue?style=for-the-badge)
&nbsp;
![Categories](https://img.shields.io/badge/Categories-6-green?style=for-the-badge)
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

</div>

---

## 🚀 Quick Start

```bash
# 1. 도구 설치
./setup.sh

# 2. CTF 문제 풀기 (자율 실행)
./machine.sh ctf ./challenge.zip

# 3. 학습 모드 (풀이 + writeup 자동 생성 + DB 저장)
./machine.sh learn ./challenge.zip

# 4. 실시간 모니터링
./machine.sh logs
```

---

## 📋 목차

- [개요](#-개요)
- [아키텍처](#-아키텍처)
- [실행 모드](#-실행-모드)
- [에이전트 파이프라인](#-에이전트-파이프라인)
- [핵심 도구](#-핵심-도구)
- [Knowledge Base](#-knowledge-base)
- [Hooks](#-hooks)
- [디렉토리 구조](#-디렉토리-구조)
- [설치](#-설치)

---

## 💡 개요

Machine은 CTF 문제를 **자율적으로 분석하고 풀이**하는 에이전트 시스템이다.

```
문제 투입 → 카테고리 감지 → 전문 에이전트 파이프라인 → 풀이 → 검증 → 리포트
```

### 핵심 설계 원칙

| 원칙 | 구현 |
|------|------|
| **할루시네이션 방지** | 모든 숫자 상수(offset, address)는 실제 툴 출력으로 검증 (`--src`) |
| **구조적 품질 게이트** | 파이프라인 스테이지 간 `quality_gate.py`로 프로그래밍 차단 |
| **자동 지식 주입** | 에이전트 스폰 시 관련 기법 문서 FTS5 검색 → systemMessage 주입 |
| **Fake Idle 감지** | 에이전트 종료 시 checkpoint 기반 완료 여부 자동 검증 |
| **비용 최적화** | 복잡한 추론(opus) vs 도구 기반 작업(sonnet) 모델 분리 |
| **학습 루프** | learn 모드로 풀이마다 writeup 자동 생성 → DB 축적 → 다음 문제에 참조 |

---

## 🏗 아키텍처

```
                        ┌──────────────────────┐
                        │    Orchestrator       │
                        │  카테고리 감지 → 파이프라인 선택  │
                        └──────────┬───────────┘
                                   │
            ┌──────────────────────┼──────────────────────┐
            ▼                      ▼                      ▼
     ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
     │  PWN Agent   │       │  REV Agent   │       │  WEB Agent   │    ...
     │  (opus)      │       │  (opus)      │       │  (sonnet)    │
     └──────┬──────┘       └──────┬──────┘       └──────┬──────┘
            ▼                      ▼                      ▼
     ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
     │   Critic     │       │   Critic     │       │   Critic     │
     │  (opus)      │       │  (opus)      │       │  (opus)      │
     └──────┬──────┘       └──────┬──────┘       └──────┬──────┘
            ▼                      ▼                      ▼
     ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
     │  Verifier    │       │  Verifier    │       │  Verifier    │
     │  (sonnet)    │       │  (sonnet)    │       │  (sonnet)    │
     └──────┬──────┘       └──────┬──────┘       └──────┬──────┘
            │                      │                      │
            └──────────────────────┼──────────────────────┘
                                   ▼
                    ┌──────────────────────────┐
                    │      state.db (SQLite)    │
                    │  key │ value │ src │ ✓    │  ← 검증된 사실만
                    └──────────────────────────┘
                                   ▼
                    ┌──────────────────────────┐
                    │   knowledge/kb.db (FTS5)  │
                    │  기법 + ExploitDB + Nuclei │  ← 자동 참조
                    └──────────────────────────┘
```

---

## 🎮 실행 모드

### `ctf` — 플래그 캡처 모드

문제를 풀어서 플래그를 획득하는 것이 목표. 속도 우선.

```bash
./machine.sh ctf ./baby_bof.zip                    # 기본
./machine.sh --timeout 1800 ctf ./baby_bof.zip     # 30분 타임아웃
./machine.sh --dry-run ctf ./baby_bof.zip          # 미리보기
MACHINE_MODEL=sonnet ./machine.sh ctf ./baby_bof.zip  # 모델 변경
```

### `learn` — 학습 모드

문제를 풀고, **정해진 템플릿에 맞춰 한국어 writeup을 자동 생성**하여 Knowledge DB에 저장.
다음 CTF에서 유사 문제가 나오면 에이전트가 자동으로 과거 풀이를 참조한다.

```bash
./machine.sh learn ./baby_bof.zip                  # 풀이 + writeup + DB 저장
./machine.sh learn --import ./my_writeup.md         # 기존 writeup 임포트
./machine.sh learn --import ~/writeups/             # 디렉토리 일괄 임포트
./machine.sh learn --import https://blog.example.com/writeup  # URL에서 가져오기
./machine.sh learn --reindex                        # Knowledge DB 재인덱싱
```

### `status` / `logs` — 모니터링

```bash
./machine.sh status    # 세션 상태 확인
./machine.sh logs      # 실시간 로그 tail
```

---

## 🤖 에이전트 파이프라인

### 카테고리별 파이프라인

```
PWN:       pwn(opus) → critic(opus) → verifier(sonnet) → reporter(sonnet)
REV:       rev(opus) → critic(opus) → verifier(sonnet) → reporter(sonnet)
WEB:       web(sonnet) → critic(opus) → verifier(sonnet) → reporter(sonnet)
CRYPTO:    crypto(opus) → critic(opus) → verifier(sonnet) → reporter(sonnet)
FORENSICS: forensics(sonnet) → critic(opus) → verifier(sonnet) → reporter(sonnet)
WEB3:      web3(opus) → critic(opus) → verifier(sonnet) → reporter(sonnet)
```

### 에이전트 상세

| Agent | Model | 역할 | 주요 도구 |
|-------|-------|------|----------|
| `pwn` | opus | 바이너리 익스플로잇 | Ghidra MCP, GDB+GEF, pwntools, ROPgadget |
| `rev` | opus | 리버스 엔지니어링 | Ghidra MCP, GDB, Frida, z3, angr |
| `web` | sonnet | 웹 취약점 분석 | ffuf, sqlmap, dalfox, SSRFmap, Playwright |
| `crypto` | opus | 암호 분석 | SageMath, z3, RsaCtfTool, hashcat |
| `forensics` | sonnet | 포렌식/스테가노 | binwalk, volatility3, tshark, zsteg |
| `web3` | opus | 스마트 컨트랙트 | Slither, Mythril, Foundry |
| `critic` | opus | 교차 검증 | GDB/Ghidra로 모든 주소/오프셋 재검증 |
| `verifier` | sonnet | 최종 검증 | 로컬 3회 실행 → 리모트 플래그 획득 |
| `reporter` | sonnet | Writeup 작성 | 템플릿 기반 한국어 풀이 문서화 |

### 품질 게이트

파이프라인 스테이지 간 `quality_gate.py`가 프로그래밍적으로 차단:

```
worker → [artifact-check --stage critic] → critic
                                              ↓
critic → [artifact-check --stage verifier] → verifier
                                                ↓
verifier → [artifact-check --stage reporter] → reporter
```

```bash
# checkpoint + state.db + solve.py 검증
python3 tools/quality_gate.py ctf-verify <challenge_dir>

# 스테이지별 아티팩트 검증
python3 tools/quality_gate.py artifact-check <challenge_dir> --stage critic
```

---

## 🔧 핵심 도구

### `state.py` — 검증된 Fact Store

에이전트 간 할루시네이션을 막는 SQLite 기반 상태 관리.
모든 사실에는 실제 툴 출력 파일 출처(`--src`)가 필요하다.

```bash
export CHALLENGE_DIR=/path/to/challenge

# fact 기록 (--src 필수)
python3 tools/state.py set --key main_addr --val 0x401234 \
    --src /tmp/gdb.txt --agent pwn

# 조회
python3 tools/state.py get --key main_addr
python3 tools/state.py facts

# handoff 전 아티팩트 검증 (실패 시 파이프라인 블로킹)
python3 tools/state.py verify --artifacts solve.py reversal_map.md

# checkpoint 관리
python3 tools/state.py checkpoint --agent pwn --phase 2 \
    --phase-name gdb_verify --status in_progress
```

### `knowledge.py` — FTS5 지식 검색

에이전트가 분석 중 언제든 기법/취약점/익스플로잇을 검색할 수 있다.

```bash
# 기법 검색
python3 tools/knowledge.py search "tcache poisoning glibc 2.35"

# 전체 테이블 통합 검색 (기법 + ExploitDB + Nuclei + PoC-in-GitHub)
python3 tools/knowledge.py search-all "CVE-2024-1234"

# 익스플로잇 DB 전용 검색
python3 tools/knowledge.py search-exploits "apache RCE"

# 외부 소스 인덱싱 (최초 1회)
python3 tools/knowledge.py index-external

# 현황
python3 tools/knowledge.py stats
```

**동의어 자동 확장**: `uaf` → `use after free`, `bof` → `buffer overflow`, `sqli` → `sql injection` 등 16개 약어 자동 매핑

### `quality_gate.py` — 파이프라인 게이트

스테이지 간 프로그래밍적 차단. Exit 0 = PASS, Exit 1 = FAIL.

```bash
# CTF 파이프라인 검증 (checkpoint + state.db + solve.py)
python3 tools/quality_gate.py ctf-verify <challenge_dir>

# 스테이지별 아티팩트 검증
python3 tools/quality_gate.py artifact-check <dir> --stage critic
python3 tools/quality_gate.py artifact-check <dir> --stage verifier
python3 tools/quality_gate.py artifact-check <dir> --stage reporter
```

### `context_digest.py` — 대용량 출력 압축

500줄 이상 출력을 핵심 패턴(주소, 플래그, 에러)만 추출하여 압축.

```bash
cat large_output.txt | python3 tools/context_digest.py --max-lines 100
python3 tools/context_digest.py --file output.txt --prefer-gemini  # Gemini 요약
```

---

## 📚 Knowledge Base

### 구조

```
knowledge/
├── kb.db                    # FTS5 인덱스 (자동 생성)
├── index.md                 # 풀었거나 시도한 문제 인덱스
├── techniques/              # 기법 문서 (12개+)
│   ├── heap_house_of_x.md   # House of Spirit/Force/Lore/...
│   ├── web_ctf_techniques.md
│   ├── gdb_oracle_reverse.md
│   └── ...
└── challenges/              # 풀이 기록 (gitignore)
    ├── _template.md          # writeup 템플릿
    └── <challenge>.md        # learn 모드가 자동 생성
```

### 지식 축적 흐름

```
learn 모드로 문제 풀이
        ↓
템플릿에 맞춰 한국어 writeup 자동 생성
        ↓
knowledge/challenges/<name>.md 저장
        ↓
FTS5 자동 인덱싱 (kb.db)
        ↓
다음 CTF에서 유사 문제 → 에이전트가 자동 참조
```

### 외부 소스 인덱싱

```bash
python3 tools/knowledge.py index-external
```

| 소스 | 경로 | 설명 |
|------|------|------|
| ExploitDB | `~/exploitdb/` | 공개 익스플로잇 CSV |
| Nuclei | `~/nuclei-templates/` | 취약점 스캔 템플릿 |
| PoC-in-GitHub | `~/PoC-in-GitHub/` | CVE별 PoC 모음 |
| PayloadsAllTheThings | `~/PayloadsAllTheThings/` | 페이로드/기법 문서 |

---

## 🪝 Hooks

| Hook | 트리거 | 역할 |
|------|-------|------|
| `knowledge_inject.sh` | PreToolUse (Agent) | 에이전트 스폰 직전 관련 기법 FTS 검색 → systemMessage 주입 |
| `check_agent_completion.sh` | SubagentStop | checkpoint.json으로 Fake Idle / 할루시네이션 / 에러 자동 감지 |

---

## 📁 디렉토리 구조

```
Machine/
├── machine.sh                       # 🚀 자율 실행 런처 (ctf / learn / status / logs)
├── CLAUDE.md                        # 📋 오케스트레이터 규칙 + 파이프라인 정의
├── setup.sh                         # 🔧 도구 일괄 설치 스크립트
│
├── .claude/
│   ├── agents/                      # 🤖 에이전트 정의 (9개)
│   │   ├── pwn.md                   #    PWN: Ghidra + GDB + pwntools
│   │   ├── rev.md                   #    REV: Ghidra + GDB + Frida + z3
│   │   ├── web.md                   #    WEB: ffuf + sqlmap + dalfox
│   │   ├── crypto.md                #    CRYPTO: SageMath + z3 + hashcat
│   │   ├── forensics.md             #    FORENSICS: binwalk + volatility3
│   │   ├── web3.md                  #    WEB3: Slither + Mythril + Foundry
│   │   ├── critic.md                #    교차 검증 (GDB/Ghidra 재확인)
│   │   ├── verifier.md              #    로컬 3회 + 리모트 플래그
│   │   └── reporter.md              #    한국어 writeup 작성
│   ├── hooks/                       # 🪝 자동 트리거
│   │   ├── knowledge_inject.sh      #    지식 자동 주입
│   │   └── check_agent_completion.sh #    완료 검증
│   ├── rules/
│   │   └── ctf_pipeline.md          #    카테고리별 파이프라인 + 게이트
│   └── settings.json                #    도구 권한 + 훅 등록
│
├── tools/
│   ├── state.py                     # 💾 SQLite fact store + checkpoint
│   ├── knowledge.py                 # 🔍 FTS5 지식 검색 (동의어 확장)
│   ├── quality_gate.py              # 🚦 파이프라인 품질 게이트
│   ├── context_digest.py            # 📝 대용량 출력 압축
│   └── gemini_query.sh              # 🤖 Gemini 요약 래퍼
│
├── knowledge/
│   ├── index.md                     # 문제 인덱스
│   ├── kb.db                        # FTS5 인덱스 (gitignore)
│   ├── techniques/                  # 기법 문서 (12개+)
│   └── challenges/                  # 풀이 기록 (gitignore)
│
├── reports/                         # 세션 리포트 출력
└── challenges/                      # 추출된 챌린지 파일
```

---

## 🛠 설치

### 요구사항

- Ubuntu 24.04 LTS (WSL2 지원)
- Python 3.12+
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) (인증 완료 상태)

### 자동 설치

```bash
git clone https://github.com/your-repo/Machine.git
cd Machine
./setup.sh
```

설치되는 도구:

| 카테고리 | 도구 |
|---------|------|
| **PWN/REV** | gdb, GEF, Ghidra, checksec, patchelf, pwntools, ROPgadget, one_gadget |
| **Web** | sqlmap, ffuf, dalfox, commix |
| **Crypto** | hashcat, john, SageMath, z3, RsaCtfTool |
| **Forensics** | binwalk, tshark, steghide, zsteg, exiftool, foremost, volatility3 |
| **Web3** | Slither, Mythril, Foundry (forge/cast/anvil) |
| **RE** | Frida, angr, Ghidra MCP |

---

<div align="center">

**Machine** — *문제를 풀고, 기록하고, 학습하는 자율 CTF 에이전트*

</div>
