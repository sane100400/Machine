# Machine

> CTF 자율 해결 에이전트 시스템 — Claude Code 기반 멀티 에이전트 파이프라인

---

## 개요

Machine은 CTF(Capture The Flag) 문제를 자율적으로 분석하고 풀이하는 에이전트 시스템이다.
카테고리별 전문 에이전트가 파이프라인을 형성하고, 오케스트레이터가 조율한다.

- **할루시네이션 방지**: 모든 숫자 상수(offset, address)는 실제 툴 출력 파일로 검증
- **상태 코드 관리**: SQLite 기반 fact store로 에이전트 간 검증된 사실만 전달
- **자동 지식 주입**: 에이전트 스폰 시 관련 기법 문서 자동 주입
- **Fake Idle 감지**: 에이전트 종료 시 자동으로 완료 여부 검증

---

## 아키텍처

```
┌─────────────────────────────────────────────────────┐
│                   Orchestrator                      │
│  카테고리 감지 → 파이프라인 선택 → 에이전트 조율      │
└──────────────────────┬──────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   PWN Pipeline   REV Pipeline   WEB Pipeline  ...
        │              │              │
        ▼              ▼              ▼
  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │ reverser │  │ reverser │  │ web-ctf  │
  │ trigger  │  │ solver   │  │  critic  │
  │  chain   │  │  critic  │  │ verifier │
  │  critic  │  │ verifier │  └──────────┘
  │ verifier │  └──────────┘
  └──────────┘
        │
        ▼
  ┌──────────────────────────────────┐
  │         state.db (SQLite)        │
  │  key │ value │ source │ verified │  ← 검증된 사실만
  └──────────────────────────────────┘
```

---

## 파이프라인

| 카테고리 | 파이프라인 | 모델 |
|---------|-----------|------|
| **PWN** | pwn-reverser → pwn-trigger → pwn-chain → critic → verifier | reverser/trigger: sonnet, chain: opus |
| **REV** | rev-reverser → rev-solver → critic → verifier | reverser: sonnet, solver: opus |
| **WEB** | web-ctf → [crypto-solver] → critic → verifier | sonnet |
| **CRYPTO** | crypto-solver → critic → verifier | opus |
| **FORENSICS** | forensics → [rev-solver] → critic → verifier | sonnet |
| **WEB3** | web3-auditor → critic → verifier | opus |
| **TRIVIAL** | ctf-solver | sonnet |

---

## 디렉토리 구조

```
Machine/
├── CLAUDE.md                        # 오케스트레이터 규칙 + 파이프라인 정의
│
├── .claude/
│   ├── agents/                      # 에이전트 정의
│   │   ├── pwn-reverser.md
│   │   ├── pwn-trigger.md
│   │   ├── pwn-chain.md
│   │   ├── rev-reverser.md
│   │   ├── rev-solver.md
│   │   ├── web-ctf.md
│   │   ├── crypto-solver.md
│   │   ├── forensics.md
│   │   ├── web3-auditor.md
│   │   ├── critic.md
│   │   ├── verifier.md
│   │   ├── reporter.md
│   │   ├── ctf-solver.md
│   │   └── _reference/
│   │       └── tools_inventory.md   # 툴 커맨드 레퍼런스
│   ├── hooks/
│   │   ├── knowledge_inject.sh      # PreToolUse: 에이전트 스폰 시 지식 주입
│   │   └── check_agent_completion.sh # SubagentStop: Fake Idle / 할루시네이션 감지
│   ├── rules/
│   │   └── ctf_pipeline.md          # 카테고리별 파이프라인 상세
│   └── settings.local.json          # 훅 등록 + 툴 권한
│
├── tools/
│   ├── state.py                     # SQLite fact store + checkpoint CLI
│   └── knowledge.py                 # FTS5 지식 검색 CLI
│
└── knowledge/
    ├── index.md                     # 풀었거나 시도한 문제 인덱스
    ├── kb.db                        # FTS5 인덱스 (gitignore)
    ├── techniques/                  # 기법 문서 (12개)
    │   ├── heap_house_of_x.md
    │   ├── web_ctf_techniques.md
    │   └── ...
    └── challenges/                  # 개인 풀이 기록 (gitignore)
        ├── _template.md
        └── <challenge>.md
```

---

## 핵심 도구

### state.py — 검증된 Fact Store

에이전트 간 할루시네이션을 막는 SQLite 기반 상태 관리.
모든 사실에는 실제 툴 출력 파일 출처(`--src`)가 필요하다.

```bash
export CHALLENGE_DIR=/path/to/challenge

# fact 기록 — 반드시 --src로 출처 파일 첨부
gdb -batch -ex "info address main" ./binary 2>&1 | tee /tmp/gdb.txt
python3 tools/state.py set --key main_addr --val 0x401234 --src /tmp/gdb.txt --agent pwn-reverser

# fact 조회
python3 tools/state.py get --key main_addr
python3 tools/state.py facts           # 전체 덤프

# handoff 전 아티팩트 검증 (실패 시 파이프라인 블로킹)
python3 tools/state.py verify --artifacts reversal_map.md trigger_poc.py

# checkpoint
python3 tools/state.py checkpoint --agent pwn-reverser --phase 2 --phase-name gdb_verify --status in_progress
python3 tools/state.py checkpoint --read
```

### knowledge.py — FTS5 지식 검색

에이전트가 분석 중 언제든 기법 문서를 검색할 수 있다.

```bash
# 검색
python3 tools/knowledge.py search "tcache poisoning glibc 2.35"
python3 tools/knowledge.py search "prototype pollution RCE node"

# 인덱스 갱신 (새 파일 추가 후)
python3 tools/knowledge.py add knowledge/techniques/new_technique.md
python3 tools/knowledge.py index   # 전체 재인덱싱
python3 tools/knowledge.py status  # 현황 확인
```

검색 결과 없음 → 에이전트는 즉시 WebSearch로 폴백한다.

---

## Hooks

| Hook | 트리거 | 역할 |
|------|-------|------|
| `knowledge_inject.sh` | PreToolUse (Task/Agent) | 에이전트 스폰 직전 관련 기법 FTS 검색 → systemMessage 주입 |
| `check_agent_completion.sh` | SubagentStop | checkpoint.json 읽어 Fake Idle / 할루시네이션 / 에러 자동 감지 → 오케스트레이터에게 경고 |

---

## Writeup 저장

```bash
# 템플릿 복사
cp knowledge/challenges/_template.md knowledge/challenges/<challenge-name>.md

# 작성 후 인덱스 갱신
python3 tools/knowledge.py add knowledge/challenges/<challenge-name>.md

# knowledge/index.md 업데이트
```

풀이 기록은 FTS 인덱싱돼 이후 유사 문제에 자동으로 참조된다.
(`.gitignore`로 개인 writeup은 push 제외)

---

## 향후 개선 방향

### 단기
- **Frida MCP** — 런타임 hook / instrumentation 자동화 (REV anti-debug 우회)
- **기법 문서 확장** — Crypto (RSA 공격 계열), Forensics (메모리/PCAP 심화) 추가
- **지식 검색 개선** — 동의어 매핑, 검색 미스 시 WebSearch 자동 폴백

### 중기
- **Mobile 파이프라인** — `android-reverser` + `android-exploit` 에이전트 추가
- **Kernel 파이프라인** — `kernel-reverser` + `kernel-exploit` 에이전트 추가
- **병렬 실행** — reverser + trigger 동시 실행 (DAG 의존성 모델)

### 장기
- **자동 오류 분류** — 에러 타입 감지 → 자동 pivot 전략
- **과거 풀이 유사도 검색** — TF-IDF / embedding 기반 유사 챌린지 제안

---

## 플래그 형식

`DH{...}` `FLAG{...}` `flag{...}` `CTF{...}` `GoN{...}` `CYAI{...}`

**로컬 flag 파일은 가짜다. 반드시 `remote(host, port)`로 검증한다.**
