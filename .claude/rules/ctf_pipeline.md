# Machine — CTF Pipeline

## Category Detection (Orchestrator MANDATORY)

Before spawning any agent, identify the challenge category:

```
1. Read challenge description / README
2. Check file types: ELF/PE/Mach-O → pwn or rev | .py/.js/URL → web or crypto | pcap/img/zip → forensics | .sol/.abi → web3
3. Check challenge tags if provided
4. If ambiguous → ask user
```

## Pipelines by Category

### PWN
```
pwn → critic → verifier → reporter
```
| Agent | Tools | Output |
|-------|-------|--------|
| pwn | Ghidra MCP (static), gdb+GEF (dynamic), checksec, ROPgadget, one_gadget, pwntools | solve.py |
| critic | gdb — cross-verify offsets/addresses | critic_review.md |
| verifier | local 3x run → remote run | flag |

### REV
```
rev → critic → verifier → reporter
```
| Agent | Tools | Output |
|-------|-------|--------|
| rev | Ghidra MCP (static), gdb+GEF, Frida (anti-debug/unpacking), z3, angr, strace/ltrace | solve.py |
| critic | verify algorithm description vs binary behavior | critic_review.md |
| verifier | python3 solve.py \| ./binary | flag |

### WEB (3-Phase 강제)
```
web → web-docker → web-remote → critic → verifier → reporter
```
| Agent | Phase | Tools | Output |
|-------|-------|-------|--------|
| web | 1. 소스 분석 | Read, Grep, Glob (네트워크 도구 금지) | web_analysis.md, solve.py 초안 |
| web-docker | 2. 로컬 검증 | docker compose, curl localhost, python3 solve.py | docker_test_report.md (2/2 성공 필수) |
| web-remote | 3. 리모트 플래그 | python3 solve.py (TARGET=REMOTE) | remote_output.txt, flag |
| critic | 검증 | cross-verify exploit logic | critic_review.md |
| verifier | 최종 확인 | flag format validation | flag |

**Phase 순서 절대 위반 금지:**
- web 에이전트는 서버에 HTTP 요청을 보내지 않는다
- web-docker는 localhost만 공격한다 (리모트 접근 금지)
- web-remote는 로컬 2/2 성공 후에만 실행된다

### CRYPTO
```
crypto → critic → verifier → reporter
```
| Agent | Tools | Output |
|-------|-------|--------|
| crypto | z3, SageMath, pycryptodome, RsaCtfTool, hashcat/john | solve.py |
| critic | math/logic cross-verify | critic_review.md |
| verifier | python3 solve.py → flag | flag |

### FORENSICS
```
forensics → critic → verifier → reporter
```
| Agent | Tools | Output |
|-------|-------|--------|
| forensics | binwalk, zsteg, steghide, tshark, volatility3, exiftool, foremost | forensics_report.md |
| critic | verify extraction chain, source artifact | critic_review.md |
| verifier | confirm flag | flag |

### WEB3
```
web3 → critic → verifier → reporter
```
| Agent | Tools | Output |
|-------|-------|--------|
| web3 | Slither (static), Mythril (symbolic), Foundry forge+cast (dynamic), Semgrep | Exploit.t.sol |
| critic | verify exploit logic, storage slots, gas limits | critic_review.md |
| verifier | forge test -vvvv → flag/ownership captured | flag |

---

## Quality Gate Checks (MANDATORY between stages)

```
worker → [artifact-check --stage critic] → critic
critic → [artifact-check --stage verifier] → verifier
verifier → [artifact-check --stage reporter] → reporter
```

```bash
# Before critic
python3 tools/quality_gate.py artifact-check <challenge_dir> --stage critic

# Before verifier (critic must have APPROVED)
python3 tools/quality_gate.py artifact-check <challenge_dir> --stage verifier

# Before reporter
python3 tools/quality_gate.py artifact-check <challenge_dir> --stage reporter
```

Gate exit 1 → do NOT proceed. Fix issues first.

---

## Failure Protocol

- 3 failures same approach → STOP, try fundamentally different approach
- 5 total failures → search writeups + knowledge base
- Remote flag only — local flag files are FAKE
