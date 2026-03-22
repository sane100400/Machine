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

### WEB
```
web → critic → verifier → reporter
```
| Agent | Tools | Output |
|-------|-------|--------|
| web | curl, sqlmap, dalfox, ffuf, SSRFmap, commix, Playwright MCP, PayloadsAllTheThings | solve.py |
| critic | verify exploit logic, auth bypass, injection proof | critic_review.md |
| verifier | run exploit → flag capture | flag |

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

## Failure Protocol

- 3 failures same approach → STOP, try fundamentally different approach
- 5 total failures → search writeups + knowledge base
- Remote flag only — local flag files are FAKE
