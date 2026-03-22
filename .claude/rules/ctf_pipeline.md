# Machine — CTF Pipeline

## Category Detection (Orchestrator MANDATORY)

Before spawning any agent, identify the challenge category:

```
1. Read challenge description / README
2. Check file types: ELF/PE/Mach-O → pwn or rev | .py/.js/URL → web or crypto | pcap/img/zip → forensics
3. Check challenge tags if provided
4. If ambiguous → ask user
```

## Pipelines by Category

### PWN
```
pwn-reverser → pwn-trigger → pwn-chain → critic → verifier → reporter
```
| Agent | Tools | Output |
|-------|-------|--------|
| pwn-reverser | Ghidra MCP (static), gdb+GEF (dynamic), checksec, ROPgadget | reversal_map.md |
| pwn-trigger | gdb+pwndbg, pwntools cyclic | trigger_report.md + trigger_poc.py |
| pwn-chain | pwntools, ROPgadget, rp++, gdb+GEF, one_gadget, libc-database | solve.py |
| critic | gdb — cross-verify offsets/addresses | — |
| verifier | local 3x run → remote run | flag |

### REV
```
rev-reverser → rev-solver → critic → verifier → reporter
```
| Agent | Tools | Output |
|-------|-------|--------|
| rev-reverser | Ghidra MCP (static), gdb+GEF, Frida (anti-debug/unpacking), strace/ltrace | reversal_map.md |
| rev-solver | z3, angr, sympy, SageMath, GDB oracle, unicorn | solve.py |
| critic | verify algorithm description vs binary behavior | — |
| verifier | python3 solve.py \| ./binary | flag |

### WEB
```
web-ctf → [crypto-solver] → critic → verifier → reporter
```
| Agent | Tools | Output |
|-------|-------|--------|
| web-ctf | curl, sqlmap, dalfox, ffuf, SSRFmap, commix, Playwright MCP, PayloadsAllTheThings | web_ctf_report.md + solve.py |
| crypto-solver | (optional) if JWT/hash/crypto component | solve.py supplement |
| verifier | run exploit → flag capture | flag |

### CRYPTO
```
crypto-solver → critic → verifier → reporter
```
| Agent | Tools | Output |
|-------|-------|--------|
| crypto-solver | z3, SageMath, pycryptodome, RsaCtfTool, hashcat/john | solve.py |
| critic | math/logic cross-verify | — |
| verifier | python3 solve.py → flag | flag |

### FORENSICS
```
forensics → [rev-solver] → critic → verifier → reporter
```
| Agent | Tools | Output |
|-------|-------|--------|
| forensics | binwalk, zsteg, steghide, tshark, volatility3, exiftool, foremost | forensics_report.md |
| rev-solver | (optional) if decryption/algorithm inversion needed | solve.py |
| verifier | confirm flag | flag |

### WEB3
```
web3-auditor → critic → verifier → reporter
```
| Agent | Tools | Output |
|-------|-------|--------|
| web3-auditor | Slither (static), Mythril (symbolic), Foundry forge+cast (dynamic), Semgrep | web3_report.md + Exploit.t.sol |
| critic | verify exploit logic, storage slots, gas limits | — |
| verifier | forge test -vvvv → flag/ownership captured | flag |

---

## Trivial Exception

If ALL of the following:
- Source code provided AND
- Vuln visible in 1-3 lines AND
- One-liner exploit AND
- <5 min estimated

→ Use `ctf-solver` (single agent, skip pipeline)

---

## Failure Protocol

- 3 failures same approach → STOP, try fundamentally different approach
- 5 total failures → search writeups + knowledge base
- Remote flag only — local flag files are FAKE

## Flag Formats

DH{...}, FLAG{...}, flag{...}, CTF{...}, GoN{...}, CYAI{...}
