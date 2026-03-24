# WASM CTF Challenge Lessons + General Efficiency Improvements

## Origin
ultrushawasm challenge: 3-4 sessions, 10+ agents, estimated 500K-1M+ tokens consumed.
15+ attempts all failed (flag not obtained).
Root causes: pipeline mismatch, duplicate analysis, ignoring hints, missing tools.

---

## Problem 1: Agent Pipeline Mismatch

### Current pipeline
```
reverser → trigger → chain → verifier → reporter (6-agent, pwn optimized)
```

### Problem
- This pipeline is optimized for **memory corruption pwn** (BOF, format string, UAF)
- WASM reversing is not a "find crash → expand primitives → chain" pattern
- trigger/chain agents had nothing to do and repeated the same analysis

### Improvement: Select pipeline based on problem type
```
if problem_type == "reversing":
    reverser(deep) → solver(direct solve) → verifier → reporter  (3-agent)
elif problem_type == "pwn":
    reverser → trigger → chain → verifier → reporter  (5-agent, current)
elif problem_type == "web":
    scanner → analyst → exploiter → reporter  (4-agent)
elif problem_type == "crypto":
    reverser → solver(z3/sympy) → verifier → reporter  (3-agent)
```

**Key difference in reversing pipeline**: Instead of trigger/chain, a single **solver** directly solves based on analysis results.

## Problem 2: Duplicate Analysis (largest token waste)

### Duplications that occurred
| Agent | What was done | Duplicate? |
|----------|--------|-------|
| reverser | WAT file analysis | original |
| chain | WAT file re-analysis | duplicate |
| chain-2 | WAT file analyzed again | duplicate |
| DWARF analysis agent | WAT + binary analysis | partially duplicate |
| WAT deep analysis agent | full WAT re-analysis | duplicate |

**5 agents reading the same 68K-line WAT file** = minimum 300K token waste

### Improvement: "Analysis result document" pattern
```
1. reverser analyzes → reversal_map.md (key findings + recommended strategy)
2. Subsequent agents read only reversal_map.md instead of the WAT file
3. When additional analysis is needed, make specific re-requests to the reverser
```

**Rule**: Do not have multiple agents directly read 68K-line files. Pass through summary documents.

## Problem 3: Hints Not Utilized

### Ignored hints
- **"Bruteforce no need"** → tried 40+ SSH passwords (direct contradiction)
- **"Almost every program has a backdoor"** → found the backdoor (authorized→sh), but after realizing it doesn't work in WASI, didn't look for another backdoor
- **"contains some pwn stuff"** → pwn = memory corruption, but didn't sufficiently explore pwn in the WASM memory model
- **Solver comment "hit a wall"** → signal that a special technique is needed, not just simple reversing

### Improvement: Hint-based hypothesis prioritization
```
At start of task:
1. Parse hints to generate hypothesis list
2. Assign priority to each hypothesis (based on hint alignment)
3. Immediately exclude approaches that contradict hints
4. After 3 failures, re-read hints and reinterpret
```

## Problem 4: Missing Tools

### Tools that were absent and caused inefficiency
| Required Tool | Current Alternative | Inefficiency |
|-------------|-----------|--------|
| WASM-specific analyzer | wasm2wat + grep/read | manual search through 68K lines |
| CTF writeup DB search | web search (not executed) | unable to reference similar problem solutions |
| Interactive binary exploit | manual Python socket | pwntools interact pattern not utilized |
| WASM runtime debugger | none | cannot observe memory state in real time |

### Recommended MCP servers / tools

#### 1. CTF Writeup Search MCP (highest ROI)
```
Function: search CTFtime, GitHub, blogs for similar challenge writeups
Effect: by searching "ultrushawasm writeup" or "WASM CTF backdoor"
      can understand solve patterns in 10 minutes
Implementation: WebSearch MCP or custom crawler
```

#### 2. WASM Analysis MCP
```
Functions:
- wasm2wat + per-function extraction (only functions of interest, not full 68K lines)
- data section parsing (automatic string/constant extraction)
- import/export list
- call graph generation
Effect: 80% reduction in reverser agent analysis time
Implementation: wabt (wasm2wat, wasm-objdump) + wasm-tools wrapper
```

#### 3. Pwntools Interactive MCP
```
Functions:
- remote(host, port) connection
- send/recv/interactive patterns
- precise timing control
- automatic binary patching (ELF/WASM)
Effect: no need to write manual socket code, automated exploit testing
Implementation: pwntools Python wrapper MCP
```

#### 4. CTF Knowledge Base MCP
```
Functions:
- local knowledge/ index search
- automatic matching of similar challenges
- failure pattern warnings ("this approach failed in challenge X")
Effect: prevents repeating the same mistakes
Implementation: local vector DB + automatic knowledge/ indexing
```

## Problem 5: 3-Strike Rule Not Followed

### Violations in ultrushawasm
```
Attempt 1-3: authentication path analysis (OK, succeeded)
Attempt 4-6: SSH access (failed → continued = ignored hints)
Attempt 7-9: binary patching → exploring server deployment methods (failed × 3)
Attempt 10-12: WASM internal flag search (failed × 3)
Attempt 13-15: server behavior modification tests (failed × 3)
```

**15 attempts, 3+ failures in each of 4 categories** → maximized total consumption.

### Improved 3-Strike application
```
Category 1: authentication (succeeded within 3) ✅
Category 2: SSH (1 failure + hint contradiction) → stop immediately ⛔
Category 3: binary patching (1 local success, 1 remote failure) → switch deployment method or stop
Category 4: different approach needed → search writeups, investigate platform features
```

Ideally should have switched to writeup search after 4-5 attempts.

---

## Generalized Principles (to add to efficient_solving.md)

### Principle 7: Choose a pipeline appropriate for the problem type
- Reversing ≠ Pwn ≠ Web ≠ Crypto
- Each requires different agent composition and flow
- Especially in reversing, trigger/chain may be unnecessary

### Principle 8: Pass large files through summary documents
- Sharing large files between agents = token explosion
- reverser summarizes key findings in reversal_map.md
- Subsequent agents read only the summary

### Principle 9: Immediately exclude approaches that contradict hints
- CTF hints are intentional. "Bruteforce no need" = do not attempt brute force
- Use hints as a hypothesis filter

### Principle 10: 5 failed attempts → search external knowledge
- Search CTFtime, GitHub, blogs for similar problems
- Keywords like "WASM CTF backdoor exploit"
- Use community knowledge when you can't solve it alone

### Principle 11: Minimize number of agents
- Only spawn agents when there is a clear task
- Do not spawn agents "just in case"
- Default is 1 analysis agent, 1 execution agent

---

## Prompt Modification Suggestions

### CLAUDE.md modifications
1. Add **problem type pipeline branching** (reversing vs pwn vs web vs crypto)
2. Add **hint parsing step** (analyze hints before forming the team)
3. Add **large file policy** (make summary document pattern mandatory)
4. Add **external search trigger** (5 failures → search writeups)
5. Strengthen **agent spawn conditions** (do not spawn without a specific task)

### Agent prompt modifications
- reverser.md: must include "Recommended Solver Strategy" section
- chain.md: "Do not directly read WAT/binary files, read only reversal_map.md"
- verifier.md: "Recommend writeup search after 5 failures"
