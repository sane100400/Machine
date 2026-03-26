# Machine v2 — CTF Pipeline

## Orchestrator Boundary (MANDATORY)

The orchestrator (main Claude session) coordinates but does NOT solve:
- **DO**: Run triage, spawn @solver, run learn.py, fix 1-2 line bugs in solver output
- **DO NOT**: Write solve.py from scratch, do full binary analysis, replace the solver
- **Why**: Solver gets a fresh context window. Orchestrator context is for coordination and retries.

## Triage-First Flow (MANDATORY)

Before any solving, run triage:

```bash
python3 tools/triage.py <challenge_dir> [--category CAT]
```

This outputs: category, difficulty, pipeline mode, knowledge context.

## Category Detection

triage.py auto-detects, but you can verify:
```
ELF/PE + network funcs → pwn
ELF/PE + correct/wrong strings → rev
docker-compose + app code → web
.py + output.txt (no binary) → crypto
.pcap/.mem/.img/images → forensics
.sol/foundry.toml → web3
```

## Pipeline Modes

### Lightweight (easy/medium)

```
triage.py → @solver (with knowledge context)
              ↓
           solve.py works? → flag → learn.py record
              ↓ (stuck 3x)
           @critic → feedback → re-spawn @solver
```

- Solver does EVERYTHING: analysis, exploit, local verification
- No mandatory critic or verifier unless solver requests it
- This is the DEFAULT mode

### Full (hard)

```
triage.py → @solver (with knowledge context)
              ↓
           solve.py → @critic (cross-verify)
              ↓
           @verifier (remote flag extraction)
              ↓
           learn.py record
```

- Used when: difficulty=hard, or multiple solver failures
- Critic validates offsets, logic, and exploit chain
- Verifier handles remote-only execution

## Web Challenge Flow

Even in lightweight mode, web challenges follow this order:

```
1. Source analysis ONLY (read code, no requests)
2. docker compose up -d → exploit on localhost
3. Verify 2/2 local runs succeed
4. Only then → remote server

All phases done by @solver — no separate web/web-docker/web-remote agents.
```

## Solver Prompt Template

```
[CRITICAL FACTS]
Flag format: <from config.json>
Server: <if provided>
Category: <from triage>

<knowledge_context from triage.py --context>

Challenge directory: <path>
Files: <list>

Solve this CTF challenge. Save solve.py to the challenge directory.
If you get stuck after 3 approaches, spawn @critic for review.
```

## Failure Protocol

| Failures | Action |
|----------|--------|
| 1-2 | Normal iteration — debug and fix |
| 3 same approach | STOP that approach, try fundamentally different one |
| 3 different approaches | Spawn @critic for second opinion |
| 5 total | Search writeups (WebSearch), check knowledge base |
| 7 total | STOP. Record failure via learn.py. Move on. |

## Quality Gates (Full Pipeline Only)

Only used in full pipeline mode (hard challenges):

```bash
# Before critic
python3 tools/quality_gate.py artifact-check <challenge_dir> --stage critic

# Before verifier
python3 tools/quality_gate.py artifact-check <challenge_dir> --stage verifier
```

Gate exit 1 → fix issues before proceeding.

## Learning Loop (ALWAYS)

Runs after every challenge attempt, success or failure:

```bash
# Success
python3 tools/learn.py record --challenge-dir DIR --status success \
    --flag "FLAG{...}" --category <cat>

# Failure
python3 tools/learn.py record --challenge-dir DIR --status failed \
    --category <cat> --notes "reason for failure"
```

This ensures the knowledge DB grows with every attempt.
