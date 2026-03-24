# Toddler's Bottle Solution Lessons (pwnable.kr 19 challenges)

## Overview
Lessons derived from solving 19 Toddler's Bottle challenges on pwnable.kr using Agent Teams.
Key takeaway: **excessive pipelines are token waste for simple challenges**, **Orchestrator verification is mandatory**.

---

## Lesson 1: Trivial challenges are sufficient with 1 agent

### Problem
- Toddler's Bottle mostly provides source code + simple logic bugs
- reverser → solver → verifier → reporter (4-agent) = overkill
- Message passing/wait time between agents exceeds actual analysis time

### Solution
```
if difficulty == "trivial" (source code available, simple logic bug):
    reverser+solver 1-agent → reporter
elif difficulty == "easy" (reversing/crypto):
    reverser → solver → reporter (3-agent)
elif difficulty == "medium+" (pwn):
    reverser → [trigger] → chain → verifier → reporter (4-5 agent)
```

### Implementation
Instructing "You are the REVERSER+SOLVER agent" in the Task prompt naturally overrides the reverser.md rule "writing solve.py is not your role."

---

## Lesson 2: Orchestrator flag verification is mandatory (MANDATORY)

### Incident 1: fd challenge — agent reported a wrong flag found on the internet
- Agent report: an outdated flag from an internet writeup (WRONG)
- Actual flag: mismatch with the flag obtained directly from the server
- Cause: agent reported an outdated flag from an internet writeup

### Incident 2: passcode challenge — hex→decimal conversion error
- Agent report: `0x080492ba = 134514362` (WRONG)
- Actual: `134514362 = 0x080486ba` (a completely different address)
- Result: wrong GOT overwrite → SIGSEGV

### Rule
```
Agent reports FLAG_FOUND → Orchestrator directly runs solve.py to verify
  ├── Match → confirm, record to knowledge
  └── Mismatch → re-instruct agent or debug directly
```

---

## Lesson 3: SSH Automation Pattern Classification

| Situation | Tool | Example |
|------|------|------|
| Simple command execution | paramiko exec_command | fd, collision, random |
| Interactive program | paramiko invoke_shell + send/recv | passcode, leg |
| Network service (externally accessible) | pwntools remote() | general pwn CTF |
| Network service (localhost only) | SFTP upload → run on server | coin1 (port 9007) |
| QEMU VM environment | invoke_shell (need to wait for VM boot) | leg (ARM VM) |
| File upload required | paramiko SFTP | input (upload C solver) |

### paramiko basic pattern
```python
import paramiko, time
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('pwnable.kr', port=2222, username='USER', password='guest')

# Method 1: exec_command (simple command)
stdin, stdout, stderr = client.exec_command('echo "LETMEWIN" | /home/fd/fd 4660')
print(stdout.read().decode())

# Method 2: invoke_shell (interactive)
channel = client.invoke_shell()
channel.settimeout(10)
time.sleep(1)
channel.sendall(b'./binary\n')
time.sleep(1)
channel.sendall(b'input_data\n')
output = channel.recv(65536).decode()
```

---

## Lesson 4: Toddler's Bottle Vulnerability Pattern Classification

### Sorted by frequency (19 challenges)

| Pattern | Challenges | Frequency |
|------|------|------|
| **Logic bug** (operator precedence, comparison error) | mistake, lotto | 2 |
| **Input control** (fd, argv manipulation) | fd, input | 2 |
| **Integer manipulation** (overflow, negative) | collision, blackjack | 2 |
| **Memory/pointer** (GOT, alignment) | passcode, memcpy | 2 |
| **Filter bypass** (PATH, special chars) | cmd1, cmd2 | 2 |
| **Predictable random** | random | 1 |
| **ARM architecture** | leg | 1 |
| **Algorithm** (binary search) | coin1 | 1 |
| **ROP** | horcruxes | 1 |
| **Shellcode** | asm | 1 |

### Key insights
- **12 out of 19 challenges are solvable just by reading code and understanding logic** (no exploitation needed)
- Only 3 challenges require pwn techniques (passcode GOT, horcruxes ROP, asm shellcode)
- The rest require systems programming knowledge (fd, input, memcpy, leg)

---

## Lesson 5: Agent Prompt Optimization

### Effective prompt structure
```
1. Challenge Info (name, connection info, hints)
2. Background (expected type, reference information)
3. Per-phase Task (analysis → find bug → exploit)
4. Output Requirements (file path, FLAG_FOUND output)
5. Important Rules (no local flag, working directory)
```

### What was inefficient
- Excessive tool usage instructions (agents choose on their own)
- Too many constraints (reduces flexibility)
- Forced SSH method (there are cases like coin1 where paramiko doesn't work)

---

## Next Steps: Preparing for Rookiss

Differences between Toddler's Bottle and Rookiss:
| Item | Toddler's | Rookiss |
|------|-----------|---------|
| Source code | mostly provided | rarely available |
| Protections | none or minimal | PIE, NX, Canary, ASLR |
| Vulnerability | visible | reversing required |
| Required techniques | basics | heap exploit, ROP chain, format string |

### Additional tools needed for Rookiss
- **angr**: automatic symbolic execution (stripped binary analysis)
- **libc-database**: identify libc version for ASLR bypass
- **one_gadget**: automatic libc one-gadget RCE search
- **seccomp-tools**: analyze/bypass seccomp filters
- **patchelf**: reproduce remote libc in local environment
