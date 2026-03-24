# GDB Oracle Reverse — Custom VM Inverse Computation Technique

## Applicable Conditions
- When a Custom VM computes a nonlinear T function
- When the input to the T function can be controlled by memory patching
- When inverse computation of round-based ciphers such as Feistel/SPN is needed
- When angr fails due to state explosion

## Core Idea
Use GDB as a "T function oracle":
1. Run the binary in GDB
2. Identify the memory address where the T function reads its state
3. Patch that memory to the desired value
4. Continue so the VM computes T
5. Read the T result value at a breakpoint

This allows obtaining T(state, round) for any arbitrary state.

## Feistel Inverse Computation Pattern

### Forward (known structure)
```
Round i (0~15):
  H2_new = H2 - T_h2(H1, i)
  H1_new = H1 - T_h1(H2_new, i)
```

### Reverse (target → input)
```
Round i (15~0, reversed):
  # Inverse H1: H1_prev = H1 + T_h1(H2, i)
  T_h1 = oracle(H2, round=i)   # Obtain T via GDB patch
  H1_prev = H1 + T_h1

  # Inverse H2: H2_prev = H2 + T_h2(H1_prev, i)
  T_h2 = oracle(H1_prev, round=i)
  H2_prev = H2 + T_h2
```

## Implementation Pattern (Python + GDB batch)

```python
import subprocess, struct

BINARY = "./target"
# Use disable-randomization on for fixed PIE address

def run_gdb_oracle(patch_addr, patch_value, read_bp, read_expr, round_bp_count):
    """Run GDB to patch specific memory and read a value at a breakpoint"""
    gdb_commands = f'''
set disable-randomization on
break *$PIE_BASE+0xXXXX
run <<< "AAAAAAAAAAAAAAAA"
# continue until round_bp_count-th hit
# patch memory
set {{long}}{patch_addr} = {patch_value}
# continue until T function computation breakpoint
continue
# read T result
print/x {read_expr}
quit
'''
    result = subprocess.run(['gdb', '-batch', '-x', '/tmp/gdb_script.gdb', BINARY],
                          capture_output=True, timeout=10)
    # parse output for T value
    return parse_t_value(result.stdout)
```

## Notes
- **PIE binary**: `set disable-randomization on` is required (fixes addresses)
- **mmap address**: Even with ASLR disabled, mmap can change → need to find mmap address at runtime
- **Round identification**: Track round number by breakpoint hit count
- **Memory patch timing**: Must patch **before** the T function reads the state
- **Total GDB executions**: Feistel 16 rounds → 32 times (T_h1 + T_h2 per round)

## References
- First applied: Damnida challenge (Custom VM, Feistel 16 rounds)
- Implementation code: `tests/wargames/extracted/Damnida/reverse_feistel.py`
- Detailed analysis: `knowledge/challenges/damnida.md`
