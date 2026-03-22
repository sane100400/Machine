# House-of-* Heap Exploitation Techniques (CTF Quick Reference)

## Master Matrix: All House-of-* Techniques

| Technique | glibc | Target | Prerequisite | One-Liner | Difficulty |
|-----------|-------|--------|--------------|-----------|------------|
| **House of Spirit** | 2.23+ | fastbin | Fake chunk header | Free fake fastbin chunk → malloc returns arbitrary ptr | Easy |
| **House of Lore** | 2.23+ | smallbin | Overwrite smallbin fd/bk | Corrupt smallbin list → malloc smallbin returns arbitrary | Medium |
| **House of Force** | <2.29 | top chunk | Top size overflow | Overwrite top chunk size → malloc huge allocation → arbitrary write | Medium |
| **House of Orange** | <2.26 | top chunk + FSOP | abort() trigger | Corrupt top chunk, trigger malloc consolidation → abort() FSOP | Hard |
| **House of Einherjar** | 2.23+ | prev_size | Single null byte | Overflow null byte in prev_size → fake consolidation → leak | Medium |
| **House of Tangerine** | 2.26+ | top chunk + tcache | tcache corruption | Abuse top chunk + tcache → arbitrary pointer (leakless) | Hard |
| **House of Water** | 2.36+ | tcache | UAF/double-free | Leakless tcache metadata control → arbitrary pointer | Hard |
| **House of Storm** | <2.29 | large/unsorted | UAF large chunk | Corrupt large+unsorted bin list → arbitrary malloc | Medium |
| **House of Roman** | <2.29 | fastbin + unsorted | All bins corrupted | Fake fastbins + unsorted attack + relative writes → RCE | Hard |
| **House of Gods** | <2.27 | arena | Multi-threaded | Thread arena hijack in 8 allocations → arbitrary malloc | Hard |
| **House of Mind (Fastbin)** | 2.23+ | fastbin + arena | Single byte overflow | Arena corruption via fastbin → heap pointer write | Medium |
| **House of IO** | 2.31-2.33 | tcache | UAF in tcache chunk | Corrupt tcache mgmt struct → arbitrary pointer | Medium |
| **House of Botcake** | 2.26+ | tcache | tcache double-free | Bypass tcache->bk==NULL check → double-free → arbitrary | Medium |
| **Tcache Poisoning** | 2.26+ | tcache | Heap leak (2.32+) | Corrupt tcache next ptr → malloc returns arbitrary | Easy |
| **Tcache Stashing Unlink** | 2.26+ | smallbin + tcache | Unlink corruption | Smallbin unlink + calloc → arbitrary address write | Hard |
| **Fastbin Reverse into Tcache** | 2.26+ | fastbin + tcache | Overwrite fastbin | Move fastbin chunk to tcache → arbitrary write | Medium |
| **Unsafe Unlink** | 2.23+ | doubly-linked | Heap overflow | Corrupt chunk metadata → unlink macro → arbitrary write | Medium |
| **Overlapping Chunks** | <2.29 | allocated chunks | Size field overflow | Overflow chunk size → allocate overlapping memory | Medium |
| **Unsorted Bin Attack** | <2.29 | unsorted bin | Unsorted corruption | Overwrite unsorted bin → write large value to arbitrary addr | Medium |
| **Unsorted Bin into Stack** | <2.29 | unsorted bin | Unsorted corruption | Similar to above but target stack address | Medium |
| **Poison Null Byte** | 2.23+ | chunk boundary | Null byte overflow | Single null byte → fake prev_size consolidation | Medium |
| **Large Bin Attack** | 2.23+ | large bin | Large bin corruption | Corrupt large bin → write to arbitrary address (size-aware) | Medium |
| **Fastbin Dup** | 2.23+ | fastbin | Heap spray | Allocate same fastbin twice (no checks pre-2.26) | Easy |
| **Fastbin Dup Consolidate** | 2.23+ | fastbin + top | Fastbin + top chunk | Place chunk on both fastbin and top → malloc double-use | Easy |
| **Decrypt Safe Linking** | 2.32+ | tcache/fastbin | Heap leak | Recover safe-linking pointer from encrypted fd (2.32+) | Medium |
| **Safe Link Double Protect** | 2.36+ | tcache | UAF + double-free | Protect pointer twice → bypass PROTECT_PTR | Hard |
| **Tcache Relative Write** | 2.30+ | tcache metadata | OOB write in tcache | Out-of-bounds metadata write → arbitrary value write | Hard |

## glibc Compatibility Matrix

```
glibc    │ Spirit │ Lore │ Force │ Orange │ Einherjar │ Tangerine │ Water │ Storm │ Roman │ Gods │ Botcake │ IO  │
────────┼────────┼──────┼───────┼────────┼───────────┼───────────┼───────┼───────┼───────┼──────┼─────────┼─────
2.23     │   ✓    │  ✓   │   ✓   │   ✓    │     ✓     │    -      │   -   │   ✓   │   ✓   │  ✓   │    -    │  -
2.24     │   ✓    │  ✓   │   ✓   │   ✓    │     ✓     │    -      │   -   │   ✓   │   ✓   │  ✓   │    -    │  -
2.25     │   ✓    │  ✓   │   ✓   │   ✓    │     ✓     │    -      │   -   │   ✓   │   ✓   │  ✓   │    -    │  -
2.26     │   ✓    │  ✓   │   ✓   │   ✗    │     ✓     │    ✓      │   -   │   ✓   │   ✓   │  ✗   │    ✓    │  -
2.27     │   ✓    │  ✓   │   ✓   │   ✗    │     ✓     │    ✓      │   -   │   ✓   │   ✓   │  ✗   │    ✓    │  -
2.28     │   ✓    │  ✓   │   ✓   │   ✗    │     ✓     │    ✓      │   -   │   ✓   │   ✓   │  ✗   │    ✓    │  -
2.29     │   ✓    │  ✓   │   ✗   │   ✗    │     ✓     │    ✓      │   -   │   ✗   │   ✗   │  ✗   │    ✓    │  -
2.30     │   ✓    │  ✓   │   ✗   │   ✗    │     ✓     │    ✓      │   -   │   ✗   │   ✗   │  ✗   │    ✓    │  -
2.31     │   ✓    │  ✓   │   ✗   │   ✗    │     ✓     │    ✓      │   -   │   ✗   │   ✗   │  ✗   │    ✓    │  ✓
2.32     │   ✓+L  │  ✓+L │   ✗   │   ✗    │     ✓     │    ✓      │   -   │   ✗   │   ✗   │  ✗   │    ✓    │  ✓
2.33     │   ✓+L  │  ✓+L │   ✗   │   ✗    │     ✓     │    ✓      │   -   │   ✗   │   ✗   │  ✗   │    ✓    │  ✓
2.34     │   ✓+L  │  ✓+L │   ✗   │   ✗    │     ✓     │    ✓      │   -   │   ✗   │   ✗   │  ✗   │    ✓    │  ✗
2.35     │   ✓+L  │  ✓+L │   ✗   │   ✗    │     ✓     │    ✓      │   -   │   ✗   │   ✗   │  ✗   │    ✓    │  ✗
2.36+    │   ✓+L  │  ✓+L │   ✗   │   ✗    │     ✓     │    ✓      │   ✓   │   ✗   │   ✗   │  ✗   │    ✓    │  ✗

Legend: ✓ = Works. ✗ = Patched/blocked. ✓+L = Works but requires leak. - = N/A
```

## Detailed Technique Breakdown

### Pre-2.29 (Golden Era)
**House of Force** (< 2.29): Overflow top chunk size field → malloc huge chunk → write anywhere
```c
// Overwrites top->size to -1 or large value
// Next malloc(size) returns ptr to target address
// Patch: Added check for top chunk size during allocation
```

**Unsorted Bin Attack** (< 2.29): Corrupt unsorted bin fd → write large value to *ptr
```c
// Corrupt unsorted_chunks(av)->fd
// Next malloc triggers: bck->fd = av  →  writes main_arena to target addr
// Patch: Added size field validation
```

**House of Storm** (< 2.29): UAF large + unsorted bin chunks
```c
// Free large, then unsorted → corrupt both bin lists
// malloc returns arbitrary chunk
// Patch: Hardened bin list checks
```

### 2.26+ Tcache Era (Introduced 2.26)
**Tcache Poisoning** (2.26+): Overwrite tcache->next pointer (requires leak on 2.32+)
```c
// tcache_perturb = random XOR on tcache next ptr (2.32+)
// Prerequisite: leak heap address to decrypt PROTECT_PTR
// No leak needed on 2.26-2.31
```

**House of Botcake** (2.26+): Bypass tcache double-free check
```c
// Free chunk A → Free chunk B → Free chunk A again
// Check: tcache[idx]->bk != NULL, but we can make it happen
// Result: arbitrary pointer from tcache
```

**House of Einherjar** (2.23+): Single null byte overflow → fake consolidation
```c
// Overflow last byte of prev_size of next chunk
// Next free triggers consolidation with fake prev chunk
// Unlink → leak or write
```

### 2.29+ (Top Chunk Hardening)
**House of Force patched**: Size validation blocks oversized allocations
**Unsorted Bin Attack patched**: Hardened validation prevents corruption

### 2.31 (Hook Removal Era)
**__malloc_hook / __free_hook removed** in 2.34+ (previously exploitable via libc ROP)

**House of IO** (2.31-2.33): Corrupt tcache mgmt struct via UAF
```c
// Heap UAF → corrupt tcache_perturb or counts
// Allows arbitrary pointer generation
// Patched 2.34+ with additional checks
```

### 2.32+ (Safe Linking Era)
**PROTECT_PTR encryption**: All tcache/fastbin pointers XOR'd with heap address
```
encrypted_ptr = ((ptr >> 12) ^ heap_addr) & MASK
```

**Decrypt Safe Linking**: Recover real pointer if heap leak available
```c
// decrypted = (encrypted_ptr << 12) ^ heap_addr
// Requires: heap leak (address of attacker-controlled chunk)
```

### 2.36+ (Newest Protections)
**House of Water**: Leakless tcache metadata control
```c
// UAF/double-free + tcache accounting bypass
// No heap leak needed → arbitrary pointer without disclosure
// Only relevant post-2.36
```

**Safe Link Double Protect**: Protect pointer twice
```c
// PROTECT_PTR(PROTECT_PTR(ptr)) → creates exploitable state
// Allows re-encryption tricks
```

## Quick Difficulty Reference

| Difficulty | Techniques | When to use |
|------------|-----------|------------|
| **Easy** (1-2 steps) | Fastbin Dup, Tcache Poisoning (2.26-2.31), House of Spirit | Direct heap corruption, no leak needed on old glibc |
| **Medium** (3-5 steps) | Lore, Botcake, Einherjar, Poison Null Byte, Large Bin Attack | Require controlled free/overflow but exploit path is linear |
| **Hard** (5+ steps) | Orange, Roman, Gods, Water, Tangerine | Multi-stage, require leakless exploits or arena manipulation |

## Post-2.34 Landscape (__malloc_hook Removal)

### What Was Removed
- `__malloc_hook` (arbitrary code execution via malloc)
- `__free_hook` (arbitrary code execution via free)
- `__realloc_hook`

### Modern Alternatives (2.34+)

1. **FSOP (File Structure Oriented Programming)**
   - Target: `_IO_list_all` linked list of FILE structures
   - Write fake FILE struct → call fclose() → vtable call → RCE
   - Still works post-2.34 but harder (needs FILE forgery)

2. **_IO_helper_jumps + setcontext**
   - Newer FSOP variant using setcontext gadgets
   - Requires: libc leak + ROP chain

3. **setcontext Gadgets** (if available)
   - Direct stack manipulation via setcontext(rdi)
   - Rare; most modern glibc hardens this

4. **execve() via ROP**
   - Most reliable: get code execution via ROP chain
   - malloc/free corruption → leak libc → ROP

### Practical CTF Strategy (Post-2.34)

```
Goal: RCE on glibc 2.34+

1. Heap corruption → leak libc address
   (e.g., unsorted bin chunk contains main_arena pointer)

2. Use heap primitive to corrupt:
   - .got entry (if writable, rare)
   - Stack canary (if leakable)
   - Function pointer in heap

3. ROP chain to execve("/bin/sh", 0, 0)
   - Requires: rop gadget chain from libc
   - Use: ropper or ROPgadget

4. Avoid FSOP on 2.34+ (possible but brittle)
```

## CTF Selection Flowchart

```
Do you have heap overflow?
├─ YES → Can you control prev_size of next chunk?
│   ├─ YES → House of Einherjar (single null byte) or Unsafe Unlink
│   └─ NO  → Continue below
├─ Can you control fastbin FD pointer?
│   ├─ YES → House of Spirit (fake chunk) or Fastbin Dup
│   └─ NO  → Continue below
├─ Can you corrupt unsorted bin?
│   ├─ YES & glibc < 2.29 → Unsorted Bin Attack
│   └─ YES & glibc >= 2.29 → Tcache attack chain
├─ Do you have heap leak?
│   ├─ YES → Tcache Poisoning (easiest arbitrary malloc)
│   ├─ Can you corrupt top chunk?
│   │   ├─ YES & glibc < 2.29 → House of Force
│   │   └─ YES & glibc >= 2.26 → House of Tangerine
│   └─ NO  → House of Water (2.36+) or House of Botcake (2.26+)
└─ Multi-threaded binary?
    └─ YES & glibc < 2.27 → House of Gods (arena hijack)
```

## One-Liner Exploitation Recipes

```bash
# Fastbin Dup (2.23-2.31): Allocate same chunk twice
# Free A → Allocate B (< fastbin_size) → Allocate A → Allocate C (same as A)
pwntools: p.malloc(fast_size) [x3] → same address returned

# House of Spirit (2.23+): Fake fastbin chunk
# Write fake chunk header → free(fake_ptr) → malloc(fastbin_size) = fake_ptr

# Tcache Poisoning (2.26+): Leak + corrupt next ptr
# Free chunk → leak heap → overwrite tcache->next → malloc returns arbitrary

# House of Einherjar: Null byte overflow → consolidation
# Overflow prev_size with 0x00 → free next chunk → triggers unlink

# Unsorted Bin Attack (< 2.29): Large allocation → unsorted bin
# Corrupt fd → malloc triggers: main_arena->fd = target_addr (write libc)

# Large Bin Attack (2.23+): Size-aware arbitrary write
# Corrupt large bin → malloc with controlled size → write to address

# Poison Null Byte: Same as Einherjar (limited null byte overflow)
```

## Tools & References

- **how2heap**: `~/tools/how2heap/` — 40+ technique implementations
- **pwntools**: `libc` module for leaking/corrupting
- **GEF/pwndbg**: `heap chunks`, `heap bins` commands
- **Ghidra/r2**: Reverse malloc implementation to understand checks

## Key Takeaway for CTF

1. **glibc < 2.29**: Easy wins with Force, Storm, Unsorted Bin Attack
2. **glibc 2.26-2.31**: Tcache era — Poisoning + Botcake dominate
3. **glibc 2.32+**: Safe Linking requires leak; Tcache Relative Write for leakless
4. **glibc 2.34+**: No hooks — focus on FSOP or ROP chains
5. **Always check**: `libc --version` and test locally first

---

**Last updated**: 2026-02-24 | **Source**: how2heap README + glibc analysis
