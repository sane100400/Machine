# Systems Security Reference & Exploitation Techniques

Structured index of UEFI, ARM MTE, EDR, hypervisors, kernel exploitation, and hardware security. Links to deeper resources rather than full explanations.

## 1. UEFI Security

### Secure Boot Bypass Techniques
- **Hydroph0bia (CVE-2025-4275)** — Insyde H2O firmware bypass. Three variants documented:
  - Part 1: Trivial bypass (initial PoC)
  - Part 2: Enhanced bypass (post-patch analysis)
  - Part 3: Fixed bypass (permanent)
  - Resources: awesome-list-systems [1108][1143][1144]

- **Key Vectors**:
  - UEFI variable manipulation (EFI_VARIABLE_NON_VOLATILE flag)
  - DBX (Denied Signature Database) blacklist evasion
  - SecureBoot disable via NVRAM write
  - Shim bypass via MOK (Machine Owner Key) downgrade
  - Reference: UEFI Secure Boot specification v1.4.2

### Firmware Rootkits
- **Trusted Execution Environment (TEE) breakouts**
  - TrustZone ARM exploitation (see ARM MTE section)
  - eBPF kernel bypass via BPFDoor (Parts 1-2, awesome-list [1101][1102])
- **DMA attacks** during boot (Rowhammer, see Hardware Security)
- **Intel SMM (System Management Mode)** exploitation (Ring -2 privilege)

### UEFI Variable Attacks
- Reading/writing NVRAM via EFI interfaces
- UEFI firmware update replay attacks
- Setup variable race conditions (between DXE and runtime)

---

## 2. ARM MTE (Memory Tagging Extension)

### How MTE Works
- **Tagged Memory**: 128-bit granules, 4-bit color tag per granule
- **Pointer Tagging**: ARM64 AArch64 TBI extension + MTE tags in bits[56:59]
- **Hardware Enforcement**: LDGM/STGM instructions for tag load/store
- **Modes**:
  - Sync: Exception on tag mismatch (SEGV)
  - Async: Deferred tag check via background scan

### Bypass Techniques
- **CVE-2025-0072**: MTE bypass via controlled use-after-free
  - Reference: awesome-list [1105]
  - Attack: Tag prediction + timing window
- **Tag Brute Force**: Sequential tag guessing (4 bits = 16 attempts per object)
- **Pointer Rotation Attack**: Abuse PSTATE.TCF[1:0] disable on context switch
- **Heap Spraying**: Allocate tagged objects, control reuse order

### Implications for Heap Exploits
- UAF becomes 16x harder (not impossible)
- Overflow tagging: must match tag of target allocation
- `malloc_mte_option` kernel config enables/disables
- Graphene OS hardened malloc uses MTE + randomization

---

## 3. EDR Bypass Techniques

### Unhooking
- **KnownDLLs Bypass**: Load DLL from system directory before EDR hooks
- **Direct Syscall**: SYSCALL(rax=SYS_*) bypasses user-mode hooks
  - Tools: WinAPI hooks unnecessary (ntdll!NtCreateProcess direct call)
  - Reference: Cobalt Strike beacon, fantastic.exe shellcode patterns
- **Memory Patching**: EDR hooks via JMP/CALL at function entry → patch entry bytes
  - Detect: Check first 5 bytes (CALL/JMP signature)
  - Restore: Original bytes from module header or fresh DLL load

### AMSI Bypass
- **AmsiScanBuffer Hook Evasion**:
  - Dynamically load AMSI DLL after EDR attachment
  - Call via COM (IContextMenuManager) instead of direct API
  - ObfuscateString + inline decoding defeats signature detection
- **DLL Injection via Callback**:
  - SetWindowsHookEx → DLL loaded before EDR sees
  - Callback executes before anti-malware hooks

### Callback Removal
- **Event Tracing for Windows (ETW) Callbacks**:
  - EtwEventWrite hook disabled by patching TRACE_HEADER_FLAG_TRACE_MESSAGE
  - Thread Notification callbacks (PsSetCreateThreadNotifyRoutine) → kernel mode only
- **WMI Event Subscriptions** (WITHIN):
  - Remove via WMI DCOM → process must have SeDebug

### Thread Hiding
- **ETHREAD Unlinking**: Remove thread from PEB (process environment block)
  - Makes thread invisible to debuggers/ETW
  - Requires kernel-mode driver or token steal

---

## 4. Hypervisor Security

### VM Escape Patterns
- **VT-x Exit Handler Exploitation**:
  - Trigger VMEXIT via privileged instruction
  - Hypervisor's VM-exit handler has bugs → escape
  - Reference: "CVE-2024-30088 Pwning Windows Kernel @ Pwn2Own" [1149]
  - "Hacking the XBox 360 Hypervisor" (Parts 1-2) [1109][1110]

- **EPT (Extended Page Tables) Attacks**:
  - Guest OS has shadow page tables (gPA → mPA)
  - Collude with hypervisor's EPT → leak host addresses
  - Reference: "KernelSnitch: Side-Channel Attacks on Kernel Data Structures" [1005]

### VT-x/VT-d Research
- **Unrestricted DMA via IOMMUs** (VT-d bypass):
  - Firmware doesn't enable IOMMU → FPGA DMA to host RAM
  - Reference: "Breaking the Sound Barrier Part I: Fuzzing CoreAudio with Mach Messages" [1039]
- **VT-x Nested Virtualization**:
  - Guest hypervisor + host hypervisor = race conditions
  - Reference: "Exploiting a 20 years old NTFS Vulnerability" [1124]

### Hyper-V Research
- **CVE-2024-30088** — Hyper-V VMFUNC exploitation
  - Exit handler stack overflow
  - Reference: awesome-list [1149]

---

## 5. MBE (Modern Binary Exploitation) Curriculum Map

### Lab Structure (RPISEC, Spring 2015)
```
Lab 01: Reverse Engineering (RE fundamentals, GDB/IDA, disassembly)
Lab 02: Memory Corruption (Stack overflows, ELF structure, calling conventions)
Lab 03: Shellcoding (Writing shellcode, encoding, scenario payloads)
Lab 04: Format Strings (Format string bugs, DTOR/GOT overwrites)
Lab 05: DEP and ROP (Data Execution Prevention, writing ROP chains, ret2libc)
Lab 06: ASLR (Leaks, partial overwrites, ASLR closure techniques)
Lab 07: Heap (Heap metadata, corruption, use-after-free, house of force)
Lab 08: Misc & Stack Cookies (Integer bugs, canary bypasses, signed/unsigned)
Lab 09: C++ (vTables, exceptions, RTTI abuse)
Lab 10: Linux Kernel (Privilege escalation, mmap_min_addr, SMEP/SMAP)
```

### Technique Coverage
| Technique | Lab(s) | Difficulty |
|-----------|--------|------------|
| Stack BOF | 02 | Easy |
| Format String | 04 | Easy |
| ROP/ret2libc | 05 | Medium |
| ASLR Leak | 06 | Medium |
| Heap UAF | 07 | Medium |
| Canary Bypass | 08 | Medium |
| vTable Hijack | 09 | Hard |
| Kernel priv-esc | 10 | Hard |

---

## 6. Hardware Security

### Side Channels (Spectre/Meltdown Variants)
- **Spectre v1** (CVE-2017-5753) — Branch prediction + cache timing
  - Bounds check bypass → speculative load → timing leak
- **Meltdown** (CVE-2017-5754) — Privilege escalation via transient execution
  - Illegal load not flushed before privilege check
  - Reference: "Exploiting Retbleed in the real world" [1141]
- **RetBleed** (CVE-2023-20569) — AMD Zen return prediction bypass
- **FLOP** (CVE-2025-XXXX) — Apple M3 false load output prediction
  - Reference: awesome-list [1059]

### Rowhammer
- **DRAM Row Conflict**: Repeated access to same row → capacitor discharge → adjacent row bit flip
- **Exploitation Path**: Row flip → PTE manipulation → arbitrary code execution
- **Reference**: "Kernel Exploitation Techniques: Turning The (Page) Tables" [1100]
- **Mitigations**: ECC RAM, LPDDR5 RFM (Refresh Management), kernel PAGETABLE_ISOLATION

### SGX (Intel Software Guard Extensions) Attacks
- **Side Channels**: Cache/timing leaks of enclave execution
- **Spectre in SGX**: Transient execution within trusted boundary
- **Rowhammer + SGX**: Flip PTE pointing to enclave page

### CPU-level Attacks
- **Fault Injection**: Glitching to bypass security
  - "EL3vated Privileges: Glitching Google WiFi Pro" [1121]
  - "Laser Fault Injection on a Budget: RP2350 Edition" [1017]

---

## 7. Quick Reference: Topic → Tools → Difficulty

### Exploitation Tools
| Tool | Domain | Difficulty |
|------|--------|------------|
| pwntools (Python) | Linux pwn | Easy |
| radare2 | RE / disasm | Easy |
| GDB/pwndbg | Debug/exploit | Easy |
| Frida | Dynamic instrumentation | Medium |
| Ropper / ROPgadget | ROP chain gen | Easy |
| angr | Symbolic execution | Hard |
| QEMU + Linux kernel | Kernel exploit | Hard |
| Ghidra | Decompilation | Easy |

### Key Papers & Resources
- **UEFI Security**: UEFI Spec v2.10, Heasman UEFI rootkit papers (CanSecWest 2015)
- **Kernel Exploitation**: "Linux Kernel Exploitation For Beginners" [1113]
- **MTE**: ARM MTE specification, CVE-2025-0072 writeup
- **EDR Bypass**: Cobalt Strike Beacon source, WinAPI hook patterns
- **Hardware**: "Exploiting the Synology TC500 at Pwn2Own Ireland 2024" [1122]

### Exploit Difficulty Levels
```
Level 1 (Trivial):    Stack overflow, trivial format string
Level 2 (Easy):       ASLR leak + ROP, canary brute-force
Level 3 (Medium):     Heap exploit, vTable hijack, SELinux bypass
Level 4 (Hard):       Kernel privilege escalation, SGX break
Level 5 (Expert):     Hypervisor escape, firmware rootkit, hardware fault
```

---

## 8. Additional References

- **awesome-list-systems**: ~/tools/awesome-list-systems/README.md (176K+, 500+ papers)
  - Topics: tools_and_repos.md, linux_kernel.md, exploitation.md, ot_security.md
- **MBE VM**: ~/tools/MBE/ (Ubuntu 14.04 32-bit, pre-setup labs)
  - Lectures, lab binaries, project templates
- **Local Tools**:
  - Radare2, GDB (+pwndbg/GEF), pwntools, ROPgadget
  - Foundry (Solidity), Slither (contract analysis)
  - Ghidra MCP, radare2-mcp, GDB MCP

---

## 9. Learning Path

1. **Foundations** (Week 1-2): MBE Lab 01-04 (RE, stack, format strings)
2. **Protections** (Week 3-4): MBE Lab 05-06 (DEP, ASLR, ROP)
3. **Heap Exploitation** (Week 5): MBE Lab 07-08 (UAF, corruption, canaries)
4. **Advanced** (Week 6-8): MBE Lab 09-10, kernel pwn, hypervisor escapes
5. **Hardware Security** (Week 9-10): Spectre/Meltdown, Rowhammer, fault injection

---

**Last Updated**: 2026-02-24
**Source**: awesome-list-systems (~500 papers), MBE curriculum, CVE research (2024-2025)
