# Toddler's Bottle 풀이 교훈 (pwnable.kr 19문제)

## 개요
pwnable.kr Toddler's Bottle 19문제를 Agent Teams로 풀면서 도출한 교훈.
핵심: **간단한 문제에 과도한 파이프라인은 토큰 낭비**, **Orchestrator 검증 필수**.

---

## 교훈 1: Trivial 문제는 1-agent로 충분하다

### 문제
- Toddler's Bottle은 대부분 소스코드 제공 + 단순 로직 버그
- reverser → solver → verifier → reporter (4-agent) = 과잉
- 에이전트 간 메시지 전달/대기 시간이 실제 분석 시간보다 긺

### 해결
```
if 난이도 == "trivial" (소스코드 있음, 단순 로직버그):
    reverser+solver 1-agent → reporter
elif 난이도 == "easy" (reversing/crypto):
    reverser → solver → reporter (3-agent)
elif 난이도 == "medium+" (pwn):
    reverser → [trigger] → chain → verifier → reporter (4-5 agent)
```

### 구현
Task 프롬프트에 "You are the REVERSER+SOLVER agent"로 지시하면 reverser.md의 "solve.py 작성은 네 역할이 아니다" 규칙을 자연스럽게 override.

---

## 교훈 2: Orchestrator 플래그 검증은 필수 (MANDATORY)

### 사건 1: fd 챌린지 — 에이전트가 인터넷에서 찾은 잘못된 플래그 보고
- 에이전트 보고: 인터넷 writeup에서 가져온 구버전 플래그 (WRONG)
- 실제 플래그: 서버에서 직접 획득한 플래그와 불일치
- 원인: 에이전트가 인터넷 writeup의 구버전 플래그를 보고

### 사건 2: passcode 챌린지 — hex→decimal 변환 오류
- 에이전트 보고: `0x080492ba = 134514362` (WRONG)
- 실제: `134514362 = 0x080486ba` (완전히 다른 주소)
- 결과: 잘못된 GOT overwrite → SIGSEGV

### 규칙
```
에이전트가 FLAG_FOUND 보고 → Orchestrator가 solve.py 직접 실행하여 검증
  ├── 일치 → 확정, knowledge 기록
  └── 불일치 → 에이전트에게 재지시 또는 직접 디버깅
```

---

## 교훈 3: SSH 자동화 패턴 분류

| 상황 | 도구 | 예시 |
|------|------|------|
| 단순 명령 실행 | paramiko exec_command | fd, collision, random |
| 대화형 프로그램 | paramiko invoke_shell + send/recv | passcode, leg |
| 네트워크 서비스 (외부 접속 가능) | pwntools remote() | 일반 pwn CTF |
| 네트워크 서비스 (localhost only) | SFTP 업로드 → 서버 내 실행 | coin1 (port 9007) |
| QEMU VM 환경 | invoke_shell (VM 부팅 대기 필요) | leg (ARM VM) |
| 파일 업로드 필요 | paramiko SFTP | input (C solver 업로드) |

### paramiko 기본 패턴
```python
import paramiko, time
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('pwnable.kr', port=2222, username='USER', password='guest')

# 방법 1: exec_command (단순 명령)
stdin, stdout, stderr = client.exec_command('echo "LETMEWIN" | /home/fd/fd 4660')
print(stdout.read().decode())

# 방법 2: invoke_shell (대화형)
channel = client.invoke_shell()
channel.settimeout(10)
time.sleep(1)
channel.sendall(b'./binary\n')
time.sleep(1)
channel.sendall(b'input_data\n')
output = channel.recv(65536).decode()
```

---

## 교훈 4: Toddler's Bottle 취약점 패턴 분류

### 빈도순 정리 (19문제)

| 패턴 | 문제 | 빈도 |
|------|------|------|
| **로직 버그** (연산자 우선순위, 비교 오류) | mistake, lotto | 2 |
| **입력 제어** (fd, argv 조작) | fd, input | 2 |
| **정수 조작** (overflow, 음수) | collision, blackjack | 2 |
| **메모리/포인터** (GOT, 정렬) | passcode, memcpy | 2 |
| **필터 우회** (PATH, 특수문자) | cmd1, cmd2 | 2 |
| **예측 가능 랜덤** | random | 1 |
| **ARM 아키텍처** | leg | 1 |
| **알고리즘** (binary search) | coin1 | 1 |
| **ROP** | horcruxes | 1 |
| **셸코드** | asm | 1 |

### 핵심 인사이트
- 19문제 중 **12문제가 "코드 읽고 로직 이해"만으로 풀림** (exploitation 불필요)
- pwn 기법이 필요한 건 3문제 (passcode GOT, horcruxes ROP, asm shellcode)
- 나머지는 시스템 프로그래밍 지식 (fd, input, memcpy, leg)

---

## 교훈 5: 에이전트 프롬프트 최적화

### 효과적이었던 프롬프트 구조
```
1. Challenge Info (이름, 접속 정보, 힌트)
2. Background (예상 유형, 참고 정보)
3. Phase별 Task (분석 → 버그 찾기 → 익스플로잇)
4. Output Requirements (파일 경로, FLAG_FOUND 출력)
5. Important Rules (로컬 flag 금지, 작업 디렉토리)
```

### 비효율적이었던 것
- 과도한 도구 사용 지침 (에이전트가 알아서 선택)
- 너무 많은 제약 조건 (유연성 감소)
- SSH 방법 강제 (coin1처럼 paramiko가 안 되는 경우 있음)

---

## 다음 단계: Rookiss 준비

Toddler's Bottle과 Rookiss의 차이:
| 항목 | Toddler's | Rookiss |
|------|-----------|---------|
| 소스코드 | 대부분 제공 | 거의 없음 |
| 보호기법 | 없거나 최소 | PIE, NX, Canary, ASLR |
| 취약점 | 눈에 보임 | 리버싱 필요 |
| 필요 기법 | 기초 | heap exploit, ROP chain, format string |

### Rookiss에서 필요한 추가 도구
- **angr**: 자동 symbolic execution (stripped binary 분석)
- **libc-database**: ASLR 우회를 위한 libc 버전 식별
- **one_gadget**: libc one-gadget RCE 자동 검색
- **seccomp-tools**: seccomp 필터 분석/우회
- **patchelf**: 로컬 환경에서 원격 libc 재현
