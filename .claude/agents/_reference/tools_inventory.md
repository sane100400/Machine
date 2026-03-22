# CTF Tools Inventory

에이전트용 실행 가능 커맨드 레퍼런스. 툴 명령어 기억이 불확실할 때 이 파일을 참조.

---

## Binary Analysis (Static)

### Ghidra MCP (PRIMARY — 모든 디컴파일)
```
mcp__ghidra__setup_context(binary_path="/abs/path/binary")
mcp__ghidra__list_functions()
mcp__ghidra__get_pseudocode(name="main")
mcp__ghidra__list_strings()
mcp__ghidra__xrefs_to(name="gets")
mcp__ghidra__get_data_at(address="0x404010")
```

### 경량 정적 분석
```bash
file ./binary
checksec --file=./binary
strings ./binary | grep -iE "flag|cat|system|/bin|shell|win|key|password"
readelf -S ./binary | grep -E "name|type|flags"
readelf -d ./binary | grep NEEDED          # dynamic deps
nm ./binary 2>/dev/null | grep -v "^$"
objdump -d ./binary | grep -A5 "<main>"
objdump -M intel -d ./binary > /tmp/disasm.txt
ldd ./binary
```

---

## Binary Analysis (Dynamic)

### GDB MCP
```
mcp__gdb__start_session(binary="/abs/path/binary")
mcp__gdb__run_command(command="b main")
mcp__gdb__run_command(command="r")
mcp__gdb__run_command(command="info registers")
mcp__gdb__run_command(command="x/32gx $rsp")
mcp__gdb__run_command(command="info address <symbol>")
mcp__gdb__run_command(command="heap chunks")        # GEF
mcp__gdb__run_command(command="vis_heap_chunks")    # GEF
```

### GDB Batch (검증용)
```bash
# 상수 검증
gdb -batch -ex "info address main" ./binary 2>&1 | tee /tmp/gdb_addr.txt

# 크래시 오프셋
python3 -c "from pwn import *; open('/tmp/cyclic','wb').write(cyclic(300))"
gdb -batch -ex "r < /tmp/cyclic" -ex "info registers" ./binary 2>&1 | tee /tmp/gdb_crash.txt

# 버퍼 사이즈 확인
gdb -batch -ex "b *<addr>" -ex "r < /tmp/cyclic" -ex "info frame" ./binary 2>&1

# 런타임 메모리 맵
gdb -batch -ex "r" -ex "info proc mappings" ./binary 2>&1

# 힙 구조
gdb -q -ex "source ~/gef/gef.py" ./binary << 'EOF'
b main
r
heap bins
heap chunks
vis_heap_chunks
quit
EOF
```

### strace / ltrace
```bash
strace ./binary 2>&1 | head -50
strace -e trace=read,write,open ./binary 2>&1
ltrace ./binary 2>&1 | head -50
```

---

## Exploit Development

### pwntools
```python
from pwn import *
context.binary = ELF('./binary')
context.arch = 'amd64'       # or 'i386', 'arm', 'aarch64'
context.os = 'linux'
context.log_level = 'info'

# 로컬
p = process('./binary')
# 원격
p = remote('host', port)
# GDB 붙이기
p = gdb.debug('./binary', gdbscript='b main\nc')

# 오프셋 찾기
cyclic(300)
cyclic_find(0x61616161)

# 페이로드
payload = flat(b'A'*72, p64(0xdeadbeef))
p.sendlineafter(b'> ', payload)
flag = p.recvline()
```

### ROPgadget
```bash
ROPgadget --binary ./binary | grep -E "pop rdi|pop rsi|pop rdx|syscall|ret$"
ROPgadget --binary ./binary --rop | head -50
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep "pop rdi"

# 특정 가젯 오프셋
ROPgadget --binary ./binary | grep "pop rdi" | head -3
```

### rp++
```bash
~/tools/rp++ -f ./binary -r 5 | grep -E "pop|ret|call"
~/tools/rp++ -f ./binary -r 3 --va 0x0 | grep "pop rdi"
```

### one_gadget
```bash
one_gadget /lib/x86_64-linux-gnu/libc.so.6
one_gadget /lib/x86_64-linux-gnu/libc.so.6 -l 2   # 더 많은 후보
```

### patchelf (바이너리 libc 교체)
```bash
patchelf --set-interpreter /path/to/ld.so ./binary
patchelf --replace-needed libc.so.6 /path/to/libc.so.6 ./binary
```

---

## Symbolic Execution / Constraint Solving

### z3
```python
from z3 import *
s = Solver()
x = BitVec('x', 64)
s.add(x * 3 == 0x1234)
if s.check() == sat:
    print(s.model())
```

### angr
```python
import angr
proj = angr.Project('./binary', auto_load_libs=False)
state = proj.factory.entry_state()
sm = proj.factory.simulation_manager(state)
sm.explore(find=0x401234, avoid=0x401256)
if sm.found:
    print(sm.found[0].posix.dumps(0))
```

---

## Web CTF

### curl
```bash
curl -s http://target/ -v
curl -s http://target/ -H "Cookie: session=..." -b "key=val"
curl -s http://target/api -X POST -d '{"key":"val"}' -H "Content-Type: application/json"
curl -s http://target/ --proxy http://127.0.0.1:8080   # Burp 경유
```

### ffuf (디렉토리/파라미터 퍼징)
```bash
# 디렉토리
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302

# 파라미터
ffuf -u "http://target/?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# POST 바디
ffuf -u http://target/login -X POST -d "username=FUZZ&password=test" -w wordlist.txt -mc 302
```

### sqlmap
```bash
sqlmap -u "http://target/?id=1" --batch --dbs
sqlmap -u "http://target/?id=1" --batch -D dbname --tables
sqlmap -u "http://target/?id=1" --batch -D dbname -T users --dump
sqlmap -u "http://target/" --data="id=1" --method POST --batch
```

### Python requests (수동 익스플로잇)
```python
import requests
s = requests.Session()

# SSTI 테스트
r = s.post('http://target/render', data={'template': '{{7*7}}'})
print(r.text)   # 49 나오면 SSTI

# SSRF
r = s.get('http://target/fetch?url=http://127.0.0.1:22')
```

---

## Crypto

### SageMath
```bash
sage -c "
n = <modulus>
e = <exponent>
# Wiener's attack, small e, etc.
"
```

### openssl
```bash
openssl s_client -connect host:443
openssl rsa -in key.pem -text -noout
openssl enc -d -aes-256-cbc -in cipher.bin -k password
```

### RsaCtfTool
```bash
python3 ~/RsaCtfTool/RsaCtfTool.py --publickey key.pub --attack all
python3 ~/RsaCtfTool/RsaCtfTool.py -n <n> -e <e> -c <c> --attack fermat
```

### hashcat / john
```bash
hashcat -m 0 hash.txt rockyou.txt          # MD5
hashcat -m 1800 hash.txt rockyou.txt       # sha512crypt
john --wordlist=rockyou.txt hash.txt
john --show hash.txt
```

---

## Forensics

### 파일 식별
```bash
file ./challenge
exiftool ./challenge
binwalk ./challenge
binwalk -e ./challenge          # 자동 추출
strings ./challenge | head -50
xxd ./challenge | head -30
```

### 스테가노그래피
```bash
zsteg ./image.png               # LSB 스테가
steghide extract -sf ./image.jpg -p ""
stegsolve ./image.png           # GUI
outguess -r ./image.jpg out.txt
```

### PCAP 분석
```bash
tshark -r ./capture.pcap -Y "http" | head -30
tshark -r ./capture.pcap -T fields -e http.request.uri | head -20
tshark -r ./capture.pcap -Y "tcp.stream eq 0" -w /tmp/stream0.pcap
strings ./capture.pcap | grep -iE "flag|pass|key"
```

### 메모리 포렌식 (Volatility3)
```bash
vol3 -f memory.dmp windows.info
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.cmdline
vol3 -f memory.dmp windows.filescan | grep -i flag
vol3 -f memory.dmp windows.dumpfiles --virtaddr <addr>
```

---

## Web3 / Smart Contract

### Foundry
```bash
export PATH="/home/sane100400/.foundry/bin:$PATH"

# 컴파일
forge build

# 테스트 (익스플로잇 검증)
forge test -vvvv --match-test testExploit

# 포크 테스트 (실제 체인 상태)
forge test --fork-url https://eth-mainnet.alchemyapi.io/v2/<key> -vvvv

# 트랜잭션 전송
cast send <contract> "withdraw()" --private-key <key> --rpc-url <rpc>
cast call <contract> "isSolved()" --rpc-url <rpc>
```

### Slither
```bash
slither . --json slither_results.json
slither . --detect reentrancy-eth,arbitrary-send-eth
slither . --print human-summary
```

### Mythril
```bash
myth analyze contracts/Target.sol --execution-timeout 300 2>&1 | tee mythril_results.txt
```

---

## 취약점 DB / 리서치

### ExploitDB
```bash
~/exploitdb/searchsploit "<service> <version>"
~/exploitdb/searchsploit --id <EDB-ID>
~/exploitdb/searchsploit -x <EDB-ID>    # 익스플로잇 보기
```

### knowledge-fts MCP
```
ToolSearch("knowledge-fts")
→ mcp__knowledge_fts__technique_search("heap tcache poisoning")
→ mcp__knowledge_fts__challenge_search("format string")
```

---

## State Store (Machine 전용)

```bash
# fact 기록 (source 파일 필수)
python3 $MACHINE_ROOT/tools/state.py set --key <k> --val <v> --src <file> --agent <name>

# fact 조회
python3 $MACHINE_ROOT/tools/state.py get --key <k>
python3 $MACHINE_ROOT/tools/state.py facts

# handoff 전 아티팩트 검증
python3 $MACHINE_ROOT/tools/state.py verify --artifacts <file1> <file2>

# checkpoint
python3 $MACHINE_ROOT/tools/state.py checkpoint --agent <name> --phase <n> --phase-name <s> --status in_progress
python3 $MACHINE_ROOT/tools/state.py checkpoint --read
```
