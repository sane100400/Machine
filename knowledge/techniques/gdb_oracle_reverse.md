# GDB Oracle Reverse — Custom VM 역연산 기법

## 적용 조건
- Custom VM이 비선형 T function을 계산하는 경우
- T function의 입력을 메모리 패치로 제어 가능한 경우
- Feistel/SPN 등 라운드 기반 암호를 역연산해야 하는 경우
- angr이 state explosion으로 실패하는 경우

## 핵심 아이디어
GDB를 "T function oracle"로 활용한다:
1. 바이너리를 GDB로 실행
2. T function이 상태를 읽는 메모리 주소를 파악
3. 해당 메모리를 원하는 값으로 패치
4. VM이 T를 계산하도록 continue
5. breakpoint에서 T 결과값을 읽기

이렇게 하면 임의의 상태에 대한 T(state, round) 값을 얻을 수 있다.

## Feistel 역연산 패턴

### Forward (알려진 구조)
```
Round i (0~15):
  H2_new = H2 - T_h2(H1, i)
  H1_new = H1 - T_h1(H2_new, i)
```

### Reverse (target → input)
```
Round i (15~0, 역순):
  # H1 역연산: H1_prev = H1 + T_h1(H2, i)
  T_h1 = oracle(H2, round=i)   # GDB 패치로 T 획득
  H1_prev = H1 + T_h1

  # H2 역연산: H2_prev = H2 + T_h2(H1_prev, i)
  T_h2 = oracle(H1_prev, round=i)
  H2_prev = H2 + T_h2
```

## 구현 패턴 (Python + GDB batch)

```python
import subprocess, struct

BINARY = "./target"
# PIE 고정을 위해 disable-randomization on

def run_gdb_oracle(patch_addr, patch_value, read_bp, read_expr, round_bp_count):
    """GDB를 실행하여 특정 메모리를 패치하고, breakpoint에서 값을 읽는다"""
    gdb_commands = f'''
set disable-randomization on
break *$PIE_BASE+0xXXXX
run <<< "AAAAAAAAAAAAAAAA"
# round_bp_count번째 hit까지 continue
# 메모리 패치
set {{long}}{patch_addr} = {patch_value}
# T function 계산 breakpoint까지 continue
continue
# T 결과 읽기
print/x {read_expr}
quit
'''
    result = subprocess.run(['gdb', '-batch', '-x', '/tmp/gdb_script.gdb', BINARY],
                          capture_output=True, timeout=10)
    # parse output for T value
    return parse_t_value(result.stdout)
```

## 주의사항
- **PIE 바이너리**: `set disable-randomization on` 필수 (주소 고정)
- **mmap 주소**: ASLR 비활성화해도 mmap은 변할 수 있음 → 런타임에 mmap 주소 탐색 필요
- **라운드 식별**: breakpoint hit 횟수로 라운드 번호를 추적
- **메모리 패치 시점**: T function이 상태를 읽기 **전**에 패치해야 함
- **총 GDB 실행 횟수**: Feistel 16라운드 → 32회 (라운드당 T_h1 + T_h2)

## 참조
- 최초 적용: Damnida 챌린지 (Custom VM, Feistel 16 rounds)
- 구현 코드: `tests/wargames/extracted/Damnida/reverse_feistel.py`
- 상세 분석: `knowledge/challenges/damnida.md`
