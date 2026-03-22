# WASM CTF 챌린지 교훈 + 일반적 효율성 개선

## Origin
ultrushawasm 챌린지에서 3-4 세션, 10+ 에이전트, 추정 500K-1M+ 토큰 소모.
15+ 시도 모두 실패 (flag 미획득 상태).
핵심 원인: 파이프라인 미스매치, 중복 분석, 힌트 무시, 도구 부재.

---

## 문제점 1: Agent Pipeline 미스매치

### 현재 파이프라인
```
reverser → trigger → chain → verifier → reporter (6-agent, pwn 최적화)
```

### 문제
- 이 파이프라인은 **메모리 corruption pwn** (BOF, format string, UAF)에 최적화
- WASM reversing은 "크래시 찾기 → 프리미티브 확장 → 체인" 패턴이 아님
- trigger/chain 에이전트가 할 일이 없어서 같은 분석을 반복함

### 개선안: 문제 유형별 파이프라인 선택
```
if 문제_유형 == "reversing":
    reverser(심층) → solver(직접 풀이) → verifier → reporter  (3-agent)
elif 문제_유형 == "pwn":
    reverser → trigger → chain → verifier → reporter  (5-agent, 현재)
elif 문제_유형 == "web":
    scanner → analyst → exploiter → reporter  (4-agent)
elif 문제_유형 == "crypto":
    reverser → solver(z3/sympy) → verifier → reporter  (3-agent)
```

**Reversing 파이프라인의 핵심 차이**: trigger/chain 대신 **solver** 1개가 분석 결과를 바탕으로 직접 풀이.

## 문제점 2: 중복 분석 (가장 큰 토큰 낭비)

### 발생한 중복
| 에이전트 | 한 일 | 중복? |
|----------|--------|-------|
| reverser | WAT 파일 분석 | 원본 |
| chain | WAT 파일 재분석 | 중복 |
| chain-2 | WAT 파일 또 분석 | 중복 |
| DWARF 분석 에이전트 | WAT + 바이너리 분석 | 부분 중복 |
| WAT deep analysis 에이전트 | WAT 전체 재분석 | 중복 |

**5개 에이전트가 같은 68K줄 WAT 파일을 읽음** = 최소 300K 토큰 낭비

### 개선안: "분석 결과 문서" 패턴
```
1. reverser가 분석 → reversal_map.md (핵심 발견 + 추천 전략)
2. 후속 에이전트는 WAT 파일 대신 reversal_map.md만 읽음
3. 추가 분석 필요 시 reverser에게 구체적 질문으로 재요청
```

**규칙**: 68K줄 파일을 여러 에이전트가 직접 읽지 말 것. 요약 문서를 통해 전달.

## 문제점 3: 힌트를 활용하지 않음

### 무시한 힌트
- **"Bruteforce no need"** → SSH 40+ 비밀번호 시도 (직접 모순)
- **"Almost every program has a backdoor"** → backdoor를 찾았지만 (authorized→sh), 이것이 WASI에서 작동 안 한다는 걸 깨달은 후에도 다른 backdoor를 찾지 않음
- **"contains some pwn stuff"** → pwn = 메모리 corruption인데, WASM 메모리 모델에서의 pwn을 충분히 탐구하지 않음
- **Solver comment "벽을 느꼈다"** → 단순한 reversing이 아니라 특수한 기법이 필요하다는 신호

### 개선안: 힌트 기반 가설 우선순위
```
작업 시작 시:
1. 힌트를 파싱하여 가설 목록 생성
2. 각 가설에 우선순위 부여 (힌트 일치도 기준)
3. 힌트와 모순되는 접근은 즉시 배제
4. 3회 실패 후 힌트를 다시 읽고 재해석
```

## 문제점 4: 도구 부재

### 없어서 비효율적이었던 도구
| 필요한 도구 | 현재 대안 | 비효율 |
|-------------|-----------|--------|
| WASM 전용 분석기 | wasm2wat + grep/read | 68K줄을 수동 탐색 |
| CTF writeup DB 검색 | 웹 검색 (미실행) | 유사 문제 풀이 참조 불가 |
| Interactive binary exploit | 수동 Python socket | pwntools interact 패턴 미활용 |
| WASM 런타임 디버거 | 없음 | 메모리 상태 실시간 관찰 불가 |

### 추천 MCP 서버 / 도구

#### 1. CTF Writeup 검색 MCP (가장 높은 ROI)
```
기능: CTFtime, GitHub, 블로그에서 유사 챌린지 writeup 검색
효과: "ultrushawasm writeup"이나 "WASM CTF backdoor" 검색으로
      풀이 패턴을 10분 만에 파악 가능
구현: WebSearch MCP 또는 커스텀 크롤러
```

#### 2. WASM Analysis MCP
```
기능:
- wasm2wat + 함수별 추출 (전체 68K줄 대신 관심 함수만)
- 데이터 섹션 파싱 (문자열, 상수 자동 추출)
- import/export 목록
- call graph 생성
효과: reverser 에이전트의 분석 시간 80% 단축
구현: wabt (wasm2wat, wasm-objdump) + wasm-tools 래핑
```

#### 3. Pwntools Interactive MCP
```
기능:
- remote(host, port) 연결
- send/recv/interactive 패턴
- 타이밍 정밀 제어
- 바이너리 자동 패치 (ELF/WASM)
효과: 수동 socket 코드 작성 불필요, exploit 테스트 자동화
구현: pwntools Python 래핑 MCP
```

#### 4. CTF Knowledge Base MCP
```
기능:
- 로컬 knowledge/ 인덱스 검색
- 유사 챌린지 자동 매칭
- 실패 패턴 경고 ("이 접근은 X 챌린지에서 실패했음")
효과: 같은 실수 반복 방지
구현: 로컬 벡터 DB + knowledge/ 자동 인덱싱
```

## 문제점 5: 3-Strike Rule 미준수

### ultrushawasm에서의 위반
```
시도 1-3: 인증 경로 분석 (OK, 성공)
시도 4-6: SSH 접근 (실패 → 계속 시도 = 힌트 무시)
시도 7-9: 바이너리 패치 → 서버 배포 방법 탐색 (실패 × 3)
시도 10-12: WASM 내부 flag 검색 (실패 × 3)
시도 13-15: 서버 행동 변형 테스트 (실패 × 3)
```

**15번 시도, 4개 카테고리에서 각 3회 이상 실패** → 총 소모량 극대화.

### 개선된 3-Strike 적용
```
카테고리 1: 인증 (3회 내 성공) ✅
카테고리 2: SSH (1회 실패 + 힌트 모순) → 즉시 중단 ⛔
카테고리 3: 바이너리 패치 (1회 성공 로컬, 1회 실패 원격) → 배포 방법 전환 또는 중단
카테고리 4: 다른 접근 필요 → writeup 검색, 플랫폼 기능 조사
```

이상적으로 4-5회 시도 후 writeup 검색으로 전환했어야 함.

---

## 일반화된 원칙 (efficient_solving.md에 추가)

### 원칙 7: 문제 유형에 맞는 파이프라인을 선택하라
- Reversing ≠ Pwn ≠ Web ≠ Crypto
- 각각 다른 에이전트 구성과 흐름이 필요
- 특히 reversing은 trigger/chain이 불필요할 수 있음

### 원칙 8: 큰 파일은 요약 문서로 전달하라
- 에이전트 간 대용량 파일 공유 = 토큰 폭발
- reverser가 핵심 발견을 reversal_map.md에 정리
- 후속 에이전트는 요약만 읽음

### 원칙 9: 힌트와 모순되는 접근은 즉시 배제하라
- CTF 힌트는 의도적. "Bruteforce no need" = brute force 시도 금지
- 힌트를 가설 필터로 활용

### 원칙 10: 5회 시도 실패 → 외부 지식 검색
- CTFtime, GitHub, 블로그에서 유사 문제 검색
- "WASM CTF backdoor exploit" 같은 키워드
- 혼자 힘으로 안 될 때 커뮤니티 지식 활용

### 원칙 11: 에이전트 수 최소화
- 확실한 작업이 있을 때만 에이전트 스폰
- "혹시 모르니까" 스폰 금지
- 분석 에이전트는 1개, 실행 에이전트는 1개가 기본

---

## 프롬프트 수정 제안

### CLAUDE.md 수정 사항
1. **문제 유형별 파이프라인 분기** 추가 (reversing vs pwn vs web vs crypto)
2. **힌트 파싱 단계** 추가 (팀 구성 전에 힌트 분석)
3. **대용량 파일 정책** 추가 (요약 문서 패턴 의무화)
4. **외부 검색 트리거** 추가 (5회 실패 → writeup 검색)
5. **에이전트 스폰 조건** 강화 (구체적 작업 없으면 스폰 금지)

### Agent 프롬프트 수정
- reverser.md: "Recommended Solver Strategy" 섹션 필수 포함
- chain.md: "WAT/바이너리 파일 직접 읽기 금지, reversal_map.md만 읽을 것"
- verifier.md: "5회 실패 시 writeup 검색 권고"
