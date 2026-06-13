# Task M000 #9 수행계획서

GitHub Issue: [#9](https://github.com/cho2659/JanusRE/issues/9)
마일스톤: M000

## 목적

Frida agent의 trace 수집 경로를 RPC와 JSON payload 중심 구조에서 Python 할당 공유 메모리 기반 binary ring buffer 구조로 전환한다.

이 작업의 핵심 목적은 Windows loader/heap lock 및 thread 동기화 민감 구간에서 Frida JS runtime의 동적 메모리 할당, RPC, JSON 직렬화 경로가 개입하는 범위를 줄이고, OEP 이후 thread attach 시점을 메인 프로세스/메인 스레드 기준으로 원자적으로 제어하는 것이다.

## 배경

현재 `frida_agent/agent.ts`는 Python에서 `rpc.exports`를 호출해 target config, trace start, stop을 전달한다. agent는 내부 JS 배열에 이벤트를 누적하고, `send()` payload로 Python에 JSON 형태의 trace chunk를 전달한다. 또한 classifier buffer, bitmap, Stalker callout user data를 agent 내부에서 `Memory.alloc`으로 확보한다.

이 구조는 OEP 극초반과 thread attach 과정에서 Frida callback, JS heap, JSON 직렬화, RPC 호출이 섞일 수 있다. 사용자는 OEP 완료 감지를 main process/main thread로 제한하고, agent 내부 메모리 할당과 RPC를 제거하며, Python이 공유 메모리를 할당해 agent가 binary record를 기록하는 구조를 요구했다.

## 범위

### 포함

- `bridge_server.py`에서 공유 메모리 생성, 초기 config 기록, ring buffer reader, stop state 기록을 구현한다.
- `frida_agent/agent.ts`에서 RPC exports 기반 start/stop/config 경로를 제거한다.
- `frida_agent/agent.ts`에서 직접 `Memory.alloc`을 호출하는 trace 수집용 메모리 확보 경로를 제거하고, Python이 제공한 공유 메모리 view를 사용하도록 바꾼다.
- OEP 완료 감지는 main PID와 main TID가 일치하는 흐름에서만 수행한다.
- 공유 메모리 header, config, target module/function-start bitmap, event ring record의 ABI를 문서화한다.
- stop/exit 시 `Stalker.unfollow()`와 `Stalker.garbageCollect()`를 호출하는 cleanup 경로를 유지한다.
- `frida_agent/agent.js`를 `agent.ts` 변경 결과로 갱신한다.

### 제외

- 그래프 UI 개선.
- `CallTreeBuilder` 부모/자식 관계 오탐 수정.
- Ghidra host/server 프로토콜 변경.
- 신규 user-level sync/message API hook 확장.
- PR merge 후 branch/worktree cleanup.

## 설계 방향

- Python이 trace 시작 전에 named file mapping 또는 동등한 Windows 공유 메모리를 만들고, agent script에는 공유 메모리 식별자와 최소 bootstrap 상수만 주입한다.
- 공유 메모리 header에는 magic, version, state, flags, main pid, main tid, config offsets, write/read index, capacity를 둔다.
- agent와 Python 사이의 동기화는 공유 메모리 state와 atomic index 갱신으로 처리한다. OEP 완료는 `INIT -> OEP_READY` 전이를 단 한 번만 성공시키는 방식으로 둔다.
- trace event는 고정 크기 binary record를 우선한다. 가변 문자열이 필요한 module/symbol 정보는 record에 직접 쓰지 않고 Python postprocess가 address 기준으로 보강하는 방향을 우선 검토한다.
- target module bitmap과 function-start bitmap은 Python이 공유 메모리에 배치하고, agent CModule/Native callout은 해당 주소를 읽어 classifier로 사용한다.
- JSON trace chunk와 `send({ type: "trace_chunk" ... })`는 수집 경로에서 제거한다. 상태 보고도 가능한 한 공유 메모리 status code로 축소한다.
- 기존 GUI/TraceSession 소비 구조는 Python reader가 binary record를 기존 dict 형태로 변환하는 adapter를 두어 단계적으로 호환시킨다.

## 예상 변경 파일

신규:

- `mydocs/tech/task_m000_9_shared_memory_abi.md`

수정:

- `bridge_server.py`
- `frida_agent/agent.ts`
- `frida_agent/agent.js`

이번 task 산출물:

- `mydocs/orders/20260613.md`
- `mydocs/plans/task_m000_9.md`
- `mydocs/plans/task_m000_9_impl.md`
- `mydocs/working/task_m000_9_stage{N}.md`
- `mydocs/report/task_m000_9_report.md`

## 잠정 단계

- **Stage 1 - 공유 메모리 ABI와 bootstrap 설계**
  - shared memory header/config/record layout 문서화.
  - Python과 agent의 책임 경계 확정.
  - 검증 관점: ABI field size, alignment, state transition, overflow 정책 검토.
- **Stage 2 - Python 공유 메모리 생성과 reader 도입**
  - `bridge_server.py`에 공유 메모리 생성, config writer, ring reader, stop state writer 추가.
  - 기존 `TraceSession` 생성 경로와 연결할 adapter 작성.
  - 검증 관점: Python 문법 검증과 synthetic binary record read.
- **Stage 3 - Agent RPC/JSON 제거와 공유 메모리 writer 전환**
  - `rpc.exports`, trace chunk `send()`, agent 내부 이벤트 배열 누적 경로 제거.
  - 공유 메모리 header/config를 읽고 binary ring buffer에 event 기록.
  - 검증 관점: `rg`로 제거 대상 확인, agent build 통과.
- **Stage 4 - OEP/main thread atomic gate와 Stalker cleanup 정리**
  - OEP 완료 감지를 main PID/main TID로 제한.
  - atomic state 전환과 scan 1회 보장.
  - stop/exit cleanup에서 `Stalker.unfollow()`와 `Stalker.garbageCollect()` 유지.
  - 검증 관점: 상태 전이와 cleanup 로그/코드 확인.
- **Stage 5 - 통합 검증과 보고**
  - 실제 spawn 또는 가능한 대체 시나리오로 공유 메모리 수집 확인.
  - stage/final report 정리.
  - 검증 관점: 빌드, py_compile, diff check, 수동 검증 결과 정리.

## 검증 계획

### 단계별 검증

- Stage 1
  - 공유 메모리 ABI 문서 리뷰.
  - state 전이와 record alignment 표 확인.
- Stage 2
  - `python -m py_compile bridge_server.py`
  - synthetic binary record를 Python reader가 기존 event dict로 변환하는지 확인.
- Stage 3
  - `npm.cmd --prefix frida_agent run build`
  - `rg -n "rpc\\.exports|Memory\\.alloc|trace_chunk|Stalker\\.parse" frida_agent/agent.ts`
- Stage 4
  - `rg -n "SetUnhandledExceptionFilter|main_tid|Stalker\\.unfollow|Stalker\\.garbageCollect" frida_agent/agent.ts bridge_server.py`
  - main thread 외 경로에서 OEP 완료 state 전환이 불가능한지 코드 리뷰.
- Stage 5
  - `python -m py_compile bridge_server.py`
  - `npm.cmd --prefix frida_agent run build`
  - `git diff --check`
  - 가능한 경우 실제 target spawn 후 공유 메모리 ring buffer event 증가 확인.

### 통합 검증

- `rpc.exports` 기반 trace start/stop/config 경로가 제거된다.
- agent trace 수집 경로에서 `Memory.alloc` 직접 호출이 남지 않는다.
- JSON trace chunk 수집 경로가 제거된다.
- `git status --short`가 PR 준비 전 빈 출력이다.
- `git diff --check`가 경고 없이 통과한다.

## 리스크

- **Frida bootstrap 리스크**: RPC 제거 후에도 agent가 공유 메모리 이름과 bootstrap config를 알아야 한다. script source 주입 또는 process environment 등 최소 전달 경로를 확정해야 한다.
- **Windows 공유 메모리 API 리스크**: Python과 Frida agent 양쪽에서 같은 mapping을 열어야 한다. handle 전달 대신 named mapping을 우선 검토한다.
- **atomic 동기화 리스크**: JS 단독으로 안전한 interlocked primitive 접근이 제한될 수 있다. CModule 또는 Windows native API 호출을 통해 원자적 state/index 갱신을 구현한다.
- **가변 데이터 리스크**: symbol/module 문자열을 ring buffer에 직접 넣으면 record 복잡도가 커진다. 우선 VA 중심 record와 Python 후처리 보강으로 단순화한다.
- **성능/overflow 리스크**: ring buffer capacity 초과 시 overwrite/drop 정책이 필요하다. header counter에 dropped count를 둔다.
- **기존 UI 호환성 리스크**: Python reader adapter가 기존 `TraceSession` 필드를 채우지 못하면 UI가 깨질 수 있다. 기존 session 구조로 변환하는 compatibility layer를 둔다.

## 승인 요청 사항

- Python 할당 named shared memory와 binary ring buffer ABI를 새 수집 경로의 기준으로 삼는 것을 승인한다.
- agent RPC exports와 JSON trace chunk 수집 경로를 제거하는 것을 승인한다.
- trace event record는 우선 VA/TID/SEQ/kind 중심 고정 크기로 두고 module/symbol 문자열은 Python 후처리로 보강하는 방향을 승인한다.
- 공유 메모리 동기화는 CModule 또는 native interlocked API를 사용해 원자적으로 구현하는 방향을 승인한다.
- 수행계획서 승인 전에는 구현계획서와 소스 변경을 진행하지 않는다.

승인되면 `task_m000_9_impl.md`에서 단계별 산출물, 검증 명령, 커밋 메시지를 구체화한다.
