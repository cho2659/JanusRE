# Task M000 #9 구현계획서

GitHub Issue: [#9](https://github.com/cho2659/JanusRE/issues/9)
수행계획서: [`task_m000_9.md`](task_m000_9.md)

## 승인 상태

본 문서는 Task #9 수행계획서 승인 이후 작성하는 구현계획서다. `bridge_server.py`, `frida_agent/agent.ts`, `frida_agent/agent.js`의 구조 변경이 포함되므로, 작업지시자가 본 구현계획서를 확인하고 명시 승인하기 전까지 소스 구현을 시작하지 않는다.

## 구현 원칙

- Git 작업과 파일 변경은 IDE가 사용하는 저장소 경로 `E:\openhwp\custom_tools\frida_delta` 안에서만 수행한다.
- `C:\tmp\frida_delta_task9` worktree는 사용하지 않는다.
- agent 내부 trace 수집 경로에서 `Memory.alloc`, `rpc.exports`, trace JSON `send()` 의존을 제거한다.
- Python이 공유 메모리 layout과 lifetime을 소유하고, agent는 bootstrap으로 받은 식별자만 사용해 mapping을 연다.
- OEP 완료는 main PID와 main TID가 일치하는 흐름에서만 atomic state 전환으로 인정한다.
- 기존 UI와 `TraceSession` 소비자는 Python binary reader adapter를 통해 최대한 유지한다.

## Stage 1 - 공유 메모리 ABI와 bootstrap 문서화

### 목적

구현 전에 Python과 agent가 공유할 binary ABI를 고정한다. ABI를 먼저 문서화해 이후 Stage의 코드 변경이 같은 구조를 따르게 한다.

### 작업

- `mydocs/tech/task_m000_9_shared_memory_abi.md` 신규 작성.
- 공유 메모리 header layout 정의.
  - magic/version/header_size/state/flags
  - main_pid/main_tid
  - record_capacity/record_size/read_index/write_index/dropped_count
  - config offset/size, module table offset/count, bitmap offset/size
  - command/status/error code fields
- state machine 정의.
  - `INIT`, `CONFIG_READY`, `SCRIPT_READY`, `OEP_READY`, `RUNNING`, `STOP_REQUESTED`, `STOPPED`, `ERROR`
- binary event record 정의.
  - 고정 크기 record: kind, tid, seq, src, dst, flags, timestamp 또는 reserved
  - module/symbol 문자열은 record에 저장하지 않고 Python 후처리에서 보강
- overflow 정책 정의.
  - ring full 시 drop count 증가 및 record 미기록을 기본값으로 둔다.
- bootstrap 정책 정의.
  - Python이 script source에 mapping name, main pid, main tid 등 최소 상수만 치환 주입한다.

### 검증

- `rg -n "FRIDA_DELTA_SHM|record_size|main_tid|STOP_REQUESTED" mydocs/tech/task_m000_9_shared_memory_abi.md`
- `git diff --check`

### 커밋

- `Task #9 Stage 1: 공유 메모리 ABI 문서화`

## Stage 2 - Python 공유 메모리 owner와 binary reader 도입

### 목적

agent 변경 전에 Python 쪽 공유 메모리 생성, config writer, binary record reader를 만든다. 실제 agent writer가 붙기 전에는 synthetic record로 reader를 검증한다.

### 작업

- `bridge_server.py`에 공유 메모리 관리 클래스를 추가한다.
  - Windows named file mapping 생성.
  - header/config/module/function-start 영역 초기화.
  - read/write index와 state field 접근 API 제공.
  - stop 요청 시 `STOP_REQUESTED` state 또는 command field 기록.
- target config 준비 후 공유 메모리에 module/function-start config를 기록한다.
- binary event reader adapter를 추가한다.
  - 공유 메모리 record를 기존 raw event dict 형태로 변환.
  - `TraceSession` 생성 흐름은 adapter 출력으로 유지.
- synthetic record writer/reader 검증용 내부 helper를 추가한다.

### 검증

- `python -m py_compile bridge_server.py`
- synthetic record를 reader가 `{"k", "src", "dst", "tid", "seq"}` dict로 변환하는지 확인.
- `git diff --check`

### 커밋

- `Task #9 Stage 2: Python 공유 메모리 reader 도입`

## Stage 3 - Agent bootstrap과 RPC 제거

### 목적

agent 제어 경로를 RPC에서 bootstrap + shared memory state로 전환한다. 이 단계에서는 Python reader가 준비된 상태에서 agent의 start/stop/config RPC를 제거한다.

### 작업

- `bridge_server.py`
  - `script.exports_sync.set_target_config`, `set_targets`, `start_trace`, `stop_trace` 호출 제거.
  - script source를 load하기 전에 bootstrap 상수를 치환한다.
  - stop 요청은 RPC 대신 공유 메모리 command/state 기록으로 전환.
- `frida_agent/agent.ts`
  - `rpc.exports` 제거.
  - script load 시 bootstrap config를 읽고 beginTrace equivalent를 자동 수행.
  - `g_targets`, function-start config는 공유 메모리 config 영역에서 읽는다.
  - 상태 보고용 `send({ type: "status" ... })`는 최소화하되, trace chunk JSON 전송은 사용하지 않는다.

### 검증

- `npm.cmd --prefix frida_agent run build`
- `python -m py_compile bridge_server.py`
- `rg -n "rpc\\.exports|exports_sync\\.(set_target_config|set_targets|start_trace|stop_trace)" frida_agent/agent.ts bridge_server.py`
- `git diff --check`

### 커밋

- `Task #9 Stage 3: Agent RPC 제어 경로 제거`

## Stage 4 - Agent 내부 할당 제거와 shared memory writer 전환

### 목적

trace 수집 경로의 agent 내부 `Memory.alloc`, JS 이벤트 배열, JSON trace chunk 전송을 제거하고 공유 메모리 binary ring writer로 전환한다.

### 작업

- `frida_agent/agent.ts`
  - `g_events`, `g_mod_events`, `g_sync_events`, `g_spawn_events`, `g_handle_events`, `g_exception_events` 누적 경로 제거 또는 binary writer 경로로 대체.
  - `sendTraceChunk()`와 `trace_complete` JSON payload 전송 제거.
  - `Memory.alloc` 기반 classifier buffer, transition buffer, bitmap, callout arena 할당 제거.
  - Python 공유 메모리 영역 안의 classifier table, bitmap, transition queue, callout data 영역을 사용하도록 변경.
  - Stalker `onReceive`에서 `Stalker.parse()` 후 JS dict 생성 대신 binary event record write로 전환하거나, 가능한 경우 native writer callout 중심으로 축소.
  - ring write index는 atomic increment/CModule helper로 갱신한다.
- `frida_agent/agent.js` 빌드 산출물 갱신.

### 검증

- `npm.cmd --prefix frida_agent run build`
- `rg -n "Memory\\.alloc|trace_chunk|trace_complete|Stalker\\.parse|g_events|g_mod_events|sendTraceChunk" frida_agent/agent.ts`
- `git diff --check`

### 커밋

- `Task #9 Stage 4: 공유 메모리 이벤트 writer 전환`

## Stage 5 - Main thread OEP gate, cleanup, 통합 검증

### 목적

OEP 완료 감지를 main PID/main TID로 제한하고, stop/exit cleanup 및 전체 end-to-end 흐름을 검증한다.

### 작업

- `frida_agent/agent.ts`
  - `SetUnhandledExceptionFilter.onLeave` 또는 승인된 OEP 완료 신호에서 main PID/main TID 일치 여부 확인.
  - atomic compare-exchange로 OEP state를 1회만 전환.
  - thread scan은 OEP state가 전환된 뒤 1회만 수행.
  - `STOP_REQUESTED` 확인 시 `Stalker.unfollow()`와 `Stalker.garbageCollect()` 호출.
- `bridge_server.py`
  - stop 버튼 경로가 공유 메모리 stop state를 기록하고 reader를 종료하도록 정리.
  - process detach/exit 시 shared memory reader와 mapping lifetime 정리.
- `mydocs/working/task_m000_9_stage*.md`, `mydocs/report/task_m000_9_report.md` 작성.

### 검증

- `python -m py_compile bridge_server.py`
- `npm.cmd --prefix frida_agent run build`
- `rg -n "main_tid|SetUnhandledExceptionFilter|Stalker\\.unfollow|Stalker\\.garbageCollect|STOP_REQUESTED" frida_agent/agent.ts bridge_server.py`
- `rg -n "rpc\\.exports|Memory\\.alloc|trace_chunk|trace_complete" frida_agent/agent.ts bridge_server.py`
- `git diff --check`
- 가능한 경우 실제 target spawn 후 공유 메모리 write index 증가와 `TraceSession` 구성 확인.

### 커밋

- `Task #9 Stage 5 + 최종 보고서: 공유 메모리 수집 구조 검증`

## 승인 요청

위 5단계 구현계획으로 Stage 1에 진입하는 것을 승인 요청한다.
