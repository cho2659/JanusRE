# Task M000 #5 구현계획서

GitHub Issue: [#5](https://github.com/cho2659/JanusRE/issues/5)

## 승인 상태

본 문서는 2026-06-06 작업지시자의 추가 지시를 반영한 상세 구현계획서다. 인터셉트 로직 수정이 포함되므로 작업지시자가 본 문서를 확인하고 명시 승인하기 전까지 `bridge_server.py`, `frida_agent/agent.ts`, `frida_agent/agent.js`, `ghidra_side/frida_bridge.py`의 코드를 변경하지 않는다.

## 용어

- `tt`: target true. 사용자가 트레이스 대상으로 체크한 Ghidra 프로젝트 로드 모듈에 속한 위치.
- `tf`: target false. 체크되지 않은 모듈 또는 타겟 모듈 밖 위치.
- `src`: 직전 위치 offset. 기본 블록 전이에서는 직전 블록의 마지막 명령 offset.
- `dst`: 현재 위치 offset. 기본 블록 전이에서는 현재 블록의 시작 offset.
- `is_jump`: 직전 블록의 마지막 명령이 jump 계열이면 `true`.
- `target module bitmap`: 현재 로드된 모듈 base와 재배치된 offset을 기준으로 어떤 위치가 `tt`인지 판별하는 Native CModule 자료구조.
- `function-start bitmap`: Ghidra가 제공한 함수 시작 offset 집합을 target module별로 bitset화한 자료구조.

## 공식 API 근거

- Frida JavaScript API 문서: `Process.attachThreadObserver(callbacks)`는 thread 추가/삭제/rename 관찰 API이고, `Process.attachModuleObserver(callbacks)`는 module 추가/삭제 관찰 API다. `onAdded`는 기존 대상도 즉시 호출될 수 있으므로 초기 상태와 이후 변경을 같은 경로로 처리한다.
- Frida JavaScript API 문서: Stalker `transform(iterator)`는 Stalker가 기본 블록을 재컴파일할 때 동기 호출되며, 기본 블록 단위 계측을 삽입하는 경로다.
- Frida JavaScript API 문서: CModule은 JavaScript에서 C 코드를 컴파일해 NativePointer 함수로 호출할 수 있는 경로다.
- Frida JavaScript API 문서: `Process.setExceptionHandler(callback)`은 process-wide native exception handler를 설치하며, callback이 `true`를 반환하지 않으면 대상 프로세스의 예외 처리기로 전달된다.
- 참조 링크: https://frida.re/docs/javascript-api/

## 현재 상태 요약

- `frida_agent/agent.ts`
  - 현재 Stalker는 `events: { call: true, ret: true }`와 `onReceive(Stalker.parse(...))`로 call/ret만 기록한다.
  - jump 계열은 기록하지 않는다.
  - target export는 `hookTargetExports()`에서 `Interceptor.attach()`로 별도 기록한다.
  - thread 생성은 `NtCreateThreadEx`, `NtCreateThread` Interceptor 기반이다.
  - module load/unload는 `LdrLoadDll`, `LdrUnloadDll` Interceptor 기반이다.
- `bridge_server.py`
  - Ghidra `project_info` 파일 목록을 `LeftPanel`에 표시한다.
  - 현재 target 모듈 trace 여부를 사용자가 개별 선택하는 UI는 없다.
  - CallTreeBuilder는 `call`, `ret`, `sync`, `spawn` 중심으로 그래프를 만든다.
- `ghidra_side/frida_bridge.py`
  - 기존 RPC `symbols`가 module별 함수 `name`, `offset`, `end`를 반환한다. 함수 시작점 bitmap의 입력으로 재사용 가능하다.

## 요구사항별 설계

### 0-1. target module trace 체크박스

- `LeftPanel`의 타겟 모듈 목록은 `QListWidget`에서 2열 `QTreeWidget` 또는 동등한 item widget 기반 UI로 교체한다.
- 컬럼:
  - 0열: 모듈 파일명
  - 1열: trace 체크박스
- 체크박스는 각 항목 오른쪽에 표시한다.
- 기본값:
  - Ghidra 프로젝트 파일 중 `.exe`는 기본 checked.
  - `.dll` 등 다른 PE는 기본 unchecked로 두되, 작업지시자가 다르게 승인하면 전체 target 기본 checked로 바꾼다.
- trace 시작 전:
  - 체크박스 변경 가능.
  - `_selected_target_modules()`가 checked 항목만 반환한다.
- trace 중:
  - 모든 체크박스와 target 모듈 선택 UI를 disabled 처리한다.
  - trace 종료 또는 실패 후 다시 enabled 처리한다.
- Frida agent에는 checked target 목록만 `setTargets()` 또는 신규 RPC로 전달한다.
- 사용자가 target을 하나도 체크하지 않은 상태로 trace 시작하면 시작을 거부하고 상태바/메시지로 알린다.

### 0-2. 왼쪽 target/loaded module 비율 조정

- 왼쪽 패널 내부도 오른쪽 함수 검색/스레드 패널처럼 `QSplitter(Qt.Vertical)`로 구성한다.
- 위쪽: target module table.
- 아래쪽: loaded module list.
- 기존 start/stop 버튼은 splitter 밖 하단 고정 영역에 둔다.
- target/loaded module의 최소 높이는 작게 유지해 사용자가 거의 접을 수 있게 한다.

### 1. thread 생성 Interceptor 제거와 attachThreadObserver 도입

- 제거 대상:
  - `hookThreadCreation()`의 `NtCreateThreadEx`, `NtCreateThread` Interceptor.
  - thread 생성 감지를 위해 ntdll 함수에 의존하는 흐름.
- 신규 흐름:
  - agent 초기화 시 `Process.attachThreadObserver({ onAdded, onRemoved, onRenamed })` 등록.
  - `onAdded(thread)`에서 `thread.id`를 받으면 `attachStalker(thread.id, "thread_observer")` 호출.
  - 완전한 추적을 위해 부착 중 해당 thread를 잠시 suspend하고, `Stalker.follow()` 완료 후 resume한다.
  - 현재 구현의 `withThreadSuspended()`를 재사용하되, observer callback thread가 대상 thread와 같거나 suspend 실패 시의 fallback 정책을 문서화하고 상태 메시지를 남긴다.
- 기존 `spawn_events` 유지 여부:
  - attachThreadObserver는 ntdll hook처럼 thread handle/start routine/caller를 직접 제공하지 않는다.
  - Stage 5에서는 `ThreadSpawnEvent`를 축소해 `api="thread_observer"`, `child_tid`, `parent_tid=0`, `start_va="unknown"` 형태로 유지한다.
  - caller/start routine 추정은 본 task 범위 밖으로 두며, 그래프 연결은 실제 call/jump/ret 이벤트를 우선한다.

### 2. tt module export Interceptor 기록 제거

- `hookTargetExports()`, `hookLoadedTargetExports()`, `g_hooked_target_exports`, `target_export`, `target_export_tail_jump` 기록 경로를 제거한다.
- target export 진입은 Stalker call 또는 jump 전이 기록으로만 표현한다.
- Python CallTreeBuilder에 남아 있는 `source == "target_export"` 특수 처리도 제거 또는 비활성화한다.
- 이 변경으로 export Interceptor와 Stalker 이벤트의 중복 기록을 없앤다.

### 3-0. 재배치 고려

- 모든 판별은 raw VA가 아니라 `module base + offset` 구조로 한다.
- Ghidra에서 받은 함수 시작점은 image base 기준 offset으로 저장한다.
- Frida에서 module load 시 실제 `mod.base`와 `mod.size`를 관찰해 offset bitmap을 해당 base에 매핑한다.
- 같은 파일명이 unload 후 다른 base로 reload되면 기존 base mapping은 제거하고 새 base mapping을 생성한다.
- module name 비교는 기존처럼 basename 소문자 정규화를 사용한다.

### 3-1. tt 판별용 Native CModule bitmap

- agent에 `TraceClassifier` 계층을 추가한다.
- JS 상태:
  - checked target module name set.
  - 현재 로드된 module table: normalized name, base, size, target enabled 여부.
  - target bitmap buffer.
- CModule 역할:
  - `classify_pair(src_va, dst_va, out)` 형태의 함수 제공.
  - src/dst 각각에 대해 module range를 찾고 offset을 계산한다.
  - target bitmap으로 `src_tt`, `dst_tt`를 판별한다.
  - 둘 다 `tf`이면 call/ret/jump 기록 경로가 즉시 반환한다.
- bitmap 구성:
  - target module은 `[0, module.size)` 범위를 true로 둔다.
  - 비트 단위는 1바이트 정확도를 원칙으로 하되, 성능/메모리 문제가 확인되면 16바이트 granularity로 낮추는 변경은 별도 승인 후 진행한다.
- module 변경:
  - `Process.attachModuleObserver({ onAdded, onRemoved })` 사용.
  - onAdded/onRemoved 시 trace 중이면 다른 thread를 잠시 suspend하고 table/bitmap을 갱신한 후 resume한다.
  - `Stalker.exclude(range)`는 사용하지 않는다.

### 3-2. function-start bitmap

- Python trace 시작 준비 단계에서 Ghidra RPC `symbols`를 checked target module별로 호출한다.
- `symbols` 응답의 `offset`을 함수 시작점으로 사용한다.
- agent에는 target module별 function-start offset 목록을 전달한다.
- agent는 CModule bitmap을 갱신한다.
- trace 시작 버튼 클릭 시점에 Ghidra 함수 시작점 수집이 아직 끝나지 않았으면:
  - target exe는 spawn/attach 후 resume 전 상태를 유지한다.
  - Frida `start_trace` RPC 호출 전 function-start bitmap 준비 완료를 기다린다.
  - timeout은 두지 않는다. 사용자가 중단하면 stop/close 흐름으로 정리한다.
- module observer에서 target module load/unload가 감지되면 재배치를 반영해 function-start bitmap의 base mapping을 갱신한다.
- bitmap 준비 중에는 관련 thread를 suspend하고 갱신 완료 후 resume한다.

### 4-1. Stalker transform 기반 jump 전이 기록

- Stalker follow 옵션을 transform 기반으로 확장한다.
- 기본 블록 시작에 callout을 삽입해 다음 값을 계산한다.
  - `dst`: 현재 block 시작 offset.
  - `src`: 이전 block 마지막 명령 offset.
  - `is_jump`: 이전 block 마지막 명령이 jump 계열이면 true.
- transform 시점에 block의 마지막 instruction mnemonic을 판별한다.
  - x64/ia32 기준 `jmp`, `j*` 조건 분기, loop 계열을 jump로 본다.
  - `call`, `ret`은 각각 기존 call/ret 의미로 분리한다.
- runtime callout의 전이 처리:
  - 먼저 CModule classifier로 src/dst가 target 범위인지 판별한다.
  - src와 dst가 둘 다 `tf`이면 아무 것도 기록하지 않는다.
  - `is_jump == true`인 경우만 jump edge 후보로 본다.
  - jump 후보 중 다음 조건이면 기록한다.
    - `dst`가 `tt`이고 function-start bitmap에 포함된다.
    - 또는 `dst`가 `tf`.
  - `dst`가 `tt`이지만 function-start가 아니면 내부 if/switch로 보고 기록하지 않는다.
- call/ret 기록도 동일한 classifier를 통과한다.
  - src/dst가 모두 `tf`이면 call/ret도 기록하지 않는다.
  - `Stalker.exclude(range)`는 절대 사용하지 않는다.
- RawEvent 확장:
  - 기존 `k: 0|1`은 `type` 명시형으로 전환하거나 `k: 0|1|2`를 추가한다.
  - 권장안: Python 호환성을 위해 agent payload에는 `k: 0(call), 1(ret), 2(jump)`를 사용하고, `source`에는 `stalker_call`, `stalker_ret`, `stalker_jump`를 넣는다.
  - `postprocess()`는 `k == 2`를 `type="jump"`로 변환한다.

### 4-2. tunnel 치환과 return 처리

#### tunnel 치환

- 목표 그래프:
  - 실제 흐름: `tt1 -(call 또는 jump)> tf1 -> tf2 -> tf3 -(call 또는 jump)> tt2`
  - 표시 흐름: `tt1 -> tf1 -> tt2`
- tunnel은 같은 thread 안에서만 성립한다.
  - `last_external_node`와 outbound/inbound 후보는 `tid`별로 독립 보관한다.
  - thread가 다르면 모듈/offset 흐름이 이어져 보여도 tunnel로 묶지 않는다.
  - thread spawn 또는 sync 이벤트로 thread 간 관계를 추정하는 것은 본 task에서 tunnel 조건으로 사용하지 않는다.
- agent 기록 정책:
  - `tt -> tf` call/jump는 외부 진입 노드 `tf1`로 기록한다.
  - `tf -> tf`는 기록하지 않는다.
  - `tf -> tt` call/jump는 기록한다.
- Python CallTreeBuilder 정책:
  - thread별로 `last_external_node`와 `last_outbound`를 둔다.
  - `tt -> tf` 이벤트를 만나면 external node를 만들고 `last_external_node`에 저장한다.
  - 동시에 outbound의 `src`는 `tt1` offset, outbound의 `dst`는 `tf1` offset으로 저장한다.
  - 이후 `tf -> tt` 이벤트가 나오면 stack top이 아니라 `last_external_node`에서 `tt2`로 edge를 연결한다.
  - 이때 inbound의 `src`가 이전 outbound의 `dst`와 같은 외부 모듈/offset이거나, 같은 thread에서 `tf1` 이후 연속 tunnel 상태로 판정될 때만 치환한다.
  - `tf -> tt` 연결 후 `last_external_node`는 제거한다.
  - 같은 thread에서 다른 `tt -> tf`가 먼저 나오면 이전 tunnel은 만료한다.
- edge kind:
  - call 기반 tunnel: `call`.
  - jump 기반 tunnel: `jump`.
  - UI 색상은 기존 call 색을 우선 재사용하고, 필요 시 후속 작업에서 jump 색상을 분리한다.

#### return 처리

- ret는 Stalker ret callout 또는 기존 ret event 경로로 확인한다.
- ret도 classifier를 통과한다.
  - 둘 다 `tf`이면 기록하지 않는다.
  - `tf -> tt` ret는 external return 후보로 본다.
  - `tt -> tf` ret는 target에서 외부로 나가는 흐름이므로 external node 또는 stack unwind에 반영한다.
- ret 대응은 outbound `src`와 inbound `dst` 대조를 우선한다.
  - `tt -> tf` outbound ret/call/jump를 저장할 때 outbound `src`는 target caller offset이다.
  - 이후 같은 thread에서 `tf -> tt` inbound ret가 오면 inbound `dst`가 저장된 outbound `src`와 같은 target module/offset인지 확인한다.
  - 일치하면 외부 호출에서 원래 target caller로 돌아온 것으로 보고 tunnel/return edge를 닫는다.
  - 불일치하면 ret stack match를 fallback으로 쓰되, 같은 thread 조건은 유지한다.
- ret matching은 기존 `_ret_stack_match_index()`를 유지하되, jump로 생성된 node는 call stack push 여부를 분리한다.
  - call node는 stack push.
  - jump node는 tail-call 성격이면 parent를 바꾸되 ret stack push는 하지 않는 정책을 기본으로 한다.

#### exception 기반 tunnel 오탐 억제

- 외부 DLL 실행 중 exception unwind가 발생하면 정상 call/jump inbound가 아니어도 `tf -> tt` 복귀처럼 보일 수 있다.
- 이 경우 tunnel이 `tt -> tf -> tt`로 잘못 닫히는 오탐이 생길 수 있으므로 `Process.setExceptionHandler(callback)` 사용을 고려한다.
- v1 정책:
  - exception handler는 예외를 삼키지 않는다.
  - callback은 exception details의 `type`, `address`, `context.pc`, `context.sp`, 현재 `tid`, classifier 결과를 기록하고 `false`를 반환해 원래 프로세스 예외 처리기로 전달한다.
  - 같은 thread의 tunnel state에 `exception_seen` marker를 남긴다.
  - marker에는 exception 발생 시점의 `pc`가 `tf`인지, `sp` 값, seq 근사값을 포함한다.
- tunnel 억제 규칙:
  - `tt -> tf` outbound 이후 같은 thread에서 exception marker가 발생하고, 그 뒤 `tf -> tt` inbound가 들어오면 기본적으로 tunnel 치환하지 않는다.
  - 단, inbound가 명확한 call/jump event이고 outbound/inbound offset 대조가 직접 일치하는 경우만 예외적으로 tunnel을 허용한다.
  - ret inbound는 exception marker가 있으면 outbound `src`와 inbound `dst`가 일치해도 exception unwind 가능성을 우선하여 tunnel을 닫지 않고 별도 `exception_return` 후보로 둔다.
  - exception marker는 같은 thread에서 다음 정상 `tt -> tt` 또는 새 `tt -> tf` outbound를 만나면 만료한다.
- Python 그래프 정책:
  - RawEvent 또는 별도 `exception_events`에 exception marker를 저장한다.
  - CallTreeBuilder는 marker 이후의 inbound를 tunnel이 아닌 `flow` 또는 미표시 후보로 처리한다.
  - UI에 exception edge를 별도 표시할지는 v2로 미룬다. v1에서는 오탐 억제가 목표다.

### 4-3. sync/handler 계열 Interceptor 정책

- 본 task의 v1 목표는 user-level DLL API hook을 늘리지 않는 것이다.
- `user32`, `kernel32`, `kernelbase`의 sync/handler/message API를 개별 Interceptor로 확장하는 방식은 유지보수 비용과 미탐 위험을 높인다.
- 따라서 다음 항목은 version 2 후보로 이월한다.
  - user32 message handler 계열 세부 추적.
  - kernel32/kernelbase sync wrapper API별 세부 추적.
  - GUI message loop 의미론 복원.
  - handle lifetime을 API별로 완전 복원하는 로직.
- v1에서 유지 또는 허용하는 낮은 수준의 hook:
  - process 종료 flush를 위한 `RtlExitUserProcess`, `NtTerminateProcess` 등 최소 종료 hook.
  - Frida observer API가 대체할 수 없는 경우에 한해 명시 승인된 ntdll 수준 fallback.
- v1에서 caller 해결 방식:
  - user-level API hook으로 caller를 찾지 않는다.
  - Stalker transform의 call/jump/ret 이벤트와 같은-thread tunnel로 `tt` 범위 안 caller를 복원한다.
  - `tt -> tf` outbound의 `src`를 caller로 저장하고, `tf -> tt` inbound의 `dst` 또는 ret inbound의 `dst`와 대조한다.
  - 이 경로로 해결되지 않는 user-level sync/handler 의미는 그래프에 억지로 그리지 않고 version 2 분석 대상으로 남긴다.

## 예상 변경 파일

수정:

- `bridge_server.py`
  - target module 체크박스 UI
  - 왼쪽 내부 splitter
  - trace 시작 시 checked target 목록과 Ghidra function-start offset 수집
  - agent RPC 호출 인자 확장
  - `postprocess()`의 jump 이벤트 처리
  - `CallTreeBuilder`의 same-thread tunnel/jump/ret 그래프 처리
  - outbound `src`와 inbound `dst` 대조 기반 ret 대응
  - exception marker 기반 tunnel 오탐 억제
- `frida_agent/agent.ts`
  - target export Interceptor 제거
  - ntdll thread creation Interceptor 제거
  - `attachThreadObserver` 도입
  - `attachModuleObserver` 도입
  - `Process.setExceptionHandler()` marker 추가
  - CModule classifier 및 bitmap 구축
  - Stalker transform/callout 기반 jump 전이 기록
  - call/ret tf-tf 필터
  - user-level sync/handler Interceptor 신규 구현 금지
- `frida_agent/agent.js`
  - `agent.ts` 변경 후 `frida-compile`로 재생성
- `ghidra_side/frida_bridge.py`
  - 기존 `symbols` RPC 재사용이 충분하면 변경 없음
  - 필요 시 function-start 전용 RPC `function_starts` 추가
- `mydocs/plans/task_m000_5_impl.md`
  - 본 구현계획서
- `mydocs/working/task_m000_5_stage{N}.md`
  - 단계별 완료 보고서

## 구현 단계

### Stage 3 - UI target 선택과 왼쪽 splitter

- `LeftPanel` target 목록을 checkbox 포함 table/tree로 교체한다.
- checked target만 trace 대상이 되도록 MainWindow/FridaWorker 전달값을 변경한다.
- trace 중 checkbox disabled 처리한다.
- 왼쪽 target/loaded module 영역을 vertical splitter로 바꾼다.
- 검증:
  - `python -m py_compile bridge_server.py`
  - trace 전 checkbox 변경 가능 확인
  - trace 중 checkbox disabled 확인
  - checked target이 0개일 때 trace 시작 거부 확인

### Stage 4 - Ghidra function-start 준비 경로

- trace 시작 전에 checked target module별 Ghidra `symbols` RPC를 호출해 함수 시작 offset 목록을 만든다.
- agent에 target module 목록과 function-start 목록을 전달하는 RPC 형태를 확정한다.
- bitmap 준비 전 target exe가 resume되지 않도록 `FridaWorker.start_trace()` 순서를 조정한다.
- 검증:
  - `python -m py_compile bridge_server.py ghidra_side/frida_bridge.py`
  - Ghidra 연결 상태에서 target별 function count 로그 확인
  - Ghidra 미연결 시 trace 시작 차단 또는 명확한 오류 표시 확인

### Stage 5 - Thread/Module observer 전환

- `hookThreadCreation()` ntdll Interceptor 제거.
- `Process.attachThreadObserver()` 등록.
- observer onAdded에서 thread suspend → Stalker attach → resume 수행.
- `hookModules()`의 LdrLoadDll/LdrUnloadDll Interceptor 제거.
- `Process.attachModuleObserver()`로 load/unload record와 bitmap 갱신을 처리한다.
- 검증:
  - `npm --prefix frida_agent run build` 또는 기존 `frida-compile agent.ts -o agent.js`
  - 새 thread 생성 시 `stalker:tid=... reason=thread_observer` 상태 로그 확인
  - module load/unload 상태 로그 확인

### Stage 6 - CModule bitmap classifier

- CModule에 module range table, target bitmap, function-start bitmap 조회 함수를 구현한다.
- JS에서 observer/RPC 결과를 CModule table에 반영한다.
- 재배치 대응을 위해 load/unload 시 base mapping을 갱신한다.
- call/ret 기록 전에 classifier를 호출해 tf-tf를 배제한다.
- `Stalker.exclude(range)`가 코드에 존재하지 않도록 확인한다.
- 검증:
  - `rg -n "Stalker\\.exclude" frida_agent/agent.ts frida_agent/agent.js` 결과 없음
  - synthetic 또는 로그 기반으로 tt-tf, tf-tt, tf-tf 판별 확인
  - tf-tf call/ret 미기록 확인

### Stage 7 - Stalker transform jump 기록

- transform에서 block start callout을 삽입한다.
- per-thread previous block state로 `src`, `dst`, `is_jump`를 계산한다.
- jump 후보 조건을 적용한다.
  - dst tt + function-start면 기록
  - dst tf면 기록
  - dst tt + function-start 아님이면 기록 안 함
- RawEvent에 `k=2` 또는 명시 type을 추가하고 Python postprocess에 연결한다.
- 검증:
  - 조건분기 내부 이동이 그래프 노드로 과다 생성되지 않는지 확인
  - target 함수 진입 jump가 기록되는지 확인
  - tf inbound/outbound jump가 기록되는지 확인

### Stage 8 - 그래프 tunnel/return 반영

- CallTreeBuilder가 `jump` 이벤트를 받도록 확장한다.
- 같은 thread에서만 `tt -> tf -> ... -> tt` tunnel 치환을 적용한다.
- thread가 다르면 tunnel 후보를 폐기한다.
- exception marker가 같은 thread의 outbound/inbound 사이에 있으면 tunnel 치환을 억제한다.
- `tf -> tf` 이벤트는 agent에서 이미 배제되지만, Python에서도 방어적으로 배제한다.
- ret 이벤트는 classifier 결과, exception marker, outbound `src`와 inbound `dst` 대조, stack match fallback 순서로 external return edge를 만든다.
- 검증:
  - synthetic trace로 같은 thread `tt1 -> tf1 -> tt2` 그래프 확인
  - synthetic trace로 다른 thread tunnel 미적용 확인
  - outbound `src`와 inbound `dst`가 일치하는 ret 복귀 확인
  - exception marker가 outbound/inbound 사이에 있는 경우 tunnel 미적용 확인
  - `tf -> tf` 노드가 생성되지 않는지 확인
  - ret 기반 복귀 edge가 기존 call stack을 과도하게 무너뜨리지 않는지 확인

### Stage 9 - 통합 검증과 보고

- 실제 target exe + Ghidra 연결로 end-to-end trace를 수행한다.
- agent.ts와 agent.js 동기화를 확인한다.
- stage 보고서와 최종 보고서를 작성한다.
- 검증:
  - `python -m py_compile bridge_server.py ghidra_side/frida_bridge.py`
  - `npm --prefix frida_agent run build` 또는 승인된 frida compile 명령
  - `git diff --check`
  - 수동 시나리오 3종:
    - checked target 1개만 trace
    - tt -> tf -> tt tunnel
    - thread가 다른 tt/tf 전이는 tunnel 미적용
    - jump로 target function entry 진입

## 데이터 형식 초안

### Agent target config

```ts
type TargetModuleConfig = {
  name: string;
  trace: boolean;
  function_starts: string[];
};
```

### RawEvent 확장

```ts
type RawEventKind = 0 | 1 | 2; // 0=call, 1=ret, 2=jump

interface RawEvent {
  k: RawEventKind;
  src: string;
  dst: string;
  tid: number;
  seq: number;
  src_module?: string;
  src_offset?: string;
  dst_module?: string;
  dst_offset?: string;
  src_tt?: boolean;
  dst_tt?: boolean;
  is_jump?: boolean;
  source?: string;
}
```

### ExceptionEvent 초안

```ts
interface ExceptionEvent {
  seq: number;
  tid: number;
  type: string;
  address: string;
  pc: string;
  sp: string;
  pc_tt?: boolean;
}
```

## 수용 기준

- target module 체크박스가 각 target 항목 오른쪽에 표시된다.
- trace 중 target 체크박스가 비활성화된다.
- 왼쪽 target/loaded module 비율을 사용자가 세로로 조정할 수 있다.
- ntdll thread creation Interceptor가 제거되고 `Process.attachThreadObserver()`가 thread 추적 진입점이 된다.
- target export Interceptor 기록이 제거된다.
- target 판별과 function-start 판별은 재배치된 module base를 반영한다.
- module load/unload는 `Process.attachModuleObserver()`로 반영된다.
- tf-tf call/ret/jump는 기록되지 않는다.
- `Stalker.exclude(range)`를 사용하지 않는다.
- jump 계열은 transform 기반으로 기록된다.
- 같은 thread의 `tt1 -> tf1 -> tf2 -> tf3 -> tt2` 흐름은 그래프에서 `tt1 -> tf1 -> tt2`로 표시된다.
- 다른 thread의 `tt -> tf -> tt` 유사 흐름은 tunnel로 치환하지 않는다.
- ret 복귀는 outbound `src`와 inbound `dst` 대조를 우선해 대응한다.
- exception marker가 같은 thread의 tunnel 후보 사이에 있으면 tunnel 오탐을 억제한다.
- `Process.setExceptionHandler()`는 exception을 삼키지 않고 원래 프로세스 예외 처리기로 전달한다.
- user-level sync/handler Interceptor 신규 구현은 v2로 이월한다.

## 리스크와 대응

- **observer API 버전 리스크**: 사용자 환경의 Frida가 `attachThreadObserver`/`attachModuleObserver`를 지원하지 않을 수 있다. 시작 시 API 존재 여부를 검사하고, 없으면 명확한 오류로 trace 시작을 중단한다.
- **thread suspend deadlock 리스크**: observer callback 중 임의 thread suspend가 민감할 수 있다. 현재 thread는 suspend하지 않고, 실패 시 상태 로그를 남긴 뒤 attach를 시도하거나 failure scan을 예약한다.
- **CModule 메모리/정렬 리스크**: 1바이트 bitset이 큰 모듈에서 메모리를 더 쓸 수 있다. 우선 정확도를 택하고, 문제가 확인되면 granularity 조정은 별도 승인 후 진행한다.
- **jump 과기록 리스크**: 조건분기 내부 이동이 그래프를 오염시킬 수 있다. `dst tt && function-start` 조건으로 target 내부 jump 기록을 함수 진입에 한정한다.
- **ret stack 리스크**: jump와 call의 stack 의미가 다르다. jump node는 기본적으로 stack push하지 않고, call node만 push한다.
- **cross-thread tunnel 오탐 리스크**: 외부 DLL을 사이에 둔 유사한 흐름이 다른 thread에서 나타날 수 있다. tunnel state를 thread별로 분리하고 thread가 다르면 치환하지 않는다.
- **exception unwind tunnel 오탐 리스크**: exception으로 외부에서 내부로 복귀하면 정상 inbound처럼 보일 수 있다. `Process.setExceptionHandler()` marker를 기록하고 marker 이후 inbound tunnel을 억제한다.
- **user-level hook 유지보수 리스크**: user32/kernel32/kernelbase wrapper를 넓게 hook하면 OS 버전/API 변형별 누락 가능성이 커진다. v1에서는 observer, ntdll 최소 hook, Stalker+tunnel만 사용하고 sync/handler 의미론은 v2로 미룬다.
- **Ghidra 미연결 리스크**: function-start bitmap을 만들 수 없으면 jump 판별이 불완전하다. 본 계획은 trace 시작을 차단하고 사용자에게 Ghidra 연결 필요 상태를 표시한다.

## 승인 요청 사항

작업지시자는 다음 항목을 확인 후 승인한다.

- checked target module만 `tt`로 판정하는 정책.
- `.exe` 기본 checked, `.dll` 기본 unchecked 정책.
- thread observer로는 기존 ntdll hook 수준의 start routine/caller를 즉시 알 수 없으므로 Stage 1에서는 spawn metadata를 축소하는 정책.
- Ghidra function-start 준비가 끝나기 전에는 target exe를 resume하지 않는 정책.
- RawEvent에 `k=2` jump를 추가하는 데이터 형식 변경.
- jump node는 기본적으로 call stack push하지 않는 그래프 정책.
- tunnel은 같은 thread에서만 적용하는 정책.
- ret 대응에서 outbound `src`와 inbound `dst` 대조를 우선하는 정책.
- `Process.setExceptionHandler()`를 예외 삼키기 용도가 아니라 tunnel 오탐 억제 marker 용도로 사용하는 정책.
- user-level sync/handler Interceptor 구현을 version 2로 이월하고, v1에서는 ntdll 최소 hook과 Stalker+tunnel로 caller를 해결하는 정책.
- 승인 전까지 코드 변경 금지.
