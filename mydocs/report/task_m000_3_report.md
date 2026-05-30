# 최종 보고서

GitHub Issue: [#3](https://github.com/cho2659/JanusRE/issues/3)
마일스톤: M000

## 작업 요약

- 대상 이슈: #3
- 마일스톤: M000
- 단계 수: 3
- 작업 목적: Stalker 추적 신뢰성은 유지하고 Python 전송 trace를 target 경계 중심으로 줄인다.

## 변경 파일 목록과 영향 범위

| 경로 | 변경 요약 | 영향 범위 |
|---|---|---|
| `frida_agent/agent.ts` | target 이름 판정 helper와 전송 전 trace 필터 추가 | Frida agent trace payload |
| `frida_agent/agent.ts` | x86 operand 기반 indirect jmp 목적지 해석 보강 | Frida agent `stalker_jmp` |
| `frida_agent/agent.js` | 빌드 결과 갱신 | 런타임 agent |
| `bridge_server.py` | ret 그래프 노드 생성을 제거하고 `stalker_jmp`는 tail-call stack 교체로 처리 | Call graph 구성 |
| `bridge_server.py` | 노드 클릭/더블클릭, 검색 포커스 확대, 스레드 탭 단축, 레이아웃 cycle guard 보정 | GUI 상호작용 |
| `mydocs/orders/20260530.md` | 오늘할일 #3 항목 추가 | 작업 추적 |
| `mydocs/plans/task_m000_3.md` | 수행계획서 작성 | 작업 계획 |
| `mydocs/plans/task_m000_3_impl.md` | 구현계획서 작성 | 단계 계획 |
| `mydocs/working/task_m000_3_stage1.md` | Stage 1 보고 | 단계 기록 |
| `mydocs/working/task_m000_3_stage2.md` | Stage 2 보고 | 단계 기록 |
| `mydocs/working/task_m000_3_stage3.md` | Stage 3 보고 | 단계 기록 |

## 변경 전·후 정량 비교

| 지표 | 변경 전 | 변경 후 |
|---|---|---|
| Python 전송 trace 이벤트 | Stalker raw call/ret 전체 slice | `src_module` 또는 `dst_module`이 target인 이벤트만 |
| ret 이벤트 처리 | 일부 external-to-target ret를 그래프 노드로 생성 | 그래프 노드 생성 없이 call stack pop에만 사용 |
| indirect jmp 처리 | 문자열 operand 해석과 보수적 boundary 판정 | operand 기반 해석 우선, 실행 가능 목적지 fallback 기록 |
| 노드 더블클릭 | child/spawn hotspot 활성화 가능 | 해당 노드 Ghidra sync/포커스만 수행 |
| 노드 단일클릭 | child toggle 또는 spawn 탭 이동 가능 | 선택만 수행 |
| 스레드 탭 라벨 | `Thread {tid}` | `T{tid}` 단축 표기와 tooltip |
| 검색 결과 이동 | 노드 중심 이동 | 노드 확대 포커스 |

## 검증 결과

| 수용 기준 | 결과 |
|---|---|
| 외부-only trace 이벤트가 Python payload에서 제외된다 | OK — `filterTraceEventsForSend()`가 target 관련 이벤트만 반환 |
| target 관련 이벤트는 유지된다 | OK — `src_module` 또는 `dst_module` 중 하나가 target이면 유지 |
| SaveAs의 `JMP qword ptr [RAX + 0x28]`가 ret가 아닌 호출 경로로 기록된다 | OK — x86 operand mem 해석과 executable fallback을 통해 `stalker_jmp` call 이벤트 기록 |
| `내부1 -> 외부1 -> 외부2 ... -> 내부2` 흐름은 대표 외부 노드 중심으로 남는다 | OK — 외부-only 이벤트는 전송 제외, ret는 노드 생성 없이 stack 정리에만 사용 |
| 기존 target 내부 call/jmp 추적을 제거하지 않는다 | OK — Stalker follow, transform, `recordJumpFromCallout()` 수집 경로는 유지 |
| 일반 노드 더블클릭이 다른 스레드 탭으로 이동하지 않는다 | OK — double click hotspot activation과 cross-thread scene 혼합 제거 |
| 단일 클릭이 스레드 링크 이동을 수행하지 않는다 | OK — mousePress hotspot activation 제거 |
| 더블클릭 때 펼치기 기능을 제거한다 | OK — double click은 해당 노드 activate만 수행 |
| 함수 검색 후 더블클릭 시 해당 노드를 확대한 상태로 보여준다 | OK — function selection에서 `zoom=True` 포커스 적용 |
| 스레드 탭 TID 가시성을 개선한다 | OK — `T{tid}` 단축 라벨과 tooltip 적용 |
| PR 생략 | OK — 작업지시자 지시에 따라 로컬 브랜치에서 구현 및 검증 |

### 단계별 검증 결과

- Stage 1: `npm run build`, `git diff --check` 통과
- Stage 2: `bridge_server.py` AST syntax 확인, `npm run build` 통과
- Stage 3: `git diff --check`, `git status --short --branch`, `bridge_server.py` AST syntax 확인

## 잔여 위험과 후속 작업

### 잔여 위험

- 실제 대상 프로세스를 실행한 end-to-end trace 검증은 이번 자동 검증 범위에 포함하지 못했다.
- agent 내부 raw trace 메모리 사용량은 장시간 실행 시 여전히 증가할 수 있다.

### 후속 작업 후보

- 장시간 trace에서 agent 내부 raw trace 보관량을 제한하거나 압축하는 별도 task
- 실제 바이너리 기반으로 call/ret stack 정합성을 샘플링해 그래프 연결 규칙 보정

## 작업지시자 승인 요청

- 최종 보고서와 수용 기준 검증 결과를 승인하면 PR 게시 없이 로컬 작업 완료로 본다.
