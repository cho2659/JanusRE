# 수행계획서

GitHub Issue: [#3](https://github.com/cho2659/JanusRE/issues/3)
마일스톤: M000

## 목적

모든 스레드와 모듈에 Stalker를 붙이는 현재 추적 신뢰성 우선 정책을 유지하면서, 종료 또는 chunk 전송 시 Python으로 넘어가는 trace 양을 줄인다.

그래프에서는 실제 흐름이 `내부1 -> 외부1 -> 외부2 ... -> 내부2`처럼 길어도, 내부 함수가 처음 호출한 외부 함수만 대표 노드로 보여 `내부1 -> 외부1 -> 내부2` 흐름으로 읽히게 한다.

## 배경

현재 구현은 Stalker call/ret 이벤트를 모듈 필터 없이 기록하고 Python으로 전달한다. 타겟 프로그램 실행 중 오버헤드는 제한적이지만, 종료 후 Python 후처리와 GUI 로드 단계에서 대량 로그로 인한 지연이 발생한다.

사용자는 최적화보다 추적 신뢰성을 우선하므로 Stalker 부착 범위를 줄이지 않고, agent 내부에서 전송 직전 필터링하는 방향을 승인했다.

## 범위

### 포함

- `frida_agent/agent.ts`에서 Python 전송 직전 target 관련 trace만 남기는 필터 추가
- `bridge_server.py`에서 ret를 그래프 노드로 그리지 않고 call stack 정리에만 사용하도록 조정
- 로컬 정적 검증과 산출물 문서 작성

### 제외

- Stalker 부착 대상 축소
- 원격 PR 생성
- Ghidra side 기능 확장
- 새 UI 기능 추가

## 설계 방향

- 수집 단계에서는 raw trace를 보존하고, 전송 단계에서만 `src` 또는 `dst`가 target 모듈인 이벤트를 선별한다.
- target 모듈 판정은 Ghidra에서 받은 파일명과 메인 EXE 기준을 사용하며, 확장자 유무 차이를 흡수한다.
- 외부-only 이벤트는 Python으로 보내지 않는다.
- 그래프 빌더는 call 이벤트만 노드로 생성한다.
- ret 이벤트는 call stack pop에만 사용해 부모-자식 관계 정합성을 보조하고, 복귀 주소를 하위 호출처럼 표시하지 않는다.

## 예상 변경 파일

신규:

- `mydocs/orders/20260530.md`
- `mydocs/plans/task_m000_3.md`
- `mydocs/plans/task_m000_3_impl.md`
- `mydocs/working/task_m000_3_stage1.md`
- `mydocs/working/task_m000_3_stage2.md`
- `mydocs/working/task_m000_3_stage3.md`
- `mydocs/report/task_m000_3_report.md`

수정:

- `frida_agent/agent.ts`
- `bridge_server.py`

## 잠정 단계

- **Stage 1 — 전송 전 trace 필터**
  - agent 내부 target 판정과 trace payload 필터 구현
  - TypeScript 정적 검증 또는 빌드 가능성 확인
- **Stage 2 — ret 그래프 제외**
  - ret 노드 생성을 제거하고 stack 정리에만 사용하도록 그래프 빌더 조정
  - Python syntax와 로직 단위 확인
- **Stage 3 — 통합 검증과 보고**
  - diff, 정적 검증, 문서 산출물 정리
  - 최종 보고서 작성

## 검증 계획

### 단계별 검증

- Stage 1
  - `git diff -- frida_agent/agent.ts`
  - 가능한 경우 Frida agent 빌드 또는 TypeScript 문법 확인
- Stage 2
  - `python -m py_compile bridge_server.py`
  - 그래프 빌더 로직 리뷰
- Stage 3
  - `git diff --check`
  - `git status --short`

### 통합 검증

- 외부-only trace 이벤트가 Python payload에서 제외되는지 코드상 확인한다.
- target 관련 call/ret/jmp trace가 유지되는지 코드상 확인한다.
- `내부1 -> 외부1 -> 외부2 ... -> 내부2` 흐름이 `내부1 -> 외부1 -> 내부2` 대표 구조로 남는지 그래프 빌더 로직상 확인한다.

## 리스크

- **메모리 사용량 유지**: 실행 중 raw trace는 계속 agent 내부에 쌓이므로 장시간 실행 시 메모리 사용량은 별도 최적화가 필요할 수 있다.
- **stack 정합성**: call/ret 이벤트가 누락되는 비정상 흐름에서는 부모-자식 관계가 흔들릴 수 있다.

## 승인 요청 사항

- 본 task는 사용자가 같은 스레드에서 계획 승인과 즉시 구현 지시를 내렸으므로, PR 생략 조건을 반영해 로컬 구현과 검증까지 진행한다.
