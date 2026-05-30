# 구현계획서

GitHub Issue: [#3](https://github.com/cho2659/JanusRE/issues/3)
수행계획서: [`task_m000_3.md`](task_m000_3.md)
마일스톤: M000

## Stage 1 — 전송 전 trace 필터

### 산출물

- `frida_agent/agent.ts`
  - target 모듈명 판정 helper 추가
  - `sendTraceChunk()`에서 raw trace slice를 전송용 filtered trace로 변환
  - status 로그에 raw/filtered 이벤트 수 표시

### 검증

- `git diff -- frida_agent/agent.ts`
- 가능한 경우 agent 빌드 또는 TypeScript 문법 확인

### 커밋 메시지

- `Task #3 Stage 1: trace 전송 필터 추가`

## Stage 2 — 외부 경유 그래프 연결

### 산출물

- `bridge_server.py`
  - 외부에서 target으로 들어오는 call이 대표 외부 노드 아래에 붙도록 현재 stack 동작 확인
  - 외부에서 target으로 복귀하는 ret 이벤트가 대표 외부 노드를 과도하게 pop하지 않도록 조정

### 검증

- `python -m py_compile bridge_server.py`
- `git diff -- bridge_server.py`

### 커밋 메시지

- `Task #3 Stage 2: 외부 경유 그래프 연결 조정`

## Stage 3 — 통합 검증과 보고

### 산출물

- `mydocs/working/task_m000_3_stage1.md`
- `mydocs/working/task_m000_3_stage2.md`
- `mydocs/working/task_m000_3_stage3.md`
- `mydocs/report/task_m000_3_report.md`
- `mydocs/orders/20260530.md`

### 검증

- `git diff --check`
- `git status --short`
- 변경 diff 최종 리뷰

### 커밋 메시지

- `Task #3 Stage 3 + 최종 보고서: trace 필터링 검증 정리`

## PR 정책

이번 task는 작업지시자가 단일 기여자 로컬 구현 및 검증을 명시했으므로 원격 PR 생성 단계는 생략한다.
