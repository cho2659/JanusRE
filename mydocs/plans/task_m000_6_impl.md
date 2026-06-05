# Task M000 #6 구현계획서

GitHub Issue: [#6](https://github.com/cho2659/JanusRE/issues/6)
수행계획서: `mydocs/plans/task_m000_6.md`

## Stage 1 - 원인 분석과 검증 케이스

### 산출물

- `bridge_server.py`
  - `CallTreeBuilder` 검증에 사용할 최소 synthetic trace helper 또는 테스트성 함수 추가
  - call/ret 불일치, 필터링으로 인한 stack 불균형, external 복귀 케이스 정리
- `mydocs/working/task_m000_6_stage1.md`

### 검증

- `python -m py_compile bridge_server.py`
- synthetic trace로 현재 오탐 재현 여부 확인

### 커밋 메시지

- `Task #6 Stage 1: 그래프 오탐 검증 케이스 정리`

## Stage 2 - CallTreeBuilder 수정

### 산출물

- `bridge_server.py`
  - ret와 현재 stack top의 callsite/target 매칭 확인
  - 불일치 ret가 이후 parent stack을 오염시키지 않도록 보수 처리
  - external-to-target ret/flow edge 오탐 완화

### 검증

- `python -m py_compile bridge_server.py`
- synthetic trace 검증 통과

### 커밋 메시지

- `Task #6 Stage 2: CallTreeBuilder 부모 관계 오탐 완화`

## Stage 3 - 최종 검증과 보고

### 산출물

- `mydocs/report/task_m000_6_report.md`
- `mydocs/orders/20260605.md`

### 검증

- `python -m py_compile bridge_server.py`
- `git diff --check`
- `git status --short`

### 커밋 메시지

- `Task #6 Stage 3 + 최종 보고서: 검증과 보고서 정리`

## 승인 요청

위 3단계 구현계획으로 Stage 1에 진입하는 것을 승인 요청한다.
