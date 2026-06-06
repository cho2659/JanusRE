# Task M000 #6 수행계획서

GitHub Issue: [#6](https://github.com/cho2659/JanusRE/issues/6)
마일스톤: M000

## 목적

그래프 생성 시 부모/자식 관계가 잘못 붙거나 같은 부모의 호출이 분리되는 문제를 줄인다. 우선 `CallTreeBuilder`의 call/ret stack 처리와 이벤트 필터링 영향을 점검하고, 오탐 edge가 생기지 않도록 보수적으로 수정한다.

## 범위

### 포함

- `CallTreeBuilder._build_thread()`의 call/ret 매칭 점검 및 수정
- 필터링된 이벤트 때문에 stack 균형이 깨지는 경우의 처리
- external 복귀/flow edge 오탐 여부 점검
- 검증 가능한 synthetic trace 또는 최소 재현 검증 추가

### 제외

- Ghidra host/server 구조 변경
- 노드 더블클릭/보라색 라벨 상호작용 변경
- Frida agent 수집 로직 변경. 필요성이 확인되면 별도 단계 승인 후 진행

## 설계 방향

- ret가 현재 stack top과 맞는지 확인하고, 맞지 않으면 잘못된 pop으로 이후 부모를 오염시키지 않는다.
- 필터링 때문에 call/ret 쌍이 깨진 경우는 새 root 또는 보수적 연결로 처리한다.
- 기존 #4 UI 변경 위에서 브랜치를 만들었으므로, 문제가 생기면 커밋 단위 cherry-pick으로 분리 가능하게 작게 커밋한다.

## 예상 변경 파일

수정:

- `bridge_server.py`
- `mydocs/orders/20260605.md`

신규:

- `mydocs/plans/task_m000_6.md`
- `mydocs/plans/task_m000_6_impl.md`
- `mydocs/working/task_m000_6_stage1.md`
- `mydocs/report/task_m000_6_report.md`

## 잠정 단계

- **Stage 1 - 원인 분석과 검증 케이스**
  - call/ret 불일치와 필터링 영향 케이스 정리
  - synthetic trace 검증 방식 준비
- **Stage 2 - CallTreeBuilder 수정**
  - stack 매칭과 보수적 parent 결정 로직 수정
  - 검증 케이스 통과 확인
- **Stage 3 - 최종 검증과 보고**
  - 문법/검증/보고서 정리

## 검증 계획

- `python -m py_compile bridge_server.py`
- synthetic trace로 부모/자식 관계 확인
- `git diff --check`
- `git status --short`

## 리스크

- 실제 런타임 trace의 불균형 원인이 agent 수집 단계에 있을 수 있다. 이 경우 Python 그래프 빌더에서 가능한 보수 처리까지만 수행하고 agent 변경은 별도 승인으로 분리한다.

## 승인 요청 사항

- 위 범위로 구현계획서 작성 단계에 진입하는 것을 승인 요청한다.
