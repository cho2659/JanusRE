# Task M000 #4 구현계획서

GitHub Issue: [#4](https://github.com/cho2659/JanusRE/issues/4)
수행계획서: `mydocs/plans/task_m000_4.md`

## 구현 원칙

- UI 배치와 스레드 선택 경로만 변경한다.
- Frida agent, Ghidra 통신, 콜 그래프 레이아웃 알고리즘은 변경하지 않는다.
- `CallGraphPanel`이 그래프 상태를 계속 소유하고, 오른쪽 패널의 스레드 목록은 선택 UI 역할만 맡는다.

## Stage 1 - 스레드 목록 패널과 선택 API

### 산출물

- `bridge_server.py`
  - 스크롤 가능한 목록형 `ThreadListPanel` 추가
  - `CallGraphPanel`에 TID 목록 변경 signal 추가
  - 외부에서 TID 선택을 요청하는 공개 메서드 추가

### 검증

- `python -m py_compile bridge_server.py`
- TID 목록 생성과 현재 TID 전환 경로 코드 점검

### 커밋 메시지

- `Task #4 Stage 1: 스레드 목록 선택 경로 추가`

## Stage 2 - 오른쪽 패널 배치와 중앙 탭 제거

### 산출물

- `bridge_server.py`
  - `MainWindow` 오른쪽 함수 검색 패널 아래에 `ThreadListPanel` 배치
  - 스레드 목록 더블클릭 signal을 그래프 전환 메서드에 연결
  - 중앙 그래프 영역에서 스레드 탭 표시를 제거하고 단일 그래프 스택으로 전환
  - 세션 재로드 시 기존 TID를 유지해 첫 스레드로 튀는 현상 방지
  - 함수 검색 결과 이동 시 대상 노드를 확대 및 포커스

### 검증

- `python -m py_compile bridge_server.py`
- 함수 검색 선택, 그래프 이동, TID 더블클릭 연결 경로 코드 점검

### 커밋 메시지

- `Task #4 Stage 2: 스레드 목록을 오른쪽 패널로 이동`

## Stage 3 - 최종 검증과 보고

### 산출물

- `mydocs/working/task_m000_4_stage3.md`
- `mydocs/report/task_m000_4_report.md`
- `mydocs/orders/20260605.md`

### 검증

- `python -m py_compile bridge_server.py`
- `git diff --check`
- `git status --short`

### 커밋 메시지

- `Task #4 Stage 3 + 최종 보고서: 검증과 보고서 정리`

## 승인 요청

위 3단계 구현계획으로 Stage 1에 진입하는 것을 승인 요청한다.
