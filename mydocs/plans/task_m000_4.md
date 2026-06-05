# Task M000 #4 수행계획서

GitHub Issue: [#4](https://github.com/cho2659/JanusRE/issues/4)
마일스톤: M000

## 목적

현재 메인 콜 그래프 영역 위에 있는 스레드 선택 UI를 오른쪽 함수 검색 패널 아래로 이동한다. 스레드는 탭 대신 스크롤 가능한 목록으로 표시하고, 사용자가 TID 항목을 더블클릭하면 해당 스레드 그래프로 이동하도록 한다.

## 배경

기존 `CallGraphPanel`은 그래프 상단에 `QTabWidget` 탭을 두어 스레드를 선택한다. 이 방식은 그래프 조작 영역과 스레드 탐색 UI가 같은 중앙 영역에 섞이고, 오른쪽 함수 검색 패널과 탐색 맥락이 분리된다. 작업지시자는 스레드 패널을 메인 패널 위가 아니라 오른쪽 함수 검색 패널 아래로 이동하고, 목록형 스크롤 UI와 TID 더블클릭 이동을 요구했다.

참고 문서:

- `AGENTS.md`
- `mydocs/manual/task_workflow_guide.md`
- `mydocs/manual/git_workflow_guide.md`
- `mydocs/manual/document_structure_guide.md`

## 범위

### 포함

- 중앙 그래프 위 스레드 탭 UI 제거 또는 내부 전환용으로만 축소
- 오른쪽 함수 검색 패널 아래에 스크롤 가능한 스레드 목록 패널 추가
- 스레드 목록에 TID와 main 표시 등 식별 정보 제공
- 스레드 목록 항목 더블클릭 시 해당 TID 그래프로 이동
- 기존 함수 검색 결과 선택, 그래프 노드 이동, Ghidra 동기화 흐름 유지

### 제외

- Frida agent의 스레드 수집/추적 로직 변경
- 콜 그래프 레이아웃 알고리즘 변경
- Ghidra 서버 통신 규약 변경
- 이슈 milestone/label 보정

## 설계 방향

- `CallGraphPanel`은 그래프 렌더링과 현재 TID 전환 상태를 계속 소유한다.
- 스레드 선택 UI는 별도 QWidget 패널로 분리해 `MainWindow` 오른쪽 패널의 `FunctionSearchPanel` 아래에 배치한다.
- 스레드 목록 패널은 `QTreeWidget` 또는 `QListWidget` 기반 목록으로 구성하고, Qt의 기본 스크롤 동작을 사용한다.
- `CallGraphPanel`은 세션 로드 후 TID 목록 변경을 signal로 외부에 알리고, 외부 패널에서 TID 선택 signal을 받아 기존 `_switch_to_tid()` 경로를 재사용한다.
- 화면 전환은 기존 `_current_tid`, `_views`, `_tab_tids` 상태와 충돌하지 않도록 최소 변경으로 구현한다.

## 예상 변경 파일

신규:

- 없음

수정:

- `bridge_server.py`
- `mydocs/orders/20260605.md`
- `mydocs/plans/task_m000_4.md`

이번 task 산출물:

- `mydocs/orders/20260605.md`
- `mydocs/plans/task_m000_4.md`
- `mydocs/plans/task_m000_4_impl.md`
- `mydocs/working/task_m000_4_stage1.md`
- `mydocs/working/task_m000_4_stage2.md`
- `mydocs/working/task_m000_4_stage3.md`
- `mydocs/report/task_m000_4_report.md`

## 잠정 단계

- **Stage 1 - 구조 분리**
  - 스레드 목록 패널 클래스와 `CallGraphPanel`의 TID 목록/선택 signal 경로 정의
  - 검증 관점: 기존 그래프 세션 로드와 현재 TID 전환 상태가 유지되는지 확인
- **Stage 2 - 오른쪽 패널 배치**
  - 함수 검색 패널 아래에 스레드 목록 패널 배치 및 기존 중앙 탭 UI 제거/대체
  - 검증 관점: 오른쪽 패널 높이 배분, 스크롤 가능성, 더블클릭 signal 연결 확인
- **Stage 3 - 검증 및 보고**
  - Python 문법 검증, UI 이벤트 경로 점검, 단계 보고서와 최종 보고서 작성
  - 검증 관점: 수용 기준 충족 여부와 남은 수동 GUI 검증 한계 명시

## 검증 계획

### 단계별 검증

- Stage 1
  - `python -m py_compile bridge_server.py`
  - TID 목록 생성/선택 경로 코드 리뷰
- Stage 2
  - `python -m py_compile bridge_server.py`
  - 오른쪽 패널 레이아웃과 더블클릭 연결 코드 리뷰
- Stage 3
  - `git diff --check`
  - `git status --short`

### 통합 검증

- 트레이스 세션 로드 후 오른쪽 함수 검색 패널 아래에 TID 목록이 표시된다.
- TID 목록은 항목 수가 많을 때 스크롤 가능하다.
- TID 항목 더블클릭 시 해당 스레드 그래프로 전환된다.
- 기존 함수 검색 결과 선택 및 Ghidra 동기화 경로가 유지된다.
- PR 준비 전 `git status --short`가 빈 출력이다.
- `git diff --check`가 경고 없이 통과한다.

## 리스크

- **기존 탭 의존성**: 내부적으로 `QTabWidget`이 현재 스레드 전환과 lazy layout에 사용되고 있어 제거 범위가 커질 수 있다. 대응은 내부 상태 유지와 외부 목록 UI 분리를 우선해 변경 폭을 줄인다.
- **GUI 수동 검증 한계**: 현재 환경에서 실제 Windows GUI 실행이 제한될 수 있다. 대응은 문법 검증과 signal 연결 경로 점검을 수행하고, 실행하지 못한 GUI 검증은 보고서에 명시한다.
- **마일스톤 미지정**: GitHub CLI 부재로 milestone/label 조회가 불가능했고 이슈 #4는 milestone 없이 생성됐다. 문서명에는 임시로 `m000`을 사용하며, 필요 시 작업지시자가 GitHub에서 보정한다.

## 승인 요청 사항

- 위 범위와 설계 방향으로 구현 계획서 작성 단계에 진입하는 것을 승인 요청한다.
- 본 task는 `bridge_server.py`의 UI 배치와 스레드 선택 동작만 변경하고, Frida/Ghidra 수집 로직은 변경하지 않는다.

승인되면 `task_m000_4_impl.md`에서 단계별 산출물, 검증 명령, 커밋 메시지를 구체화한다.
