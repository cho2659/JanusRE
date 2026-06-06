# Task M000 #4 Stage 1 완료 보고서

GitHub Issue: [#4](https://github.com/cho2659/JanusRE/issues/4)
구현계획서: [`task_m000_4_impl.md`](../plans/task_m000_4_impl.md)
Stage: 1

## 단계 목적

오른쪽 패널로 옮길 스레드 목록 UI와 그래프 패널의 외부 선택 API를 준비했다. 실제 오른쪽 패널 배치와 중앙 탭 제거는 Stage 2에서 수행한다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `bridge_server.py` | `ThreadListPanel` 추가, `CallGraphPanel`의 스레드 목록/현재 TID signal 추가, 외부 TID 선택용 `select_thread()`와 `thread_entries()` 추가 |

## 본문 변경 정도 / 본문 무손실 여부

코드 작업이므로 문서 본문 보존 항목은 해당 없다. 기존 그래프 탭 전환, 함수 검색, Ghidra 동기화 경로는 제거하지 않고 외부 스레드 목록 연결 준비만 추가했다.

## 검증 결과

실행 명령:

```bash
python -m py_compile bridge_server.py
git diff --check
```

결과:

- OK: `python -m py_compile bridge_server.py` 통과
- OK: `git diff --check` 통과

## 잔여 위험

- Stage 1은 연결 준비 단계라 새 `ThreadListPanel`이 아직 `MainWindow`에 배치되지 않았다.
- `_switch_to_tid()`가 기존 `QTabWidget`에 의존한다. 중앙 탭 제거는 Stage 2에서 처리한다.

## 다음 단계 영향

- Stage 2에서 `MainWindow` 오른쪽 패널에 `ThreadListPanel`을 배치하고 `thread_activated`를 `CallGraphPanel.select_thread()`에 연결한다.
- Stage 2에서 중앙 그래프 영역의 스레드 탭 표시를 제거하거나 단일 표시 구조로 바꾼다.

## 승인 요청

- Stage 1 산출물과 검증 결과를 승인하면 Stage 2로 진행한다.
