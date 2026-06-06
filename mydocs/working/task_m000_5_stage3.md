# Task M000 #5 Stage 3 완료 보고서

GitHub Issue: [#5](https://github.com/cho2659/JanusRE/issues/5)
구현계획서: [`task_m000_5_impl.md`](../plans/task_m000_5_impl.md)
Stage: 3 - UI target 선택과 왼쪽 splitter

## 단계 목적

Ghidra 프로젝트 파일별 trace 여부를 사용자가 선택할 수 있게 하고, trace 중에는 선택 상태를 고정한다. 왼쪽 target module 영역과 loaded module 영역도 세로 splitter로 비율 조정 가능하게 만든다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `bridge_server.py` | `LeftPanel` target module 목록을 checkbox 포함 `QTreeWidget`으로 변경, loaded module 목록과 vertical splitter로 분리, trace 중 target 목록 비활성화, checked target만 `FridaWorker`/graph/function panel target set으로 전달 |
| `mydocs/plans/task_m000_5_impl.md` | 승인 전 추가 지시를 반영한 구현계획서 갱신 |

## 검증 결과

실행 명령:

```bash
python -m py_compile bridge_server.py
git diff --check
```

결과:

- OK: Python 문법 검증 통과
- OK: diff 공백 검사 통과

참고:

- `git diff --check`에서 Windows line ending 경고가 출력되었으나 공백 오류는 없었다.

## 잔여 확인

- 실제 GUI에서 checkbox 위치, trace 중 비활성화, 왼쪽 splitter 드래그 동작 수동 확인 필요
- checked target이 0개일 때 trace 시작이 거부되는지 수동 확인 필요

## 다음 단계

작업지시자 승인 후 Stage 4 - Ghidra function-start 준비 경로를 진행한다.
