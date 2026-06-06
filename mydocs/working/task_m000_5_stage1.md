# Task M000 #5 Stage 1 완료 보고서

GitHub Issue: [#5](https://github.com/cho2659/JanusRE/issues/5)
구현계획서: [`task_m000_5_impl.md`](../plans/task_m000_5_impl.md)
Stage: 1

## 단계 목적

노드 클릭/더블클릭/펼침 상호작용을 제거해 더블클릭 시 노드 위치가 이상하게 이동하는 문제를 막는다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `bridge_server.py` | `NodeItem`의 hotspot, custom 클릭 처리, custom 더블클릭 활성화, 펼침 토글 제거. 하위 호출 목록은 정적 표시만 유지 |
| `mydocs/orders/20260605.md` | #5 진행 항목 추가 |
| `mydocs/plans/task_m000_5.md` | #5 수행계획서 추가 |
| `mydocs/plans/task_m000_5_impl.md` | #5 구현계획서 추가 |

## 본문 변경 정도 / 본문 무손실 여부

코드 작업이므로 문서 본문 보존 항목은 해당 없다. Frida, Ghidra, CallTreeBuilder 로직은 변경하지 않았다.

## 검증 결과

실행 명령:

```bash
python -m py_compile bridge_server.py
git diff --check
```

결과:

- OK: Python 문법 검증 통과
- OK: diff 공백 검사 통과

## 잔여 위험

- 실제 GUI에서 더블클릭 시 위치 이동이 사라졌는지는 수동 확인이 필요하다.

## 다음 단계 영향

- 노드 더블클릭 Ghidra 이동과 하위 호출 펼침 기능은 제거된 상태다.

## 승인 요청

- Stage 1 산출물과 검증 결과를 승인하면 보고 정리 단계로 진행한다.
