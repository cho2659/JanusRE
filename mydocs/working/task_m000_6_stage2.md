# Task M000 #6 Stage 2 완료 보고서

GitHub Issue: [#6](https://github.com/cho2659/JanusRE/issues/6)
구현계획서: [`task_m000_6_impl.md`](../plans/task_m000_6_impl.md)
Stage: 2

## 단계 목적

`CallTreeBuilder`의 ret 처리에서 stack top과 실제 ret source가 맞지 않아 이후 호출의 부모가 오염되는 문제를 완화했다. 추가로 작업지시자가 제시한 `CHwpSDKSampleDlg::InsertText` 사례처럼 같은 함수의 여러 callsite가 각각 부모 anchor로 분리되는 문제를 보정했다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `bridge_server.py` | ret source와 stack 노드를 module/offset 또는 symbol base로 매칭, 일치하는 ancestor까지 unwind, 불일치 ret는 stack을 비워 stale parent 오염 방지, target_export source anchor를 symbol base로 병합, synthetic 정상/오탐/anchor 병합 검증 보강 |

## 본문 변경 정도 / 본문 무손실 여부

코드 작업이므로 문서 본문 보존 항목은 해당 없다. Frida agent 수집 로직은 변경하지 않았고, Python 그래프 빌더의 parent stack 처리만 수정했다.

## 검증 결과

실행 명령:

```bash
python -m py_compile bridge_server.py
.venv\Scripts\python.exe -c "import json, bridge_server as b; print(json.dumps(b._run_calltree_synthetic_checks(), ensure_ascii=False, indent=2))"
git diff --check
```

결과:

- OK: `python -m py_compile bridge_server.py` 통과
- OK: synthetic 검증에서 `mismatched_ret_parent_pollution.passed == true`
- OK: synthetic 검증에서 `balanced_nested_parent.passed == true`
- OK: synthetic 검증에서 `target_export_anchor_merge.passed == true`
- OK: `git diff --check` 통과

## 잔여 위험

- 실제 trace에서 ret source symbol이 없고 offset도 함수 entry와 다르면 보수 처리로 stack이 비워져 일부 깊은 관계가 root로 분리될 수 있다. 이는 잘못된 부모 오탐보다 안전한 동작으로 판단했다.
- external-to-target ret의 flow node는 매칭된 stack 노드가 있을 때만 부모를 붙인다.
- symbol base가 같은 source anchor는 하나로 병합한다. 동일 이름의 서로 다른 overload/thunk가 같은 module 안에서 같은 symbol base로 들어오면 하나의 부모로 묶일 수 있으나, 현재 문제인 callsite별 부모 분리보다 분석상 유리하다고 판단했다.

## 다음 단계 영향

- Stage 3에서 최종 검증과 보고서 정리를 수행한다.

## 승인 요청

- Stage 2 산출물과 검증 결과를 승인하면 Stage 3으로 진행한다.
