# Task M000 #6 Stage 1 완료 보고서

GitHub Issue: [#6](https://github.com/cho2659/JanusRE/issues/6)
구현계획서: [`task_m000_6_impl.md`](../plans/task_m000_6_impl.md)
Stage: 1

## 단계 목적

그래프 부모/자식 오탐을 코드로 재현할 수 있는 최소 synthetic trace 검증 경로를 만들었다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `bridge_server.py` | `_SyntheticTraceSession`, synthetic call/ret 생성 함수, `_run_calltree_synthetic_checks()` 추가 |

## 본문 변경 정도 / 본문 무손실 여부

코드 작업이므로 문서 본문 보존 항목은 해당 없다. 실제 `CallTreeBuilder` 로직은 아직 수정하지 않았고, Stage 2 수정 전 재현 검증만 추가했다.

## 검증 결과

실행 명령:

```bash
python -m py_compile bridge_server.py
.venv\Scripts\python.exe -c "import json, bridge_server as b; print(json.dumps(b._run_calltree_synthetic_checks(), ensure_ascii=False, indent=2))"
```

결과:

- OK: `python -m py_compile bridge_server.py` 통과
- OK: synthetic 검증 실행 통과
- 재현: 불일치 ret 이후 `C` 노드가 root가 아니라 `A`의 자식으로 붙는 현재 오탐을 확인

핵심 출력:

```json
{
  "current_c_parent": "A",
  "expected_after_fix": "",
  "reproduced": true
}
```

## 잔여 위험

- Stage 1은 재현까지만 수행했다. 실제 stack 보수 처리와 flow edge 완화는 Stage 2에서 진행한다.
- 기본 `python`에는 `networkx`가 없어 import 기반 synthetic 검증은 `.venv\Scripts\python.exe`를 사용했다.

## 다음 단계 영향

- Stage 2에서 `current_c_parent`가 빈 값이 되도록 `CallTreeBuilder`의 ret 불일치 처리를 수정한다.

## 승인 요청

- Stage 1 산출물과 검증 결과를 승인하면 Stage 2로 진행한다.
