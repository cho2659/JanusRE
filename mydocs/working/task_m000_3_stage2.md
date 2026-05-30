# 단계 보고서

GitHub Issue: [#3](https://github.com/cho2659/JanusRE/issues/3)
구현계획서: [`task_m000_3_impl.md`](../plans/task_m000_3_impl.md)
Stage: 2

## 단계 목적

ret 복귀 주소가 그래프 노드로 표시되지 않도록 하고, ret는 call stack 정리에만 사용되게 조정한다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `bridge_server.py` | ret를 그래프 노드로 그리지 않고 call stack pop에만 사용하도록 조정 |

## 본문 변경 정도 / 본문 무손실 여부

기존 그래프 필터 정책은 유지했다. ret 복귀 주소를 그래프 노드로 만들면 실제 call이 아닌 다음 실행 위치가 하위 호출처럼 보이므로, ret는 stack 정리에만 사용한다.

## 검증 결과

실행 명령:

```bash
python -c "import ast, pathlib; ast.parse(pathlib.Path('bridge_server.py').read_text(encoding='utf-8')); print('bridge_server.py syntax OK')"
git diff -- bridge_server.py
```

결과:

- OK — `bridge_server.py syntax OK`를 확인했다.
- OK — 변경 범위가 `CallTreeBuilder._build_thread()`의 ret 처리에 한정됨을 확인했다.

## 잔여 위험

- call/ret 이벤트가 누락되는 비정상 흐름에서는 stack 정합성이 흔들릴 수 있다.

## 다음 단계 영향

- 통합 검증에서는 ret 노드가 그래프에 생성되지 않는지 최종 diff로 확인한다.

## 승인 요청

- Stage 2 산출물과 검증 결과를 승인하면 다음 단계로 진행한다.
