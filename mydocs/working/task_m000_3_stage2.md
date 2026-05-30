# 단계 보고서

GitHub Issue: [#3](https://github.com/cho2659/JanusRE/issues/3)
구현계획서: [`task_m000_3_impl.md`](../plans/task_m000_3_impl.md)
Stage: 2

## 단계 목적

외부 구간을 거쳐 target으로 돌아오는 흐름이 그래프에서 대표 외부 노드 아래의 내부 복귀 노드로 남도록 조정한다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `bridge_server.py` | external-to-target ret 노드 생성 후 stack top을 내부 복귀 노드로 교체 |

## 본문 변경 정도 / 본문 무손실 여부

기존 그래프 필터 정책은 유지했다. 외부에서 내부로 돌아오는 ret 이벤트 처리만 조정해 이후 내부 호출이 대표 외부 경유 노드 아래에 이어지도록 했다.

## 검증 결과

실행 명령:

```bash
python -c "import ast, pathlib; ast.parse(pathlib.Path('bridge_server.py').read_text(encoding='utf-8')); print('bridge_server.py syntax OK')"
git diff -- bridge_server.py
```

결과:

- OK — `bridge_server.py syntax OK`를 확인했다.
- OK — 변경 범위가 `CallTreeBuilder._build_thread()`의 external-to-target ret 처리에 한정됨을 확인했다.

## 잔여 위험

- Frida ret 이벤트의 실제 src/dst 의미는 대상 바이너리별 실측으로 추가 확인할 필요가 있다.

## 다음 단계 영향

- 통합 검증에서는 `내부1 -> 외부1 -> 내부2` 대표 구조가 코드상 유지되는지 최종 diff로 확인한다.

## 승인 요청

- Stage 2 산출물과 검증 결과를 승인하면 다음 단계로 진행한다.
