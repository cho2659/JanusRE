# Task M000 #5 Stage 8 완료 보고서

GitHub Issue: [#5](https://github.com/cho2659/JanusRE/issues/5)
구현계획서: [`task_m000_5_impl.md`](../plans/task_m000_5_impl.md)
Stage: 8 - 그래프 tunnel/return 반영

## 단계 목적

같은 thread 안의 `tt -> tf -> tt` 흐름을 tunnel로 치환하고, ret은 그래프 node/edge가 아니라 stack unwind와 tunnel 후보 검증 보조 정보로만 사용한다. exception으로 외부에서 내부로 돌아오는 경우 tunnel 오탐을 막기 위한 marker를 추가한다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `mydocs/plans/task_m000_5_impl.md` | ret을 별도 그래프 edge로 만들지 않는 정책으로 계획 수정 |
| `frida_agent/agent.ts` | `Process.setExceptionHandler()` marker 기록, `exception_events` payload 전송 추가 |
| `frida_agent/agent.js` | `agent.ts` 빌드 결과 반영 |
| `bridge_server.py` | `jump` 그래프 처리, same-thread tunnel 상태, ret 비표시 처리, exception marker 기반 tunnel 억제, synthetic 검사 추가 |

## 본문 변경 정도 / 본문 무손실 여부

계획서는 ret 처리 정책 문장만 수정했다. 코드에서는 기존 call graph 생성 흐름을 유지하되 `jump`를 추가하고, ret node/edge 생성 경로를 제거했다.

## 검증 결과

실행 명령:

```bash
npm.cmd --prefix frida_agent run build
python -m py_compile bridge_server.py ghidra_side/frida_bridge.py
.\.venv\Scripts\python.exe -c "import bridge_server as b, json; r=b._run_calltree_synthetic_checks(); print(json.dumps({k:v.get('passed') for k,v in r.items()}, ensure_ascii=False, sort_keys=True))"
rg -n 'exception_events|setExceptionHandler|exception_since_outbound|_tunnel_inbound_matches|_ret_closes_outbound|ret_not_rendered|same_thread_tunnel|edges\.append\(CallEdge\(.*flow|base_key = "ret_' frida_agent\agent.ts bridge_server.py mydocs\plans\task_m000_5_impl.md
git diff --check
```

결과:

- OK: Frida agent 빌드 통과
- OK: Python compile 통과
- OK: synthetic 검사 6개 모두 통과
  - `same_thread_tunnel`
  - `ret_not_rendered`
  - `exception_suppresses_tunnel`
  - 기존 parent/anchor 회귀 검사
- OK: ret node/flow edge 생성 경로 제거 확인
- OK: exception marker payload와 tunnel 억제 경로 확인
- OK: diff 공백 검사 통과

참고:

- system Python은 `frida` 모듈이 없어 synthetic 실행에 실패했으므로 프로젝트 `.venv` Python으로 재실행했다.
- `git diff --check`에서 Windows line ending 경고가 출력되었으나 공백 오류는 없었다.

## 잔여 위험

- 실제 exception 발생 시 marker가 tunnel 후보 사이에 정확히 들어오는지 런타임 확인이 필요하다.
- jump/tunnel 시각 스타일은 기존 call edge 스타일을 재사용한다.

## 다음 단계 영향

- Stage 9에서 통합 빌드, syntax, synthetic, 검색 검증을 묶어 최종 보고서를 작성한다.
