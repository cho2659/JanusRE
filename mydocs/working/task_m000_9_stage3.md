# Task M000 #9 Stage 3 보고서

GitHub Issue: [#9](https://github.com/cho2659/JanusRE/issues/9)
구현계획서: [`task_m000_9_impl.md`](../plans/task_m000_9_impl.md)
Stage: 3 - Agent bootstrap과 RPC 제거

## 단계 목적

Python RPC exports 기반 start/stop/config 제어 경로를 제거하고, Python이 shared memory bootstrap 값을 agent script source에 치환하는 경로를 도입했다. agent는 script load 시 자동으로 trace 초기화를 시작한다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `bridge_server.py` | `SharedTraceMemory.apply_bootstrap()` 추가, script source bootstrap 치환, `exports_sync.*` start/config/stop 호출 제거 |
| `frida_agent/agent.ts` | bootstrap placeholder 상수 추가, `rpc.exports` 제거, script load 시 thread 열거 후 `beginTrace()` 자동 실행 |
| `frida_agent/agent.js` | `agent.ts` 빌드 산출물 갱신 |

## 본문 변경 정도 / 본문 무손실 여부

기존 JSON trace chunk 수집 경로는 Stage 4 전환 전까지 유지했다. 이번 단계에서는 제어 RPC만 제거했다.

## 검증 결과

실행 명령:

```bash
python -m py_compile bridge_server.py
.venv\Scripts\python.exe -c "import bridge_server as b; print(b._run_shared_memory_synthetic_checks())"
npm.cmd --prefix frida_agent run build
rg -n "rpc\.exports|exports_sync\.(set_target_config|set_targets|start_trace|stop_trace)|start_trace rpc|stop_trace rpc" frida_agent/agent.ts frida_agent/agent.js bridge_server.py
git diff --check
```

결과:

- OK: Python 문법 검증 통과.
- OK: shared memory synthetic check 통과.
- OK: agent build 통과.
- OK: RPC exports 및 Python `exports_sync.*` 호출 제거 확인. `rg` 결과 없음이 정상이다.
- OK: `git diff --check` 통과. 출력된 CRLF 메시지는 줄끝 안내다.

## 잔여 위험

- agent는 아직 shared memory mapping을 직접 열어 event를 쓰지 않는다. Stage 4에서 writer 전환을 구현한다.
- target config는 shared memory에 준비돼 있지만 agent classifier가 아직 그 config를 읽지 않는다. Stage 4에서 함께 전환한다.
- stop 요청은 Python shared memory command로 기록되지만 agent polling/cleanup 연결은 Stage 5에서 마무리한다.

## 다음 단계 영향

- Stage 4는 agent 내부 이벤트 배열, `Memory.alloc`, trace JSON chunk 전송을 shared memory writer로 바꾼다.
- bootstrap placeholder는 `agent.js`에 남아 있어야 하며 Python load 직전에 치환된다.

## 승인 요청

- Stage 3 산출물과 검증 결과를 승인하면 Stage 4로 진행한다.
