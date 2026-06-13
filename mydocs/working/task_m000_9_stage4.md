# Task M000 #9 Stage 4 보고서

GitHub Issue: [#9](https://github.com/cho2659/JanusRE/issues/9)
구현계획서: [`task_m000_9_impl.md`](../plans/task_m000_9_impl.md)
Stage: 4 - Stalker 이벤트 shared memory writer 전환

## 단계 목적

Agent의 `send(trace_chunk)` 기반 JSON 이벤트 전송 경로와 JS 이벤트 큐를 제거하고, Stalker transform callout에서 CModule이 shared memory ring buffer에 바이너리 레코드를 직접 기록하도록 전환했다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `frida_agent/agent.ts` | `g_events`, `g_mod_events`, `sendTraceChunk`, `Stalker.parse`, `onReceive`, agent 내부 `Memory.alloc` 경로 제거. CModule에서 shared memory mapping을 열고 call/ret/jump 레코드를 ring buffer에 직접 기록 |
| `frida_agent/agent.js` | `agent.ts` 빌드 산출물 갱신 |
| `bridge_server.py` | Frida JSON trace payload 수신 경로 제거. wake event 기반 shared memory collector thread 추가. `BLOCK_ON_FULL` 무결성 모드에서 ring full 시 drop 대신 대기하도록 synthetic writer 동작 보정 |

## 본문 변경 정도 / 본문 무손실 여부

trace 이벤트의 주 경로는 JS 객체 배열에서 shared memory 바이너리 레코드로 변경되었다. 기존 GUI 세션 구성은 Python collector가 shared memory를 drain한 이벤트를 `_chunk_events`에 누적한 뒤 `postprocess()`에 넘기는 방식으로 유지했다.

## 검증 결과

실행 명령:

```bash
npm run build
python -m py_compile bridge_server.py
.venv\Scripts\python.exe -c "import bridge_server as b; print(b._run_shared_memory_synthetic_checks())"
rg -n "trace_chunk|sendTraceChunk|Stalker\.parse|Memory\.alloc|onReceive|g_events|g_mod_events|g_sent_events|g_sent_mod_events|_append_trace_payload" frida_agent/agent.ts bridge_server.py frida_agent/agent.js
git diff --check
```

결과:

- OK: agent build 통과.
- OK: Python 문법 검증 통과.
- OK: shared memory synthetic check 통과.
- OK: 금지된 JSON trace chunk, Stalker parse, agent 내부 Memory.alloc, JS 이벤트 큐 경로 검색 결과 없음.
- OK: `git diff --check` 통과. CRLF 안내만 출력됐다.

## 구현 메모

- shared memory `config_flags`에 `BLOCK_ON_FULL`이 켜진 상태로 FridaWorker가 `SharedTraceMemory`를 생성한다.
- CModule writer는 ring이 full이면 `Sleep(0)`으로 yield하며 Python collector가 `read_index`를 전진시킬 때까지 대기한다.
- high watermark 통지는 Windows Event Object로 전달되고, Python collector thread가 wake event를 기다리며 drain한다.
- CModule callout용 데이터는 agent heap이 아니라 shared memory callout arena에서 할당된다.

## 잔여 위험

- CModule 컴파일은 실제 Frida 런타임에서 최종 확인해야 한다. TypeScript build는 CModule C 코드의 런타임 컴파일까지 검증하지 않는다.
- call/ret transform callout은 분기 instruction 주소를 기록하며, Stalker `onReceive` call target 파싱 경로는 제거됐다.
- module load/unload 이름 문자열은 shared memory 바이너리 이벤트에 아직 포함되지 않는다.

## 승인 요청

- Stage 4 산출물과 검증 결과를 승인하면 다음 단계에서 실제 타겟 실행 검증과 남은 stop/command 처리 정리를 진행한다.
