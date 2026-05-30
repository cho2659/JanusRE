# 단계 보고서

GitHub Issue: [#3](https://github.com/cho2659/JanusRE/issues/3)
구현계획서: [`task_m000_3_impl.md`](../plans/task_m000_3_impl.md)
Stage: 4

## 단계 목적

Frida user-mode thread hook만으로는 디버거가 관찰하는 전체 스레드 생성 이벤트를 보장하지 못하는 문제를 보완한다.

## 사용자 지시 반영

- `CREATE_THREAD_DEBUG_EVENT` 기반으로 스레드 생성 즉시 부착 가능하도록 조치한다.
- 성공 및 실패를 기록하고 전체 추적한 TID를 모두 기록한다.
- jmp 수정은 후속 지시 전까지 변경하지 않는다.
- 구현 내용을 커밋한다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `bridge_server.py` | Windows debug event watcher 추가, thread event 수신 시 Frida `follow_tid` RPC 호출 |
| `frida_agent/agent.ts` | `thread_events` 기록 및 `followTid` RPC 추가 |
| `frida_agent/agent.js` | agent 빌드 결과 갱신 |

## 실행 불능 원인 및 복구

초기 구현은 `DebugActiveProcess()` 기반 watcher를 `frida.resume()` 전에 시작했다.
대상 프로세스가 Frida spawn 직후 suspended 상태였기 때문에, debuggee 이벤트 continue 흐름과 Frida resume 순서가 충돌해 타겟 실행이 지연 또는 정지될 수 있었다.

복구 조치:

- `start_trace()`와 `frida.resume()`을 먼저 완료한다.
- `frida.resume()` 성공 후 debug event watcher를 시작한다.
- debug event loop는 이벤트 수신 후 즉시 `ContinueDebugEvent()`를 호출한다.
- follow RPC는 별도 worker thread에서 수행한다.

## 검증 결과

실행 명령:

```bash
npm run build
python -c "import ast, pathlib; ast.parse(pathlib.Path('bridge_server.py').read_text(encoding='utf-8')); print('bridge_server.py syntax OK')"
git diff --check
```

결과:

- OK — `npm run build` 성공.
- OK — `bridge_server.py syntax OK`.
- OK — `git diff --check` 통과. CRLF 경고만 표시됨.

## 잔여 위험

- Windows debug event watcher는 대상이 이미 다른 디버거에 붙어 있으면 실패할 수 있다.
- 실제 대상 실행에서 `thread_events`에 `debug_create_thread` 기반 follow 결과가 기록되는지 수동 검증이 필요하다.

