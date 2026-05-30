# 단계 보고서

GitHub Issue: [#3](https://github.com/cho2659/JanusRE/issues/3)
구현계획서: [`task_m000_3_impl.md`](../plans/task_m000_3_impl.md)
Stage: 5

## 단계 목적

Stage 4에서 추가한 Windows debug event watcher가 대상 스레드 재개를 막는 문제를 우선 복구한다.

## 사용자 관찰

작업지시자는 "추적 강제 종료를 해야 타겟이 뜬다"고 보고했다.

## 원인 판단

`DebugActiveProcess()`가 붙은 프로세스는 debug event 처리 동안 debuggee 스레드가 정지될 수 있다.
추적 강제 종료 후 타겟이 뜨는 현상은 debug object detach 또는 cleanup 과정에서 정지 상태가 풀렸다는 신호다.

따라서 현재 구현은 thread create 이벤트 수신 자체보다 타겟 실행 안정성을 우선해야 한다.

## 복구 조치

- `ENABLE_DEBUG_EVENT_WATCHER = False` 기본값을 추가했다.
- watcher 코드는 보존하되 기본 실행 경로에서는 `DebugActiveProcess()`를 호출하지 않는다.
- 기존 Frida Stalker 및 thread census 기록은 유지한다.

## 검증 결과

실행 명령:

```bash
python -c "import ast, pathlib; ast.parse(pathlib.Path('bridge_server.py').read_text(encoding='utf-8')); print('bridge_server.py syntax OK')"
git diff --check
```

결과:

- OK — `bridge_server.py syntax OK`.
- OK — `git diff --check` 통과. CRLF 경고만 표시됨.

## 후속 계획

debug event 방식은 별도 안전 설계 후 재도입한다.
다음 설계에서는 debuggee event drain, attach/detach 타이밍, `ContinueDebugEvent()` 상태, 예외 이벤트 처리, Frida RPC와의 상호 대기를 분리해 검증해야 한다.

