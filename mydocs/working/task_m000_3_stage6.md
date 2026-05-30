# 단계 보고서

GitHub Issue: [#3](https://github.com/cho2659/JanusRE/issues/3)
구현계획서: [`task_m000_3_impl.md`](../plans/task_m000_3_impl.md)
Stage: 6

## 단계 목적

스레드 추적 진단 기록을 오해 없는 형태로 정리하고, export Interceptor가 Stalker의 target export thunk 관찰을 방해하지 않도록 제거한다.

## 사용자 지시 반영

- 디버깅용 `seen_tids` 기록을 제거한다.
- trace 저장 시 실제 기록된 TID의 합계와 목록을 별도 `thread_summary`로 저장한다.
- target 모듈 내부 여부와 무관하게 기록된 TID를 합산한다.
- `codex_solution_for_jmp.md` 73번 줄의 `stalker_jmp` 판정 수정을 구현한다.
- export Interceptor를 제거해 Stalker가 Interceptor trampoline 때문에 혼동하지 않게 한다.
- 다른 Interceptor가 Stalker를 방해하는지 확인한다.

## 변경 요약

| 파일 | 변경 요약 |
|---|---|
| `frida_agent/agent.ts` | target export 전체 `Interceptor.attach()` 제거, same-symbol/executable fallback jmp 기록 제거, `seen_tids` snapshot 제거 |
| `frida_agent/agent.js` | agent 빌드 결과 갱신 |
| `bridge_server.py` | 저장 시 `thread_summary` 생성, 실패한 debug event watcher scaffolding 제거 |

## Interceptor 검토

남은 Interceptor는 다음 목적에 한정된다.

- `LdrLoadDll`, `LdrUnloadDll`: 모듈 타임라인과 target range 갱신.
- `NtCreateThreadEx`, `NtCreateThread`: 스레드 생성 이벤트와 즉시 Stalker follow 시도.
- `RtlExitUserProcess`, `NtTerminateProcess`, `ExitProcess`, `TerminateProcess`: 종료 시 flush.

이들은 `hwpsdk.dll` 같은 target 모듈 export entry를 패치하지 않는다. 따라서 SaveAs thunk의 `hwpsdk.dll!0x1556` 원본 instruction을 trampoline으로 옮기는 직접 원인이 되지 않는다.

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

- target export Interceptor 제거 후 SaveAs jmp가 실제 trace에 들어오는지 대상 실행으로 확인해야 한다.
- `target_export` source는 기존 저장 파일 호환을 위해 Python 그래프 빌더에 남아 있다.

