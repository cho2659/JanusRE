# Task M000 #5 Stage 5 완료 보고서

GitHub Issue: [#5](https://github.com/cho2659/JanusRE/issues/5)
구현계획서: [`task_m000_5_impl.md`](../plans/task_m000_5_impl.md)
Stage: 5 - Thread/Module observer 전환

## 단계 목적

ntdll 기반 thread 생성 및 module load/unload Interceptor 의존을 줄이고 Frida observer API로 전환한다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `frida_agent/agent.ts` | `Process.attachModuleObserver()`로 module load/unload 기록 전환, `Process.attachThreadObserver()`로 신규 thread 관찰 및 Stalker attach 전환, observer handle 보관 추가 |
| `frida_agent/agent.js` | `agent.ts` 빌드 결과 반영 |

## 검증 결과

실행 명령:

```bash
npm.cmd --prefix frida_agent run build
rg -n "NtCreateThread|LdrLoadDll|LdrUnloadDll|attachThreadObserver|attachModuleObserver|thread_observer|module_observer" frida_agent/agent.ts
git diff --check
```

결과:

- OK: Frida agent 빌드 통과
- OK: `NtCreateThread`, `LdrLoadDll`, `LdrUnloadDll` 기반 hook 문자열 제거 확인
- OK: `attachThreadObserver`, `attachModuleObserver` 기반 observer 경로 확인
- OK: diff 공백 검사 통과

참고:

- `git diff --check`에서 Windows line ending 경고가 출력되었으나 공백 오류는 없었다.

## 잔여 확인

- 실제 trace에서 신규 thread 생성 시 `thread_observer:add` 및 `stalker:tid=... reason=thread_observer` 로그 확인 필요
- 실제 module load/unload 시 `module_observer:add/remove` 로그 확인 필요

## 다음 단계

Stage 6 - CModule bitmap classifier를 진행한다.
