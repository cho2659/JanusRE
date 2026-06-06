# Task M000 #5 Stage 4 완료 보고서

GitHub Issue: [#5](https://github.com/cho2659/JanusRE/issues/5)
구현계획서: [`task_m000_5_impl.md`](../plans/task_m000_5_impl.md)
Stage: 4 - Ghidra function-start 준비 경로

## 단계 목적

trace 시작 전에 checked target module별 Ghidra 함수 시작 offset을 준비하고, agent가 이후 bitmap 단계에서 사용할 target config를 받을 수 있게 한다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `bridge_server.py` | checked target module별 `symbols` RPC 결과로 `function_starts` config 생성, Ghidra 미연결/함수 시작점 없음 시 trace 시작 차단, `FridaWorker`가 target config를 agent에 전달 |
| `frida_agent/agent.ts` | `TargetModuleConfig`와 `setTargetConfig()` RPC 추가, module별 function-start offset 저장 |
| `frida_agent/agent.js` | `agent.ts` 빌드 결과 반영 |

## 검증 결과

실행 명령:

```bash
python -m py_compile bridge_server.py
npm.cmd --prefix frida_agent run build
git diff --check
```

결과:

- OK: Python 문법 검증 통과
- OK: Frida agent 빌드 통과
- OK: diff 공백 검사 통과

참고:

- PowerShell 실행 정책 때문에 `npm --prefix frida_agent run build`는 `npm.ps1`에서 차단되어 `npm.cmd --prefix frida_agent run build`로 실행했다.
- `git diff --check`에서 Windows line ending 경고가 출력되었으나 공백 오류는 없었다.

## 잔여 확인

- 실제 Ghidra 연결 상태에서 target별 function-start count 로그 수동 확인 필요
- Ghidra 미연결 시 trace 시작 차단 동작 수동 확인 필요

## 다음 단계

Stage 5 - Thread/Module observer 전환을 진행한다.
