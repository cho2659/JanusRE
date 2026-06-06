# Task M000 #5 Stage 7 완료 보고서

GitHub Issue: [#5](https://github.com/cho2659/JanusRE/issues/5)
구현계획서: [`task_m000_5_impl.md`](../plans/task_m000_5_impl.md)
Stage: 7 - Stalker transform jump 기록

## 단계 목적

Stalker transform callout을 통해 jmp/jcc 계열 블록 전이를 기록한다. jump 기록은 tt/tf bitmap과 함수 시작점 bitmap을 사용하여 내부 분기 중복 기록을 줄인다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `frida_agent/agent.ts` | `RawEvent.k=2` jump 이벤트 추가, block transition 상태 추가, transform callout 기반 `stalker_jump` 기록 추가 |
| `frida_agent/agent.js` | `agent.ts` 빌드 결과 반영 |
| `bridge_server.py` | `k=2` 이벤트를 `type="jump"`로 후처리하고 `is_jump` 전달 추가 |

## 본문 변경 정도 / 본문 무손실 여부

코드 작업이다. 기존 call/ret Stalker 이벤트 수집은 유지했고, transform callout은 jump 전이 기록만 추가한다.

## 검증 결과

실행 명령:

```bash
npm.cmd --prefix frida_agent run build
python -m py_compile bridge_server.py ghidra_side/frida_bridge.py
rg -n 'stalker_jump|recordJumpEvent|recordBlockTransition|isJumpMnemonic|is_jump|k:\s*2' frida_agent\agent.ts bridge_server.py
rg -n 'Stalker\.exclude' frida_agent\agent.ts frida_agent\agent.js
git diff --check
```

결과:

- OK: Frida agent 빌드 통과
- OK: Python compile 통과
- OK: `stalker_jump`, `recordJumpEvent`, `k: 2`, `is_jump` 경로 확인
- OK: `Stalker.exclude` 미사용 확인
- OK: diff 공백 검사 통과

참고:

- `Stalker.exclude` 검색은 결과 없음이 기대값이므로 exit code 1이 정상이다.
- `git diff --check`에서 Windows line ending 경고가 출력되었으나 공백 오류는 없었다.

## 잔여 위험

- transform callout은 각 basic block 끝에서 이전 block jump 여부를 기록하므로 이벤트 시점은 실제 branch 직후에 가깝다. 런타임 trace에서 순서와 누락 여부를 확인해야 한다.

## 다음 단계 영향

- Stage 8에서 그래프 builder가 `jump` 이벤트와 tt/tf 필드를 사용해 tunnel edge를 구성한다.
