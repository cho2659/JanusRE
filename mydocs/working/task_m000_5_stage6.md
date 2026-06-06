# Task M000 #5 Stage 6 완료 보고서

GitHub Issue: [#5](https://github.com/cho2659/JanusRE/issues/5)
구현계획서: [`task_m000_5_impl.md`](../plans/task_m000_5_impl.md)
Stage: 6 - CModule bitmap classifier

## 단계 목적

tt/tf 판별을 JS 범위 탐색 대신 Native CModule bitmap test로 전환하고, 둘 다 tf인 call/ret 기록을 agent 단계에서 배제한다. 또한 tt module export Interceptor 기록 경로를 제거한다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `frida_agent/agent.ts` | target module record, target/function-start bitmap, CModule `bitmap_test`, module observer 기반 record 갱신, tf-tf call/ret 필터, target export Interceptor 비활성화 추가 |
| `frida_agent/agent.js` | `agent.ts` 빌드 결과 반영 |
| `bridge_server.py` | trace event 후처리에 `src_tt`, `dst_tt` 전달 추가 |

## 본문 변경 정도 / 본문 무손실 여부

코드 작업이다. 기존 trace 이벤트 형식은 유지하면서 `src_tt`, `dst_tt` 필드만 추가했다. 서버의 과거 `target_export` synthetic 처리 로직은 기존 로그 호환을 위해 유지했으며, agent에서는 더 이상 `target_export`를 생성하지 않는다.

## 검증 결과

실행 명령:

```bash
npm.cmd --prefix frida_agent run build
python -m py_compile bridge_server.py ghidra_side/frida_bridge.py
rg -n "target_export|Interceptor\\.attach|Stalker\\.exclude|bitmap_test|classifyAddress|src_tt|dst_tt|rebuildTargetModuleRecords" frida_agent/agent.ts bridge_server.py
git diff --check
```

결과:

- OK: Frida agent 빌드 통과
- OK: Python compile 통과
- OK: agent의 `target_export` 생성 경로 제거 확인
- OK: `Interceptor.attach`는 process exit hook 2곳만 남음 확인
- OK: `Stalker.exclude` 미사용 확인
- OK: `bitmap_test`, `classifyAddress`, `src_tt`, `dst_tt` 경로 확인
- OK: diff 공백 검사 통과

참고:

- `git diff --check`에서 Windows line ending 경고가 출력되었으나 공백 오류는 없었다.

## 잔여 위험

- bitmap은 byte 단위 offset bitset이므로 대형 모듈에서 메모리 사용량이 module size / 8에 비례한다.
- 실제 trace에서 module load/unload 후 target record가 정상 갱신되는지 런타임 확인이 필요하다.

## 다음 단계 영향

- Stage 7에서 Stalker transform jump 기록은 `classifyAddress()`와 function-start bitmap을 재사용한다.
