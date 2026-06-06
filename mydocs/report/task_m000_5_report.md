# Task M000 #5 최종 보고서

GitHub Issue: [#5](https://github.com/cho2659/JanusRE/issues/5)
마일스톤: M000

## 작업 요약

- 대상 이슈: #5
- 마일스톤: M000
- 단계 수: 9
- 작업 목적: UI 크기/선택 제약을 완화하고, Frida trace를 observer, bitmap classifier, jump/tunnel 기반으로 전환한다.

## 변경 파일 목록과 영향 범위

| 경로 | 변경 요약 | 영향 범위 |
|---|---|---|
| `bridge_server.py` | target module trace checkbox, splitter 유연화, Ghidra goto 보강, zoom 하한, 종료 시 pid/path 대조 후 kill, function-start config, jump/tunnel graph, ret 비표시, exception marker 처리 | PySide6 GUI, trace orchestration, graph builder |
| `frida_agent/agent.ts` | thread/module observer 전환, CModule bitmap classifier, target export Interceptor 비활성화, Stalker transform jump 기록, exception marker payload | Frida runtime tracing |
| `frida_agent/agent.js` | `agent.ts` 빌드 결과 | Frida 실행 agent |
| `ghidra_side/frida_bridge.py` | Ghidra 측 symbol/function offset config 지원 | Ghidra bridge |
| `mydocs/plans/task_m000_5_impl.md` | 승인된 구현 계획과 ret 비표시 정책 반영 | 작업 기록 |
| `mydocs/working/task_m000_5_stage*.md` | 단계별 완료 보고서 | 작업 기록 |

## 변경 전·후 정량 비교

| 지표 | 변경 전 | 변경 후 |
|---|---|---|
| target module 선택 | UI 선택 없음 | module별 trace checkbox |
| thread 생성 추적 | ntdll thread 생성 hook 중심 | `Process.attachThreadObserver()` 중심 |
| module load/unload 추적 | loader hook 중심 | `Process.attachModuleObserver()` 중심 |
| tt/tf 판별 | JS/module lookup 중심 | CModule bitmap test |
| jump 계열 추적 | call/ret 중심 | Stalker transform jump event 추가 |
| ret 그래프 표시 | external return flow node/edge 생성 가능 | ret은 stack/tunnel 보조 정보로만 사용 |
| target export Interceptor | 사용 | agent 생성 경로 비활성화 |

## 검증 결과

| 수용 기준 | 결과 |
|---|---|
| Frida agent 빌드 | OK — `npm.cmd --prefix frida_agent run build` 통과 |
| Python syntax | OK — `python -m py_compile bridge_server.py ghidra_side/frida_bridge.py` 통과 |
| 그래프 synthetic 검사 | OK — 6개 검사 모두 `true` |
| `Stalker.exclude(range)` 미사용 | OK — 검색 결과 없음 |
| observer 전환 확인 | OK — `attachThreadObserver`, `attachModuleObserver` 경로 확인 |
| exception marker | OK — `Process.setExceptionHandler()`와 `exception_events` payload 확인 |
| ret 비표시 | OK — synthetic `ret_not_rendered` 통과, ret flow 생성 경로 제거 |

### 단계별 검증 결과

- Stage 1: Ghidra goto, window/splitter, zoom/kill 기초 수정 완료
- Stage 2: Stage 1 보강 및 문서화 완료
- Stage 3: target module trace checkbox와 좌측 splitter 완료
- Stage 4: Ghidra function-start offset config 준비 완료
- Stage 5: Frida thread/module observer 전환 완료
- Stage 6: CModule bitmap classifier와 tf-tf 필터 완료
- Stage 7: Stalker transform jump 기록 완료
- Stage 8: same-thread tunnel, ret 비표시, exception marker 억제 완료
- Stage 9: 통합 검증과 최종 보고서 완료

## 잔여 위험과 후속 작업

### 잔여 위험

- 실제 대상 프로세스에서 observer attach, module unload, exception marker 순서가 의도대로 들어오는지 런타임 확인이 필요하다.
- bitmap 메모리는 module size / 8에 비례한다.
- jump/tunnel edge는 현재 기존 call edge 스타일을 재사용한다.

### 후속 작업 후보

- version 2에서 user-level sync/handler hook 의미론 확장 여부를 별도 이슈로 검토한다.
- 실제 trace 샘플 기반으로 exception marker 이후 inbound 처리 정책을 미세 조정한다.

## 작업지시자 승인 요청

- 최종 보고서와 수용 기준 검증 결과를 승인하면 PR 게시 절차로 진행한다.
