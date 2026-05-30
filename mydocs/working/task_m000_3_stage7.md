# 단계 보고서

GitHub Issue: [#3](https://github.com/cho2659/JanusRE/issues/3)
구현계획서: [`task_m000_3_impl.md`](../plans/task_m000_3_impl.md)
Stage: 7

## 단계 목적

Stalker coverage는 유지하면서 SaveAs 등 외부 DLL 실행량이 큰 구간의 Frida hot path symbol 해석 비용을 줄인다.

## 사용자 지시 반영

- Stalker는 target이 아닌 모듈도 계속 따라간다.
- 외부 모듈에서 외부 모듈로 가는 경우에는 Frida에서 symbol을 해석하지 않는다.
- 이 판단은 함수 단위가 아니라 DLL/module 단위로 수행한다.
- target module이 한쪽이라도 포함되면 기존처럼 Frida symbol 해석을 유지한다.

## 변경 요약

| 파일 | 변경 요약 |
|---|---|
| `frida_agent/agent.ts` | `recordTraceEvent()`에서 `srcIsTarget` 또는 `dstIsTarget`일 때만 `symbolName()` 호출 |
| `frida_agent/agent.js` | agent 빌드 결과 갱신 |

## 기대 효과

SaveAs 버튼처럼 `shdk.dll`, MFC, COM, shell 관련 외부 DLL 호출이 폭증하는 구간에서 외부↔외부 call/ret의 `DebugSymbol.fromAddress()` 및 export symbol 탐색 비용을 줄인다.

Frida가 외부 모듈 symbol 해석을 담당해야 하는 이유는 Ghidra 프로젝트에 로드된 target 모듈 외부 symbol 해석을 Python/Ghidra 쪽에서 아직 충분히 제공하지 못하기 때문이다. 따라서 target과 연결되는 경계 이벤트의 symbol은 유지한다.

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

- 실제 SaveAs 동작에서 오버헤드 완화 정도는 대상 실행으로 확인해야 한다.
- 외부↔외부 이벤트는 module/RVA는 유지되지만 symbol 필드는 비어 있을 수 있다.

