# 단계 보고서

GitHub Issue: [#3](https://github.com/cho2659/JanusRE/issues/3)
구현계획서: [`task_m000_3_impl.md`](../plans/task_m000_3_impl.md)
Stage: 8

## 단계 목적

target export Interceptor 제거 후 SaveAs entry trace가 보이지 않는 문제를 보정한다.

## 원인 판단

Stage 6에서 target export 전체 `Interceptor.attach()`를 제거하면서 `target_export` 이벤트도 사라졌다.
Stalker 기본 call 이벤트만으로 export entry가 보여야 하지만, 실제 SaveAs 실행에서는 entry 이벤트가 관찰되지 않았다.

따라서 원본 target export를 패치하지 않으면서 entry 이벤트를 되살리는 경로가 필요하다.

## 변경 요약

| 파일 | 변경 요약 |
|---|---|
| `frida_agent/agent.ts` | target export entry 주소 set을 만들고, Stalker transform이 해당 주소를 실행할 때 callout으로 `target_export` 이벤트 기록 |
| `frida_agent/agent.js` | agent 빌드 결과 갱신 |

## 방식

- target 모듈의 function export 주소를 `g_target_export_entries`에 저장한다.
- Stalker transform에서 instruction 주소가 target 범위이고 export entry와 일치하면 callout을 넣는다.
- callout은 현재 stack top의 return address를 읽어 `returnAddress -> exportEntry` call 이벤트를 기록한다.
- `Interceptor.attach()`는 사용하지 않으므로 SaveAs thunk의 원본 instruction을 trampoline으로 옮기지 않는다.

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

- Stalker가 해당 스레드를 follow하지 못하면 이 방식도 entry를 기록할 수 없다.
- target instruction마다 target range 확인이 추가되므로 실제 오버헤드 정도는 대상 실행으로 확인해야 한다.

