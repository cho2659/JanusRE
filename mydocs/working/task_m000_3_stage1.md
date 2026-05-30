# 단계 보고서

GitHub Issue: [#3](https://github.com/cho2659/JanusRE/issues/3)
구현계획서: [`task_m000_3_impl.md`](../plans/task_m000_3_impl.md)
Stage: 1

## 단계 목적

Stalker 수집 범위는 유지하면서 Python으로 전달되는 trace payload만 줄이기 위해 agent 전송 직전 필터를 추가한다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `frida_agent/agent.ts` | target 모듈명 확장자 유무 판정 helper와 `filterTraceEventsForSend()` 추가 |
| `frida_agent/agent.js` | `agent.ts` 변경분을 `npm run build`로 반영 |

## 본문 변경 정도 / 본문 무손실 여부

수집 경로와 raw trace 저장은 유지했다. 전송 단계에서만 `src_module` 또는 `dst_module`이 target인 trace를 선별한다.

## 검증 결과

실행 명령:

```bash
npm run build
git diff --check
```

결과:

- OK — `frida-compile agent.ts -o agent.js`가 성공했다.
- OK — `git diff --check`가 whitespace 오류 없이 통과했다. CRLF 경고만 표시됐다.

## 잔여 위험

- agent 내부 raw trace 배열은 계속 전체 이벤트를 보관하므로 장시간 실행 메모리 사용량은 별도 후속 최적화 대상이다.

## 다음 단계 영향

- Python은 이미 필터링된 trace만 받으므로 그래프 빌더는 target 경계 이벤트 중심으로 동작한다.

## 승인 요청

- Stage 1 산출물과 검증 결과를 승인하면 다음 단계로 진행한다.
