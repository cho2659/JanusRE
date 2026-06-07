# Task M000 #5 Stage 9 보고서

## 목적

spawn 직후 `frida.resume()` 전 구간에서 모든 thread를 scan/attach하면서 Windows Loader Lock 구간과 `SuspendThread`가 맞물려 교착될 수 있는 문제를 완화한다.

## 변경 방침

- OEP 도달 전에는 Python 서버가 넘긴 `initialTids`만 Stalker attach 대상으로 삼는다.
- `start_before_initial`, `start_after_initial` 전체 thread scan은 pre-resume 경로에서 제거한다.
- `Process.attachThreadObserver()`는 유지하되, OEP 전 신규 thread는 attach하지 않고 관찰/기록만 한다.
- main module PE header에서 OEP RVA를 읽어 OEP VA에 hook을 설치하고, OEP 도달 후 deferred scan을 수행한다.
- `Stalker.exclude`는 사용하지 않는다.

## 검증 계획

- `npx tsc --noEmit`
- `npm run build`
- `rg`로 pre-resume `scanThreads("start_before_initial")`, `scanThreads("start_after_initial")` 제거 확인
- `agent.js` 빌드 산출물 갱신 확인

