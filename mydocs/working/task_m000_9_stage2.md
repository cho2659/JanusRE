# Task M000 #9 Stage 2 보고서

GitHub Issue: [#9](https://github.com/cho2659/JanusRE/issues/9)
구현계획서: [`task_m000_9_impl.md`](../plans/task_m000_9_impl.md)
Stage: 2 - Python 공유 메모리 owner와 binary reader 도입

## 단계 목적

agent 변경 전에 Python 쪽에서 named shared memory, Windows Event Object wakeup 채널, binary record reader를 준비했다. 사용자 추가 요구인 80% 위험 수위 wakeup, Blocking Flag, 이중 버퍼링 config도 ABI와 Python owner에 반영했다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `bridge_server.py` | `SharedTraceMemory`, `_WindowsEvent`, shared memory header/config writer, synthetic event writer/reader, FridaWorker 생성/stop/cleanup 연결 |
| `mydocs/tech/task_m000_9_shared_memory_abi.md` | wake event, `BLOCK_ON_FULL`, double buffering ring 0/1, high watermark field 추가 |
| `mydocs/plans/task_m000_9_impl.md` | Stage 2/4 작업 항목에 Event Object, Blocking Flag, double buffering 반영 |

## 본문 변경 정도 / 본문 무손실 여부

코드에는 agent와 병행 가능한 Python owner/reader를 추가했다. 기존 RPC 수집 경로는 Stage 3 전까지 유지했다. 문서는 추가 요구사항만 보강했다.

## 검증 결과

실행 명령:

```bash
python -m py_compile bridge_server.py
.venv\Scripts\python.exe -c "import bridge_server as b; print(b._run_shared_memory_synthetic_checks())"
rg -n "SharedTraceMemory|_WindowsEvent|BLOCK_ON_FULL|DOUBLE_BUFFERING|WAKE_ON_HIGH_WATERMARK|_run_shared_memory_synthetic_checks|shared trace" bridge_server.py mydocs/tech/task_m000_9_shared_memory_abi.md mydocs/plans/task_m000_9_impl.md
git diff --check
```

결과:

- OK: `python -m py_compile bridge_server.py` 통과.
- OK: `.venv` 환경에서 synthetic shared memory check가 `OK shared memory synthetic checks`를 출력.
- OK: Event Object, Blocking Flag, double buffering, owner/reader 코드 위치 확인.
- OK: `git diff --check` 통과. 출력된 CRLF 메시지는 경고성 줄끝 안내다.

## 잔여 위험

- Python owner는 준비됐지만 agent는 아직 shared memory를 열지 않는다. Stage 3에서 bootstrap과 RPC 제거를 구현해야 한다.
- double buffering은 config/layout을 마련한 상태이며, 실제 agent-side ring 전환은 Stage 4에서 구현한다.
- Blocking Flag는 header/config와 synthetic full 처리에 반영됐고, 실제 writer wait는 Stage 4에서 구현한다.

## 다음 단계 영향

- Stage 3은 `SharedTraceMemory.bootstrap_values()`로 agent script placeholder를 치환하고 `rpc.exports` 제어 경로를 제거한다.
- stop 요청은 이미 `SharedTraceMemory.request_stop()`로 기록 가능하므로 Stage 3에서 RPC stop fallback을 제거할 수 있다.

## 승인 요청

- Stage 2 산출물과 검증 결과를 승인하면 Stage 3로 진행한다.
